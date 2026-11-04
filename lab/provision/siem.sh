#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# SIEM node: Docker + single-node Wazuh (manager, indexer, dashboard).
#
# Pinned to Wazuh 4.9 so the lab stays reproducible. If you change WAZUH_TAG,
# record it in the thesis: rule and decoder behaviour differs between releases.
#
# This script also does one thing the upstream install does not: it enables
# <logall_json>yes</logall_json>. Without it the manager only writes
# alerts.json, which contains *rule-matched* events. The bridge needs the raw
# Sysmon stream (archives.json), because the detection pack is applied on the
# Python side. See lab/README.md, "Why archives.json".
# ---------------------------------------------------------------------------
set -euo pipefail

SUBNET="${1:-192.168.56.0/24}"
WAZUH_TAG="v4.9.0"
INSTALL_DIR="/opt/wazuh-docker"

echo "[1/7] base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl git jq unzip ufw python3

echo "[2/7] docker"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
usermod -aG docker vagrant || true
systemctl enable --now docker

echo "[3/7] wazuh-docker ${WAZUH_TAG}"
if [ ! -d "${INSTALL_DIR}" ]; then
  git clone --depth 1 --branch "${WAZUH_TAG}" \
      https://github.com/wazuh/wazuh-docker.git "${INSTALL_DIR}"
fi
cd "${INSTALL_DIR}/single-node"

# ---------------------------------------------------------------------------
# Enable full JSON archiving before the stack starts.
# ---------------------------------------------------------------------------
MANAGER_CONF=""
for candidate in \
    "config/wazuh_cluster/wazuh_manager.conf" \
    "config/wazuh_cluster/ossec.conf" \
    "config/wazuh_manager.conf"; do
  if [ -f "${candidate}" ]; then MANAGER_CONF="${candidate}"; break; fi
done

if [ -z "${MANAGER_CONF}" ]; then
  echo "!! could not find the manager config under $(pwd)/config" >&2
  exit 1
fi

echo "[4/7] enabling logall_json in ${MANAGER_CONF}"
python3 - "${MANAGER_CONF}" <<'PY'
import re
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    text = fh.read()

def set_tag(text, tag, value):
    pattern = rf"<{tag}>\s*(?:yes|no)\s*</{tag}>"
    if re.search(pattern, text):
        return re.sub(pattern, f"<{tag}>{value}</{tag}>", text)
    if "<global>" in text:
        return text.replace(
            "<global>", f"<global>\n    <{tag}>{value}</{tag}>", 1)
    return text.replace(
        "</ossec_config>",
        f"  <global>\n    <{tag}>{value}</{tag}>\n  </global>\n</ossec_config>",
        1)

for tag, value in (("jsonout_output", "yes"),
                   ("alerts_log", "yes"),
                   ("logall", "no"),
                   ("logall_json", "yes")):
    text = set_tag(text, tag, value)

with open(path, "w", encoding="utf-8") as fh:
    fh.write(text)
print("  logall_json=yes, jsonout_output=yes")
PY

grep -q "<logall_json>yes</logall_json>" "${MANAGER_CONF}" || {
  echo "!! failed to enable logall_json" >&2; exit 1; }

echo "[5/7] generating indexer certificates (first run only)"
if [ ! -f ./config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
  docker compose -f generate-indexer-certs.yml run --rm generator
fi

# OpenSearch refuses to start when vm.max_map_count is the Ubuntu default
# (65530). This is required, not optional; without it the indexer container
# crash-loops and the dashboard never comes up.
sysctl -w vm.max_map_count=262144 >/dev/null
echo "vm.max_map_count=262144" >/etc/sysctl.d/99-wazuh.conf

echo "[6/7] starting the stack (this takes 3-5 minutes)"
docker compose up -d

# If the stack was already running, pick up the config change.
if [ "${MANAGER_CONF}" != "" ]; then
  docker compose restart wazuh.manager >/dev/null 2>&1 || true
fi

echo "[7/7] firewall, upload endpoint, capture helper"
# Vagrant SSH arrives over the NAT interface (10.0.2.2), not the host-only
# subnet, so allowing 22 only from $SUBNET locks you out the moment ufw is
# enabled. Keep SSH open; everything else stays scoped to the lab network.
ufw allow 22/tcp || true
ufw allow from "${SUBNET}" to any port 443   proto tcp || true
ufw allow from "${SUBNET}" to any port 1514  proto tcp || true
ufw allow from "${SUBNET}" to any port 1515  proto tcp || true
ufw allow from "${SUBNET}" to any port 8088  proto tcp || true
ufw allow from "${SUBNET}" to any port 55000 proto tcp || true
ufw allow from "${SUBNET}" to any port 9200  proto tcp || true
ufw allow from "${SUBNET}" to any port 22    proto tcp || true
ufw --force enable || true

# ---------------------------------------------------------------------------
# Ground-truth upload endpoint (writes into the shared folder).
# ---------------------------------------------------------------------------
mkdir -p /opt/lab /vagrant/lab/out
if [ -f /vagrant/lab/collect/upload-server.py ]; then
  cp /vagrant/lab/collect/upload-server.py /opt/lab/upload-server.py
  cat >/etc/systemd/system/lab-upload.service <<'UNIT'
[Unit]
Description=Mini-SOC lab ground-truth upload endpoint
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/lab/upload-server.py --outdir /vagrant/lab/out
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now lab-upload.service
fi

# ---------------------------------------------------------------------------
# pull-alerts: copy telemetry out of the manager container.
#
# Default source is archives.json (all events). Pass `alerts` as the second
# argument, or set WAZUH_SOURCE=alerts, to get only rule-matched alerts.
# ---------------------------------------------------------------------------
cat >/usr/local/bin/pull-alerts <<'EOF'
#!/usr/bin/env bash
# usage: pull-alerts [ISO8601-SINCE] [archives|alerts]
set -euo pipefail

SINCE="${1:-}"
WHICH="${2:-${WAZUH_SOURCE:-archives}}"
mkdir -p /vagrant/lab/out

CID="$(docker ps --format '{{.Names}}' | grep -E 'wazuh.*manager' | head -n1)"
if [ -z "${CID}" ]; then
  echo "manager container not running" >&2
  exit 1
fi

if [ "${WHICH}" = "alerts" ]; then
  SRC=/var/ossec/logs/alerts/alerts.json
  OUT=/vagrant/lab/out/alerts.json
else
  SRC=/var/ossec/logs/archives/archives.json
  OUT=/vagrant/lab/out/archives.json
fi

TMP="$(mktemp)"
if ! docker cp "${CID}:${SRC}" "${TMP}" 2>/dev/null; then
  echo "!! ${SRC} not found." >&2
  echo "   archives.json only exists when <logall_json>yes</logall_json> is set." >&2
  echo "   Falling back to alerts.json (rule-matched events only)." >&2
  SRC=/var/ossec/logs/alerts/alerts.json
  OUT=/vagrant/lab/out/alerts.json
  docker cp "${CID}:${SRC}" "${TMP}"
fi

if [ -n "${SINCE}" ] && command -v jq >/dev/null 2>&1; then
  # Wazuh writes '2026-01-05T01:02:32.123+0000'; compare at second resolution.
  KEY="${SINCE:0:19}"
  jq -c --arg s "${KEY}" 'select((.timestamp // "")[0:19] >= $s)' "${TMP}" > "${OUT}"
else
  cp "${TMP}" "${OUT}"
fi
rm -f "${TMP}"

BYTES="$(stat -c %s "${OUT}" 2>/dev/null || echo 0)"
echo "wrote ${OUT} ($(wc -l < "${OUT}") lines, ${BYTES} bytes)"
echo "now run (on the host):"
echo "  python lab/bridge/build_dataset.py --alerts lab/out/$(basename "${OUT}") \\"
echo "         --truth lab/out/ground_truth.csv"
EOF
chmod +x /usr/local/bin/pull-alerts

cat >/usr/local/bin/lab-status <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "--- containers"
docker ps --format '{{.Names}}\t{{.Status}}'
echo "--- agents"
CID="$(docker ps --format '{{.Names}}' | grep -E 'wazuh.*manager' | head -n1 || true)"
[ -n "${CID}" ] && docker exec "${CID}" /var/ossec/bin/agent_control -l || true
echo "--- archive sizes (inside manager)"
[ -n "${CID}" ] && docker exec "${CID}" sh -c 'ls -lh /var/ossec/logs/archives/ 2>/dev/null | tail -n 5' || true
echo "--- upload endpoint"
curl -s --max-time 3 http://127.0.0.1:8088/health || echo "not responding"
EOF
chmod +x /usr/local/bin/lab-status

cat >/vagrant/lab/out/README.txt <<'EOF'
Files written here by the lab:

  archives.json      raw Wazuh archive stream (all events)  <- default capture
  alerts.json        rule-matched alerts only (fallback)
  ground_truth.csv   uploaded by run-atomics.ps1 on the victim
  run_manifest.json  versions and pass/fail counts for that run
  lab_dataset.csv    written by lab/bridge/build_dataset.py

Archives are rotated daily by the manager. Pull them before rotation, or
increase <logall_json> retention in the manager config if you need a longer
history. Full archiving is high volume: expect ~1 GB/day on a busy desktop.
EOF

echo
echo "Wazuh dashboard: https://192.168.56.10  (admin / SecretPassword)"
echo "Credentials are the upstream docker-compose defaults; change them."
echo "Upload endpoint: http://192.168.56.10:8088/health"
echo "Check agents:    lab-status"
echo "Pull telemetry:  pull-alerts '$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%S)'"
