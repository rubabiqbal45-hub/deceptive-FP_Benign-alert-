"""Synthetic mini-SOC alert generator.

Design goal
-----------
Produce alerts where some benign activity is *behaviourally indistinguishable*
from malicious activity under the deployed detection rule.  That is the
operational definition of a **deceptive false positive** used in this study:

    a benign alert whose context is so close to a true positive that
    suppressing it would also suppress a real attack in the same
    behavioural cluster.

Every detection rule is therefore fired by *both* a benign and a malicious
playbook, with identical rule name, process, parent process and command-line
template.  Only context differs.  No rule is a free win.

Cyber-kill-chain content is mapped to MITRE ATT&CK technique IDs so the feature
table can be joined with real telemetry later.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import numpy as np
import pandas as pd

from soc_triage.schema import RULE_SEVERITY, RULE_CATALOG

# --------------------------------------------------------------------------
# Rule-level metadata
# --------------------------------------------------------------------------
# Severity is a property of the *rule*, never of the playbook.  If severity
# tracked the ground-truth label the classifier would learn a trivial shortcut
# and the whole experiment would be invalid.  The catalog lives in
# ``soc_triage.schema`` so the lab bridge emits identical severities.

assert set(RULE_SEVERITY) == set(RULE_CATALOG)


@dataclass(frozen=True)
class Playbook:
    name: str
    kind: str                 # "benign" | "attack"
    deceptive: bool           # participates in a lookalike pair
    rule_id: str
    rule_name: str
    technique: str
    roles: tuple[str, ...]
    asset_types: tuple[str, ...]
    process: str
    parent: str
    cmd_template: str
    weight: float
    hour_mu: float = 11.0
    hour_sigma: float = 2.5
    off_hours_p: float = 0.15
    mismatch_p: float = 0.05
    blend: float = 0.2        # 0 = clean, 1 = maximally confused with the other class


ROLES = ("it_admin", "developer", "finance", "hr", "exec", "service_account", "sales")
ASSET_TYPES = ("workstation", "server", "domain_controller", "file_share")

# --------------------------------------------------------------------------
# Benign playbooks (7 lookalike + 2 clearly benign)
# --------------------------------------------------------------------------

BENIGN_PLAYBOOKS: tuple[Playbook, ...] = (
    Playbook(
        name="it_psexec_deploy", kind="benign", deceptive=True,
        rule_id="R-1021-002", rule_name="Remote Service Execution via PsExec",
        technique="T1021.002",
        roles=("it_admin",), asset_types=("workstation", "server"),
        process="psexec.exe", parent="services.exe",
        cmd_template=r"psexec.exe \\{host} -s -d cmd.exe /c {task}",
        weight=1.3, hour_mu=11.0, off_hours_p=0.12,
        mismatch_p=0.03, blend=0.45,
    ),
    Playbook(
        name="backup_powershell_enc", kind="benign", deceptive=True,
        rule_id="R-1059-001", rule_name="Suspicious PowerShell Encoded Command",
        technique="T1059.001",
        roles=("service_account",), asset_types=("server", "file_share"),
        process="powershell.exe", parent="taskeng.exe",
        cmd_template="powershell.exe -nop -w hidden -enc {b64}",
        weight=0.9, hour_mu=2.0, hour_sigma=1.0,
        off_hours_p=0.95, mismatch_p=0.06, blend=0.50,
    ),
    Playbook(
        name="monitoring_rundll32", kind="benign", deceptive=True,
        rule_id="R-1218-011", rule_name="Rundll32 Proxy Execution",
        technique="T1218.011",
        roles=("service_account", "it_admin"), asset_types=("server",),
        process="rundll32.exe", parent="svchost.exe",
        cmd_template="rundll32.exe {dll},Entry",
        weight=0.8, hour_mu=13.0, off_hours_p=0.60,
        mismatch_p=0.04, blend=0.40,
    ),
    Playbook(
        name="dev_curl_download", kind="benign", deceptive=True,
        rule_id="R-1105", rule_name="Ingress Tool Transfer over HTTP",
        technique="T1105",
        roles=("developer",), asset_types=("workstation",),
        process="curl.exe", parent="code.exe",
        cmd_template="curl.exe -o {file} {url}",
        weight=1.0, hour_mu=14.0, off_hours_p=0.20,
        mismatch_p=0.05, blend=0.35,
    ),
    Playbook(
        name="helpdesk_remote_tool", kind="benign", deceptive=True,
        rule_id="R-1219", rule_name="Remote Access Tool Execution",
        technique="T1219",
        roles=("it_admin", "service_account"), asset_types=("workstation", "server"),
        process="winvnc.exe", parent="services.exe",
        cmd_template="winvnc.exe -connect {ip}",
        weight=0.9, hour_mu=12.0, off_hours_p=0.15,
        mismatch_p=0.04, blend=0.40,
    ),
    Playbook(
        name="it_procdump_diag", kind="benign", deceptive=False,
        rule_id="R-1003-001", rule_name="LSASS Memory Access",
        technique="T1003.001",
        roles=("it_admin", "developer"), asset_types=("server", "workstation"),
        process="procdump.exe", parent="cmd.exe",
        cmd_template="procdump.exe -ma lsass.exe {out}",
        weight=1.0, hour_mu=11.5, off_hours_p=0.20,
        mismatch_p=0.05, blend=0.18,
    ),
    Playbook(
        name="vendor_schtask_update", kind="benign", deceptive=False,
        rule_id="R-1053-005", rule_name="Scheduled Task Creation",
        technique="T1053.005",
        roles=("service_account", "it_admin"), asset_types=("server", "workstation"),
        process="schtasks.exe", parent="services.exe",
        cmd_template="schtasks.exe /create /tn {t} /tr {cmd} /sc minute",
        weight=1.1, hour_mu=3.5, hour_sigma=1.5,
        off_hours_p=0.75, mismatch_p=0.06, blend=0.18,
    ),
    Playbook(
        name="finance_macro_doc", kind="benign", deceptive=False,
        rule_id="R-1204-002", rule_name="Office Macro Execution",
        technique="T1204.002",
        roles=("finance", "hr"), asset_types=("workstation",),
        process="excel.exe", parent="explorer.exe",
        cmd_template="excel.exe {xlsm}",
        weight=1.2, hour_mu=10.5, off_hours_p=0.10,
        mismatch_p=0.04, blend=0.12,
    ),
    Playbook(
        name="hr_vpn_login", kind="benign", deceptive=False,
        rule_id="R-1133", rule_name="External Remote Service Login",
        technique="T1133",
        roles=("hr", "sales", "exec"), asset_types=("workstation",),
        process="vpn_client.exe", parent="explorer.exe",
        cmd_template="vpn_client.exe --connect {gw}",
        weight=1.4, hour_mu=9.0, off_hours_p=0.25,
        mismatch_p=0.05, blend=0.10,
    ),
)

# --------------------------------------------------------------------------
# Malicious playbooks — one per rule above, all lookalikes
# --------------------------------------------------------------------------

ATTACK_PLAYBOOKS: tuple[Playbook, ...] = (
    Playbook(
        name="phish_powershell_enc", kind="attack", deceptive=True,
        rule_id="R-1059-001", rule_name="Suspicious PowerShell Encoded Command",
        technique="T1059.001",
        roles=("finance", "hr", "sales", "exec"), asset_types=("workstation",),
        process="powershell.exe", parent="winword.exe",
        cmd_template="powershell.exe -nop -w hidden -enc {b64}",
        weight=1.2, hour_mu=10.0, off_hours_p=0.35,
        mismatch_p=0.45, blend=0.55,
    ),
    Playbook(
        name="cred_psexec_lateral", kind="attack", deceptive=True,
        rule_id="R-1021-002", rule_name="Remote Service Execution via PsExec",
        technique="T1021.002",
        roles=("it_admin",), asset_types=("server", "domain_controller"),
        process="psexec.exe", parent="services.exe",
        cmd_template=r"psexec.exe \\{host} -s -d cmd.exe /c {task}",
        weight=1.0, hour_mu=11.0, off_hours_p=0.55,
        mismatch_p=0.40, blend=0.60,
    ),
    Playbook(
        name="lsass_dump", kind="attack", deceptive=False,
        rule_id="R-1003-001", rule_name="LSASS Memory Access",
        technique="T1003.001",
        roles=("developer", "finance", "it_admin", "service_account"), asset_types=("workstation", "server"),
        process="procdump.exe", parent="cmd.exe",
        cmd_template="procdump.exe -ma lsass.exe {out}",
        weight=0.9, hour_mu=11.0, off_hours_p=0.40,
        mismatch_p=0.55, blend=0.18,
    ),
    Playbook(
        name="ransomware_schtask", kind="attack", deceptive=False,
        rule_id="R-1053-005", rule_name="Scheduled Task Creation",
        technique="T1053.005",
        roles=("service_account", "it_admin", "developer"), asset_types=("server", "workstation"),
        process="schtasks.exe", parent="cmd.exe",
        cmd_template="schtasks.exe /create /tn {t} /tr {cmd} /sc minute",
        weight=0.8, hour_mu=3.0, hour_sigma=1.5,
        off_hours_p=0.80, mismatch_p=0.50, blend=0.18,
    ),
    Playbook(
        name="c2_beacon", kind="attack", deceptive=True,
        rule_id="R-1071-001", rule_name="Application Layer C2 Beacon",
        technique="T1071.001",
        roles=("finance", "sales", "developer", "hr", "exec", "service_account"), asset_types=("workstation",),
        process="rundll32.exe", parent="explorer.exe",
        cmd_template="rundll32.exe {dll},Start",
        weight=1.2, hour_mu=12.0, off_hours_p=0.50,
        mismatch_p=0.40, blend=0.50,
    ),
    Playbook(
        name="dll_sideload", kind="attack", deceptive=True,
        rule_id="R-1218-011", rule_name="Rundll32 Proxy Execution",
        technique="T1218.011",
        roles=("finance", "sales", "hr", "exec"), asset_types=("workstation",),
        process="rundll32.exe", parent="winword.exe",
        cmd_template="rundll32.exe {dll},Entry",
        weight=1.1, hour_mu=10.5, off_hours_p=0.30,
        mismatch_p=0.45, blend=0.55,
    ),
)

# A benign counterpart exists for the C2 rule as well, so that no rule is a
# free win for the classifier.
BENIGN_PLAYBOOKS = BENIGN_PLAYBOOKS + (
    Playbook(
        name="edr_heartbeat", kind="benign", deceptive=True,
        rule_id="R-1071-001", rule_name="Application Layer C2 Beacon",
        technique="T1071.001",
        roles=("service_account",), asset_types=("workstation", "server"),
        process="rundll32.exe", parent="explorer.exe",
        cmd_template="rundll32.exe {dll},Start",
        weight=1.0, hour_mu=12.0, off_hours_p=0.45,
        mismatch_p=0.05, blend=0.45,
    ),
)

# Latent "clean" vs "anomalous" distributions: (mean, sd) of a clipped normal.
# The gap is deliberately small — each individual context signal is weak, and
# only their combination carries real information.  This mirrors a real SOC,
# where no single field tells you whether an alert is a false positive.
_CLEAN = {
    "novelty": (0.38, 0.19),
    "peer": (0.36, 0.19),
    "cmd": (0.36, 0.19),
    "dst": (0.32, 0.18),
    "signed": (0.72, 0.16),
    "lineage": (1.4, 0.9),
}
_ANOMALOUS = {
    "novelty": (0.58, 0.20),
    "peer": (0.58, 0.20),
    "cmd": (0.58, 0.20),
    "dst": (0.54, 0.20),
    "signed": (0.44, 0.22),
    "lineage": (2.7, 1.0),
}

_TASKS = ("install_msi", "restart_svc", "apply_patch", "rotate_logs", "sync_inventory")
_DLLS = ("C:\\Windows\\System32\\perfmon.dll", "C:\\Windows\\System32\\winmm.dll",
         "C:\\ProgramData\\Corp\\monitor.dll", "C:\\Users\\Public\\lib\\upd.dll")
_URLS = ("https://cdn.corp.example/asset.zip", "http://update.corp.example/patch.exe",
         "https://files.dev.example/v2.tar.gz")
_IPS = ("10.20.4.11", "10.20.4.55", "10.20.9.3")


def _render(template: str, host: str, rng: np.random.Generator) -> str:
    """Fill a command-line template with plausible random tokens.

    Every random draw comes from the seeded generator. The base64 payload used
    to come from ``os.urandom``, which silently defeated reproducibility: two
    runs with the same seed produced different command lines, different
    command-line features, and slightly different model metrics.
    """
    if "{b64}" in template:
        enc = base64.b64encode(rng.bytes(30)).decode().rstrip("=")
        return template.replace("{b64}", enc)
    return (
        template
        .replace("{host}", host)
        .replace("{task}", str(rng.choice(_TASKS)))
        .replace("{dll}", str(rng.choice(_DLLS)))
        .replace("{url}", str(rng.choice(_URLS)))
        .replace("{file}", "bundle.zip")
        .replace("{ip}", str(rng.choice(_IPS)))
        .replace("{gw}", "vpn.corp.example")
        .replace("{t}", "CorpUpdater")
        .replace("{cmd}", "C:\\Windows\\Temp\\svc.exe")
        .replace("{xlsm}", "Q3_forecast.xlsm")
        .replace("{out}", "C:\\Windows\\Temp\\d.dmp")
    )


def _weighted_index(rng: np.random.Generator, weights: np.ndarray) -> int:
    return int(rng.choice(len(weights), p=weights / weights.sum()))


def _host_table(rng: np.random.Generator):
    rows = []
    for i in range(1, 47):
        rows.append((f"WS-{i:03d}", "workstation", int(rng.integers(1, 4))))
    for i in range(1, 11):
        rows.append((f"SRV-{i:02d}", "server", int(rng.integers(3, 6))))
    rows.append(("DC-01", "domain_controller", 5))
    for i in range(1, 4):
        rows.append((f"FS-{i:02d}", "file_share", int(rng.integers(3, 5))))
    df = pd.DataFrame(rows, columns=["host_id", "asset_type", "asset_criticality"])
    pools = {t: df.loc[df.asset_type == t, "host_id"].to_numpy() for t in ASSET_TYPES}
    return df, pools


def _user_table(rng: np.random.Generator):
    counts = {"it_admin": 6, "developer": 10, "finance": 12, "hr": 9,
              "exec": 8, "service_account": 6, "sales": 14}
    rows, n = [], 0
    for role, c in counts.items():
        for _ in range(c):
            n += 1
            rows.append((f"u{n:03d}", role))
    df = pd.DataFrame(rows, columns=["user_id", "user_role"])
    pools = {r: df.loc[df.user_role == r, "user_id"].to_numpy() for r in ROLES}
    return df, pools


def _context(rng: np.random.Generator, pb: Playbook, is_attack: bool,
             hard: bool) -> dict[str, float]:
    """Sample the context vector, blending clean/anomalous behaviour.

    ``hard`` samples are drawn close to the *opposite* class, which is what
    makes some false positives deceptive and some attacks stealthy.
    """
    w = 0.60 * pb.blend
    if hard:
        w = min(0.90, w + rng.uniform(0.20, 0.40))

    def draw(key: str, anomalous: bool) -> float:
        m, s = (_ANOMALOUS if anomalous else _CLEAN)[key]
        return float(np.clip(rng.normal(m, s), 0.0, 4.0))

    def mix(key: str) -> float:
        clean = draw(key, False)
        anom = draw(key, True)
        # benign -> pushed toward anomalous; attack -> pushed toward clean
        return (1.0 - w) * anom + w * clean if is_attack else (1.0 - w) * clean + w * anom

    def jitter(x: float, s: float = 0.10) -> float:
        return float(np.clip(x + rng.normal(0.0, s), 0.0, 1.0))

    return {
        "host_novelty": jitter(mix("novelty")),
        "peer_rarity": jitter(mix("peer")),
        "cmdline_distance": jitter(mix("cmd")),
        "dst_reputation": jitter(mix("dst"), 0.08),
        "signed_ratio": jitter(mix("signed")),
        "lineage_depth": int(round(np.clip(mix("lineage"), 0.0, 4.0))),
    }


def generate_alerts(cfg) -> pd.DataFrame:
    """Return a labelled alert stream covering the configured time span."""
    rng = np.random.default_rng(cfg.seed)
    hosts, host_pools = _host_table(rng)
    users, user_pools = _user_table(rng)
    host_meta = hosts.set_index("host_id")

    start = pd.Timestamp(cfg.start_date)
    total_days = cfg.weeks * 7
    biz_days = np.array([d for d in np.arange(total_days)
                         if (start + pd.Timedelta(days=int(d))).weekday() < 5])

    books = {"benign": BENIGN_PLAYBOOKS, "attack": ATTACK_PLAYBOOKS}
    weights = {k: np.array([p.weight for p in v]) for k, v in books.items()}

    rows: list[dict] = []
    scenario = 0
    last_attack_host: str | None = None

    while len(rows) < cfg.n_alerts:
        kind = "attack" if rng.random() < cfg.attack_rate else "benign"
        pool = books[kind]
        pb = pool[_weighted_index(rng, weights[kind])]
        is_attack = kind == "attack"

        asset = str(rng.choice(pb.asset_types))
        if is_attack and last_attack_host is not None and rng.random() < 0.25:
            host = last_attack_host
            asset = str(host_meta.loc[host, "asset_type"])
        else:
            host = str(rng.choice(host_pools[asset]))
        if is_attack:
            last_attack_host = host

        role = str(rng.choice(pb.roles))
        user = str(rng.choice(user_pools[role]))

        day = int(rng.choice(biz_days))
        if rng.random() < pb.off_hours_p:
            hour = int(rng.choice([0, 1, 2, 3, 4, 5, 21, 22, 23]))
        else:
            hour = int(np.clip(rng.normal(pb.hour_mu, pb.hour_sigma), 7, 20))
        t0 = start + pd.Timedelta(days=day, hours=hour,
                                  minutes=int(rng.integers(0, 60)),
                                  seconds=int(rng.integers(0, 60)))

        n_emit = int(rng.integers(1, 6))
        hard = rng.random() < (0.35 if is_attack else 0.18)
        ctx = _context(rng, pb, is_attack, hard)
        # Instrumentation noise: roughly one alert in eight arrives with a
        # corrupted context field, standing in for telemetry gaps in real SIEMs.
        if rng.random() < 0.12:
            corrupt = str(rng.choice(["host_novelty", "peer_rarity",
                                      "cmdline_distance", "dst_reputation",
                                      "signed_ratio"]))
            ctx[corrupt] = float(rng.random())
        cmd = _render(pb.cmd_template, host, rng)
        mismatch = bool(rng.random() < (pb.mismatch_p + (0.10 if hard else 0.0)))
        scenario += 1

        for _ in range(n_emit):
            rows.append({
                "scenario_id": scenario,
                "playbook": pb.name,
                "ts": t0 + pd.Timedelta(seconds=int(rng.integers(0, 1800))),
                "host_id": host,
                "asset_type": asset,
                "asset_criticality": int(host_meta.loc[host, "asset_criticality"]),
                "user_id": user,
                "user_role": role,
                "rule_id": pb.rule_id,
                "rule_name": pb.rule_name,
                "technique": pb.technique,
                "severity": RULE_SEVERITY[pb.rule_id],
                "process_name": pb.process,
                "parent_process": pb.parent,
                "command_line": cmd,
                "event_count": int(rng.poisson(6 if is_attack else 3)) + 1,
                "host_novelty": ctx["host_novelty"],
                "peer_rarity": ctx["peer_rarity"],
                "cmdline_distance": ctx["cmdline_distance"],
                "dst_reputation": ctx["dst_reputation"],
                "signed_ratio": ctx["signed_ratio"],
                "lineage_depth": ctx["lineage_depth"],
                "role_asset_mismatch": int(mismatch),
                "burst_size": n_emit,
                "label": int(is_attack),
                "is_deceptive_fp": int(pb.deceptive and not is_attack),
                "is_deceptive_attack": int(pb.deceptive and is_attack),
            })

    df = pd.DataFrame(rows[: cfg.n_alerts * 2])
    df = df.sort_values("ts", kind="mergesort").reset_index(drop=True)
    df["alert_id"] = [f"AL-{i:06d}" for i in range(len(df))]
    df["week"] = ((df["ts"] - start).dt.days // 7 + 1).astype(int)
    df["dow"] = df["ts"].dt.day_of_week.astype(int)
    return df


def inject_drift(df: pd.DataFrame, cfg) -> pd.DataFrame:
    """Simulate a benign-automation rollout that inflates FPs after week N.

    A new admin script starts firing a previously-quiet rule on many hosts, so
    the model's learned base rate for that rule silently becomes wrong.
    """
    rng = np.random.default_rng(cfg.seed + 7)
    out = df.copy()
    target = (out["week"] >= cfg.drift_week) & (out["rule_id"] == "R-1219")
    if not target.any():
        return out
    idx = out.index[target]
    pick = rng.choice(idx, size=int(len(idx) * 0.55), replace=False)
    for col, scale in (("host_novelty", 0.35), ("peer_rarity", 0.30),
                       ("cmdline_distance", 0.30), ("dst_reputation", 0.40)):
        out.loc[pick, col] = np.clip(out.loc[pick, col] * scale, 0, 1)
    return out


def inject_adversarial(df: pd.DataFrame, cfg) -> pd.DataFrame:
    """Simulate an attacker deliberately imitating benign administrative context.

    A fraction of attacks adopt the context profile of the corresponding benign
    playbook: aligned role, business hours, good destination reputation and a
    baseline-typical command line.
    """
    rng = np.random.default_rng(cfg.seed + 11)
    out = df.copy()
    out["adversarial"] = 0
    atk_idx = out.index[out["label"] == 1]
    n = int(len(atk_idx) * cfg.adversarial_fraction)
    if n == 0:
        return out
    pick = rng.choice(atk_idx, size=n, replace=False)
    out.loc[pick, "host_novelty"] = np.clip(rng.beta(2, 6, n), 0, 1)
    out.loc[pick, "peer_rarity"] = np.clip(rng.beta(1.5, 6, n), 0, 1)
    out.loc[pick, "cmdline_distance"] = np.clip(rng.beta(1.5, 8, n), 0, 1)
    out.loc[pick, "dst_reputation"] = np.clip(rng.beta(1.2, 10, n), 0, 1)
    out.loc[pick, "signed_ratio"] = np.clip(rng.beta(9, 1.5, n), 0, 1)
    out.loc[pick, "role_asset_mismatch"] = 0
    out.loc[pick, "adversarial"] = 1
    return out
