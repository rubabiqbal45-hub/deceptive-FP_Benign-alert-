# Mini-SOC lab: capture real telemetry, run the same pipeline

This directory builds a small, isolated SOC range and turns its telemetry into
the **exact table** that `run_experiments.py` already consumes. Nothing in
`src/soc_triage/` changes. That is the point: the synthetic study supplies the
scale, the lab supplies the reality check.

```
Windows victim ──Sysmon──► Wazuh agent ──► Wazuh manager ──► archives.json
      │                                                          │
      └── run-atomics.ps1 ──► ground_truth.csv ──► lab/bridge ───┘
                                                      │
                                                      ▼
                                            lab/out/lab_dataset.csv
                                                      │
                                                      ▼
                              python run_experiments.py --source csv
```

---

## 1. What this lab can and cannot show

**It can show**

* that the adapter is real: raw Sysmon/Wazuh events survive normalisation,
  de-duplication, detection, feature construction, labelling and schema checks;
* that the *deceptive false positive* definition is computable from measured
  telemetry rather than asserted by a generator;
* per-rule detection behaviour, including which rules fire for benign
  administrative work;
* whether the feature set still separates classes when the features are
  **measured** instead of sampled from the generator's latent distributions.

**It cannot show**

* enterprise-scale queueing or cost effects. Two VMs over three days produce
  a few thousand detections; the queue is never under pressure. The operations
  section of the lab report will read ~0 minutes of wait and that is honest,
  not a result.
* tight statistical guarantees. Risk-controlled suppression needs enough
  calibration attacks to certify a bound. A short capture has tens, not
  thousands, so the certified bounds are loose or infeasible. The pipeline
  prints a warning when this happens; report it.
* external validity. This is a range with one victim, a handful of users and a
  scripted attacker. Effect sizes are directional only.

The synthetic study (`results/report.md`) remains the primary evidence. The
lab answers a different question: *does the pipeline survive contact with real
data?*

---

## 2. Topology

| VM | IP | Role | RAM | Notes |
|---|---|---|---|---|
| `soc-siem` | 192.168.56.10 | Wazuh 4.9 single-node (Docker) + upload endpoint | 6 GB | manager, indexer, dashboard |
| `soc-victim` | 192.168.56.12 | Windows Server 2022, Sysmon, Wazuh agent | 4 GB | atomic + benign traffic |
| `dc-01` *(optional)* | 192.168.56.11 | AD DS `corp.local`, users, file share | 2 GB | makes lateral movement real |

Host-only network `192.168.56.0/24`. Both Windows boxes can reach the internet
for tooling downloads during provisioning; after that, **disconnect them**.
Nothing in this lab needs a real external C2, and the scripts deliberately use
unresolvable `*.example` domains.

---

## 3. Prerequisites

| Item | Minimum | Check |
|---|---|---|
| Vagrant | 2.3 | `vagrant --version` |
| VirtualBox | 7.x | `VBoxManage --version` |
| Free disk | ~40 GB | boxes + virtual disks |
| Free RAM | 10 GB for two VMs | 12 GB if you add `dc-01` |
| Python (host) | 3.11+ | `python --version` |

A host shell that can run `vagrant` and `python`.

**Windows host, one-time setup.** Run this once in an elevated PowerShell:

```powershell
winget install --id Hashicorp.Vagrant --exact
winget install --id Oracle.VirtualBox --exact

# VirtualBox needs this when VBS/WSL2 already own the hypervisor
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All
```

Then, if `C:` is short on space, keep the large artifacts off it. These are
user-level settings and are reversible:

```powershell
[Environment]::SetEnvironmentVariable("VAGRANT_HOME", "D:\vagrant.d", "User")
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" setproperty machinefolder "D:\VirtualBox VMs"
```

Open a **new** terminal afterwards so `vagrant` and `VBoxManage` are on
`PATH`. Verify the hypervisor is usable before downloading any boxes:

```powershell
VBoxManage list hostinfo | Select-String "HW virtualization"
# Processor supports HW virtualization: yes
```

If the host has less than the recommended RAM, scale the VMs down without
editing the Vagrantfile. Defaults are 6144 / 4096 / 2048 MB:

```powershell
$env:LAB_SIEM_MEM   = "4096"
$env:LAB_VICTIM_MEM = "3072"
vagrant up soc-siem soc-victim
```

Finally, PowerShell blocks unsigned scripts by default. Scope the bypass to
one window; do not change the machine policy:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

Snapshot after provisioning completes, before you run any attack:

```powershell
vagrant snapshot save soc-siem  clean
vagrant snapshot save soc-victim clean
```

You will want to roll back after a messy run.

---

## 4. Phase 0 — validate the bridge without any VMs (5 minutes)

Do this first. It proves the Python side before you spend an hour on VMs.

```powershell
python lab/make_fixture.py --n-alerts 4000
python lab/bridge/build_dataset.py `
    --alerts lab/out/fixture/alerts.json `
    --truth  lab/out/fixture/ground_truth.csv `
    --out    lab/out/fixture/lab_dataset.csv
python run_experiments.py --source csv `
    --path lab/out/fixture/lab_dataset.csv --outdir results_fixture
```

Expected on the reference machine: 3,052 detections, 8 rules, 4.0% attack rate,
38.6% deceptive-FP rate, 26 test attacks. Do **not** expect the synthetic
numbers here.

Reference run on that fixture:

| Model | ROC-AUC | PR-AUC | ECE |
|---|---|---|---|
| B2 logistic regression | 0.9396 | 0.5095 | 0.0213 |
| B0 rule severity | 0.7784 | 0.0587 | 0.4771 |
| B3 random forest | 0.7031 | 0.4236 | 0.0360 |
| M1 native GBM triage | 0.6594 | 0.4321 | 0.0133 |
| B1 rule base-rate | 0.6152 | 0.0378 | 0.0165 |

The proposed model **loses to logistic regression** at this size, and the
report now prints a small-capture caveat saying so. That is the correct
behaviour, not a tuning failure:

* Training contains 64 attack examples across 8 rules; the test window has 26,
  concentrated in two rules. Ranking metrics at that size are mostly variance.
* Hyperparameters (`max_leaf_nodes=63`, 800 boosting rounds) are set for the
  48k-alert stream. On 1,456 rows a *single* tree already reaches train
  ROC-AUC 0.98 and held-out 0.76, and every extra round makes held-out ranking
  worse: the model has enough capacity to memorise 64 positives.
* The bridge measures only what an analyst could see at triage time.
  `lineage_depth` collapses to a constant on the fixture because the synthetic
  Wazuh payload contains no parent-process creation records; the real Sysmon
  capture does. `hist_*` features also drift strongly across the split (79% of
  test rows exceed the training maximum), which trees cannot extrapolate
  across but a linear model can.

The honest reading: the adapter is validated end-to-end on realistic payloads,
the deceptive-FP definition is computable from a capture, and the model result
is **not** interpretable at 3k rows. The generator/bridge gap is itself a
finding for the thesis — it says a deployable version needs either a longer
capture or hyperparameters chosen per-data-size, and that a simple logistic
baseline is hard to beat on small SOC data.

The fixture is a **plumbing test only**. Its ground truth comes from the
simulator, so it cannot support any claim about detection quality.

---

## 5. Phase 1 — bring up the range (60–90 min first time)

```powershell
cd lab
vagrant up soc-siem soc-victim
```

What happens:

1. `siem.sh` installs Docker, clones `wazuh-docker` at `v4.9.0`, **enables
   `<logall_json>yes</logall_json>`**, starts the stack, installs a
   ground-truth upload endpoint on port 8088, and writes `pull-alerts` and
   `lab-status` helpers.
2. `windows-common.ps1` installs Sysmon with `lab/sysmon/sysmon-lab.xml`,
   installs the Wazuh agent, adds the Sysmon and Security event channels,
   enables logon/process-creation auditing, and drops PsExec/procdump in
   `C:\Tools`.

Verify:

```powershell
vagrant ssh soc-siem -c "lab-status"
```

You want three containers `Up`, the agent listed as `Active`, and
`http://127.0.0.1:8088/health` returning `{"ok": true}`.

Open the dashboard at <https://192.168.56.10> (`admin` / `SecretPassword`,
the upstream defaults — change them if the VM is ever reachable from a real
network).

### Why `archives.json`

`alerts.json` contains only events that matched a Wazuh rule. The bridge
applies its **own** detection pack (`lab/bridge/detect.py`) so the rule
semantics are stable across Wazuh ruleset versions. That means it needs the
raw Sysmon stream, which Wazuh writes to `archives.json` only when
`<logall_json>` is enabled.

Full archiving is high volume (order of a gigabyte per day per busy desktop)
and is a **lab-only setting**. Production deployments forward selected events;
they do not keep every Sysmon record.

Archives rotate daily inside the container. Pull before rotation, or raise
retention in the manager config if you need a longer window.

---

## 6. Phase 2 — run the attack and benign captures

On the victim:

```powershell
cd C:\vagrant\lab\attack       # if the shared folder is mounted
# otherwise copy this directory to the victim first (see §10)
.\install-atomic.ps1
.\run-atomics.ps1 -DryRun      # list what will execute
.\run-atomics.ps1              # execute + write + upload ground truth
```

`run-atomics.ps1`:

* reads `atomics.csv` (technique → rule mapping);
* discovers test numbers from the installed atomics version by keyword, so a
  renumbered test does not silently run the wrong thing;
* records a UTC window per test and writes `lab/out/ground_truth.csv`;
* uploads it to the SIEM so the host can read it from the shared folder;
* marks tests that look blocked by Defender with `status=blocked`.

Then generate the benign twin traffic:

```powershell
.\run-benign.ps1 -Count 8 -GapSeconds 60
```

Run it again on two or three quiet days, and during working hours, so the
benign class is not all "attack hour". A capture that only contains attack
windows will make the model look far better than it is.

### Why the benign script looks like the attack script

`run-benign.ps1` deliberately uses the same binaries and parent processes as
the atomic tests: encoded PowerShell from a management shell, `schtasks
/create`, `curl -o`, `rundll32` from PowerShell, PsExec maintenance, VNC.
That is what makes a false positive *deceptive* under the thesis definition —
its behavioural signature (`rule | process | parent`) also occurs in the
malicious class, so suppressing it suppresses a real attack too.

Benign traffic that shares nothing with the attacks is merely noisy. It would
inflate the suppression numbers without testing the thing the thesis is about.

---

## 7. Phase 3 — export and run (10 minutes)

From the repo root on the host:

```powershell
cd lab
.\collect\export-wazuh.ps1 -Since 2026-02-10T00:00:00
```

That pulls `archives.json`, builds `lab/out/lab_dataset.csv`, and runs the
study into `results_lab/`. The manual equivalent:

```powershell
vagrant ssh soc-siem -c "pull-alerts '2026-02-10T00:00:00' archives"
python lab\bridge\build_dataset.py `
    --alerts lab\out\archives.json `
    --truth  lab\out\ground_truth.csv
python run_experiments.py --source csv `
    --path lab\out\lab_dataset.csv --outdir results_lab
```

Read `results_lab/report.md`. The provenance banner states that the data is an
ingested capture, §6 is reported as unavailable (drift/adversarial injection
would be fabrication on real data), and the limitations section changes
accordingly.

### Build-time checks the bridge performs

| Check | Failure means |
|---|---|
| per-rule detection counts printed | a rule at zero is usually a Sysmon filter problem |
| `attack rate`, `deceptive FP rate` | near 0% attack → ground truth did not match |
| `deceptive attacks` | 0 → benign and attack signatures never overlap |
| hard error on `no true positives` | wrong host name, wrong timezone, or blocked atomics |

Do not "fix" a zero by loosening `--slack-seconds` until something matches.
Find out why the event is missing.

---

## 8. Phase 4 — optional domain controller

```powershell
vagrant up dc-01             # promotes the forest, schedules a reboot
vagrant reload dc-01         # wait for the reboot
vagrant provision dc-01      # creates OUs, users, groups, \\dc-01\finance
```

Users and roles mirror `lab/inventory/users.csv` (`alice`, `bob`,
`svc-backup`, `svc-monitor`, `carol`, `dave`, `erin`, `frank`). Keep the two
lists in sync: the bridge resolves identities by account name, and a missing
account degrades silently to `role=unclassified`, which switches off
`role_asset_mismatch`.

Join the victim to the domain by hand if you want domain logons:

```powershell
Add-Computer -DomainName corp.local -Credential CORP\alice -Restart
```

---

## 9. Detection coverage

`lab/bridge/detect.py` is a transparent Sigma-lite pack over Sysmon fields.
It is intentionally not tied to Wazuh rule IDs, which change between ruleset
versions and are often disabled.

| Rule | Technique | Evidence used | Status |
|---|---|---|---|
| R-1021-002 | T1021.002 | ProcessCreate: `psexec.exe` / `psexesvc.exe` | full |
| R-1059-001 | T1059.001 | ProcessCreate: PowerShell + `-enc`/`-encodedcommand` + `-nop`/`hidden`/`bypass` | full |
| R-1218-011 | T1218.011 | ProcessCreate: `rundll32.exe` + DLL argument | full |
| R-1105 | T1105 | ProcessCreate: `curl`/`certutil`/`bitsadmin` + URL + output flag | full |
| R-1219 | T1219 | ProcessCreate: known remote-access binaries | full |
| R-1053-005 | T1053.005 | ProcessCreate: `schtasks /create` | full |
| R-1071-001 | T1071.001 | NetworkConnect: `rundll32`/`regsvr32`/`mshta` to non-infrastructure port | full |
| R-1003-001 | T1003.001 | ProcessAccess: `lsass.exe` with dump-capable access mask, or `procdump lsass` | full |
| R-1133 | T1133 | NetworkConnect to 3389 / `mstsc.exe` / Security 4624 type 3 or 10 | needs RDP enabled + Security channel |
| R-1204-002 | T1204.002 | ProcessCreate: Office parent spawning a scripting child | needs Office installed |

Two caveats worth stating in the write-up:

* **R-1003-001 has no benign twin.** Every lab tool that touches LSASS is
  either an attack test or a credential dumper. Inventing a benign one would
  fabricate the label. Expect zero deceptive FPs for this rule.
* **R-1204-002 is only exercised if Office is installed.** The atomic loader
  is skipped otherwise; the rule then never appears in the capture.

---

## 10. Ground truth and its failure modes

Ground truth is a **schedule**, not an oracle: `run-atomics.ps1` records the
UTC window in which each test executed, and the bridge labels an alert
malicious when host + timestamp (+ rule, by default) fall inside that window.

Known failure modes, all of which must be reported rather than tuned away:

| Failure | Effect |
|---|---|
| Defender blocks a test | no telemetry; `status=blocked`; that technique contributes no TPs |
| an atomic leaves a service running | later benign traffic gets labelled malicious (too high attack rate) |
| clock skew between victim and SIEM | windows miss the events; raise `--slack-seconds` only after checking NTP |
| the test fires a *different* rule than mapped | that rule contributes no TPs; check the per-rule counts |
| a background admin task runs during an attack window | mislabelled benign alert (label noise) |
| hostname / alias mismatch | zero matched TPs; check `lab/inventory/hosts.csv` |

`--match time` (host + time only) is available for sensitivity analysis. It
labels more aggressively and is *not* the primary configuration.

---

## 11. Validation checklist

Run through this before trusting a capture.

- [ ] `lab-status` shows three containers up and the agent `Active`.
- [ ] `docker exec <manager> grep logall_json /var/ossec/etc/ossec.conf`
      shows `yes`.
- [ ] Windows event log has Sysmon events 1, 3, 10, 11, 22 after activity.
- [ ] `run-atomics.ps1 -DryRun` lists a plausible test per technique.
- [ ] `ground_truth.csv` has one row per executed test, with UTC timestamps
      and `status` mostly `executed`.
- [ ] `run-benign.ps1` ran at least once during an attack window **and** on a
      quiet day.
- [ ] `build_dataset.py` prints 8 rules with non-zero counts (or explains why
      a rule is absent).
- [ ] `deceptive attacks > 0`; if zero, the benign/attack signatures did not
      overlap and the central claim cannot be evaluated.
- [ ] The report's split rule is what you expect (`time-fraction` for short
      captures).
- [ ] You have read the limitations section and can state the sample size.

---

## 12. Troubleshooting

**`vagrant` is not recognized.** The MSI installs to
`C:\Program Files\Vagrant\bin` but an already-open terminal keeps the old
`PATH`. Open a new terminal. If it still fails:
`$env:Path += ";C:\Program Files\Vagrant\bin"`.

**Box download dies part-way (`Recv failure: Connection was reset`).**
Vagrant's downloader cannot resume, so a 5 GB box that fails at 54% starts
again from zero. Fetch it with `curl` instead, which can resume, then register
the file:

```powershell
$url = "https://vagrantcloud.com/ubuntu/boxes/jammy64/versions/20241002.0.0/providers/virtualbox/unknown/vagrant.box"
curl.exe -L -C - --retry 20 --retry-all-errors `
    -o D:\vagrant.d\cache\jammy64.box $url
vagrant box add --name ubuntu/jammy64 --provider virtualbox D:\vagrant.d\cache\jammy64.box
```

Check the byte count against the server's `Content-Length` before adding: a
truncated file registers as a broken box and fails later, during import.

**`... cannot be loaded because running scripts is disabled`.**
Execution policy, not a missing file. Scope the bypass to the shell you are
using: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`.

**`VT-x is not available (VERR_VMX_NO_VMX)`.** Something else owns the
hypervisor — VBS, Credential Guard, WSL2, or Docker Desktop. Do not disable it;
enable the Windows Hypervisor Platform so VirtualBox can share it:
`Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All`,
then reboot. Confirm with
`VBoxManage list hostinfo | Select-String "HW virtualization"`.

**Indexer crash-loops, dashboard never comes up.**
`docker ps -a` shows the indexer restarting with a `max virtual memory areas`
error. The provisioner sets `vm.max_map_count=262144`; if you are on a
hand-built VM, set it yourself and persist it in
`/etc/sysctl.d/99-wazuh.conf`.

**`vagrant up` fails with a doubled path** such as
`lab/lab/provision/siem.sh`. Provisioner paths are resolved relative to the
Vagrantfile, which already lives in `lab/`. They must be `provision/siem.sh`,
not `lab/provision/siem.sh`, and the synced folder must be the repository root
(`".."`) because every guest-side script expects `/vagrant/lab/...`.

**Agent not connecting.** On the victim:
`Get-Service WazuhSvc`; `Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50`.
Check outbound 1514/tcp to 192.168.56.10 and that the VM is on the host-only
network.

**`archives.json` missing.** `logall_json` is not active. Check
`/var/ossec/etc/ossec.conf` inside the manager container, then
`docker compose restart wazuh.manager`. The file only appears after new events
arrive.

**No detections.** Sysmon service stopped, the config did not apply
(`Sysmon64.exe -c C:\lab\sysmon\sysmon-lab.xml`), or the agent is not reading
the Sysmon channel. `detect.coverage` will be empty.

**No true positives.** In order: is the atomic actually executing (log in
`C:\lab\out\run-*`)? Is the clock UTC on both sides? Does `host` in
`ground_truth.csv` match an alias in `lab/inventory/hosts.csv`? Is the rule
mapping in `atomics.csv` the rule that fired?

**Attack rate is implausibly high.** An atomic left something running
(PsExec service, VNC, scheduled task) and benign time is now inside a labelled
window. Clean up (`Invoke-AtomicTest ... -Cleanup`), snapshot-roll back, and
re-capture.

**Defender quarantines tools.** Add `C:\AtomicRedTeam`, `C:\Tools`,
`C:\ProgramData\lab` to exclusions. Disabling Defender entirely is possible
(`windows-common.ps1 -DisableDefender`) but changes what the environment
represents; if you do it, say so.

**`vagrant ssh` unavailable on Windows.** Install the OpenSSH client, or use
`vagrant ssh-config soc-siem` and `scp` with the printed key. Every command the
helper runs is in §7.

**The Windows guest has no `C:\vagrant`.** Guest Additions / SMB is not
mounted. Copy `lab/attack` and `lab/sysmon` across with `vagrant upload` or
WinRM. The upload endpoint means you do **not** need a shared folder to get
ground truth back to the host.

**Disk fills up.** `archives.json` is the culprit. `docker exec <manager> sh -c
'du -sh /var/ossec/logs/archives'`. Rotation is daily; a multi-day capture may
need a larger disk or a narrower Sysmon filter.

---

## 13. Honest reporting template

Use language along these lines:

> The lab capture validated the ingestion path on real Sysmon/Wazuh telemetry
> (N alerts over D days, K rules). The measured feature set produced ROC-AUC
> X, versus Y on synthetic data; the difference quantifies the cost of
> computing context causally from a short history. At this size a simple
> logistic baseline may match or beat the boosted model; that is a statement
> about sample size, not about the method, and it is reported rather than
> hidden. Queueing and cost figures
> from this capture are not interpretable because the alert volume is far below
> any real SOC. Statistical risk-control bounds are loose for the same reason:
> the calibration window contained only M attacks. The lab therefore supports
> the claim that the framework is *deployable*, not the claim that it delivers
> a specific operational saving.

Do not merge `results_lab/report.md` into `results/report.md`. Keep the two
side by side and explain the gap.

---

## 14. Files

```
lab/
  Vagrantfile                 three VMs, host-only network
  provision/siem.sh           Wazuh + logall_json + upload endpoint + helpers
  provision/windows-common.ps1 Sysmon, agent, auditing, tooling
  provision/dc.ps1            optional AD forest + users + share
  sysmon/sysmon-lab.xml       narrow, volume-aware Sysmon config
  attack/install-atomic.ps1   Atomic Red Team bootstrap
  attack/run-atomics.ps1      execute tests, write + upload ground truth
  attack/run-benign.ps1       benign twin traffic
  attack/atomics.csv          technique -> rule mapping
  collect/upload-server.py    ground-truth endpoint on the SIEM
  collect/export-wazuh.ps1    pull -> build -> run, on the host
  bridge/                     Wazuh/Sysmon -> pipeline dataset
  inventory/                  hosts and users (CMDB stand-in)
  make_fixture.py             no-VM plumbing test
  tests/test_bridge.py        adapter unit tests
  out/                        capture artifacts (git-ignored)
```

---

## 15. Teardown

```powershell
cd lab
vagrant destroy -f
```

Remove `lab/out/` and `results_lab/` if you do not need the artifacts. The
Wazuh VM holds nothing outside its own disk; `vagrant destroy` removes it.
