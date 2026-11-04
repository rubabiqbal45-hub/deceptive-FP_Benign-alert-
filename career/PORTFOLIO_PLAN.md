# Cybersecurity Portfolio Plan — SOC Analyst / Detection Engineering

**Written:** 2026-11-03
**Target role:** SOC Analyst (Tier 1 → Tier 2) → Detection Engineer
**Goal:** three projects that a hiring manager can verify in under 10 minutes each.

---

## 1. What actually gets screened

Detections engineering interviews do not ask "do you know what MITRE ATT&CK is". They
ask for evidence of these six things. Every project below is designed to produce one.

| Signal | What a reviewer looks for | Which project proves it |
|---|---|---|
| **Detection-as-code** | Rules in git, versioned, reviewed, tested | P1 |
| **ATT&CK coverage + gap analysis** | Navigator layers, mapped techniques, honest gaps | P1 |
| **Measured detection quality** | Precision/recall per rule, FP examples, not vibes | P1 |
| **Log fluency** | Sysmon event IDs, Security log fields, auditd, Zeek | P1, P3 |
| **Tuning loop with evidence** | "Rule X fired 4,182 times on benign; here is the change" | P1 |
| **IR communication** | Timeline, scope, root cause, exec summary | P3 |

Two things that are *not* differentiating, despite feeling productive: collecting
certifications, and building another vulnerable-web-app pentest. Skip those for now.

---

## 2. Honest inventory of what you already have

`Default Project/` — *Native ML Alert Triage* research framework. I verified it:

* 21 modules, ~110 KB of Python, **17/17 tests pass**, full pipeline runs on CPU.
* Publishes a real methodological finding (the "Mode A vs Mode B guarantee" gap).
* Produces a regenerated report with detection, queueing, cost, drift, adversarial results.

**What it proves:** strong applied-ML and evaluation discipline. Calibration,
temporal splits, causal features, cost modelling — genuinely above bootcamp level.

**What it does not prove:** that you have ever touched a real log line, written a
detection, or operated a SIEM. The README itself admits the alert stream is synthetic
(§7.1). A SOC hiring manager reads this as *ML research*, not *security engineering*.

**Verdict:** keep it, don't rebuild it. Its value doubles the moment it is fed real
alerts — which is exactly what P1 produces and P2 consumes.

---

## 3. The three projects

The sequencing matters: **P1 output is P2 input.** That coupling is the story —
one continuous pipeline from raw telemetry to a triaged queue, all on real data.
Two disconnected repos tell a weaker story than one chain.

```
P1  raw telemetry ──► Sigma rules ──► measured alert stream
                                            │
P2                                          ▼
                     triage model + risk-controlled suppression
                                            │
P3                                          ▼
                                    IR report on a real intrusion
```

---

### P1 — Detection Engineering Workbench  ★ flagship

**Repo:** `detection-engineering-lab`
**Time:** 3–4 weeks
**This is the project that gets you the interview.** Everything else supports it.

**Build**

1. **Rule pack** — 20–25 Sigma rules you authored or substantially tuned, spanning
   execution, persistence, privilege escalation, credential access, lateral movement,
   and defense evasion. Each rule carries: rationale, ATT&CK technique, required log
   sources, known blind spots, and a changelog entry when tuned.
2. **Backtest harness** — the differentiator. Sigma is a *format*, not an engine, so
   convert or interpret it, then score every rule against labelled telemetry:
   * lint every rule with `sigma-cli` (catches schema and logic errors);
   * evaluate against normalised OTRF `Security-Datasets` JSON (Windows/Sysmon,
     Linux/auditd) through a small evaluator you write for the Sigma condition
     grammar subset you use — and **document that subset and its limits**;
   * emit per-rule `true_positives / false_positives / precision / recall`, plus the
     actual FP events that fired, so tuning claims are inspectable.
3. **Tuning report** — for the 5–8 noisiest rules: what fired, why benign, the exact
   change (field condition, filter, correlation window), and the measured before/after.
   This single document is worth more than the other 15 rules combined.
4. **ATT&CK Navigator layer** — JSON layer showing which techniques are covered by a
   *passing* rule (precision above your stated floor), and which are gap-only.
5. **CI** — GitHub Actions: lint all rules, run the backtest, fail on regression.

**Acceptance criteria**

* `make backtest` reproduces every number in the report from a clean clone.
* Every rule has a measured precision on real telemetry, or is explicitly marked
  "unvalidated — no data available", with the reason.
* At least one rule is shown being *retired* because it could not beat the FP floor.
  Retiring a rule is a stronger signal than writing one.

**Honest constraint:** public ATT&CK datasets are attack-heavy. Benign volume is the
scarce input. Plan for a benign baseline from **Splunk BOTS** (labelled benign+attack)
or, better, self-collected Sysmon from your own Windows machine over ~1 week of normal
work. If you collect it yourself, say so — an analyst with their own baseline dataset
is memorable.

---

### P2 — Real-telemetry external validation  ★ cheapest win

**Repo:** extend `Default Project` (rename to `soc-alert-triage` when it goes public)
**Time:** 1–2 weeks, because ~80% of the machinery already exists

**Build**

1. **Ingestion adapter** — implement `src/soc_triage/datasets/sigma_alerts.py` that
   maps P1's fired-alert output onto the existing schema (`alert_id, ts, rule_id,
   label, host_id, user_id, ...`). `synth/generator.py` stays as the schema reference.
2. **Re-run the whole study on real alerts** — SAME code, no evaluation changes.
   The pipeline is already causal and split-safe, so this is a config swap.
3. **Degradation report** — synthetic vs real, side by side: ROC-AUC, PR-AUC, ECE,
   suppression rate, attacks missed under mode B, cluster-suppression outcomes.
   The point is *not* that numbers stay high. The point is an honest account of what
   breaks and why — which is the thesis contribution, now externally tested.
4. **Prospective check** — hold out the last 2 weeks of real alerts entirely, fit
   nothing on them, and report. That is what "external validity" actually means.

**Acceptance criteria**

* One command runs real data end-to-end and writes the same `results/` artefacts.
* Report states explicitly where the synthetic conclusions did **not** hold.
* The "deceptive false positive" definition is re-tested on real rules, with the
  cluster-suppression refusal cases named.

**Why this matters:** it converts a limitation into a contribution, and it is the
only project here that an academic reviewer would also accept. Cheap, high credibility.

---

### P3 — Incident response case study  ★ communication proof

**Repo:** `ir-case-study-<scenario>`
**Time:** 1 week

**Build**

1. Pick one public scenario with real artefacts (OTRF compound scenario, a
   CyberDefenders/BlueTeamLabs challenge, or a public ransomware EVTX set).
2. Reconstruct the intrusion from logs alone: **timeline, initial access, execution,
   persistence, lateral movement, impact**, each mapped to ATT&CK.
3. **Detection gap analysis** — which steps had *no* detection, and which of your P1
   rules would have caught them. Feed those back into P1 as new rules.
4. **Two write-ups**: a 1-page executive summary in non-technical language, and a
   full technical report with queries and evidence citations.

**Acceptance criteria**

* Every claim in the timeline traces to a specific log record (timestamp + field).
* At least two detections in P1 originate from gaps found here.

**Why this matters:** this is the artefact that separates "can build models" from
"can be trusted on shift". Tier 1/2 hiring is largely a communication judgement.

---

## 4. Sequence and schedule

| Week | Work | Output |
|---|---|---|
| 1 | P1 scaffold, telemetry acquisition, normalisation, first 8 rules | working backtest on 1 dataset |
| 2 | P1 rule pack to 20+, tuning report | per-rule precision table |
| 3 | P1 Navigator layer, CI, write-ups | repo is presentable |
| 4 | P2 adapter, real re-run | degradation report |
| 5 | P3 scenario, timeline, gap analysis | IR report |
| 6 | Polish: READMEs, pinned repos, blog posts, resume bullets | application-ready |

If time is tight, ship **P1 only, done properly**. A half-finished P1 is worse than
no P1, because the README will promise measurements it cannot reproduce.

---

## 5. Definition of done (applies to every project)

A project is portfolio-ready only when all of these are true:

- [ ] `git log` shows iterative commits, not one "initial commit" dump
- [ ] A fresh clone + one documented command reproduces every number in the README
- [ ] The README states the headline result **as a number**, in the first 8 lines
- [ ] Limitations are written down by you, before a reviewer finds them
- [ ] No secrets, no API keys, no personal hostnames in the repo
- [ ] Public repo, MIT or Apache-2.0 licence, pinned on your GitHub profile
- [ ] CI green on the default branch

---

## 6. Career hygiene (do these in week 6, not now)

* One GitHub profile README: three pinned repos, one line each, with the headline number.
* Two blog posts, not six: "How I backtested 25 Sigma rules" and "Why the standard
  selective-classification guarantee fails at a 3% base rate".
* Resume bullets phrased as outcomes with numbers, never as tool lists:
  *"Backtested 25 ATT&CK-mapped Sigma rules against 1.2M real Sysmon events;
  cut false positives 71% across the five noisiest rules while retaining all
  true positives."*
* Be ready to answer, out loud: *what did you get wrong, and how did you find out?*
  That question is asked in almost every detection interview, and the projects above
  are built to give you a real answer.

---

## 7. Environment constraints (so the plan stays honest)

Verified on this machine: Python 3.15, numpy/pandas/scikit-learn/scipy installed,
git installed, network reachable to GitHub and PyPI.

**Available:** SigmaHQ rule corpus, OTRF Security-Datasets, EVTX-ATTACK-SAMPLES,
Splunk BOTS, `sigma-cli`/`pySigma` via pip.

**Not available here:** no Splunk/Elastic/Wazuh install, no Windows AD lab, no `gh`
CLI, and no virtualisation. So:

* Backtesting runs in Python over downloaded JSON, not inside a SIEM. This is fine,
  and arguably better — you will understand rule semantics instead of trusting a
  vendor's converter.
* Anything requiring a live AD lab, Sysmon installation, or a SIEM UI must be done by
  you on your own machine; I can write the config, the Sysmon XML, the collection
  script and the troubleshooting guide, but I cannot execute it here.
* `gh` is missing, so publishing is a manual `git remote add` + push until you install it.

---

## 8. Next action

Start P1. First concrete step is telemetry: probe the OTRF datasets, normalise Windows
Sysmon and Linux auditd into one event schema, and prove that a single hand-written
Sigma rule fires on a known-malicious Atomic Red Team execution and *not* on benign
activity. Everything else in P1 builds on that one working evaluation.
