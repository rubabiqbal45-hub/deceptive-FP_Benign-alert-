# Native ML Alert Triage — Research Framework

Reference implementation for the MS thesis:

> **An Automated Native Machine Learning Framework to Reduce Alert Fatigue and
> Deceptive False Positives in Enterprise SOC**

The repository is a complete, reproducible experiment: it synthesises a SOC
alert stream containing *deceptive* false positives, trains a triage model,
applies a statistically bounded suppression policy, and reports detection,
queueing, cost, drift and adversarial results as a single markdown report.

Everything runs offline on CPU with four dependencies.

---

## Quick start

```bash
pip install -r requirements.txt

python run_experiments.py          # full study (~2-3 min, 48k alerts)
python run_experiments.py --quick  # smaller run for iteration
python run_experiments.py --seed 7 --outdir results_seed7

# run the same pipeline on a real lab capture (see lab/README.md)
python run_experiments.py --source csv --path lab/out/lab_dataset.csv

python -m unittest discover -s tests -v
python -m unittest discover -s lab/tests -v
```

Outputs land in `results/`:

| File | Contents |
|---|---|
| `report.md` | Full results, auto-written, thesis-ready tables |
| `metrics.json` | Every number, machine readable |
| `model_comparison.csv` | Baseline vs proposed model |
| `fn_budget_curve.csv` | Alert reduction at fixed FN budgets |
| `operating_curve.csv` | Cost/threshold sweep |
| `cost_sensitivity.csv` | Break-even analysis |
| `weekly_clean.csv`, `weekly_drift.csv` | Per-week metrics under drift |
| `adversarial.csv` | Recall under context imitation |
| `cluster_report.csv` | Per-cluster suppression decisions |
| `deceptive_clusters.csv` | Which clusters hid lookalike FPs |
| `feature_importance.csv` | Permutation importance |
| `scored_sample.csv` | 3k scored alerts for inspection |

---

## 1. The research problem, formalised

### 1.1 Deceptive false positive

A *deceptive false positive* is a benign alert that is behaviourally
indistinguishable from a true positive **under the deployed detection logic**:

> An alert is a deceptive FP if suppressing it would, by the same rule,
> suppress a real attack belonging to the same behavioural cluster.

This is operational, not rhetorical. In the generator, every detection rule is
fired by **both** a benign playbook and a malicious playbook with identical
rule name, process, parent process and command-line template. If you suppress
the rule, you suppress the attack.

### 1.2 Why "reduce alert volume" is the wrong objective

The naive formulation — *suppress the noisy alerts* — is unsafe for exactly the
rules that generate the most fatigue, because those are the rules attackers
hide behind. The framework therefore never asks "how many alerts can we
remove?"; it asks:

> **How many alerts can we remove while bounding, with statistical confidence,
> the number of real attacks we throw away?**

### 1.3 Two guarantees (and why only one is useful)

| Mode | Bound | Question answered |
|---|---|---|
| **A** — selective classification | FN rate **among suppressed** alerts ≤ α | "Are the alerts we hid mostly benign?" |
| **B** — recall control (primary) | share of **all attacks** suppressed ≤ β | "How many real attacks did we lose?" |

Mode A is the standard textbook guarantee. On a 2.9% alert base rate it can be
obeyed while **discarding a third of all attacks** — a result this repo
reproduces deliberately, because that gap is itself one of the contributions.

---

## 2. Architecture

```
Endpoint / SIEM telemetry
        │
        ▼
Detection layer (Sigma-style rules)        ← reused, not rebuilt
        │
        ▼
[M1] Normalisation + ATT&CK mapping
        │
        ▼
[M2] Context enrichment (role, asset criticality, novelty,
     peer rarity, destination reputation, command-line distance)
        │
        ▼
[M3] Triage engine
     ├─ Platt calibration (dedicated 30% of calibration window)
     ├─ Risk-controlled suppression   (modes A and B)
     ├─ Behavioural-cluster suppression (signature / context)
     └─ Three-way action: suppress | rank | escalate
        │
        ▼
[M4] Analyst queue simulation + cost model + drift/adversarial tests
```

"Native" in this implementation means: CPU-only, offline, deterministic,
no external API calls, inference on the SIEM node. Deliberately **not** an
LLM-based triage layer.

---

## 3. Experimental design

| Choice | Rationale |
|---|---|
| **Temporal split** (train w1–6, calibrate w7–8, test w9–12) | Random splits leak future behaviour and inflate results |
| **Causal history features** (expanding counts, shifted statistics) | An alert only sees what existed before it arrived |
| **Dedicated calibration slice** | Platt scaling and risk control never share data |
| **Temporal + adversarial stress tests** | Static AUC hides both failure modes |
| **Clean vs lookalike pairs** | Makes the deceptive-FP claim measurable rather than asserted |
| **No attack-only rules** | Prevents rule ID from becoming a label shortcut |

### Feature groups

* **Static context** — severity, asset criticality, command-line shape
* **Temporal** — hour, weekday, deviation from user's personal baseline
* **Causal history** — prior occurrences of (user, rule), (host, rule), host burst rate
* **Behavioural** — host novelty, peer rarity, command-line distance from baseline,
  destination reputation, signed-binary ratio, role/asset mismatch

---

## 4. Results (seeded reference run)

48,000 alerts over 12 weeks · 2.89% attack rate · 16,367 held-out test alerts

### 4.1 Detection quality

| Model | ROC-AUC | PR-AUC | ECE |
|---|---|---|---|
| B2 logistic regression | 0.9873 | 0.9088 | 0.0605 |
| B3 random forest | 0.9902 | 0.9083 | 0.0235 |
| **M1 native GBM triage** | **0.9859** | 0.9036 | **0.0065** |
| B1 rule base-rate | 0.7348 | 0.0529 | 0.0035 |
| B0 rule severity | 0.6993 | 0.0461 | 0.3699 |

The proposed model matches tree-ensemble accuracy (ΔPR-AUC 0.005) while being
**3.6× better calibrated** than the random forest — which is what the
risk-control threshold and the cost model actually depend on. Static severity
ranking (what many SIEMs do by default) has PR-AUC 0.046, i.e. essentially no
signal.

### 4.2 Suppression

| Mode | Bound | Alert suppression | FN in suppressed | Attacks missed | Recall |
|---|---|---|---|---|---|
| A: α among suppressed | 0.0148 | **97.98%** | 0.0086 | **29.93%** | 70.07% |
| **B: β of all attacks** | 0.0172 | **52.17%** | 0.0004 | **0.65%** | **99.35%** |

**Mode A is the trap.** It obeys its stated guarantee (0.86% ≤ 1.5%) and still
loses nearly a third of real attacks. Mode B removes 52% of the queue while
keeping 99.35% of detections.

### 4.3 Cluster suppression (rule whitelisting)

| Variant | Clusters suppressed | Coverage | Attacks suppressed |
|---|---|---|---|
| **signature, Bonferroni** | 6 / 13 | **59.47%** | **0** |
| signature, marginal | 7 / 13 | 66.44% | 0 |
| context, marginal | 2 / 36 | 6.62% | **9** |

Six detection signatures can be safely whitelisted because they are genuinely
pure-benign. Three clusters were **refused despite containing deceptive false
positives** — the mechanism by which whitelisting hides attackers. Naive
context clustering suppressed two clusters that contained 9 real attacks.

### 4.4 SOC operations

| Metric | Baseline (review all) | Triaged |
|---|---|---|
| Mean time in queue | 366.1 min | **4.8 min** |
| 95th percentile wait | 686.8 min | **18.5 min** |
| SLA breach rate | 96.3% | **9.2%** |
| Analysts needed for 5% SLA | 19 | **9** |
| Annual cost | $1,033,954 | **$561,230 (−45.7%)** |

### 4.5 Robustness

| Group | n | Recall |
|---|---|---|
| Ordinary attacks | 323 | 86.7% |
| Adversarial (context-imitation) attacks | 138 | **74.6%** |

ROC-AUC falls 0.986 → 0.978 when attackers imitate benign context. The model
degrades but does not collapse, because it also uses rule-level and novelty
evidence — full evasion requires the attacker to fabricate a plausible history
baseline too, not just copy a command line.

### 4.6 Cost break-even

Suppression is only economically defensible below a certain implied cost per
missed alert. The sensitivity grid makes that assumption explicit instead of
hiding it:

| P(exploit \| miss) | Implied cost/miss | Optimal keep fraction | Suppression optimal? |
|---|---|---|---|
| 1e-4 | $120 | 5.2% | yes |
| 1e-3 | $1,200 | 22.1% | yes |
| 1e-2 | $12,000 | 54.3% | yes |
| 5e-2 | $60,000 | 54.3% | yes |

---

## 5. Repository layout

```
run_experiments.py            CLI entry point (--source synth|csv)
src/soc_triage/
  config.py                   Every experimental parameter, one dataclass
  schema.py                   Canonical alert schema + rule catalog (shared)
  splits.py                   Week split, with a short-capture fallback
  io.py                       Dataset loading/validation for --source csv
  pipeline.py                 End-to-end orchestration + report generation
  synth/generator.py          Playbooks, lookalike pairs, drift/adversarial injection
  features/build.py           Causal feature engineering
  models/
    triage.py                 Baselines + gradient-boosted triage engine
    calibration.py            Platt scaling
    selective.py              Risk-controlled + recall-controlled selectors
    cluster.py                Signature/context cluster suppression with FN bound
    explain.py                Global importance + per-alert ablation attribution
  eval/
    metrics.py                Detection metrics incl. FN-budget curves
    queue_sim.py              M/G/c analyst queue on business-time coordinates
    cost.py                   Cost sweep + break-even sensitivity
    robustness.py             Weekly drift, adversarial recall, recalibration
lab/
  Vagrantfile                 3-VM range (Wazuh, victim, optional DC)
  provision/                  SIEM + Windows + AD provisioning
  sysmon/                     Narrow Sysmon config
  attack/                     Atomic Red Team + benign twin traffic
  collect/                    Ground-truth upload + capture-to-results helper
  bridge/                     Wazuh/Sysmon -> pipeline dataset
  README.md                   Full lab runbook, validation checklist, limits
tests/test_smoke.py           17 tests incl. an end-to-end run
lab/tests/test_bridge.py      10 adapter tests (no VMs required)
```

---

## 6. Mapping to thesis chapters

| Chapter | Artefacts |
|---|---|
| Ch. 1 Introduction | §1 above; the Mode A vs Mode B gap is the motivating problem |
| Ch. 2 Literature review | `models/triage.py` baselines = the comparison taxonomy |
| Ch. 3 Methodology | §1.1 definition, §2 architecture, §3 design, `synth/`, `features/` |
| Ch. 4 Implementation | `models/`, `eval/`, `config.py` |
| Ch. 5 Results | `results/report.md` (regenerated, not hand-written) |
| Ch. 6 Discussion | §4.2–4.6, especially the adversarial and break-even analyses |
| Ch. 7 Limitations | §7 below |

---

## 7. Limitations (state these explicitly in the thesis)

1. **The alert stream is synthetic.** It validates the pipeline and the
   evaluation methodology — not real-world efficacy. The injected signal is
   deliberately weakened (heavy class overlap, 12% corrupted context fields,
   stealthy attacks) so the task is not trivial, but it is still a simulation.
   External validity requires a real capture: the `lab/` range included in this
   repository is the first step, and public datasets (**Splunk BOTS**, **OTRF
   Mordor**, **EVTX-ATTACK-SAMPLES**, **DARPA OpTC**, **LANL**) are the next.
2. **Lookalike false positives are oversampled** (54% of the stream) because
   they are the object of study. A production stream has a much smaller share.
3. **Queue parameters are assumed**, not measured: 8 working hours, 10
   alerts/hour/analyst, lognormal handling time. A live pilot is needed before
   any operational claim.
4. **Label noise and alert duplication** are not simulated.
5. **Mode B is feasible only if the calibration window contains enough
   attacks.** With ~173 calibration attacks the smallest certifiable β is about
   1.7%; the selector reports infeasibility instead of silently returning a
   useless threshold. A short lab capture has far fewer, and the report says so.

---

## 8. Real telemetry: the mini-SOC lab

The generator is isolated behind one interface, and `lab/` now implements the
other side of it: a three-VM range that captures real Sysmon telemetry through
Wazuh and converts it to the identical table.

```
Windows victim (Sysmon + Wazuh agent)
        │
        ▼
Wazuh manager ──► archives.json ──┐
                                  ├─► lab/bridge ──► lab_dataset.csv
run-atomics.ps1 ──► ground_truth.csv ─┘                     │
                                                           ▼
                              python run_experiments.py --source csv --path ...
```

What the bridge does, in order: normalise Wazuh JSON (both `eventdata` and raw
XML layouts), de-duplicate repeated decodes, apply a transparent Sigma-lite rule
pack over Sysmon fields, compute the context features **causally** from the
capture (trailing windows only), attach ground truth from the atomic-test
schedule, and derive the deceptive-FP labels by signature overlap — the same
definition the generator uses.

Ground truth is a purple-team schedule, not a human oracle: `run-atomics.ps1`
executes Atomic Red Team tests, records the UTC window of each, and marks tests
that Defender blocks. `run-benign.ps1` generates the benign twin traffic that
shares process lineage with the tests — that overlap is what makes a false
positive *deceptive* rather than merely noisy.

```powershell
cd lab
vagrant up soc-siem soc-victim
# on the victim:
.\install-atomic.ps1
.\run-atomics.ps1
.\run-benign.ps1 -Count 8
# on the host:
.\collect\export-wazuh.ps1 -Since 2026-02-10T00:00:00
```

The full runbook — topology, prerequisites, validation checklist, troubleshooting
and the honest limits of a small capture — is in [`lab/README.md`](lab/README.md).

**Read this before quoting lab numbers.** A two-VM, multi-day capture produces a
few thousand detections and tens of calibration attacks. It answers "does the
adapter work on real telemetry?" and "is the deceptive-FP definition
computable?" It cannot answer "how much money does this save?" — the queue is
never under pressure, and the statistical bounds are loose. Keep
`results_lab/` and `results/` side by side; do not merge them.

---

## 9. Configuration

All knobs live in `src/soc_triage/config.py`:

```python
alpha_suppress = 0.02    # Mode A: FN rate among suppressed alerts
beta_recall    = 0.02    # Mode B: share of all attacks suppressed
alpha_safety   = 0.75    # margin absorbed by temporal drift
alpha_delta    = 0.05    # 1 - confidence of the bound
n_analysts     = 8
analyst_alerts_per_hour = 10.0
breach_cost    = 1_200_000.0
p_exploit_given_miss = 0.05
```

Reproducibility: a single `seed` drives generation, model training, calibration
splits and queue simulation.

---

## 10. What is genuinely novel here

1. An **operational definition** of the deceptive false positive with a
   measurable failure mode (suppression-induced FN inside a behavioural
   cluster).
2. Evidence that the standard selective-classification guarantee is **the wrong
   guarantee** for alert triage at low base rates.
3. **Cluster-level suppression with a simultaneous FN bound** that distinguishes
   rules that are safe to whitelist from rules that hide attackers.
4. A **cost break-even analysis** that forces the SOC to state its implicit
   `P(exploit | miss)` assumption.
5. A **reproducible lookalike-benign testbed** in which no rule is a free win.

Points 1, 2 and 3 are publishable at ARES / DFRWS / IEEE S&P Workshops.
