"""Native ML alert-triage research framework.

Companion code for the thesis:
    "An Automated Native Machine Learning Framework to Reduce Alert Fatigue
     and Deceptive False Positives in Enterprise SOC"

Pipeline
--------
synth.generator   -> labelled SOC alert stream with lookalike (deceptive) FPs
features.build    -> causal, leakage-free feature engineering
models.triage     -> baselines + gradient-boosted triage model
models.selective  -> risk-controlled suppression (selective classification)
models.cluster    -> behavioural-cluster suppression with an FN bound
eval.*            -> detection, queueing, cost and drift/robustness metrics
pipeline          -> end-to-end experiment runner
"""

__version__ = "0.1.0"
