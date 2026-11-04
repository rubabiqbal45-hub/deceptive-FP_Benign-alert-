from __future__ import annotations

from soc_triage.synth.generator import (
    ATTACK_PLAYBOOKS,
    BENIGN_PLAYBOOKS,
    inject_adversarial,
    inject_drift,
    generate_alerts,
)

__all__ = [
    "ATTACK_PLAYBOOKS",
    "BENIGN_PLAYBOOKS",
    "generate_alerts",
    "inject_drift",
    "inject_adversarial",
]
