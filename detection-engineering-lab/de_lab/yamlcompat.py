"""YAML loading without a C extension.

PyYAML has no wheel for very new CPython builds and cannot compile without a
toolchain, so the lab uses ``ruamel.yaml``'s safe pure-Python loader and falls
back to PyYAML when it happens to be installed. Both return plain dicts/lists,
which is all Sigma parsing needs.
"""

from __future__ import annotations

from typing import Any


def load_yaml(text: str) -> Any:
    try:
        from ruamel.yaml import YAML

        return YAML(typ="safe", pure=True).load(text)
    except ImportError:  # pragma: no cover - depends on interpreter build
        import yaml

        return yaml.safe_load(text)
