"""Asset and identity inventory.

The classifier needs to know what a host *is* (workstation, server, domain
controller) and what a user *does* — that is where `asset_criticality` and
`role_asset_mismatch` come from.  In a real SOC this comes from CMDB + HR; in
the lab it is two CSVs.

Everything degrades gracefully: an unknown host or user is inferred from its
name rather than dropped, because a live capture always contains machines that
were never enrolled.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

_DEFAULT_HOSTS = pd.DataFrame(
    columns=["host_id", "asset_type", "asset_criticality", "allowed_roles", "aliases"]
)
_DEFAULT_USERS = pd.DataFrame(columns=["user_id", "user_role", "account"])

_CRIT = {"domain_controller": 5, "server": 4, "file_share": 3, "workstation": 2}


def _split_roles(value) -> set[str]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return set()
    return {p.strip() for p in str(value).split("|") if p.strip()}


def _slug(text: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "_", text.strip().lower()).strip("_")
    return text or "unknown"


@dataclass
class Inventory:
    hosts: pd.DataFrame
    users: pd.DataFrame

    def __post_init__(self) -> None:
        # Precomputed lookups: a live capture can be 100k alerts, and scanning
        # a DataFrame once per alert would dominate runtime.
        self._host_by_name: dict[str, dict] = {}
        self._roles_by_host: dict[str, set[str]] = {}
        self._roles_by_asset: dict[str, set[str]] = {}

        for _, row in self.hosts.iterrows():
            rec = {
                "host_id": str(row["host_id"]),
                "asset_type": str(row["asset_type"]),
                "asset_criticality": int(row["asset_criticality"]),
            }
            names = {str(row["host_id"]).lower()}
            names |= {a.lower() for a in _split_roles(row.get("aliases"))}
            for n in names:
                self._host_by_name[n] = rec

            roles = _split_roles(row.get("allowed_roles"))
            self._roles_by_host[rec["host_id"]] = roles
            self._roles_by_asset.setdefault(rec["asset_type"], set()).update(roles)

        self._user_by_account: dict[str, dict] = {}
        for _, row in self.users.iterrows():
            rec = {"user_id": str(row["user_id"]),
                   "user_role": str(row["user_role"])}
            for key in (str(row["account"]).lower(), str(row["user_id"]).lower()):
                self._user_by_account[key] = rec

    # ------------------------------------------------------------- lookups
    def resolve_host(self, raw: str) -> dict:
        raw = str(raw or "").strip()
        if not raw:
            return {"host_id": "unknown", "asset_type": "workstation",
                    "asset_criticality": 2}
        hit = self._host_by_name.get(raw.lower())
        return dict(hit) if hit else self._infer_host(raw)

    def _infer_host(self, raw: str) -> dict:
        low = raw.lower()
        if low.startswith("dc") or "domaincontroller" in low:
            asset = "domain_controller"
        elif low.startswith(("fs", "nas", "fileshare")):
            asset = "file_share"
        elif low.startswith(("srv", "server", "app", "db")):
            asset = "server"
        else:
            asset = "workstation"
        return {"host_id": raw, "asset_type": asset,
                "asset_criticality": _CRIT.get(asset, 2)}

    def resolve_user(self, raw: str) -> dict:
        raw = str(raw or "").strip()
        account = raw.split("\\")[-1].strip()
        if not account:
            return {"user_id": "unknown", "user_role": "unclassified"}
        hit = self._user_by_account.get(account.lower())
        if hit:
            return dict(hit)
        return {"user_id": _slug(account), "user_role": "unclassified"}

    # ------------------------------------------------------- authorisation
    def roles_for_asset(self, host_id: str, asset_type: str) -> set[str]:
        roles = self._roles_by_host.get(host_id)
        if roles:
            return roles
        return self._roles_by_asset.get(asset_type, set())

    def role_asset_mismatch(self, role: str, host_id: str, asset_type: str) -> int:
        allowed = self.roles_for_asset(host_id, asset_type)
        if not allowed or role == "unclassified":
            return 0
        return 0 if role in allowed else 1


def load_inventory(directory: str | Path | None) -> Inventory:
    hosts = _DEFAULT_HOSTS.copy()
    users = _DEFAULT_USERS.copy()
    if directory is None:
        return Inventory(hosts, users)

    directory = Path(directory)
    hpath, upath = directory / "hosts.csv", directory / "users.csv"
    if hpath.exists():
        hosts = pd.read_csv(hpath, dtype=str)
        hosts["asset_criticality"] = pd.to_numeric(
            hosts.get("asset_criticality", 2), errors="coerce"
        ).fillna(2).astype(int)
    if upath.exists():
        users = pd.read_csv(upath, dtype=str)
    return Inventory(hosts, users)
