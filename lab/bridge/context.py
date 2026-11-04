"""Behavioural context features computed from telemetry.

The synthetic generator samples these from latent distributions. On real data
they must be *measured*, and measured causally — an alert may only use what
happened before it arrived.  This module is the honest counterpart of the
generator's `_context`.

Feature definitions (all bounded to [0, 1] unless noted)
--------------------------------------------------------
host_novelty        How unusual this rule is for this host so far.
peer_rarity         Fraction of same-class hosts that have never fired this rule.
cmdline_distance    1 - best Jaccard similarity to the user's recent command lines.
dst_reputation      Rarity (and blocklist membership) of the destination address.
signed_ratio        Expanding share of this host's binaries that are signed.
lineage_depth       Depth of the process in its parent chain (0-8).
role_asset_mismatch 1 if the user's role is not authorised for this asset class.
burst_size          Alerts on the same host in the preceding 5 minutes, inclusive.
event_count         Raw telemetry events on the host in the preceding 15 minutes.

Both volume features are *trailing* windows on purpose. A centred +/-5-minute
window would let an alert's burst size depend on alerts that had not arrived
yet, which is the classic look-ahead leak in alert-triage work. The synthetic
generator uses the final size of a scenario burst instead; on real telemetry
that number is not available at triage time, so the bridge measures what an
analyst could actually see.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque

import numpy as np
import pandas as pd

from soc_triage.schema import REQUIRED_COLUMNS

_TOKEN = re.compile(r"[a-z0-9_.\\/-]{2,}")
DEFAULT_BLOCKLIST = frozenset({
    "185.220.101.1", "45.155.205.233", "91.219.236.166", "193.32.162.157",
})


def _tokens(text: str) -> set[str]:
    return set(_TOKEN.findall(str(text).lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _prior_counts(codes: np.ndarray, ts_ns: np.ndarray, window_ns: int) -> np.ndarray:
    """Count strictly-prior events in the same group within a window."""
    out = np.zeros(len(ts_ns), dtype=float)
    for g in np.unique(codes):
        idx = np.flatnonzero(codes == g)
        arr = ts_ns[idx]
        left = np.searchsorted(arr, arr - window_ns, side="left")
        now = np.searchsorted(arr, arr, side="left")
        out[idx] = now - left
    return out


def _trailing_counts(codes: np.ndarray, ts_ns: np.ndarray,
                     window_ns: int) -> np.ndarray:
    """Count same-group events in [t - window, t], inclusive of self."""
    out = np.zeros(len(ts_ns), dtype=float)
    for g in np.unique(codes):
        idx = np.flatnonzero(codes == g)
        arr = ts_ns[idx]
        lo = np.searchsorted(arr, arr - window_ns, side="left")
        hi = np.searchsorted(arr, arr, side="right")
        out[idx] = hi - lo
    return out


def _process_depth(df: pd.DataFrame, cap: int = 8) -> np.ndarray:
    """Depth in the process tree, resolved through Sysmon GUIDs."""
    guid_depth: dict[str, int] = {}
    out = np.zeros(len(df), dtype=float)
    for i, (guid, pguid) in enumerate(
        zip(df["process_guid"].to_numpy(), df["parent_guid"].to_numpy())
    ):
        if not guid:
            continue
        depth = guid_depth.get(pguid, 0) + 1 if pguid else 1
        depth = min(depth, cap)
        guid_depth[guid] = depth
        out[i] = float(depth)
    return out


def enrich(detections: pd.DataFrame,
           events: pd.DataFrame,
           inventory,
           blocklist: frozenset[str] = DEFAULT_BLOCKLIST,
           burst_window_s: int = 300,
           event_window_s: int = 900) -> pd.DataFrame:
    if detections.empty:
        return detections.copy()

    d = detections.sort_values("ts", kind="mergesort").reset_index(drop=True).copy()
    ev = events.sort_values("ts", kind="mergesort")

    # ----------------------------------------------------------- identity
    host_cache: dict[str, dict] = {}
    user_cache: dict[str, dict] = {}
    recs = []
    for host_raw, user_raw in zip(d["host_raw"], d["user_raw"]):
        h = host_cache.get(host_raw)
        if h is None:
            h = inventory.resolve_host(host_raw)
            host_cache[host_raw] = h
        u = user_cache.get(user_raw)
        if u is None:
            u = inventory.resolve_user(user_raw)
            user_cache[user_raw] = u
        recs.append((h, u))

    d["host_id"] = [h["host_id"] for h, _ in recs]
    d["asset_type"] = [h["asset_type"] for h, _ in recs]
    d["asset_criticality"] = [h["asset_criticality"] for h, _ in recs]
    d["user_id"] = [u["user_id"] for _, u in recs]
    d["user_role"] = [u["user_role"] for _, u in recs]
    d["role_asset_mismatch"] = [
        float(inventory.role_asset_mismatch(u["user_role"], h["host_id"],
                                           h["asset_type"]))
        for h, u in recs
    ]

    # ------------------------------------------------- process-tree depth
    depth_by_event = dict(zip(events["event_uid"], _process_depth(events)))
    d["lineage_depth"] = d["event_uid"].map(depth_by_event).fillna(0.0)

    # ---------------------------------------------- windowed volume counts
    ts_ns = d["ts"].to_numpy(dtype="datetime64[ns]").astype("int64")
    host_codes = pd.factorize(d["host_id"], sort=False)[0]
    d["burst_size"] = _trailing_counts(host_codes, ts_ns, burst_window_s * 10**9)

    ev_ns = ev["ts"].to_numpy(dtype="datetime64[ns]").astype("int64")
    host_map = {r: inventory.resolve_host(r)["host_id"]
                for r in ev["host_raw"].astype(str).unique()}
    ev_host = ev["host_raw"].astype(str).map(host_map).fillna(ev["host_raw"])
    ev_codes = pd.factorize(ev_host, sort=False)[0]
    ev_prior = _prior_counts(ev_codes, ev_ns, event_window_s * 10**9)
    ev_lookup = pd.DataFrame({"host_id": ev_host.to_numpy(),
                              "ts": ev_ns, "prior": ev_prior})

    cnt = np.zeros(len(d), dtype=float)
    for hid, idx in d.groupby("host_id", sort=False).indices.items():
        sub = ev_lookup[ev_lookup["host_id"] == hid]
        if sub.empty:
            continue
        arr_ts = np.sort(sub["ts"].to_numpy())
        arr_prior = sub["prior"].to_numpy()[np.argsort(sub["ts"].to_numpy())]
        pos = np.searchsorted(arr_ts, ts_ns[idx], side="left") - 1
        cnt[idx] = np.where(pos >= 0, arr_prior[np.maximum(pos, 0)], 0.0)
    d["event_count"] = cnt

    # --------------------------------- causal expanding behavioural state
    host_rule_n: dict[tuple[str, str], int] = defaultdict(int)
    host_n: dict[str, int] = defaultdict(int)
    asset_rule_hosts: dict[tuple[str, str], set[str]] = defaultdict(set)
    asset_hosts: dict[str, set[str]] = defaultdict(set)
    host_signed: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    dst_n: dict[str, int] = defaultdict(int)
    user_cmds: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))

    novelty, rarity, cmd_dist, dst_rep, signed_ratio = [], [], [], [], []

    for row in d.itertuples(index=False):
        host, rule, asset = row.host_id, row.rule_id, row.asset_type
        prior_same = host_rule_n[(host, rule)]
        prior_host = host_n[host]
        novelty.append(1.0 - (prior_same + 1.0) / (prior_host + 2.0))

        peers = asset_hosts[asset]
        seen = asset_rule_hosts[(asset, rule)]
        rarity.append(1.0 - (len(seen) / len(peers)) if peers else 0.5)

        toks = _tokens(row.command_line)
        history = user_cmds[row.user_id]
        cmd_dist.append(0.5 if not history else
                        1.0 - max(_jaccard(toks, h) for h in history))

        dst = str(row.dst_ip or "").strip()
        if dst in blocklist:
            dst_rep.append(1.0)
        elif not dst:
            dst_rep.append(0.35)
        else:
            dst_rep.append(float(np.clip(1.0 - dst_n[dst] / 10.0, 0.05, 1.0)))

        s = row.signed
        if isinstance(s, float) and not np.isnan(s):
            host_signed[host][0] += int(s)
            host_signed[host][1] += 1
        n_signed, n_total = host_signed[host]
        signed_ratio.append(n_signed / n_total if n_total else 0.5)

        # --- update state *after* computing, so nothing looks ahead
        host_rule_n[(host, rule)] += 1
        host_n[host] += 1
        asset_rule_hosts[(asset, rule)].add(host)
        asset_hosts[asset].add(host)
        user_cmds[row.user_id].append(toks)
        if dst:
            dst_n[dst] += 1

    d["host_novelty"] = novelty
    d["peer_rarity"] = rarity
    d["cmdline_distance"] = cmd_dist
    d["dst_reputation"] = dst_rep
    d["signed_ratio"] = signed_ratio

    for c in ("host_novelty", "peer_rarity", "cmdline_distance",
              "dst_reputation", "signed_ratio"):
        d[c] = pd.to_numeric(d[c], errors="coerce").fillna(0.5).clip(0.0, 1.0)

    return d


def missing_columns(df: pd.DataFrame) -> list[str]:
    return [c for c in REQUIRED_COLUMNS if c not in df.columns]
