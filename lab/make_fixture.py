"""Generate a Wazuh-shaped NDJSON fixture from the synthetic stream.

Purpose
-------
Let you validate the *entire* lab bridge — normalise, detect, enrich, label,
schema check, pipeline run — **without building any VMs**.  If this works, the
only thing the lab changes is where the bytes come from.

Honesty note
------------
This is a plumbing test, not evidence. The ground truth is copied from the
simulator, so a perfect score here proves the adapter is wired correctly and
proves nothing about detection quality on real telemetry.

    python lab/make_fixture.py --n-alerts 4000
    python lab/bridge/build_dataset.py \
        --alerts lab/out/fixture/alerts.json \
        --truth  lab/out/fixture/ground_truth.csv
    python run_experiments.py --source csv --path lab/out/lab_dataset.csv
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_triage.config import DEFAULT  # noqa: E402
from soc_triage.synth.generator import generate_alerts  # noqa: E402

# Rules the lab detection pack can reproduce from Sysmon alone.
EMITTABLE = {
    "R-1021-002", "R-1059-001", "R-1218-011", "R-1105",
    "R-1219", "R-1003-001", "R-1053-005", "R-1071-001",
}

IMAGE_PATH = {
    "psexec.exe": r"C:\Tools\PsExec.exe",
    "powershell.exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "rundll32.exe": r"C:\Windows\System32\rundll32.exe",
    "curl.exe": r"C:\Windows\System32\curl.exe",
    "winvnc.exe": r"C:\Program Files\TightVNC\tvnserver.exe",
    "procdump.exe": r"C:\Tools\procdump.exe",
    "schtasks.exe": r"C:\Windows\System32\schtasks.exe",
}
PARENT_PATH = {
    "services.exe": r"C:\Windows\System32\services.exe",
    "taskeng.exe": r"C:\Windows\System32\taskeng.exe",
    "svchost.exe": r"C:\Windows\System32\svchost.exe",
    "code.exe": r"C:\Users\dave\AppData\Local\Programs\Microsoft VS Code\Code.exe",
    "cmd.exe": r"C:\Windows\System32\cmd.exe",
    "explorer.exe": r"C:\Windows\explorer.exe",
    "winword.exe": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
}
SIGNED = {
    "powershell.exe": "true", "rundll32.exe": "true", "curl.exe": "true",
    "schtasks.exe": "true", "psexec.exe": "false", "procdump.exe": "false",
    "winvnc.exe": "false",
}
DEST_POOL = ("52.168.117.21", "10.20.4.11", "185.220.101.1",
             "13.107.42.14", "10.20.9.3")


def _guid(seed: str) -> str:
    h = hashlib.sha1(seed.encode()).hexdigest()
    return "{" + f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}".upper() + "}"


def _xml(ev: dict) -> str:
    parts = "".join(
        f"<Data Name=\"{k}\">{v}</Data>" for k, v in ev.items() if v
    )
    return (
        "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">"
        f"<EventData>{parts}</EventData></Event>"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="synthetic -> Wazuh NDJSON fixture")
    ap.add_argument("--n-alerts", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(ROOT / "lab" / "out" / "fixture"))
    args = ap.parse_args(argv)

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    cfg = replace(DEFAULT, n_alerts=args.n_alerts, seed=args.seed)
    df = generate_alerts(cfg)
    df = df[df["rule_id"].isin(EMITTABLE)].reset_index(drop=True)
    df = df.sort_values("ts", kind="mergesort").reset_index(drop=True)

    users = pd.read_csv(ROOT / "lab" / "inventory" / "users.csv", dtype=str)
    account = dict(zip(users["user_id"], users["account"]))

    rng = np.random.default_rng(args.seed)
    lines: list[str] = []
    truth_rows: list[dict] = []

    for i, row in enumerate(df.itertuples(index=False)):
        proc = str(row.process_name).lower()
        event_id = "3" if row.rule_id == "R-1071-001" else "1"
        dst = str(rng.choice(DEST_POOL)) if event_id == "3" else ""

        ev = {
            "Image": IMAGE_PATH.get(proc, proc),
            "CommandLine": row.command_line,
            "ParentImage": PARENT_PATH.get(str(row.parent_process).lower(), ""),
            "ParentCommandLine": "",
            "User": f"LAB\\{account.get(row.user_id, row.user_id)}",
            "ProcessGuid": _guid(f"{i}-proc"),
            "ParentProcessGuid": _guid(f"{i}-parent"),
            "IntegrityLevel": "System" if "svc" in account.get(row.user_id, "") else "Medium",
            "Signed": SIGNED.get(proc, "false"),
            "Signature": "Microsoft Windows" if SIGNED.get(proc) == "true" else "",
            "DestinationIp": dst,
            "DestinationPort": "443" if dst else "",
            "TargetImage": "",
            "GrantedAccess": "",
        }
        if row.rule_id == "R-1003-001":
            ev["TargetImage"] = r"C:\Windows\System32\lsass.exe"
            ev["GrantedAccess"] = "0x1010"

        alert = {
            "timestamp": pd.Timestamp(row.ts).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
            "agent": {"id": "001", "name": str(row.host_id)},
            "rule": {"id": "92052", "description": "Sysmon - Event " + event_id,
                     "level": str(row.severity)},
            "data": {"win": {"system": {"computer": str(row.host_id),
                                        "eventID": event_id}}},
        }
        # every 7th alert goes through the raw-XML path instead of eventdata
        if i % 7 == 0:
            alert["full_log"] = _xml(ev)
        else:
            alert["data"]["win"]["eventdata"] = ev

        lines.append(json.dumps(alert))
        if i % 50 == 0:  # duplicate decode, to exercise deduplication
            lines.append(json.dumps(alert))

    alerts_path = outdir / "alerts.json"
    alerts_path.write_text("\n".join(lines), encoding="utf-8")

    attacks = df[df["label"] == 1]
    for sid, g in attacks.groupby("scenario_id"):
        truth_rows.append({
            "run_id": f"run-{sid:05d}",
            "rule_id": g["rule_id"].iloc[0],
            "technique": g["technique"].iloc[0],
            "action": "atomic",
            "host": g["host_id"].iloc[0],
            "start_utc": pd.Timestamp(g["ts"].min()).isoformat(),
            "end_utc": pd.Timestamp(g["ts"].max()).isoformat(),
            "executor": "fixture",
        })

    truth = pd.DataFrame(truth_rows)
    truth_path = outdir / "ground_truth.csv"
    truth.to_csv(truth_path, index=False)

    print(f"wrote {len(lines):,} alert lines -> {alerts_path}")
    print(f"wrote {len(truth):,} ground-truth runs -> {truth_path}")
    print(f"rules covered: {sorted(df['rule_id'].unique())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
