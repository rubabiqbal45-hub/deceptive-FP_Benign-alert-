"""Adapter tests: Wazuh/Sysmon telemetry -> pipeline dataset.

These do not need Vagrant, Wazuh or Windows.  They exercise the parts most
likely to break silently: decoder layouts, de-duplication, every deployed
detection rule, the causality of the context features, and the
deceptive-FP derivation.

Run with either::

    python -m unittest discover -s lab/tests -v
    pytest lab/tests
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from lab.bridge import context, detect, inventory, label, normalize  # noqa: E402
from lab.bridge.build_dataset import build  # noqa: E402
from soc_triage.config import DEFAULT  # noqa: E402
from soc_triage.io import load_dataset  # noqa: E402
from soc_triage.schema import REQUIRED_COLUMNS, assert_schema  # noqa: E402
from soc_triage.splits import split_info, temporal_split  # noqa: E402

INV = inventory.load_inventory(ROOT / "lab" / "inventory")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _sysmon(ts: str, ev: dict | None = None, *, event_id: int = 1,
            host: str = "soc-victim") -> dict:
    return {
        "timestamp": ts,
        "agent": {"id": "001", "name": host},
        "rule": {"id": "92052", "description": "test", "level": "3"},
        "data": {"win": {
            "system": {"computer": host, "eventID": str(event_id)},
            "eventdata": ev or {},
        }},
    }


def _guid(n: int) -> str:
    return "{" + f"00000000-0000-0000-0000-{n:012d}" + "}"


def _proc(n: int, image: str, cmd: str,
          parent: str = r"C:\Windows\System32\cmd.exe",
          ts: str = "2026-02-10T10:00:00.000+0000", event_id: int = 1,
          **extra) -> dict:
    ev = {
        "Image": image,
        "CommandLine": cmd,
        "ParentImage": parent,
        "ParentCommandLine": "",
        "User": r"LAB\dave",
        "ProcessGuid": _guid(n),
        "ParentProcessGuid": _guid(9000 + n),
        "Signed": "true",
        "IntegrityLevel": "Medium",
    }
    ev.update(extra)
    return _sysmon(ts, ev, event_id=event_id)


def _capture(tmp: Path, alerts: list[dict], truth: pd.DataFrame):
    alerts_path = tmp / "archives.json"
    alerts_path.write_text("\n".join(json.dumps(a) for a in alerts),
                           encoding="utf-8")
    truth_path = tmp / "ground_truth.csv"
    truth.to_csv(truth_path, index=False)
    return alerts_path, truth_path


class BridgeTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()


# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------


class TestNormalize(BridgeTestCase):
    def test_reads_eventdata_and_raw_xml(self):
        a = _proc(1, r"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami")
        b = _sysmon("2026-02-10T10:01:00.000+0000")
        b["full_log"] = (
            "<Event><EventData>"
            r'<Data Name="Image">C:\Tools\PsExec.exe</Data>'
            r'<Data Name="CommandLine">PsExec.exe -s cmd</Data>'
            r'<Data Name="ProcessGuid">{B}</Data>'
            "</EventData></Event>"
        )

        df = normalize.normalize([a, b])
        self.assertEqual(df["image_name"].tolist(), ["cmd.exe", "psexec.exe"])
        self.assertEqual(df["event_id"].tolist(), [1, 1])
        self.assertTrue(df["ts"].is_monotonic_increasing)
        self.assertEqual(df["command_line"].iloc[1], "PsExec.exe -s cmd")

    def test_deduplicate_collapses_repeated_decodes(self):
        a = _proc(7, r"C:\Tools\PsExec.exe", "PsExec.exe -s cmd")
        df = normalize.normalize([a, a, a])
        self.assertEqual(len(df), 3)
        self.assertEqual(len(normalize.deduplicate(df)), 1)


# ---------------------------------------------------------------------------
# detection pack
# ---------------------------------------------------------------------------


class TestDetect(BridgeTestCase):
    def test_fires_every_supported_rule(self):
        alerts = [
            _proc(1, r"C:\Tools\PsExec.exe", "PsExec.exe -accepteula \\host cmd",
                  ts="2026-02-10T10:00:00.000+0000"),
            _proc(2, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                  "powershell.exe -NoP -W Hidden -EncodedCommand AAAA",
                  ts="2026-02-10T10:01:00.000+0000"),
            _proc(3, r"C:\Windows\System32\rundll32.exe",
                  r"rundll32.exe C:\ProgramData\lab\printui.dll,PrintUIEntry",
                  ts="2026-02-10T10:02:00.000+0000"),
            _proc(4, r"C:\Windows\System32\curl.exe",
                  r"curl.exe -o C:\ProgramData\lab\a.zip https://updates.example/a.zip",
                  ts="2026-02-10T10:03:00.000+0000"),
            _proc(5, r"C:\Program Files\TightVNC\tvnserver.exe",
                  "tvnserver.exe -run", ts="2026-02-10T10:04:00.000+0000"),
            _proc(6, r"C:\Windows\System32\schtasks.exe",
                  "schtasks.exe /Create /TN Lab\\B /TR cmd.exe /SC DAILY",
                  ts="2026-02-10T10:05:00.000+0000"),
            _proc(7, r"C:\Tools\procdump.exe", "procdump.exe -ma lsass.exe out.dmp",
                  ts="2026-02-10T10:06:00.000+0000", event_id=10,
                  TargetImage=r"C:\Windows\System32\lsass.exe",
                  GrantedAccess="0x1010"),
            _proc(8, r"C:\Windows\System32\mshta.exe",
                  "mshta.exe https://intranet.example/portal.hta",
                  ts="2026-02-10T10:07:00.000+0000", event_id=3,
                  DestinationIp="203.0.113.7", DestinationPort="443"),
        ]

        events = normalize.deduplicate(normalize.normalize(alerts))
        det = detect.detect(events)

        self.assertEqual(set(det["rule_id"]), {
            "R-1021-002", "R-1059-001", "R-1218-011", "R-1105",
            "R-1219", "R-1053-005", "R-1003-001", "R-1071-001",
        })
        self.assertTrue(det["severity"].between(2, 5).all())
        self.assertTrue(det["rule_name"].notna().all())

    def test_does_not_fire_on_ordinary_activity(self):
        alerts = [
            _proc(1, r"C:\Windows\System32\notepad.exe", "notepad.exe notes.txt"),
            _proc(2, r"C:\Program Files\Microsoft VS Code\Code.exe",
                  r"Code.exe C:\Users\dave\project",
                  parent=r"C:\Windows\explorer.exe"),
        ]
        det = detect.detect(normalize.deduplicate(normalize.normalize(alerts)))
        self.assertTrue(det.empty)


# ---------------------------------------------------------------------------
# causal context
# ---------------------------------------------------------------------------


class TestContext(BridgeTestCase):
    def test_features_are_trailing_only(self):
        alerts = [
            _proc(1, r"C:\Tools\PsExec.exe", "PsExec.exe -s cmd",
                  ts="2026-02-10T10:00:00.000+0000"),
            _proc(2, r"C:\Tools\PsExec.exe", "PsExec.exe -s cmd",
                  ts="2026-02-10T10:01:00.000+0000"),
            _proc(3, r"C:\Tools\PsExec.exe", "PsExec.exe -s cmd",
                  ts="2026-02-10T10:02:00.000+0000"),
        ]

        def run(subset):
            ev = normalize.deduplicate(normalize.normalize(subset))
            return context.enrich(detect.detect(ev), ev, INV)

        full = run(alerts)
        head = run(alerts[:2])

        for col in ("host_novelty", "peer_rarity", "signed_ratio",
                    "burst_size", "event_count", "cmdline_distance"):
            np.testing.assert_allclose(
                full[col].to_numpy()[:2], head[col].to_numpy()[:2],
                rtol=0, atol=1e-9,
                err_msg=f"{col} changed when a later alert was appended",
            )

        self.assertGreater(full["host_novelty"].iloc[0],
                           full["host_novelty"].iloc[2])
        self.assertEqual(full["burst_size"].tolist(), [1.0, 2.0, 3.0])


# ---------------------------------------------------------------------------
# labelling
# ---------------------------------------------------------------------------


class TestLabels(BridgeTestCase):
    def test_build_dataset_derives_deceptive_labels(self):
        psexec = r"C:\Tools\PsExec.exe"
        parent = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        alerts = [
            _proc(1, psexec, "PsExec.exe -s cmd /c whoami", parent=parent,
                  ts="2026-02-10T10:00:00.000+0000"),
            _proc(2, psexec, "PsExec.exe -s cmd /c whoami", parent=parent,
                  ts="2026-02-10T10:10:00.000+0000"),
            _proc(3, psexec, "PsExec.exe -s cmd /c whoami", parent=parent,
                  ts="2026-02-10T10:20:00.000+0000"),
        ]
        truth = pd.DataFrame([{
            "run_id": "run-1", "rule_id": "R-1021-002",
            "technique": "T1021.002", "atomic_test": "1", "action": "atomic",
            "host": "SOC-VICTIM",
            "start_utc": "2026-02-10T10:09:00Z",
            "end_utc": "2026-02-10T10:11:00Z",
            "executor": "test", "status": "executed", "description": "test",
        }])
        alerts_path, truth_path = _capture(self.tmp, alerts, truth)

        df = build(alerts_path, truth_path, ROOT / "lab" / "inventory",
                   verbose=False)

        assert_schema(df)
        self.assertTrue(set(REQUIRED_COLUMNS) <= set(df.columns))
        self.assertEqual(len(df), 3)
        self.assertEqual(int(df["label"].sum()), 1)
        self.assertEqual(int(df["is_deceptive_fp"].sum()), 2)
        self.assertEqual(int(df["is_deceptive_attack"].sum()), 1)
        self.assertEqual(df["host_id"].unique().tolist(), ["soc-victim"])
        self.assertTrue(df["ts"].is_monotonic_increasing)

    def test_refuses_unlabelled_capture(self):
        alerts = [_proc(1, r"C:\Tools\PsExec.exe", "PsExec.exe -s cmd")]
        alerts_path, truth_path = _capture(self.tmp, alerts,
                                           label.truth_template())
        with self.assertRaises(ValueError):
            build(alerts_path, truth_path, ROOT / "lab" / "inventory",
                  verbose=False)


# ---------------------------------------------------------------------------
# dataset loading and splitting
# ---------------------------------------------------------------------------


class TestDataset(BridgeTestCase):
    def _write_valid(self, n: int = 12) -> Path:
        rows = []
        for i in range(n):
            rows.append({
                "alert_id": f"AL-{i:06d}",
                "ts": f"2026-02-10T10:{i:02d}:00",
                "week": 1,
                "dow": 1,
                "host_id": "soc-victim",
                "asset_type": "workstation",
                "asset_criticality": 2,
                "user_id": "dave",
                "user_role": "developer",
                "rule_id": "R-1021-002",
                "rule_name": "Remote Service Execution via PsExec",
                "technique": "T1021.002",
                "severity": 4,
                "process_name": "psexec.exe",
                "parent_process": "powershell.exe",
                "command_line": "PsExec.exe -s cmd",
                "event_count": 3,
                "burst_size": 1,
                "lineage_depth": 2,
                "host_novelty": 0.4,
                "peer_rarity": 0.5,
                "cmdline_distance": 0.2,
                "dst_reputation": 0.1,
                "signed_ratio": 0.0,
                "role_asset_mismatch": 0,
                "label": 1 if i == n - 1 else 0,
                "is_deceptive_fp": 0,
                "is_deceptive_attack": 0,
            })
        path = self.tmp / "lab_dataset.csv"
        pd.DataFrame(rows).to_csv(path, index=False)
        return path

    def test_roundtrip_and_short_capture_split(self):
        df = load_dataset(self._write_valid())
        self.assertEqual(len(df), 12)
        self.assertEqual(df["label"].sum(), 1)

        train, calib, test = temporal_split(df, DEFAULT)
        self.assertTrue(len(train) and len(calib) and len(test))
        self.assertEqual(len(train) + len(calib) + len(test), 12)
        self.assertLessEqual(train["ts"].max(), calib["ts"].min())
        self.assertLessEqual(calib["ts"].max(), test["ts"].min())
        self.assertEqual(split_info(df, DEFAULT)["mode"], "time-fraction")

    def test_rejects_missing_columns(self):
        path = self.tmp / "broken.csv"
        pd.DataFrame({
            "ts": ["2026-02-10T10:00:00"],
            "label": [0],
            "is_deceptive_fp": [0],
            "is_deceptive_attack": [0],
        }).to_csv(path, index=False)
        with self.assertRaisesRegex(ValueError, "missing required columns"):
            load_dataset(path)

    def test_schema_rejects_unsorted_time(self):
        df = pd.DataFrame({c: [1, 1] for c in REQUIRED_COLUMNS})
        df["ts"] = pd.to_datetime(["2026-02-10 10:01", "2026-02-10 10:00"])
        df["label"] = [0, 1]
        df["is_deceptive_fp"] = [0, 0]
        df["is_deceptive_attack"] = [0, 0]
        with self.assertRaisesRegex(ValueError, "sorted ascending"):
            assert_schema(df)


if __name__ == "__main__":
    unittest.main()
