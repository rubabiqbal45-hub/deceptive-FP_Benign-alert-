#!/usr/bin/env python3
"""Tiny ground-truth upload endpoint for the lab.

Runs on the SIEM VM and accepts the files the Windows host produces:

    POST /ground_truth   -> <shared>/lab/out/ground_truth.csv
    POST /manifest       -> <shared>/lab/out/run_manifest.json
    GET  /health         -> {"ok": true}

Why this exists: the Windows Vagrant guest does not reliably get a shared
folder (it depends on Guest Additions / SMB), and the host-only network is the
one path that always works.  This keeps the capture loop to one command on the
Windows box instead of a manual file copy.

No authentication. It is bound to the lab network only, and the runbook tells
you to leave it stopped when you are not capturing:

    sudo systemctl stop lab-upload
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024
TARGETS = {
    "/ground_truth": "ground_truth.csv",
    "/manifest": "run_manifest.json",
}


def _atomic_write(dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(dest.parent), prefix=".upload-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class Handler(BaseHTTPRequestHandler):
    outdir: Path = Path("/vagrant/lab/out")

    def log_message(self, fmt, *args):  # quieter than the default
        print(f"{self.address_string()} {fmt % args}", flush=True)

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            self._send(200, {"ok": True, "outdir": str(self.outdir)})
        else:
            self._send(404, {"error": "unknown path"})

    def do_POST(self):  # noqa: N802
        name = TARGETS.get(self.path.split("?")[0])
        if name is None:
            self._send(404, {"error": "unknown path"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            self._send(400, {"error": "empty body"})
            return
        if length > MAX_BYTES:
            self._send(413, {"error": "payload too large"})
            return

        data = self.rfile.read(length)
        dest = self.outdir / name
        try:
            _atomic_write(dest, data)
        except OSError as exc:
            self._send(500, {"error": str(exc)})
            return

        rows = data.count(b"\n") - 1 if name.endswith(".csv") else None
        self._send(200, {"ok": True, "path": str(dest), "bytes": len(data),
                         "rows": rows})


def main() -> int:
    ap = argparse.ArgumentParser(description="lab ground-truth upload endpoint")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--outdir", default="/vagrant/lab/out")
    args = ap.parse_args()

    Handler.outdir = Path(args.outdir)
    Handler.outdir.mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"listening on {args.host}:{args.port} -> {Handler.outdir}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
