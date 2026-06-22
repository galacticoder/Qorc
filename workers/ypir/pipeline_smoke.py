#!/usr/bin/env python3
"""Full YPIR tier-2 pipeline smoke: worker HTTP service + client daemon + the real query cycle.

Build both bins first (see BUILD_NOTES.md):
  RUSTFLAGS="-C target-cpu=native -L native=$HOME/.local/lib" cargo build --release --bin ypir_worker --bin ypir_client

Then start the worker and run this:
  YPIR_WORKER_ADDR=127.0.0.1:8792 YPIR_NUM_ITEMS=2048 YPIR_BLOB_LEN=16384 ./target/release/ypir_worker &
  python3 pipeline_smoke.py

It uploads a DB (slot 5 = a ramp blob), drives the daemon (query-record -> POST /v1/query ->
recover-record), and asserts the recovered blob equals what was uploaded. Exit 0 = pass.
"""
import base64, json, subprocess, urllib.request, sys, os

BASE = os.environ.get("YPIR_WORKER_URL", "http://127.0.0.1:8792")
BLOB = int(os.environ.get("YPIR_BLOB_LEN", "16384"))
NUM = os.environ.get("YPIR_NUM_ITEMS", "2048")
SLOT = 5


def post(path, data):
    r = urllib.request.Request(BASE + path, data=data, method="POST",
                               headers={"Content-Type": "application/octet-stream"})
    return urllib.request.urlopen(r, timeout=120).read()


def main():
    ramp = bytes(i % 256 for i in range(BLOB))
    body = bytearray(SLOT * BLOB) + ramp  # slots 0..4 empty, slot 5 = ramp
    print("[smoke] POST /v1/databases", len(body), "bytes ->", post("/v1/databases", bytes(body)).decode())

    d = subprocess.Popen(["./target/release/ypir_client"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         env={"YPIR_NUM_ITEMS": NUM, "YPIR_BLOB_LEN": str(BLOB), "PATH": "/usr/bin"})

    def daemon(obj):
        d.stdin.write((json.dumps(obj) + "\n").encode()); d.stdin.flush()
        return json.loads(d.stdout.readline())

    q = daemon({"op": "query-record", "slot": SLOT})
    print("[smoke] query-record ok=", q["ok"], "handle=", q["handle"], "req=", len(q["request"]), "b64")
    resp = post("/v1/query", base64.b64decode(q["request"]))
    print("[smoke] /v1/query -> response", len(resp), "bytes")
    rec = daemon({"op": "recover-record", "handle": q["handle"], "response": base64.b64encode(resp).decode()})
    blob = base64.b64decode(rec["blob"]) if rec.get("ok") else b""
    ok = blob[:BLOB] == ramp
    print("[smoke] recover-record ok=", rec.get("ok"), " blob matches uploaded ramp:", ok)
    d.stdin.close(); d.wait()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
