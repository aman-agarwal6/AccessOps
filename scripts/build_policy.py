"""Deterministically package exactly the Rego source loaded by the local engine."""

import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build():
    entries = {
        path.name: path.read_bytes().replace(b"\r\n", b"\n")
        for path in sorted((ROOT / "policies").glob("*.rego"))
        if not path.name.endswith("_test.rego")
    }
    if not entries:
        raise SystemExit("No policy source")
    source_digest = hashlib.sha256(
        b"".join(name.encode() + b"\0" + value for name, value in entries.items())
    ).hexdigest()
    entries[".manifest"] = json.dumps(
        {"revision": source_digest, "roots": ["accessops"]}, sort_keys=True
    ).encode()
    data = io.BytesIO()
    with gzip.GzipFile(fileobj=data, mode="wb", mtime=0, filename="") as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, value in sorted(entries.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(value), 0o444, 0
                archive.addfile(info, io.BytesIO(value))
    target = ROOT / ".local/policy/bundle.tar.gz"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data.getvalue())
    bundle_digest = hashlib.sha256(data.getvalue()).hexdigest()
    runtime = ROOT / ".local/policy-runtime.env"
    runtime.write_text("ACCESSOPS_POLICY_SHA256=" + bundle_digest + "\n", encoding="utf-8")
    print("Policy bundle SHA256 " + bundle_digest)


if __name__ == "__main__":
    build()
