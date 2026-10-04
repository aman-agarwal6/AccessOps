"""Correct only the handed-over lab CA certificate; never export its key."""

import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path("/var/lib/adlab/private/lab-tls")


def openssl(*args):
    return subprocess.run(
        ["openssl", *map(str, args)], check=True, capture_output=True, timeout=10
    ).stdout


def main():
    started = dt.datetime.now(dt.timezone.utc)
    try:
        ca, key, leaf = ROOT / "ca.crt", ROOT / "ca.key", ROOT / "server.crt"
        for path in (ca, key, leaf):
            if not path.resolve().is_relative_to(ROOT.resolve()) or path.is_symlink():
                raise ValueError
        before = ca.read_bytes()  # Public certificate only; key stays in OpenSSL.
        subject = openssl("x509", "-in", ca, "-noout", "-subject", "-nameopt", "RFC2253")
        public_key = openssl("x509", "-in", ca, "-noout", "-pubkey")
        ski = openssl("x509", "-in", ca, "-noout", "-ext", "subjectKeyIdentifier")
        leaf_hash = hashlib.sha256(leaf.read_bytes()).hexdigest()
        extensions = Path("/tmp/accessops-ca-extensions.conf")
        extensions.write_text(
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
        )
        corrected = ROOT / "ca.strict.crt"
        openssl(
            "x509",
            "-in",
            ca,
            "-signkey",
            key,
            "-days",
            "365",
            "-extfile",
            extensions,
            "-out",
            corrected,
        )
        if (
            openssl("x509", "-in", corrected, "-noout", "-subject", "-nameopt", "RFC2253")
            != subject
            or openssl("x509", "-in", corrected, "-noout", "-pubkey") != public_key
            or openssl("x509", "-in", corrected, "-noout", "-ext", "subjectKeyIdentifier") != ski
        ):
            raise ValueError
        openssl("verify", "-x509_strict", "-CAfile", corrected, leaf)
        suffix = started.strftime("%Y%m%dT%H%M%SZ")
        backup = ROOT / ("ca.before-key-usage." + suffix + ".crt")
        if backup.exists():
            raise ValueError
        shutil.copyfile(ca, backup)
        backup.chmod(0o600)
        os.replace(corrected, ca)
        ca.chmod(0o644)
        public_ca = Path("/run/lab-ca/ca.crt")
        public_ca.write_bytes(ca.read_bytes())
        public_ca.chmod(0o644)
        if hashlib.sha256(leaf.read_bytes()).hexdigest() != leaf_hash:
            raise ValueError
        print(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "origin": "connected_samba_ad_certificate_correction",
                    "startedAt": started.isoformat(),
                    "finishedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "status": "passed",
                    "sameSubject": True,
                    "samePublicKey": True,
                    "sameSubjectKeyIdentifier": True,
                    "leafUnchanged": True,
                    "strictOpenSSLVerification": True,
                    "beforeCertificateSha256": hashlib.sha256(before).hexdigest(),
                    "afterCertificateSha256": hashlib.sha256(ca.read_bytes()).hexdigest(),
                    "limitations": [
                        "Only the synthetic lab CA certificate was reissued; no private key was exported, no OS trust was modified, and no directory or credential state was reset."
                    ],
                }
            )
        )
        return 0
    except Exception:
        print(
            "Scoped CA correction failed; preserve certificate state for review.", file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
