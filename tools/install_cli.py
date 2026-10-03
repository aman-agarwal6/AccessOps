"""Install official, checksum-pinned free tools into this project's .local/bin."""

import argparse
import hashlib
import io
import platform
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASES = {
    ("syft", "Windows"): (
        "https://github.com/anchore/syft/releases/download/v1.54.0/syft_1.54.0_windows_amd64.zip",
        "77f4b472779058e819eec9a054753a5071a996aaa40db31a290f8b256748593f",
        "syft.exe",
    ),
    ("syft", "Linux"): (
        "https://github.com/anchore/syft/releases/download/v1.54.0/syft_1.54.0_linux_amd64.tar.gz",
        "54a87372498168b2d033e876fd41fa4e8035b872699e525a57046e1f2f09c860",
        "syft",
    ),
    ("actionlint", "Windows"): (
        "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_windows_amd64.zip",
        "6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9",
        "actionlint.exe",
    ),
    ("actionlint", "Linux"): (
        "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz",
        "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
        "actionlint",
    ),
    ("gitleaks", "Windows"): (
        "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip",
        "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
        "gitleaks.exe",
    ),
    ("gitleaks", "Linux"): (
        "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
        "gitleaks",
    ),
    ("gh", "Windows"): (
        "https://github.com/cli/cli/releases/download/v2.102.0/gh_2.102.0_windows_amd64.zip",
        "ae64e556ecc240b200f7eba60d550e4bb60d78e860e69dd88c449405b86067f4",
        "gh.exe",
    ),
    ("gh", "Linux"): (
        "https://github.com/cli/cli/releases/download/v2.102.0/gh_2.102.0_linux_amd64.tar.gz",
        "bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386",
        "gh",
    ),
}


def install(tool: str) -> Path:
    if platform.machine().lower() not in {"amd64", "x86_64"}:
        raise ValueError("This pinned bootstrap supports x64 Windows/Linux only")
    url, expected, binary = RELEASES[(tool, platform.system())]
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(128_000_001)
    if len(data) > 128_000_000 or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Official tool archive checksum/size mismatch")
    # Read only the known binary. Never extract remote archive paths or links.
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            matches = [name for name in archive.namelist() if name.split("/")[-1] == binary]
            if len(matches) != 1 or archive.getinfo(matches[0]).file_size > 128_000_000:
                raise ValueError("Unexpected binary entry")
            content = archive.read(matches[0])
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            matches = [member for member in archive if member.name.split("/")[-1] == binary]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 128_000_000:
                raise ValueError("Unexpected binary entry")
            content = archive.extractfile(matches[0]).read()
    destination = ROOT / ".local" / "bin" / binary
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    destination.chmod(0o755)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=("gitleaks", "gh", "actionlint", "syft"))
    print(install(parser.parse_args().tool))
