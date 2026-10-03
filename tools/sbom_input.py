"""Stage only application lockfiles for a declared-dependency SBOM."""

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "output" / "sbom-source"
INPUTS = {
    "backend/requirements.lock": "python/requirements.txt",
    "frontend/package-lock.json": "javascript/package-lock.json",
    "frontend/package.json": "javascript/package.json",
}

for source, destination in INPUTS.items():
    target = TARGET / destination
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / source, target)
print(
    "Application runtime locks staged; OS/container layers and optional model weights are outside this SBOM."
)
