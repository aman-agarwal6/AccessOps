"""Check direct requirement pins and runtime/development lock consistency."""

import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?==(\d[A-Za-z0-9.!+_-]*)")
HASH = re.compile(r"--hash=sha256:[a-f0-9]{64}")
INCLUDE = re.compile(r"-r\s+([A-Za-z0-9_./-]+\.txt)")


def merge(target, incoming):
    for name, version in incoming.items():
        if name in target and target[name] != version:
            raise ValueError(f"Conflicting pins for {name}")
        target[name] = version


def read_pins(path, root, locked=False, stack=()):
    path, root = Path(path).resolve(), Path(root).resolve()
    if not path.is_relative_to(root):
        raise ValueError("Requirement include escapes backend")
    if path in stack or len(stack) >= 16:
        raise ValueError("Requirement include cycle or excessive nesting")
    result, hashed = {}, set()
    previous, continued = None, False
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = raw.split("#", 1)[0].strip()
        if not text:
            continue
        following = text.endswith("\\")
        text = text.removesuffix("\\").strip()
        pin, include = PIN.fullmatch(text), INCLUDE.fullmatch(text)
        if include and not locked and not continued and not following:
            merge(result, read_pins(path.parent / include[1], root, stack=(*stack, path)))
        elif pin and not continued and (locked or not following):
            previous = re.sub(r"[-_.]+", "-", pin[1]).lower()
            merge(result, {previous: pin[2]})
        elif locked and continued and previous and HASH.fullmatch(text):
            hashed.add(previous)
        else:
            raise ValueError(f"{path.name}:{number}: unsupported requirement syntax")
        continued = following
    if not result or continued or locked and set(result) != hashed:
        raise ValueError(f"{path.name}: empty, incomplete, or unhashed requirements")
    return result


def require_matching(expected, actual, label):
    for name, version in expected.items():
        if actual.get(name) != version:
            raise ValueError(f"{label}: missing or mismatched pin for {name}=={version}")


def check_locks(backend=BACKEND):
    backend = Path(backend).resolve()
    runtime = read_pins(backend / "requirements.txt", backend)
    development = read_pins(backend / "requirements-dev.txt", backend)
    runtime_lock = read_pins(backend / "requirements.lock", backend, locked=True)
    development_lock = read_pins(backend / "requirements-dev.lock", backend, locked=True)
    require_matching(runtime, runtime_lock, "Runtime lock")
    require_matching(runtime, development, "Development requirements")
    require_matching(development, development_lock, "Development lock")
    require_matching(runtime_lock, development_lock, "Runtime/development locks")


if __name__ == "__main__":
    try:
        check_locks()
    except (OSError, ValueError) as error:
        raise SystemExit(f"Lock consistency failed: {error}") from None
    print("Direct pins and runtime/development locks are consistent.")
