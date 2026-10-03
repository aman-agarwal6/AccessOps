import tempfile
import unittest
from pathlib import Path

from check_locks import check_locks, read_pins


class LockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.backend = self.root / "backend"
        self.backend.mkdir()
        self.write("requirements.txt", "Demo_Name[crypto]==1.2.3\n")
        self.write("requirements-dev.txt", "-r requirements.txt\npytest==9.1.1\n")
        self.write("requirements.lock", self.lock({"demo-name": "1.2.3", "transitive": "2.0"}))
        self.write(
            "requirements-dev.lock",
            self.lock({"demo-name": "1.2.3", "transitive": "2.0", "pytest": "9.1.1"}),
        )

    def write(self, name, content):
        (self.backend / name).write_text(content, encoding="utf-8")

    def lock(self, pins):
        return "".join(
            f"{name}=={version} \\\n    --hash=sha256:" + "a" * 64 + "\n    # via test\n"
            for name, version in pins.items()
        )

    def test_normalized_extras_multiline_hashes_and_recursive_includes(self):
        self.write("nested.txt", "-r requirements.txt\n")
        self.write("requirements-dev.txt", "-r nested.txt\npytest==9.1.1\n")
        check_locks(self.backend)

    def test_missing_and_changed_pins_cannot_test_old_locked_versions(self):
        for lock in [
            {"demo-name": "1.2.2", "transitive": "2.0"},
            {"transitive": "2.0"},
        ]:
            with self.subTest(lock=lock), self.assertRaisesRegex(ValueError, "Runtime lock"):
                self.write("requirements.lock", self.lock(lock))
                check_locks(self.backend)
        self.write("requirements.lock", self.lock({"demo-name": "1.2.3", "transitive": "2.1"}))
        with self.assertRaisesRegex(ValueError, "Runtime/development locks"):
            check_locks(self.backend)
        self.write("requirements.lock", self.lock({"demo-name": "1.2.3", "transitive": "2.0"}))
        for version in ["9.1.0", None]:
            pins = {"demo-name": "1.2.3", "transitive": "2.0"}
            if version:
                pins["pytest"] = version
            self.write("requirements-dev.lock", self.lock(pins))
            with (
                self.subTest(version=version),
                self.assertRaisesRegex(ValueError, "Development lock"),
            ):
                check_locks(self.backend)
        self.write("requirements-dev.txt", "pytest==9.1.1\n")
        with self.assertRaisesRegex(ValueError, "Development requirements"):
            check_locks(self.backend)

    def test_include_cycles_and_traversal_are_rejected(self):
        self.write("nested.txt", "-r requirements-dev.txt\n")
        for include, message in [
            ("-r requirements-dev.txt\n", "cycle"),
            ("-r nested.txt\n", "cycle"),
            ("-r ../outside.txt\n", "escapes"),
        ]:
            with self.subTest(include=include), self.assertRaisesRegex(ValueError, message):
                self.write("requirements-dev.txt", include)
                read_pins(self.backend / "requirements-dev.txt", self.backend)

    def test_unsupported_inputs_and_unhashed_locks_fail_closed(self):
        for value in ["demo>=1.2", "demo==1.*", "demo==1.2; python_version>'3'", "-e ./demo"]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "unsupported"):
                self.write("requirements.txt", value)
                read_pins(self.backend / "requirements.txt", self.backend)
        self.write("requirements.lock", "demo-name==1.2.3\n")
        with self.assertRaisesRegex(ValueError, "unhashed"):
            read_pins(self.backend / "requirements.lock", self.backend, locked=True)


if __name__ == "__main__":
    unittest.main()
