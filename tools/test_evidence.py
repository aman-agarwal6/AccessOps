import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from evidence import junit_summary, source_fingerprint, verify_contents

TEMP_ROOT = Path(__file__).resolve().parents[1] / ".local" / "evidence-tests"
TEMP_ROOT.mkdir(parents=True, exist_ok=True)


class EvidenceTests(unittest.TestCase):
    def test_source_fingerprint_covers_docs_and_container_inputs_without_secrets(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            root = Path(directory)
            (root / "infra").mkdir()
            (root / "docs").mkdir()
            (root / "backend" / ".venv").mkdir(parents=True)
            (root / "README.md").write_text("reviewed setup")
            (root / "infra" / "Dockerfile.backend").write_text("FROM verified-image")
            (root / "docs" / "standards.md").write_text("supported boundaries")
            (root / "backend" / ".env").write_text("NONFUNCTIONAL_TEST_ENV")
            (root / "backend" / ".venv" / "private.py").write_text("excluded runtime")
            result = source_fingerprint(root)
            self.assertEqual(
                set(result), {"README.md", "infra/Dockerfile.backend", "docs/standards.md"}
            )
            old = result["docs/standards.md"]
            (root / "docs" / "standards.md").write_text("changed boundary")
            self.assertNotEqual(old, source_fingerprint(root)["docs/standards.md"])

    def make_archive(self, directory, member="verification.json", tamper=False):
        path = Path(directory) / "receipt.tar.gz"
        data = b'{"passed":1}'
        manifest = {
            "origin": "local",
            "revision": "test",
            "files": {member: hashlib.sha256(data).hexdigest()},
        }
        with tarfile.open(path, "w:gz") as archive:
            for name, content in [
                ("manifest.json", json.dumps(manifest).encode()),
                (member, data + (b" " if tamper else b"")),
            ]:
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return path

    def test_passed_failed_skipped_preserved(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            path = Path(directory) / "tests.xml"
            path.write_text(
                '<testsuite><testcase name="a"/><testcase name="b"><failure/></testcase><testcase name="c"><skipped/></testcase></testsuite>'
            )
            result = junit_summary(path)
            self.assertEqual(
                (result["total"], result["passed"], result["failed"], result["skipped"]),
                (3, 1, 1, 1),
            )

    def test_empty_report_cannot_be_passing_evidence(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            path = Path(directory) / "tests.xml"
            path.write_text('<testsuite tests="100"/>')
            with self.assertRaises(ValueError):
                junit_summary(path)

    def test_content_hash_validates(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            self.assertEqual(verify_contents(self.make_archive(directory))["origin"], "local")

    def test_tampered_content_rejected(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            with self.assertRaises(ValueError):
                verify_contents(self.make_archive(directory, tamper=True))

    def test_traversal_rejected_without_extracting(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            with self.assertRaises(ValueError):
                verify_contents(self.make_archive(directory, "../escape"))


if __name__ == "__main__":
    unittest.main()
