"""Transfer packaging must exclude private workspace files and reject tampering."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from package_transfer import SOURCE_FILES, build_bundle, read_lock
from verify_bundle import sha256, verify_bundle


class TransferTests(unittest.TestCase):
    def setUp(self):
        reports = Path(__file__).resolve().parents[1] / 'reports'
        reports.mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(dir=reports)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / 'source'
        self.wheels = self.root / 'wheels'
        self.wheels.mkdir()
        self.output = self.root / 'bundle.zip'
        for name in SOURCE_FILES:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic file\n', encoding='utf-8')
        self.wheel = self.wheels / 'synthetic-1.0-py3-none-any.whl'
        with zipfile.ZipFile(self.wheel, 'w') as archive:
            archive.writestr('synthetic-1.0.dist-info/METADATA', 'Name: synthetic\nVersion: 1.0\n')
        self.lock = self.source / 'requirements-offline.txt'
        self.lock.write_text('synthetic==1.0 --hash=sha256:' + sha256(self.wheel) + '\n', encoding='utf-8')

    def build(self):
        return build_bundle(self.source, self.wheels, self.output, 'synthetic-revision')

    def extract(self):
        with zipfile.ZipFile(self.output) as archive:
            archive.extractall(self.root / 'extracted')
        return self.root / 'extracted/PolicyCompare'

    def test_only_allowlisted_sources_and_locked_wheels_enter_archive(self):
        for name in ('.git/config', '.git/security-before-sanitization.bundle', '.env',
                     '.deps/private.py', 'snapshots/raw.json', 'reports/private.txt', 'logs/private.log'):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('SYNTHETIC-DO-NOT-PACK', encoding='utf-8')
        manifest = self.build()
        self.assertEqual(set(manifest['files']), set(SOURCE_FILES) | {'wheelhouse/' + self.wheel.name})
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(len(archive.namelist()), len(manifest['files']) + 1)
            self.assertTrue(all(name.startswith('PolicyCompare/') for name in archive.namelist()))
            self.assertTrue(all(b'SYNTHETIC-DO-NOT-PACK' not in archive.read(name) for name in archive.namelist()))
        self.assertEqual(verify_bundle(self.extract()), [])
        self.assertEqual(self.output.with_suffix('.zip.sha256').read_text(encoding='ascii').split()[0], sha256(self.output))

    def test_output_is_deterministic_and_cannot_overwrite_previous_release(self):
        self.build()
        with self.assertRaises(ValueError):
            self.build()
        second = self.root / 'second.zip'
        build_bundle(self.source, self.wheels, second, 'synthetic-revision')
        self.assertEqual(sha256(self.output), sha256(second))

    def test_changed_missing_or_extra_payload_fails_integrity(self):
        self.build()
        root = self.extract()
        original = (root / 'csm.py').read_bytes()
        (root / 'csm.py').write_bytes(b'changed')
        self.assertTrue(verify_bundle(root))
        (root / 'csm.py').write_bytes(original)
        (root / 'unexpected.py').write_text('extra', encoding='utf-8')
        self.assertTrue(verify_bundle(root))
        (root / 'unexpected.py').unlink()
        (root / 'csm.py').unlink()
        self.assertTrue(verify_bundle(root))

    def test_generated_runtime_files_do_not_invalidate_original_payload(self):
        self.build()
        root = self.extract()
        for name in ('reports/run/result.json', '.venv/pyvenv.cfg', 'tests/__pycache__/example.pyc'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('runtime file', encoding='utf-8')
        self.assertEqual(verify_bundle(root), [])

    def test_missing_or_changed_wheel_prevents_build(self):
        self.wheel.write_bytes(b'not a wheel')
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            self.build()
        self.assertFalse(self.output.exists())

    def test_wheel_with_changed_hash_or_extra_unapproved_artifact_is_rejected(self):
        digest = hashlib.sha256(b'wrong').hexdigest()
        self.lock.write_text('synthetic==1.0 --hash=sha256:' + digest, encoding='utf-8')
        with self.assertRaises(ValueError):
            self.build()
        self.lock.write_text('synthetic==1.0 --hash=sha256:' + sha256(self.wheel), encoding='utf-8')
        (self.wheels / 'extra.txt').write_text('unapproved', encoding='utf-8')
        with self.assertRaises(ValueError):
            self.build()

    def test_missing_source_prevents_incomplete_release(self):
        (self.source / 'fmc.py').unlink()
        with self.assertRaises(ValueError):
            self.build()

    def test_dependency_lock_requires_unique_exact_pins_and_hashes(self):
        for content in ('', 'synthetic>=1.0', 'synthetic==1.0 --hash=sha256:invalid',
                        self.lock.read_text(encoding='utf-8') * 2):
            self.lock.write_text(content, encoding='utf-8')
            with self.subTest(content=content), self.assertRaises(ValueError):
                read_lock(self.lock)

    def test_unsafe_or_malformed_manifest_is_rejected(self):
        self.build()
        root = self.extract()
        for files in ({'../outside': {'size': 1, 'sha256': 'invalid'}}, {'csm.py': None}, {}):
            (root / 'MANIFEST.json').write_text(json.dumps({'format': 1, 'files': files}), encoding='utf-8')
            with self.subTest(files=files):
                self.assertTrue(verify_bundle(root))


if __name__ == '__main__':
    unittest.main()
