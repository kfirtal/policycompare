"""Verify transfer-file integrity using only Python's standard library."""
import hashlib
import json
from pathlib import Path, PurePosixPath


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def generated_file(path):
    """These directories may be created after installing/testing the bundle."""
    return (path.parts[0] in {'.venv', 'reports', 'logs', 'snapshots'}
            or '__pycache__' in path.parts)


def verify_bundle(root):
    root = Path(root).resolve()
    errors = []
    try:
        manifest = json.loads((root / 'MANIFEST.json').read_text(encoding='utf-8'))
        files = manifest['files']
        if manifest['format'] != 1 or not isinstance(files, dict) or not files:
            raise ValueError()
    except (OSError, ValueError, KeyError, TypeError):
        return ['Invalid or missing manifest']
    for name, expected in files.items():
        if not isinstance(name, str) or not isinstance(expected, dict):
            errors.append('Invalid file record')
            continue
        relative = PurePosixPath(name)
        if (relative.is_absolute() or '..' in relative.parts or '\\' in name
                or relative.as_posix() != name or ':' in name):
            errors.append('Unsafe manifest path')
            continue
        path = root.joinpath(*relative.parts)
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            errors.append('File escapes bundle: ' + name)
            continue
        try:
            if path.stat().st_size != expected['size'] or sha256(path) != expected['sha256']:
                errors.append('Changed file: ' + name)
        except (OSError, ValueError, KeyError, TypeError):
            errors.append('Missing or invalid file: ' + name)
    expected_names = set(files) | {'MANIFEST.json'}
    for path in root.rglob('*'):
        relative = path.relative_to(root)
        if not generated_file(relative) and (path.is_file() or path.is_symlink()):
            if relative.as_posix() not in expected_names:
                errors.append('Unexpected file: ' + relative.as_posix())
    return errors


def main():
    errors = verify_bundle(Path(__file__).resolve().parent)
    if errors:
        # Do not echo manifest-controlled paths or file contents to a terminal.
        print('FAIL: bundle integrity check failed; issues: ' + str(len(errors)))
        return 1
    print('PASS: all bundle files match the SHA-256 manifest.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
