"""Build an allowlisted ZIP; never copy a workspace or Git history wholesale."""
import argparse
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

from verify_bundle import sha256


SOURCE_FILES = (
    '.gitignore', 'README.md', 'LAB_GUIDE.md', 'TRANSFER_README_HE.md', 'DEPENDENCIES.md',
    'requirements.txt', 'requirements-offline.txt',
    'compare.py', 'csm.py', 'fmc.py', 'rule.py', 'normalization.py',
    'transport.py', 'response_validation.py', 'errors.py', 'snapshots.py', 'lab.py',
    'verify_bundle.py', 'package_transfer.py',
    'tests/test_api_validation.py', 'tests/test_cli.py', 'tests/test_clients.py',
    'tests/test_compare.py', 'tests/test_lab.py', 'tests/test_policy_inventories.py',
    'tests/test_snapshots.py', 'tests/test_transfer.py',
    'examples/csm.json', 'examples/fmc-network-drift.json', 'examples/fmc-service-drift.json',
)


def read_lock(path):
    """The release lock uses one pinned package with SHA-256 hashes per line."""
    locked = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        fields = line.split()
        pin = re.fullmatch(r'([a-z0-9-]+)==([0-9.]+)', fields[0])
        hashes = [re.fullmatch(r'--hash=sha256:([0-9a-f]{64})', field) for field in fields[1:]]
        if pin is None or not hashes or not all(hashes) or pin[1] in locked:
            raise ValueError('Invalid dependency lock')
        locked[pin[1]] = (pin[2], {value[1] for value in hashes})
    if not locked:
        raise ValueError('Empty dependency lock')
    return locked


def wheel_files(directory, locked):
    paths = sorted(directory.iterdir())
    found = {name: set() for name in locked}
    if not paths:
        raise ValueError('No dependency wheels found')
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.suffix != '.whl':
            raise ValueError('Only regular wheel files are allowed in wheelhouse')
        with zipfile.ZipFile(path) as wheel:
            metadata_files = [name for name in wheel.namelist() if name.endswith('.dist-info/METADATA')]
            if len(metadata_files) != 1:
                raise ValueError('Invalid wheel metadata')
            metadata = BytesParser().parsebytes(wheel.read(metadata_files[0]))
        name = (metadata.get('Name') or '').lower().replace('_', '-')
        digest = sha256(path)
        if name not in locked or metadata.get('Version') != locked[name][0] or digest not in locked[name][1]:
            raise ValueError('Wheel does not match the dependency lock')
        found[name].add(digest)
    if any(found[name] != hashes for name, (_, hashes) in locked.items()):
        raise ValueError('Wheelhouse is missing locked artifacts')
    return paths


def build_bundle(root, wheels, output, revision):
    """Package exact source files and verified wheels, then emit an archive hash."""
    root, wheels, output = Path(root).resolve(), Path(wheels).resolve(), Path(output).resolve()
    if output.exists() or output.with_suffix('.zip.sha256').exists():
        raise ValueError('Refusing to overwrite an existing release')
    sources = {name: root / name for name in SOURCE_FILES}
    for name, path in sources.items():
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError('Missing or unsafe source file: ' + name)
    locked = read_lock(root / 'requirements-offline.txt')
    for path in wheel_files(wheels, locked):
        sources['wheelhouse/' + path.name] = path
    # Keep one byte snapshot so archived content always matches its manifest.
    contents = {name: path.read_bytes() for name, path in sources.items()}
    manifest = dict(format=1, source_revision=revision,
                    target='Windows / Python 3.12; CSM 4.25 / FMC 7.6.5+',
                    dependencies={name: version for name, (version, _) in locked.items()},
                    files={name: {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
                           for name, data in sorted(contents.items())})
    contents['MANIFEST.json'] = json.dumps(manifest, ensure_ascii=False, indent=2).encode('utf-8')
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(contents.items()):
            # Fixed metadata omits local paths, owners and filesystem times.
            entry = zipfile.ZipInfo('PolicyCompare/' + name, date_time=(2020, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
    digest = sha256(output)
    output.with_suffix('.zip.sha256').write_text(digest + '  ' + output.name + '\n', encoding='ascii')
    return manifest


def main():
    parser = argparse.ArgumentParser(description='Build a clean transfer ZIP from explicit allowed files')
    parser.add_argument('--wheel-dir', type=Path, default=Path('dist/wheelhouse'))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    # A release must point to a committed source snapshot.
    status = subprocess.run(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=root,
                            capture_output=True, text=True, check=True)
    if status.stdout:
        parser.error('Commit source changes before building a release')
    revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root,
                              capture_output=True, text=True, check=True).stdout.strip()
    manifest = build_bundle(root, args.wheel_dir, args.output, revision)
    print('Transfer ZIP built; payload files: ' + str(len(manifest['files'])))


if __name__ == '__main__':
    raise SystemExit(main())
