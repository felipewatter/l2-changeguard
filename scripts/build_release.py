"""Deterministic, offline source distribution without secrets or VCS artifacts."""
from __future__ import annotations

import hashlib
import json
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = ('src/', 'tests/', 'examples/', 'docs/', 'scripts/', '.github/', '.gitignore',
           'README.md', 'README.en.md', 'CHANGELOG.md', 'LICENSE', 'SECURITY.md',
           'CONTRIBUTING.md', 'pyproject.toml')
IGNORE = {'__pycache__', '.pytest_cache', '.git', 'dist', 'build'}


def included(path: Path) -> bool:
    rel = path.relative_to(ROOT).as_posix()
    return (path.is_file() and not path.is_symlink()
            and not any(part in IGNORE or part.endswith('.egg-info') or part.endswith('.pyc') for part in path.parts)
            and any(rel.startswith(prefix) if prefix.endswith('/') else rel == prefix for prefix in INCLUDE))


def build(destination: Path) -> tuple[Path, Path, Path]:
    version = tomllib.loads((ROOT/'pyproject.toml').read_text(encoding='utf-8'))['project']['version']
    destination.mkdir(parents=True, exist_ok=True)
    prefix = f'l2-changeguard-v{version}'
    paths = sorted((p for p in ROOT.rglob('*') if included(p)), key=lambda p:p.relative_to(ROOT).as_posix())
    manifest = {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    if not paths or 'README.md' not in manifest:
        raise ValueError('distribution missing mandatory source files')
    manifest_path = destination/f'{prefix}-manifest.json'
    manifest_path.write_text(json.dumps({'version':version,'sha256':manifest}, indent=2, sort_keys=True)+'\n',encoding='utf-8')
    archive = destination/f'{prefix}-source.zip'
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in paths:
            info=zipfile.ZipInfo(prefix+'/'+p.relative_to(ROOT).as_posix(),date_time=(2026, 11, 9, 0, 0, 0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o100644 << 16
            z.writestr(info, p.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    checksums = destination/f'{prefix}-SHA256SUMS.txt'
    checksums.write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in (archive,manifest_path)),encoding='utf-8')
    return archive, manifest_path, checksums


if __name__=='__main__':
    for path in build(Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'dist'):
        print(path)
