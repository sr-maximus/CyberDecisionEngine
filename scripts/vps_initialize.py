"""Initialize empty runtime volumes from explicitly selected public reference catalogs."""
import os
import shutil
from pathlib import Path


def main():
    data, reports = Path('/app/data'), Path('/app/reports')
    for target in (data, reports):
        target.mkdir(parents=True, exist_ok=True)
        os.chown(target, 10001, 10001)
    # Never copy the data root, run snapshots, reports, recovery or auth state.
    for relative in Path('/app/scripts/vps_reference_files.txt').read_text().splitlines():
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('Invalid reference path')
        source, target = Path('/seed') / path, data / path
        if source.is_symlink() or not source.is_file():
            raise ValueError(f'Missing public reference: {relative}')
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copyfile(source, target)
            os.chown(target, 10001, 10001)
        parent = target.parent
        while parent != data:
            os.chown(parent, 10001, 10001)
            parent = parent.parent


if __name__ == '__main__':
    main()
