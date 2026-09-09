"""Reject tracked runtime data, secrets and collection artifacts before publication."""
from pathlib import Path
import subprocess


def main():
    root = Path(__file__).resolve().parents[1]
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    references = {'data/' + line for line in (root / 'scripts/vps_reference_files.txt').read_text().splitlines()}
    failures = []
    for name in filter(None, tracked):
        path = Path(name)
        if (root / path).is_symlink():
            failures.append(name)
        if name.startswith('data/') and name not in references and path.name != '.gitkeep':
            failures.append(name)
        if name.startswith(('reports/', 'outputs/', 'screenshots/')) and path.name != '.gitkeep':
            failures.append(name)
        if name.startswith(('.codex/', '.codebase-memory/', 'graphify-out/')):
            failures.append(name)
        if path.name.startswith('.env') and not path.name.endswith('.example'):
            failures.append(name)
        if path.suffix.lower() in {'.sqlite', '.db', '.dump', '.sql', '.pem', '.key', '.p12', '.pfx', '.lkg'}:
            failures.append(name)
        if name.startswith('docs/') and path.suffix.lower() in {'.png', '.jpg', '.jpeg', '.docx'}:
            failures.append(name)
    if failures:
        raise SystemExit('Private or unapproved files tracked:\n' + '\n'.join(sorted(set(failures))))
    print(f'Public file policy passed: {len(list(filter(None, tracked)))} tracked paths.')


if __name__ == '__main__':
    main()
