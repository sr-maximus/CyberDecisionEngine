"""Create private operator credentials outside Git for the SSH-only VPS profile.

The reverse proxy authenticates every application request. The browser bootstrap
only initializes the legacy single-operator UI; it is not tenant authorization.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
from datetime import datetime, timezone


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--secret-dir', type=Path, default=Path('/etc/cde/secrets'))
    args = parser.parse_args()
    root = args.secret_dir
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    credentials = root / 'operator-credentials.json'
    if credentials.exists():
        login = json.loads(credentials.read_text())
    else:
        login = {'username': 'superadmin', 'password': secrets.token_urlsafe(24)}
        with os.fdopen(os.open(credentials, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as handle:
            json.dump(login, handle)
    subprocess.run(
        ['htpasswd', '-i', '-B', '-C', '12', '-c', str(root / 'operator.htpasswd'), login['username']],
        input=(login['password'] + '\n').encode(), check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    user = {
        'id': 'private-operator', 'username': login['username'],
        'passwordHash': hashlib.sha256(login['password'].encode()).hexdigest(),
        'fullName': 'Operador privado', 'role': 'super_admin', 'permissions': [],
        'mfaEnabled': False, 'mustChangePassword': False,
        'createdAt': datetime.now(timezone.utc).isoformat(),
    }
    # There is no password in this page. It is served only behind the SSH tunnel
    # and the reverse proxy password, and never becomes part of the public image.
    serialized = json.dumps(user).replace('<', '\\u003c')
    page = '''<!doctype html><html lang="es"><meta charset="utf-8">
<title>Acceso privado</title><p>Inicializando acceso del operador…</p><script>
const user = USER_JSON;
const key = "cyberdecision.users";
let users = [];
try { users = JSON.parse(localStorage.getItem(key) || "[]"); } catch (_) {}
if (!Array.isArray(users)) users = [];
users = users.filter(item => item && item.id !== user.id);
users.push(user);
localStorage.setItem(key, JSON.stringify(users));
localStorage.setItem("cyberdecision.session", JSON.stringify({
  userId: user.id, issuedAt: Date.now(), lastActivity: Date.now()
}));
location.replace("/");
</script></html>'''.replace('USER_JSON', serialized)
    (root / 'operator-setup.html').write_text(page)
    for name in ('operator.htpasswd', 'operator-setup.html'):
        (root / name).chmod(0o444)
    print('Private operator files prepared; credentials are not printed.')


if __name__ == '__main__':
    main()
