"""Provision server accounts into a private directory; never print passwords.

Run once on the administrator host, then mount auth_users.json read-only in API.
Re-running preserves existing accounts. Keep public-credentials.json private.
"""
import argparse
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

def hash_password(password: str) -> str:
    # Standard-library-only bootstrap, using the server's validated digest format.
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
    return f"pbkdf2_sha256$600000${salt}${digest.hex()}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--superadmin-credentials", help="Existing private JSON with username/password")
    args = parser.parse_args()
    folder = Path(args.output_dir)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    config = folder / "auth_users.json"
    credentials_file = folder / "public-credentials.json"
    if config.exists() or credentials_file.exists():
        if not config.exists() or not credentials_file.exists():
            raise SystemExit("Partial credential state: preserve files and investigate before retrying")
        print("Existing public accounts preserved")
        return
    admin_password = (json.loads(Path(args.superadmin_credentials).read_text())["password"]
                      if args.superadmin_credentials else secrets.token_urlsafe(24))
    if len(admin_password) < 16:
        raise SystemExit("Administrator password must contain at least 16 characters")
    records, credentials = [], []
    for username, role, name, password in [
        ("superadmin", "super_admin", "Administrador", admin_password),
        ("operador", "analyst", "Operador", secrets.token_urlsafe(24)),
    ]:
        records.append({"id": username, "username": username, "role": role, "fullName": name,
                        "passwordHash": hash_password(password), "disabled": False,
                        "createdAt": datetime.now(timezone.utc).isoformat()})
        credentials.append({"username": username, "role": role, "password": password})
    # Exclusive creation avoids overwriting credentials from an earlier provisioning.
    for path, payload in [(credentials_file, {"users": credentials}), (config, {"users": records})]:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(payload, stream, indent=2)
    print("Created superadmin and operador; credentials are in the private output directory")


if __name__ == "__main__":
    main()
