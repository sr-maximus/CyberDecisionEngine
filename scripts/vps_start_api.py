"""Load the database secret inside the container; do not expose it in Compose output."""
import os
from pathlib import Path
from urllib.parse import quote

password = Path('/run/secrets/db_password').read_text().strip()
if len(password) < 32:
    raise SystemExit('Database secret must contain at least 32 characters')
db_user = quote(os.environ.get('CDE_DATABASE_USER', 'cde'), safe='')
os.environ['DATABASE_URL'] = f'postgresql://{db_user}:{quote(password, safe="")}@postgres:5432/cyberdecisionengine'
os.execvp('uvicorn', ['uvicorn', 'cyberdeck_api.main:app', '--host', '0.0.0.0', '--port', '8000', '--workers', '1'])
