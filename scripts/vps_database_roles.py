"""Separate database administrator and application roles on an existing private VPS.

Run on the Docker host as root, after backing up a nonempty deployment. A fresh
installation uses deploy/vps/create-app-db.sh instead. Secrets never print.
"""
from pathlib import Path
import os
import secrets
import subprocess


def main():
    root = Path('/etc/cde/secrets')
    path = root / 'db_admin_password'
    if not path.exists():
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as handle:
            handle.write(secrets.token_hex(32))
    password = path.read_text().strip()
    if len(password) != 64 or any(ch not in '0123456789abcdef' for ch in password):
        raise SystemExit('Invalid database administrator secret format')
    path.chmod(0o444)
    def sql(user, statement):
        return subprocess.run(
            ['docker', 'exec', '-i', 'cde-vps-postgres-1', 'psql', '-X', '-q',
             '-U', user, '-d', 'postgres', '-v', 'ON_ERROR_STOP=1'],
            input=statement.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    if sql('cde_dbadmin', 'SELECT 1;').returncode:
        result = sql('cde', "CREATE ROLE cde_dbadmin LOGIN SUPERUSER PASSWORD '" + password + "';")
        if result.returncode:
            raise SystemExit('Could not initialize separate database administrator')
    app_password = (root / 'db_password').read_text().strip()
    if len(app_password) != 64 or any(ch not in '0123456789abcdef' for ch in app_password):
        raise SystemExit('Invalid application secret format')
    # The PostgreSQL bootstrap role cannot lose SUPERUSER. Rotate its old app
    # password and move application ownership to a separate, unprivileged role.
    statement = "ALTER ROLE cde PASSWORD '" + password + "';\n"
    statement += "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='cde_app') THEN CREATE ROLE cde_app LOGIN; END IF; END $$;\n"
    statement += "ALTER ROLE cde_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '" + app_password + "';\n"
    statement += "ALTER DATABASE cyberdecisionengine OWNER TO cde_app;\n"
    if sql('cde_dbadmin', statement).returncode:
        raise SystemExit('Could not configure isolated application database role')
    ownership = """ALTER SCHEMA public OWNER TO cde_app;
DO $$ DECLARE item record; BEGIN
 FOR item IN SELECT tablename FROM pg_tables WHERE schemaname='public' LOOP
  EXECUTE format('ALTER TABLE public.%I OWNER TO cde_app', item.tablename);
 END LOOP;
END $$;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO cde_app;
"""
    result = subprocess.run(
        ['docker', 'exec', '-i', 'cde-vps-postgres-1', 'psql', '-X', '-q',
         '-U', 'cde_dbadmin', '-d', 'cyberdecisionengine', '-v', 'ON_ERROR_STOP=1'],
        input=ownership.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise SystemExit('Could not transfer application table ownership')
    print('Application cde_app is isolated from cluster administrator credentials.')


if __name__ == '__main__':
    main()
