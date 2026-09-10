#!/bin/sh
set -eu
app_password=$(cat /run/secrets/db_password)
case "$app_password" in
  ''|*[!0-9a-f]*) echo 'Application database secret must be hexadecimal' >&2; exit 1;;
esac
[ "${#app_password}" -eq 64 ] || exit 1
psql -X --username "$POSTGRES_USER" --dbname postgres -v ON_ERROR_STOP=1 >/dev/null <<SQL
CREATE ROLE cde_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '$app_password';
CREATE DATABASE cyberdecisionengine OWNER cde_app;
SQL
unset app_password
