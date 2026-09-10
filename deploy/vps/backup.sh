#!/usr/bin/env bash
# Consistent, encrypted backup of the private single-node profile.
set -euo pipefail
source /etc/cde/deployment.env
export CDE_SECRET_DIR CDE_RELEASE
export RESTIC_REPOSITORY=/var/backups/cde/repository
export RESTIC_PASSWORD_FILE=/etc/cde/secrets/backup-password
cd /opt/cde/app
compose() { docker compose -f deploy/vps/compose.yml -f deploy/vps/operator.yml "$@"; }
exec 9>/run/lock/cde-backup.lock
flock -n 9 || exit 0
umask 077
work=/var/backups/cde/staging
# This directory contains only this script's transient copies, under the lock.
rm -rf -- "$work"
mkdir -m 700 "$work"
was_running=$(docker inspect cde-vps-api-1 --format '{{.State.Running}}')
resume() { if [ "$was_running" = true ]; then compose start api >/dev/null; fi; }
cleanup() { resume || true; rm -rf -- "$work"; }
trap cleanup EXIT
if [ "$was_running" = true ]; then compose stop -t 60 api >/dev/null; fi
compose exec -T postgres pg_dump -U cde_dbadmin -d cyberdecisionengine -Fc > "$work/database.dump"
docker run --rm --network none --read-only --user 0:0 --cap-drop ALL \
  --mount type=volume,src=cde-vps_runtime_data,dst=/state/data,readonly \
  --mount type=volume,src=cde-vps_runtime_reports,dst=/state/reports,readonly \
  --mount type=bind,src="$work",dst=/backup \
  --entrypoint python "cde-vps-api:${CDE_RELEASE}" -c \
  'import tarfile; t=tarfile.open("/backup/state.tar.gz","w:gz"); t.add("/state/data",arcname="data"); t.add("/state/reports",arcname="reports"); t.close()'
cp -a /etc/cde "$work/config"
git rev-parse HEAD > "$work/release.txt"
resume
was_running=false
# Stable paths yield incremental snapshots despite the temporary staging path.
cd "$work"
restic backup --tag cde database.dump state.tar.gz config release.txt
restic forget --tag cde --keep-daily 7 --keep-weekly 4 --keep-monthly 3 --prune
restic check
date -u +%FT%TZ > /var/backups/cde/last-success
