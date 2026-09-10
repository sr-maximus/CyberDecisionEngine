#!/usr/bin/env bash
set -euo pipefail
for service in postgres api web; do
  status=$(docker inspect "cde-vps-${service}-1" --format '{{.State.Health.Status}}')
  [ "$status" = healthy ] || { logger -p daemon.err "CDE service $service is $status"; exit 1; }
done
used=$(df --output=pcent / | tail -1 | tr -dc '0-9')
[ "$used" -lt 80 ] || { logger -p daemon.err "CDE disk utilization at ${used}%"; exit 1; }
# A missing/stale successful backup makes the health check fail visibly.
[ -f /var/backups/cde/last-success ] || exit 1
age=$(( $(date +%s) - $(stat -c %Y /var/backups/cde/last-success) ))
[ "$age" -lt 93600 ] || { logger -p daemon.err 'CDE backup is overdue'; exit 1; }
echo 'Application health, disk and backup freshness passed.'
