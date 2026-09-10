#!/bin/bash
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo 'Run as root' >&2; exit 1; }
: "${CDE_RELEASE:?Set CDE_RELEASE to the tested image tag}"
[[ "$CDE_RELEASE" =~ ^[a-zA-Z0-9_.-]+$ ]] || exit 1
cd /opt/cde/app
install -d -m 700 /etc/cde/secrets /var/backups/cde
printf 'CDE_SECRET_DIR=/etc/cde/secrets\nCDE_RELEASE=%s\n' "$CDE_RELEASE" > /etc/cde/deployment.env
chmod 600 /etc/cde/deployment.env
if [ ! -f /etc/cde/secrets/backup-password ]; then umask 077; openssl rand -hex 32 > /etc/cde/secrets/backup-password; fi
export RESTIC_REPOSITORY=/var/backups/cde/repository RESTIC_PASSWORD_FILE=/etc/cde/secrets/backup-password
if [ ! -f "$RESTIC_REPOSITORY/config" ]; then restic init; fi
cat > /etc/systemd/system/cde-firewall.service <<'UNIT'
[Unit]
Description=CyberDecisionEngine container network restrictions
After=docker.service ufw.service
Requires=docker.service
PartOf=docker.service
[Service]
Type=oneshot
ExecStart=/opt/cde/app/deploy/vps/egress-firewall.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target docker.service
UNIT
cat > /etc/systemd/system/cde-backup.service <<'UNIT'
[Unit]
Description=CyberDecisionEngine encrypted consistent backup
After=docker.service cde-firewall.service
[Service]
Type=oneshot
ExecStart=/opt/cde/app/deploy/vps/backup.sh
TimeoutStartSec=1h
UMask=0077
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
UNIT
cat > /etc/systemd/system/cde-backup.timer <<'UNIT'
[Unit]
Description=Nightly CyberDecisionEngine backup
[Timer]
OnCalendar=*-*-* 03:30:00 UTC
RandomizedDelaySec=10m
Persistent=true
[Install]
WantedBy=timers.target
UNIT
cat > /etc/systemd/system/cde-healthcheck.service <<'UNIT'
[Unit]
Description=CyberDecisionEngine health and backup checks
After=docker.service
[Service]
Type=oneshot
ExecStart=/opt/cde/app/deploy/vps/healthcheck.sh
UNIT
cat > /etc/systemd/system/cde-healthcheck.timer <<'UNIT'
[Unit]
Description=CyberDecisionEngine local health monitoring
[Timer]
OnBootSec=5m
OnUnitActiveSec=5m
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now cde-firewall.service
systemctl start cde-backup.service
systemctl enable --now cde-backup.timer cde-healthcheck.timer
# The API health probe may still be starting after the consistent backup.
for attempt in {1..12}; do
  if /opt/cde/app/deploy/vps/healthcheck.sh; then break; fi
  sleep 5
done
systemctl start cde-healthcheck.service
systemctl --no-pager list-timers 'cde-*'
