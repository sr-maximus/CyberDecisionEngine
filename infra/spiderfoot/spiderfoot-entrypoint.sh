#!/usr/bin/env sh
set -eu

exec su -s /bin/sh spiderfoot -c "$(printf '%s ' "$@")"
