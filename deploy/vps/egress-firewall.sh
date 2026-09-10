#!/usr/bin/env bash
# Restrict only this Compose project's bridges; leave unrelated containers alone.
set -euo pipefail
project=${CDE_PROJECT:-cde-vps}
ipt() { iptables -w 10 "$@"; }
ipt -N CDE_EGRESS 2>/dev/null || true
ipt -F CDE_EGRESS
ipt -A CDE_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
for destination in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4; do
  ipt -A CDE_EGRESS -d "$destination" -j REJECT
done
ipt -A CDE_EGRESS -p tcp -m multiport --dports 53,80,443 -j RETURN
ipt -A CDE_EGRESS -p udp --dport 53 -j RETURN
ipt -A CDE_EGRESS -j REJECT
ipt -N CDE_HOST_INPUT 2>/dev/null || true
ipt -F CDE_HOST_INPUT
ipt -A CDE_HOST_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
ipt -A CDE_HOST_INPUT -j REJECT
for network in database application outbound ingress; do
  id=$(docker network inspect "${project}_${network}" --format '{{.Id}}')
  ipv6=$(docker network inspect "${project}_${network}" --format '{{.EnableIPv6}}')
  [ "$ipv6" = false ] || { echo 'IPv6 networks need a separate egress policy' >&2; exit 1; }
  bridge=$(docker network inspect "${project}_${network}" --format '{{index .Options "com.docker.network.bridge.name"}}')
  [ -n "$bridge" ] || bridge="br-${id:0:12}"
  ipt -C INPUT -i "$bridge" -j CDE_HOST_INPUT 2>/dev/null || ipt -I INPUT 1 -i "$bridge" -j CDE_HOST_INPUT
  if [ "$network" = outbound ] || [ "$network" = ingress ]; then
    ipt -C DOCKER-USER -i "$bridge" -j CDE_EGRESS 2>/dev/null || ipt -I DOCKER-USER 1 -i "$bridge" -j CDE_EGRESS
  fi
done
echo 'Container egress and host access restrictions applied.'
