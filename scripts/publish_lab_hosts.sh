#!/bin/bash
# Publish the laboratory container addresses to the host.
#
# The whole block is replaced on every run: an earlier version appended
# lines, which left duplicate and colliding entries behind - the
# application names resolved to each other's addresses.
set -u
BLOCK="# >>> B-Hunters benchmark laboratory >>>"
END="# <<< B-Hunters benchmark laboratory <<<"

sudo sed -i "\|^${BLOCK}|d" /etc/hosts
sudo sed -i "\|^${END}|d" /etc/hosts
sudo sed -i "/bench-dvga$/d; /bench-juice-shop$/d; /bench-webgoat$/d" /etc/hosts

{
  echo "$BLOCK"
  echo "# The applications are addressed by their container addresses, so the"
  echo "# platform process and the worker containers use the same URL and port."
  for app in dvga juice-shop webgoat; do
    cid="bh-bench-$app"
    if ! docker ps --format '{{.Names}}' | grep -qx "$cid"; then
      echo "  $app: the container is not running" >&2
      continue
    fi
    ip=$(docker inspect "$cid" --format '{{range $k,$v := .NetworkSettings.Networks}}{{if eq $k "dev_default"}}{{$v.IPAddress}}{{end}}{{end}}')
    if [ -n "$ip" ] && [ "$ip" != "invalid IP" ]; then
      printf "%s\tbench-%s\n" "$ip" "$app" | sudo tee -a /etc/hosts >/dev/null
      echo "  bench-$app -> $ip"
    else
      echo "  bench-$app -> no address on the worker network" >&2
    fi
  done
  echo "$END"
} | sudo tee -a /etc/hosts >/dev/null

echo "--- the published entries ---"
grep -E "bench-(dvga|juice-shop|webgoat)$" /etc/hosts | sort -u
