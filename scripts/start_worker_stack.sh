#!/bin/bash
# Start the whole scanner worker stack against the live Karton backend.
#
# The benchmark drives these containers: the producer publishes a task and
# the workers pick it up from Redis and write their results into the
# report document.
set -u
CONFIG=/home/sniper/pentest/dev/b-hunters.ini
NETWORK=dev_default

WORKERS="nmap dirsearch paramspider webtechnology wapiti nuclei sqlmap dalfox ssti katana ffuf wayback xray jsscanner getjs gowitness subrecon"

for worker in $WORKERS; do
  image="b-hunters-local/$worker:1.2.0"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "  SKIP $worker (no image)"
    continue
  fi
  container="bh-worker-$worker"
  docker rm -f "$container" >/dev/null 2>&1
  docker run -d --name "$container" --network "$NETWORK" \
    -v "$CONFIG:/etc/b-hunters/b-hunters.ini:ro" \
    -e BHUNTERS_CONFIG=/etc/b-hunters/b-hunters.ini \
    "$image" >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    printf "  %-16s up\n" "$worker"
  else
    printf "  %-16s FAILED\n" "$worker"
  fi
done

echo "--- the workers that are running ---"
docker ps --filter name=bh-worker --format '{{.Names}}' | sort | tr '\n' ' '
echo
