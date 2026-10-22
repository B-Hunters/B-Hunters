#!/bin/bash
# Recreate the vulnerable application laboratory and publish the container
# addresses to the host.
#
# The host resolves the laboratory names to the container addresses rather
# than to 127.0.0.1, so the platform process and the worker containers
# address the same application with the same URL and the same port.
set -u
COMPOSE_DIR=/home/sniper/pentest/bench-lab
CONFIG=/home/sniper/pentest/dev/b-hunters.ini
APPS="${1:-dvga,juice-shop,webgoat}"
IFS=","
read -r -a APP_LIST <<< "$APPS"

cd /home/sniper/pentest/repos/B-Hunters
export BHUNTERS_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin"
export BHUNTERS_MONGO_DB="b-hunters-bench"
export BHUNTERS_BENCH_DIR="$COMPOSE_DIR"
export BHUNTERS_BENCH_WORKER_NETWORK="dev_default"

/home/sniper/pentest/.venv/bin/python -m b_hunters.cli bench lab down >/dev/null 2>&1
/home/sniper/pentest/.venv/bin/python -m b_hunters.cli bench lab up --applications "$APPS" 2>&1 | tail -1

echo "--- waiting for the applications ---"
sleep 25

# Publish the container addresses to the host.
sudo sed -i '/# B-Hunters benchmark laboratory/,/bench-webgoat$/d' /etc/hosts
{
  echo
  echo "# B-Hunters benchmark laboratory: the applications are addressed by their"
  echo "# container addresses so that the platform process and the worker"
  echo "# containers use the same URL and the same port."
} | sudo tee -a /etc/hosts >/dev/null

for app in ${APP_LIST[@]}; do
  cid="bh-bench-$app"
  ip=$(docker inspect "$cid" --format '{{range .NetworkSettings.Networks}}{{if eq .NetworkID "x"}}{{end}}{{end}}' 2>/dev/null)
  ip=$(docker inspect "$cid" --format '{{range $k,$v := .NetworkSettings.Networks}}{{if eq $k "dev_default"}}{{$v.IPAddress}}{{end}}{{end}}' 2>/dev/null)
  if [ -n "$ip" ]; then
    echo "$ip	bench-$app" | sudo tee -a /etc/hosts >/dev/null
    echo "  bench-$app -> $ip"
  else
    echo "  bench-$app -> NOT on dev_default"
  fi
done

echo "--- reachability from the host ---"
for app in ${APP_LIST[@]}; do
  case "$app" in
    dvga) port=5013 ;;
    juice-shop) port=3000 ;;
    webgoat) port=8080 ;;
    *) port=80 ;;
  esac
  printf "  bench-%-12s " "$app"
  curl -s --max-time 12 -o /dev/null -w "%{http_code}\n" "http://bench-$app:$port/" 2>/dev/null || echo "unreachable"
done

echo "--- reachability from a worker container ---"
docker run --rm --network dev_default alpine:3 sh -c 'for h in '"$(echo $APPS | tr ',' ' ')"'; do :; done; for h in '"$(for app in ${APP_LIST[@]}; do echo -n "bench-$app "; done)"'; do printf "  %-24s " "$h"; getent hosts $h | head -1; done' 2>&1 | tail -5
