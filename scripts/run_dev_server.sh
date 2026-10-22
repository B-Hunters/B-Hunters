#!/bin/bash
# Development launcher for the B-Hunters platform API.
export BHUNTERS_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin"
export BHUNTERS_MONGO_DB="b-hunters-ui"
export BHUNTERS_HOST=127.0.0.1
export BHUNTERS_PORT=8099
export BHUNTERS_ENVIRONMENT=development
export BHUNTERS_SESSION_COOKIE_SECURE=false
export BHUNTERS_KARTON_CONFIG_PATH=/home/sniper/pentest/dev/karton.ini
cd /home/sniper/pentest/repos/B-Hunters
exec /home/sniper/pentest/.venv/bin/python -m uvicorn b_hunters.platform.api.app:app --host 127.0.0.1 --port 8099 --log-level warning
