"""Drive a real scan through the Karton queues with the real workers.

This creates the scan and report documents the way the framework does,
then sends the ``subdomain``/``new`` task that the workers bind to.  The
workers are real containers; they pick the task up from Redis and write
their results back into MongoDB.
"""

import json
import sys
import time

from bson import ObjectId
from karton.core import Config, Producer, Task
from pymongo import MongoClient

CONFIG = "/home/sniper/pentest/dev/b-hunters-host.ini"
MONGO = "mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin"
DB_NAME = "b-hunters-workers"

target = sys.argv[1] if len(sys.argv) > 1 else "bench-juice-shop"
url = sys.argv[2] if len(sys.argv) > 2 else f"http://{target}:3000"

client = MongoClient(MONGO)
db = client[DB_NAME]

# 1. The scan document, exactly as the CLI creates it.
scan_id = str(ObjectId())
db["scans"].insert_one(
    {
        "_id": ObjectId(scan_id),
        "Domain": target,
        "Type": "single",
        "Description": f"real worker run against {target}",
    }
)

# 2. The report document, exactly as subrecon creates it.
report_id = ObjectId()
db["reports"].insert_one(
    {
        "_id": report_id,
        "Domain": target,
        "Ports": [],
        "Technology": {},
        "Vulns": {},
        "Paths": [],
        "Paths403": [],
        "Screenshot": "",
        "data": {},
    }
)

# 3. The domain document, exactly as subrecon creates it.
db["domains"].insert_one(
    {
        "Scanid": scan_id,
        "Domain": target,
        "report_id": report_id,
        "resolve": True,
        "active": True,
        "status": {"processing": [], "finished": [], "failed": []},
    }
)

# 4. The task the workers bind to.
config = Config(path=CONFIG)
producer = Producer(config=config, identity="B-Hunters-ClI")

# The payload contract, exactly as subrecon writes it:
#   subdomain / data / source are per-task (not persistent),
#   report_id / scan_id / domain are persistent for the whole subtree.
task = Task({"type": "subdomain", "stage": "new"})
task.add_payload("data", url)
task.add_payload("subdomain", target)
task.add_payload("source", "subrecon")
task.add_payload("report_id", str(report_id), persistent=True)
task.add_payload("scan_id", scan_id, persistent=True)
task.add_payload("domain", target, persistent=True)
task.add_payload("scantype", "single", persistent=True)
producer.send_task(task)

print(f"scan_id   : {scan_id}")
print(f"report_id : {report_id}")
print(f"target    : {url}")
print(f"task uid  : {task.uid}")

# 5. Wait for a worker to write its result into the report document.
deadline = time.time() + 120
while time.time() < deadline:
    report = db["reports"].find_one({"_id": report_id})
    domain = db["domains"].find_one({"Scanid": scan_id})
    status = domain.get("status", {}) if domain else {}
    if report.get("Ports") or status.get("finished") or status.get("failed"):
        time.sleep(2)
        report = db["reports"].find_one({"_id": report_id})
        domain = db["domains"].find_one({"Scanid": scan_id})
        print("\n--- report document ---")
        print(json.dumps({"Ports": report.get("Ports"), "Technology": report.get("Technology")}, default=str)[:900])
        print("--- domain status ---")
        print(json.dumps(domain.get("status", {}), default=str)[:400])
        break
    time.sleep(2)
else:
    print("TIMEOUT: no worker wrote a result within 120s")
    domain = db["domains"].find_one({"Scanid": scan_id})
    print("status:", json.dumps(domain.get("status", {}) if domain else {}, default=str))
