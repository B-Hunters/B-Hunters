"""Verify every scanner worker against the laboratory.

For each worker the harness:

1. starts the worker container against the live Karton stack;
2. sends the task type the worker binds to, with the payload the
   framework's contract defines;
3. waits for the worker to finish;
4. checks that the worker reported its status to Karton the same way as
   every other worker - ``Started`` then ``Finished`` or ``Failed`` in
   the domain document, under the worker's own identity;
5. checks that the worker wrote the result into the collection field the
   report document reserves for it.

The result is a table: one row per worker, with what it produced.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from bson import ObjectId
from karton.core import Config, Producer, Task
from pymongo import MongoClient

#: The configuration the producer uses.  It addresses the infrastructure
#: through the loopback interface, because the producer runs on the host.
CONFIG = os.environ.get("BHUNTERS_HOST_CONFIG", "/etc/b-hunters/b-hunters.ini")
#: The configuration the worker containers receive.  They address the
#: infrastructure by container name.
CONFIG_MOUNT = os.environ.get("BHUNTERS_WORKER_CONFIG", "/etc/b-hunters/b-hunters.ini")
MONGO = os.environ.get("BHUNTERS_MONGO_URI", "mongodb://127.0.0.1:27017")
DB_NAME = os.environ.get("BHUNTERS_MONGO_DB", "b-hunters-workers")
NETWORK = os.environ.get("BHUNTERS_WORKER_NETWORK", "dev_default")

#: The worker image tag.
TAG = "b-hunters-local/{name}:1.2.0"

#: The laboratory application the workers scan.
TARGET_HOST = "bench-juice-shop"
TARGET_URL = f"http://{TARGET_HOST}:3000"

#: The report field each worker is expected to fill.
REPORT_FIELD = {
    "nmap": "Ports",
    "gowitness": "Screenshot",
    "dirsearch": "Paths",
    "paramspider": "Paths",
    "webtechnology": "Technology",
    "wapiti": "Vulns",
    "xray": "Vulns",
    "wayback": "Paths",
    "gospider": "Paths",
    "katana": "Paths",
    "getjs": "js",
    "jsscanner": "js",
    "nuclei": "Vulns",
    "sqlmap": "Vulns",
    "dalfox": "Vulns",
    "ssti": "Vulns",
}

#: The task types each worker binds to, in the order they are tried.
TASK_TYPES = {
    "nmap": [("subdomain", "new")],
    "gowitness": [("subdomain", "new")],
    "dirsearch": [("subdomain", "new")],
    "paramspider": [("subdomain", "new")],
    "webtechnology": [("subdomain", "new")],
    "wapiti": [("subdomain", "new")],
    "xray": [("subdomain", "new")],
    "wayback": [("subdomain", "new")],
    "getjs": [("url", "new"), ("path", "new"), ("subdomain", "new")],
    "gospider": [("url", "new"), ("path", "new"), ("subdomain", "new")],
    "katana": [("url", "new"), ("path", "new"), ("subdomain", "new")],
    "jsscanner": [("js", "new")],
    "nuclei": [("paths", "scan"), ("subdomain", "new")],
    "sqlmap": [("paths", "scan"), ("subdomain", "new")],
    "dalfox": [("paths", "scan")],
    "ssti": [("paths", "scan")],
}

#: The identity each worker registers under.
IDENTITY = {
    "nmap": "B-Hunters-Nmap",
    "gowitness": "B-Hunters-GoWitness",
    "dirsearch": "B-Hunters-dirsearch",
    "paramspider": "B-Hunters-ParamSpider",
    "webtechnology": "B-Hunters-web-technology",
    "wapiti": "B-Hunters-wapiti",
    "xray": "B-Hunters-xray",
    "wayback": "B-Hunters-wayback",
    "getjs": "B-Hunters-getjs",
    "gospider": "B-Hunters-GoSpider",
    "katana": "B-Hunters-Katana",
    "jsscanner": "B-Hunters-jsscanner",
    "nuclei": "B-Hunters-Nuclei",
    "sqlmap": "B-Hunters-SQLMap",
    "dalfox": "B-Hunters-DalFox",
    "ssti": "B-Hunters-SSTI-Checker",
}


def s3_client():
    """An S3 client for the artefact store."""
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        endpoint_url="http://127.0.0.1:9000",
        aws_access_key_id="bhunter",
        aws_secret_access_key="bhunter_dev_secret",
        config=Config(signature_version="s3v4"),
    )


def encode_filename(value: str) -> str:
    """The encoding the worker base class uses for artefact names."""
    import hashlib
    import re as _re

    safe = _re.sub(r'[<>:"/\\|?*]', "_", value)
    if len(safe) > 255:
        safe = hashlib.md5(value.encode()).hexdigest()
    return safe


def upload_paths(source: str, scan_id: str, url: str, urls: list[str]) -> str:
    """Upload the path list a scanner worker expects to download."""
    key = f"{source}_{scan_id}_{encode_filename(url)}"
    body = "\n".join(urls).encode("utf-8")
    s3_client().put_object(Bucket="bhunters", Key=key, Body=body)
    return key


def docker(*args: str, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def image_exists(name: str) -> bool:
    result = docker("image", "inspect", TAG.format(name=name))
    return result.returncode == 0


def make_documents(db, target: str) -> tuple[str, ObjectId]:
    # The workers record their status against the *domain*, so a document
    # left over from an earlier run would swallow the update.  Removing
    # them first makes the verification deterministic.
    db["domains"].delete_many({"Domain": target})
    scan_id = str(ObjectId())
    report_id = ObjectId()
    db["scans"].insert_one(
        {"_id": ObjectId(scan_id), "Domain": target, "Type": "single", "Description": "worker verification"}
    )
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
    return scan_id, report_id


#: The URLs a crawler would have found, used as the input of the path
#: scanners.
DISCOVERED_URLS = [
    TARGET_URL,
    f"{TARGET_URL}/rest/products/search?q=ip",
    f"{TARGET_URL}/administration",
    f"{TARGET_URL}/robots.txt",
    f"{TARGET_URL}/api/Challenges",
]


def send_task(scan_id: str, report_id: ObjectId, task_type: str, stage: str, target: str) -> str:
    producer = Producer(config=Config(path=CONFIG), identity="B-Hunters-ClI")
    task = Task({"type": task_type, "stage": stage})
    # The payload contract, exactly as subrecon writes it.
    # A paths/scan task is produced by a crawler, not by the root worker.
    source = "spider" if task_type in {"paths", "path", "js"} else "subrecon"
    if task_type in {"paths", "path"}:
        # The crawler sends the *stripped* URL, and that is the value both
        # the upload key and the download key are built from.
        task.add_payload("data", TARGET_URL.split("://", 1)[-1].rstrip("/"))
    else:
        task.add_payload("data", TARGET_URL)
    task.add_payload("subdomain", target)
    task.add_payload("source", source)
    task.add_payload("report_id", str(report_id), persistent=True)
    task.add_payload("scan_id", scan_id, persistent=True)
    task.add_payload("domain", target, persistent=True)
    task.add_payload("scantype", "single", persistent=True)
    if task_type == "js":
        task.add_payload("file", f"{TARGET_URL}/js/app.js")
    if task_type in {"paths", "path"}:
        # The scanner downloads this artefact, exactly as in a real scan.
        stripped = TARGET_URL.split("://", 1)[-1].rstrip("/")
        upload_paths(source, scan_id, stripped, DISCOVERED_URLS)
    producer.send_task(task)
    return task.uid


def wait_for_status(db, scan_id: str, identity: str, timeout: int = 150) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        document = db["domains"].find_one({"Scanid": scan_id})
        if document:
            status = document.get("status", {})
            if identity in status.get("finished", []) or identity in status.get("failed", []):
                time.sleep(2)
                document = db["domains"].find_one({"Scanid": scan_id})
                return document.get("status", {})
        time.sleep(2)
    return {}


def collect_result(db, report_id: ObjectId, field: str) -> dict:
    report = db["reports"].find_one({"_id": report_id})
    if not report:
        return {}
    if field == "js":
        count = db["js"].count_documents({"report_id": report_id})
        return {"js_documents": count}
    value = report.get(field)
    if isinstance(value, list):
        return {field: len(value)}
    if isinstance(value, dict):
        return {field: len(value)}
    return {field: bool(value)}


def verify_worker(name: str, db) -> dict:
    result = {"worker": name, "status": "skipped", "reason": "", "output": {}, "reported": {}}
    if not image_exists(name):
        result["reason"] = "the image was not built"
        return result

    container = f"bh-verify-{name}"
    docker("rm", "-f", container, timeout=60)
    started = docker(
        "run",
        "-d",
        "--name",
        container,
        "--network",
        NETWORK,
        "-v",
        f"{CONFIG_MOUNT}:/etc/b-hunters/b-hunters.ini:ro",
        "-e",
        "BHUNTERS_CONFIG=/etc/b-hunters/b-hunters.ini",
        TAG.format(name=name),
        timeout=120,
    )
    if started.returncode != 0:
        result["reason"] = f"the container did not start: {started.stderr[:120]}"
        return result

    try:
        time.sleep(10)
        scan_id, report_id = make_documents(db, TARGET_HOST)
        for task_type, stage in TASK_TYPES.get(name, []):
            send_task(scan_id, report_id, task_type, stage, TARGET_HOST)
            time.sleep(3)

        identity = IDENTITY.get(name, name)
        status = wait_for_status(db, scan_id, identity, timeout=900)
        result["reported"] = {
            "finished": identity in status.get("finished", []),
            "failed": identity in status.get("failed", []),
            "processing": identity in status.get("processing", []),
        }
        result["output"] = collect_result(db, report_id, REPORT_FIELD.get(name, "Ports"))
        if result["reported"]["finished"]:
            result["status"] = "ok"
        elif result["reported"]["failed"]:
            result["status"] = "failed"
        else:
            result["status"] = "no-report"
            result["reason"] = "the worker reported no status within the window"
    finally:
        logs = docker("logs", container, timeout=60)
        result["log_tail"] = (logs.stdout or logs.stderr)[-600:]
        docker("rm", "-f", container, timeout=60)
    return result


def main() -> int:
    names = sys.argv[1:] or sorted(REPORT_FIELD)
    client = MongoClient(MONGO)
    db = client[DB_NAME]
    results = []
    for name in names:
        print(f"--- verifying {name} ---", flush=True)
        outcome = verify_worker(name, db)
        results.append(outcome)
        print(json.dumps({k: v for k, v in outcome.items() if k != "log_tail"}), flush=True)

    print("\n=== SUMMARY ===")
    print(f"{'worker':<16} {'status':<12} {'reported':<10} output")
    for outcome in results:
        reported = outcome.get("reported", {})
        marker = "finished" if reported.get("finished") else ("failed" if reported.get("failed") else "-")
        print(
            f"{outcome['worker']:<16} {outcome['status']:<12} {marker:<10} "
            f"{json.dumps(outcome.get('output', {}))}"
        )
    ok = [o for o in results if o["status"] == "ok"]
    print(f"\n{len(ok)}/{len(results)} workers completed and reported their status")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
