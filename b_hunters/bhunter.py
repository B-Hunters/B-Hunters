import hashlib
import json
import os
import random
import re
import socket
import string
import tempfile
import time

import pymongo
import requests
import tldextract
from bson import ObjectId
from karton.core import Config, Karton


class ScopeViolation(Exception):
    """A worker was asked to scan a host the scan excludes.

    The scan names the hosts it must not touch - the out-of-scope
    assets of a bug bounty programme - and a worker that reached one
    anyway would be testing a host nobody authorised.
    """


class BHunters(Karton):
    def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        # The configuration comes from the environment: the workers are
        # containers and the file is mounted into them.  A positional
        # argument would be Karton's own configuration, and ours wins,
        # so it is refused rather than silently ignored.
        if args:
            raise TypeError(
                "the worker base class takes its configuration from BHUNTERS_CONFIG"
            )
        config = Config(path=os.environ.get("BHUNTERS_CONFIG", "/etc/b-hunters/b-hunters.ini"))
        kwargs["config"] = config
        super().__init__(**kwargs)
        self.db=self.monogocon()

    def update_task_status(self,url,status):
        if status == "Started":
            # The one place every worker passes through before it
            # touches the target.  A host the scan excludes is refused
            # here, so the worker stops before it sends a request.
            self.assert_in_scope(url)
        self.waitformongo()
        collection=self.db["domains"]
        if status == "Started":
            collection.update_one(
                {
                    "Domain": url
                },
                {
                    "$addToSet": {"status.processing": self.identity}
                }
            )
        elif status == "Finished":
            collection.update_one(
                {
                    "Domain": url
                },
                {
                    "$pull": {"status.processing": self.identity},
                    "$addToSet": {"status.finished": self.identity}
                }
            )
        elif status == "Failed":
            collection.update_one(
                {
                    "Domain": url
                },
                {
                    "$pull": {"status.processing": self.identity},
                    "$addToSet": {"status.failed": self.identity}
                }
            )
        self.send_discord_webhook(f"{self.identity} Started processing {url}",f"Status {status}","status")
        if status == "Failed":
            # The original comparison used a differently-cased literal, so a
            # failed task was never reported and Karton silently marked it
            # as finished.  Raising here makes the failure visible to Karton
            # (which then retries or marks the task as crashed) instead of
            # hiding it.
            raise Exception(f"Failed to process {url}")

    def auth_payload(self,task):
        """The authentication payload of a task.

        A scan can name an identity: the platform puts the identity's
        cookies and headers into the payload of the task it publishes.
        The payload is optional - a scan without an identity carries
        none - and it holds secrets, so it is never written into a log
        line and never part of an error message.
        """
        payload = getattr(task,"payload",None)
        if not isinstance(payload, dict):
            return {}
        auth = payload.get("auth")
        if not isinstance(auth, dict):
            return {}
        return auth

    def auth_cookies(self,task):
        """The cookies the task's authentication payload carries.

        This is the cookie mapping on its own, for the tools that take a
        cookie jar rather than a header.
        """
        cookies = self.auth_payload(task).get("cookies")
        if not isinstance(cookies, dict):
            return {}
        return dict(cookies)

    def auth_headers(self,task):
        """The request headers the task's authentication payload asks for.

        The cookies become a single ``Cookie`` header, the headers of
        the payload are merged in, and the extra headers are merged
        last, so a caller can override a header the payload already
        carries.  A task without an authentication payload yields no
        header at all, which leaves the tool's own invocation alone.

        The values are the session of the target and they are secrets:
        they are returned to the caller and to nobody else.
        """
        headers = {}
        cookies = self.auth_cookies(task)
        if cookies:
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in cookies.items()
            )
        payload = self.auth_payload(task)
        for key in ("headers", "extra"):
            values = payload.get(key)
            if isinstance(values, dict):
                headers.update(values)
        return headers

    def is_string(self,var):
        return isinstance(var, str)

    def is_array(self,var):
        return isinstance(var, list)

    # ------------------------------------------------------------------
    # The exclusions of the scan
    # ------------------------------------------------------------------
    def denied_hosts(self):
        """The hosts the scan must not touch.

        The list travels with the task, so every worker inherits it -
        and the workers are separate containers that discover hosts of
        their own.  A bug bounty programme names the assets that are out
        of scope, and the discovery worker hands every subdomain it
        finds to the rest of the fleet: without this, a worker would
        scan a host the scan was told to leave alone.
        """
        return self._task_list("denied_hosts")

    def enabled_workers(self):
        """The workers this scan asked for.

        The Karton router hands a task to every consumer whose filters
        match it, so a task for ``subdomain``/``new`` reaches thirteen
        workers whatever the scan asked for.  The list of the workers
        the scan wants travels with the task, and a worker that is not
        on it does nothing at all.

        An empty list means the scan said nothing, and every worker
        runs - which is what a scan that was not started by the
        platform does.
        """
        return self._task_list("enabled_workers")

    def _task_list(self, name):
        """A list the task carries, persistently."""
        task = getattr(self, "current_task", None)
        if task is None:
            return ()
        raw = (task.payload_persistent or {}).get(name) or ()
        if isinstance(raw, str):
            raw = [raw]
        return tuple(str(item).strip() for item in raw if str(item).strip())

    def is_enabled_for_scan(self, task=None):
        """Whether this worker is one the scan asked for."""
        enabled = self._task_list("enabled_workers")
        if not enabled:
            return True
        return self.identity in enabled

    def internal_process(self, task):
        """Skip the task when the scan did not ask for this worker.

        The router cannot be told which consumer a task is for: it sends
        a task to every consumer whose filters match.  So the worker
        decides, and a worker that the scan did not ask for ends the
        task without touching the target - the same way Karton ends a
        task whose binds are no longer valid.
        """
        if not self.is_enabled_for_scan(task):
            self.current_task = task
            self.log.info("skipped: this scan did not ask for %s", self.identity)
            try:
                from karton.core.task import TaskState

                self.backend.set_task_status(task, TaskState.FINISHED)
            except Exception:  # pragma: no cover - the backend may be down
                self.log.exception("could not finish the skipped task")
            return
        return super().internal_process(task)

    def is_denied_host(self, host):
        """Whether a host is one of the scan's exclusions."""
        from b_hunters.platform.security.scope import host_matches

        candidate = str(host or "").strip().lower()
        if not candidate:
            return False
        candidate = candidate.split("://", 1)[-1]
        candidate = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[1]
        candidate = candidate.split(":", 1)[0]

        return any(host_matches(candidate, pattern) for pattern in self.denied_hosts())

    def assert_in_scope(self, host):
        """Refuse to scan a host the scan excludes.

        Every worker calls ``update_task_status(host, "Started")``
        before it touches the target, so this is the one place the
        refusal has to be: the worker stops before it sends a single
        request to a host it was not authorised to test.
        """
        if self.is_denied_host(host):
            raise ScopeViolation(
                f"{host} is out of scope for this scan "
                f"(denied: {', '.join(self.denied_hosts())})"
            )
        return True

    def is_local_ip(self, ip_address):
        """Return True when the address must not be scanned.

        Uses the platform's shared range check so that link-local addresses
        (169.254.0.0/16, which includes the cloud metadata endpoint
        169.254.169.254), CGNAT space and IPv6 equivalents are covered as
        well - the previous prefix list covered only part of RFC 1918.
        """
        from b_hunters.platform.security.scope import is_blocked_ip

        return is_blocked_ip(ip_address)

    def no_resolve_or_local_ip(self,subdomain):
        try:
            ip_addresses = socket.gethostbyname_ex(subdomain)[-1]
            for ip_address in ip_addresses:
                if self.is_local_ip(ip_address):
                    return True
            return False
        except socket.gaierror:
            return True
    def generate_random_filename(self):
        temp_dir = tempfile.gettempdir()
        # A unique scratch-file name; this is not a secret.
        random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=10))  # noqa: S311
        filename = os.path.join(temp_dir, random_name)
        return filename
    def get_main_domain(self,url):
        extracted = tldextract.extract(url)
        main_domain = extracted.registered_domain
        return main_domain
    def add_https_if_missing(self, url):
        # Regular expression to check if URL starts with http:// or https://
        pattern = re.compile(r'^(http|https)://')

        # If URL doesn't start with http:// or https://, add https:// to the beginning
        if not re.match(pattern, url):
            url = "https://" + url

        # Try connecting using HTTPS with verification disabled
        try:
            # Disable certificate verification with verify=False
            requests.get(url, verify=False, timeout=5)  # noqa: S501
            return url  # If it responds, return the HTTPS URL
        except requests.exceptions.RequestException:
            # If the HTTPS request fails, attempt with HTTP
            http_url = url.replace("https://", "http://")
            try:
                requests.get(http_url, timeout=5)
                return http_url  # If it responds, return the HTTP URL
            except requests.exceptions.RequestException:
                return url  # Return None if both HTTPS and HTTP fail

    def check_https(self,url):
        # Regular expression to check if URL starts with http:// or https://
        pattern = re.compile(r'^(http|https)://')

        # If URL doesn't start with http:// or https://, add https:// to the beginning
        if re.match(pattern, url):
            return True

        return False


    def send_discord_webhook(self,title,message,channel="main"):
        """
        Sends a message to a Discord webhook.

        The webhook is optional: a deployment without a ``[Webhook]``
        section in the configuration file must not break every worker, so a
        missing or empty URL simply skips the notification.
        """
        webhook_section = {}
        try:
            webhook_section = dict(self.config["Webhook"])
        except (KeyError, TypeError):
            webhook_section = {}
        hooks={
            "main": webhook_section.get("discord_report", ""),
            "status": webhook_section.get("discord_task_status", "")
        }
        webhook_url=hooks.get(channel, "")
        if not webhook_url:
            self.log.debug(f"No Discord webhook configured for channel '{channel}'; skipping")
            return
        embed = {
        "title": title,
        "description": message,
        "color": 0x426cf5  # Embed color, you can use hex color codes
    }

        webhook_url=hooks[channel]
        data = {
            "embeds": [embed]
        }

        headers = {
            "Content-Type": "application/json"
        }
        trials=5
        while trials>0:
            try:
                requests.post(
                    webhook_url,
                    data=json.dumps(data),
                    headers=headers,
                    timeout=10,
                )
                break
            except Exception:
                trials-=1
                if trials>0:
                    time.sleep(10)
    #: The MIME types a server may use for a JavaScript file.  The
    #: ``application/javascript`` type was never registered and RFC 9239
    #: obsoleted it in favour of ``text/javascript``; Flask, Werkzeug and
    #: most modern servers send the latter.
    JS_CONTENT_TYPES = (
        "application/javascript",
        "text/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "text/ecmascript",
    )

    def checkjs(self,url):
        """Is the URL a JavaScript file?

        The check is on the media type, not on the file name: a ``.js``
        URL served as ``text/html`` is not a script, and a script served
        with a name the crawler happened not to keep is.
        """
        try:
            response = requests.get(url,timeout=10)
            content_type = response.headers.get("Content-Type","")
            media_type = content_type.split(";")[0].strip().lower()
            return media_type in self.JS_CONTENT_TYPES
        except Exception:
            return False

    def monogocon(self):
        mongoconfig=self.config["mongo"]
        username =mongoconfig["user"]
        password = mongoconfig["password"]
        db=mongoconfig["db"]
        host = mongoconfig["host"] # This could be your server address or "localhost" for a local server
        port =  mongoconfig["port"] # MongoDB default port

        # Connection string with authentication
        connection_string = f"mongodb://{username}:{password}@{host}:{port}/"
        client = pymongo.MongoClient(connection_string)
        self.client=client
        try:
            client.admin.command('ping')
        except pymongo.errors.ConnectionFailure:
            raise Exception("Mongo Connection Failed")

        db = client[db]
        return db
    def is_mongo_alive(self):
        try:
            # Ping the server to check connectivity
            self.client.admin.command('ping')
            return True
        except Exception:
            return False
    def waitformongo(self):
        tries = 0
        max_tries = 10
        retry_interval = 5  # seconds
        while tries < max_tries:
            if self.is_mongo_alive():
                return

            tries += 1
            self.log.warning(f"MongoDB is not available. Retrying in {retry_interval} seconds... (try {tries}/{max_tries})")
            time.sleep(retry_interval)
            # Reconnect only if necessary
            self.db=self.monogocon()
        raise Exception("MongoDB is not available after 10 tries.")

    @staticmethod
    def is_on_target(subdomain, link):
        """Is the link part of the target?

        A crawler collects the third-party links of a page as well: a page
        that links to youtube.com or google.com makes the crawler record
        those, and a scanner that is handed the raw list probes the
        third-party hosts instead of the target.  The comparison ignores
        the scheme and the path, and it takes the port into account,
        because the target is named as host:port.
        """
        if not link:
            return False
        target_host, _, target_port = (subdomain or "").partition(":")
        target_host = target_host.lower()

        candidate = str(link).strip()
        if "://" in candidate:
            candidate = candidate.split("://", 1)[1]
        candidate = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[1]
        host, _, port = candidate.partition(":")

        if host.lower() != target_host:
            return False
        if target_port and port != target_port:
            return False
        return True

    def checklinksexist(self,subdomain,links):
        missing_links=[]
        if links =="":
            return []
        if isinstance(links,str):
            links=links.splitlines()

        # Only the target itself is scanned.  A link to a third-party host
        # is not a finding of the target, and probing it spends the
        # scanner's budget on somebody else's website.
        links = [link for link in links if self.is_on_target(subdomain, link)]
        if not links:
            return []

        self.waitformongo()
        collection=self.db["domains"]

        # The record of what has been checked belongs to the scan, not to
        # the host.  A host can have several scans - the laboratory is
        # scanned again and again - and a host-keyed record makes the
        # second scan skip the URLs it has never tested.
        scanid = getattr(self,"scanid","") or ""
        if not scanid:
            existing_document = collection.find_one({"Domain": subdomain})
            if existing_document is None:
                self.log.error("No document found for the specified domain.")
                return []
            scanid = existing_document["Scanid"]

        collection=self.db["scans"]
        existing_document = collection.find_one({"_id": ObjectId(scanid)})
        if existing_document is None:
            self.log.error(f"No scan document found for the scan id {scanid}.")
            return []
        existing_links = existing_document.get("ScanLinks", {}).get(self.identity, [])
        missing_links = [link for link in links if link not in existing_links]
        if missing_links:
            collection.update_one({"_id": ObjectId(scanid)}, {"$push": {f"ScanLinks.{self.identity}": {"$each": missing_links}}})
        return missing_links
    def encode_filename(self, url_or_path):
        """
        Encodes a URL or path to be a valid filename by replacing unsupported characters.
        """
        # Define characters that are not typically allowed in filenames
        invalid_chars = r'[<>:"/\\|?*]'

        # Replace invalid characters with underscores
        safe_name = re.sub(invalid_chars, '_', url_or_path)

        # Ensure the filename isn't too long (max 255 characters is a common limit)
        if len(safe_name) > 255:
            # If it's too long, hash it to ensure uniqueness
            # Shortening a filename for the filesystem, not a security control.
            hash_object = hashlib.md5(url_or_path.encode(), usedforsecurity=False)  # noqa: S324
            safe_name = hash_object.hexdigest()

        return safe_name

    def publish_task_with_artifact(self, task, bucket, key, body):
        """Publish a task that carries the artefact its consumers will read.

        The Karton collector removes every object in the bucket that no
        registered task references, and a raw write is referenced by
        nobody.  A task that carries the artefact keeps it alive for the
        life of the scan and releases it when the last consumer is done.

        The consumers keep downloading it by the key they compute; only
        the lifetime of the object changes.
        """
        from b_hunters.artifacts import publish_with_artifact

        publish_with_artifact(
            self.backend, task, bucket=bucket, key=key, body=body
        )
        self.send_task(task)
