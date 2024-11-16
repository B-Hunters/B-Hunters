from karton.core import Karton, Config
import socket
import tempfile
import random
import string
import os
import requests
import json
import pymongo
import tldextract
import re
import base64
import hashlib
class BHunters(Karton):
    def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        config = Config(path="/etc/b-hunters/b-hunters.ini")
        super().__init__(config=config,*args, **kwargs)
        self.db=self.monogocon()
    
    def update_task_status(self,url,status):
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
        if status=="failed":
            raise Exception(f"Failed to process {url}")
        
    def is_string(self,var):
        return isinstance(var, str)

    def is_array(self,var):
        return isinstance(var, list)
    def is_local_ip(self,ip_address):
        # List of local IP address prefixes
        local_ip_prefixes = ["127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."]
        for prefix in local_ip_prefixes:
            if ip_address.startswith(prefix):
                return True
        return False

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
        random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=10))  # Generate a random string
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
            requests.get(url, verify=False,timeout=5)
            return url  # If it responds, return the HTTPS URL
        except requests.exceptions.RequestException:
            # If the HTTPS request fails, attempt with HTTP
            http_url = url.replace("https://", "http://")
            try:
                requests.get(http_url,timeout=5)
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
        """
        hooks={
            "main":self.config["Webhook"]["discord_report"],
            "status":self.config["Webhook"]["discord_task_status"]
        }
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
        response = requests.post(webhook_url, data=json.dumps(data), headers=headers)
        


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
        try:
            client.admin.command('ping')
        except pymongo.errors.ConnectionFailure:
            raise Exception("Mongo Connection Failed")

        db = client[db]
        return db    
    def checklinksexist(self,subdomain,links):
        collection=self.db["domains"]
        missing_links=[]
        if isinstance(links,str):
            links=links.splitlines()
        existing_document = collection.find_one({"Domain": subdomain})
        if existing_document is None:
            self.log.error("No document found for the specified domain.")
            
        else:
            existing_links = existing_document.get("ScanLinks", {}).get(self.identity, [])
            missing_links = [link for link in links if link not in existing_links]
            if missing_links:
                collection.update_one({"Domain": subdomain}, {"$push": {f"ScanLinks.{self.identity}": {"$each": missing_links}}})
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
            hash_object = hashlib.md5(url_or_path.encode())
            safe_name = hash_object.hexdigest()
        
        return safe_name
