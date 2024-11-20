import logging
import argparse
from colorama import Fore, Style, init
from karton.core import Config, Resource, Task
from karton.core import Producer, Task
import pymongo
import re
import os
import json
from karton.core.inspect import KartonAnalysis, KartonQueue, KartonState
import time
import datetime
def monogocon(config):
    mongoconfig=config["mongo"]
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

# Initialize colorama for cross-platform compatibility
init(autoreset=True)

def main():
    # Create the argument parser
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}B-HUNTERS CLI: A tool for Bug Bounty automation and separation"
    )

    # Display banner
    banner = f"""
{Fore.BLUE}$$$$$$$\          $$\   $$\                      $$\                                   
$$  __$$\         $$ |  $$ |                     $$ |                                  
$$ |  $$ |        $$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\   $$$$$$$\ 
$$$$$$$\ |$$$$$$\ $$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ $$  _____|
$$  __$$\ \______|$$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|\$$$$$$\  
$$ |  $$ |        $$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |       \____$$\ 
$$$$$$$  |        $$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      $$$$$$$  |
\_______/         \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      \_______/ 
{Fore.GREEN}                                            0xBormaa - 2024                                            
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    logging.info(banner)

    # Add subcommands
    subparsers = parser.add_subparsers(dest='command', required=True, help=f"{Fore.YELLOW}Specify either 'scan', 'report' , or 'status'")

    parser.add_argument('--config', '-c', type=str, help=f"{Fore.YELLOW}Optional path to configuration file", default="/etc/b-hunters/b-hunters.ini")

    # Scan command
    scan_parser = subparsers.add_parser('scan', help=f"{Fore.CYAN}Run a scan operation on a specified domain")
    scan_parser.add_argument('--domain', '-d', type=str, required=True, help=f"{Fore.YELLOW}Target domain for scanning")
    scan_parser.add_argument('--description', type=str, help=f"{Fore.YELLOW}Optional description for the scan")
    scan_parser.add_argument('--scantype', "-t", choices=['single', 'multi'], required=True, help=f"{Fore.YELLOW}Type of scan: 'single' or 'multi'")

    # Report command
    report_parser = subparsers.add_parser('report', help=f"{Fore.CYAN}Generate a scan report")
    report_parser.add_argument('--domain', '-d', type=str, required=True, help=f"{Fore.YELLOW}Specify the domain for the report")
    report_parser.add_argument('--output', '-o', type=str, help=f"{Fore.YELLOW}Optional path to save the report output")

    # Status  command
    status_parser = subparsers.add_parser('status', help=f"{Fore.CYAN}Get the status of the system")
    status_parser.add_argument('-s','--stuck', action='store_true', help=f"{Fore.YELLOW}Optional argument to restart stuck tasks periodically")
    # Parse the arguments
    args = parser.parse_args()
    config = Config(path=args.config)
    global db, s3,producer
    db=monogocon(config)

    producer=Producer(config=config,identity="B-hunters-ClI")
    s3=producer.backend.s3
    # Execute commands
    if args.command == 'scan':
        run_scan(args.domain, args.scantype, args.description)
    
    elif args.command == 'report':
        generate_report(args.domain, args.output)
    elif args.command == 'status':
        global state, tools
        state = KartonState(producer.backend)
        tools = list(state.binds.keys())

        status_report()
        if args.stuck:
            logging.info(f"{Fore.YELLOW}Periodically restarting stuck tasks...")
            while True:
                restart_stuck_tasks()
                logging.info("Sleeping for 3 hours...")
                time.sleep(60*3)
        
def getfilesnames():
    files = []
    continuation_token = None

    while True:
        # List objects in the bucket
        if continuation_token:
            response = s3.list_objects_v2(Bucket="bhunters", ContinuationToken=continuation_token)
        else:
            response = s3.list_objects_v2(Bucket="bhunters")

        # Append the file keys to the list
        if 'Contents' in response:
            for obj in response['Contents']:
                files.append(obj['Key'])

        # Check if there are more objects to fetch
        if response.get('IsTruncated'):  # True if there are more objects
            continuation_token = response['NextContinuationToken']
        else:
            break

    return files

# Example scan function
def run_scan(domain, scantype, description=None):
    collection = db["scans"]
    existing_document = collection.find_one({"Domain": domain})
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.rstrip('/')    

    if existing_document is None:
        new_document = {"Domain": domain,"Type":scantype,"Description":description}
        result = collection.insert_one(new_document)
        if result.acknowledged:
            scan_id=str(result.inserted_id)
            task = Task({"type": 'domain',
            "stage": 'new'})

            task.add_payload("domain", domain,persistent=True)
            task.add_payload("scantype", scantype,persistent=True)
            task.add_payload("data", domain)
            task.add_payload("scan_id", scan_id)
            task.add_payload("source", "producer")
            producer.send_task(task)
            logging.info(f"{Fore.GREEN}Starting Scanning {domain} with type {scantype}. Description: {description}")

        else:
            logging.info(f"{Fore.RED}Error at starting the scan")
    else:
        logging.info(f"{Fore.RED}Domain already exists")
    # Scan logic here

# Example report function
def generate_report(domain, output=None):
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.rstrip('/')    
    if output:
        output=os.path(output)
    else:
        output=os.path.join("/tmp", f"{domain}_report/")
    
    if not os.path.exists(output):
        os.makedirs(output)
    else:
        logging.error(f"{Fore.RED}Error: Output path is exist")
        exit()
    logging.info(f"{Fore.YELLOW}Report will be saved to {output}")

    collection = db["scans"]
    query = {"Domain": domain}
    scan = collection.find_one(query)
    if scan:
        scan_id=str(scan["_id"])
        scantype = scan.get("Type", "Unknown")
        description = scan.get("Description", "No description available")
        logging.info(f"{Fore.GREEN}Domain: {scan['Domain']}, Scantype: {scantype}, Description: {description}")
    else:
        logging.error(f"{Fore.RED}Scan not found")
        exit()
    collection = db["domains"]
    query = {"Scanid": scan_id}
    documents = list(collection.find(query))  

    # Check the count of documents
    document_count = len(documents)
    if document_count== 0:
        
        logging.error(f"{Fore.RED}No domains found")
        exit()
    logging.info(f"{Fore.MAGENTA}Found {document_count} domains")
    processing_domains = [document["Domain"] for document in documents if document["status"]["processing"]]
    processing_domains = ",".join(processing_domains) if processing_domains else ""
    for document in documents:
        
        failed_tasks = ",".join(document["status"]["failed"]) if document["status"]["failed"] else ""
        if failed_tasks:
            failed=document["status"]["failed"]
            logging.info(f"{Fore.RED}{document['Domain']} has {len(failed)} failed tasks {failed_tasks}")
        processing_tasks = ",".join(document["status"]["processing"]) if document["status"]["processing"] else ""
        if processing_tasks:
            processing=document["status"]["processing"]
            logging.info(f"{Fore.BLUE}{document['Domain']} has {len(processing)} prcoessing tasks {processing_tasks}")

    if processing_domains:
        response = input(f"{Fore.YELLOW}Some domains are still processing ({processing_domains}), do you want to continue? [y/N]: ")
        if response.lower() != "y":
            logging.error(f"{Fore.RED}Aborting")
            exit()
    files=getfilesnames()
    subdomains=[]
    for document in documents:
        subdomains.append(document["Domain"])
        if document["active"]==True:
            
            domain=document["Domain"]
            logging.info(f"{Fore.MAGENTA}Creating report for domain {domain}")

            outputfolder=os.path.join(output, domain)
            if not os.path.exists(f"{outputfolder}"):
                os.makedirs(f"{outputfolder}")

            domain_files=[]
            for i in files:
                
                if domain in i:
                    domain_files.append(i)
            for i in domain_files:
                data=s3.get_object(Bucket="bhunters", Key=i)["Body"]
                foldername=i.split("_")[0]
                outputfoldertool=os.path.join(outputfolder,foldername)
                if not os.path.exists(f"{outputfoldertool}"):
                    os.makedirs(f"{outputfoldertool}")
                outputfile=os.path.join(outputfoldertool,"_".join(i.split("_")[1:])+".txt")
                with open(outputfile, "wb") as f:
                    f.write(data.read())
            Ports=document["Ports"]
            if Ports:
                ports_data = json.dumps(Ports, indent=4)
                outputfile=os.path.join(outputfolder,"ports.json")
                with open(outputfile, "w") as f:
                    f.write(ports_data)
            Technology=document["Technology"]
            if Technology:
                technology_data = json.dumps(Technology, indent=4)
                outputfile=os.path.join(outputfolder,"technology.json")
                with open(outputfile, "w") as f:
                    f.write(technology_data)
            Vulns=document["Vulns"]
            vulnsdirs=Vulns.keys()
            vulnsdir=os.path.join(outputfolder,"vulns")
            if not os.path.exists(f"{vulnsdir}"):
                os.makedirs(f"{vulnsdir}")
            for i in vulnsdirs:
                vulns_data = json.dumps(Vulns[i], indent=4)
                outputfile=os.path.join(vulnsdir,f"{i}.json")
                with open(outputfile, "w") as f:
                    f.write(vulns_data)              
            Paths=document["Paths"]
            if Paths:
                outputfilejson=outputfolder+"/dirsearch.json"
                with open(outputfilejson, "w") as f:
                    json.dump(Paths, f, indent=4)
                outputtxt=outputfolder+"/dirsearch.txt"
                pathslist=Paths[0]
                data=[]
                for i in pathslist:
                    data.append(i.split(" ")[-1])
                with open(outputtxt, "w") as f:
                    f.write("\n".join(data))
            Paths403=document["Paths403"]
            if Paths403:
                outputtxt=outputfolder+"/paths403.txt"
                paths403data=[]
                for i in Paths403:
                    for j in i:
                        paths403data.append(j["pathurl"])
                with open(outputtxt, "w") as f:
                    f.write("\n".join(paths403data))              

            Screenshot=document["Screenshot"]
            if Screenshot:
                outputfile=os.path.join(outputfolder,"screenshot.png")
                with open(outputfile, "wb") as f:
                    f.write(Screenshot)
            Toolsdata=document["data"]
            toolsnames=Toolsdata.keys()
            for i in toolsnames:
                tool_data = json.dumps(Toolsdata[i], indent=4)
                outputfile=os.path.join(outputfolder,f"{i}.json")
                with open(outputfile, "w") as f:
                    f.write(tool_data)              
            collectionjs = db["js"]
            query = {"domain": domain}
            jsdata = list(collectionjs.find(query))  
            if jsdata:
                jsresult=[]
                jslinks=[]
                for i in jsdata:
                    if i["Vulns"] !=[]:
                        
                        jsresult.append({"url":i["url"],"Vulns":i["Vulns"]})
                    jslinks.append(i["url"])
                jsvulns_data = json.dumps(jsresult, indent=4)
                outputfile=os.path.join(vulnsdir,f"jsvulns.json")
                with open(outputfile, "w") as f:
                    f.write(jsvulns_data)
                outputfile=os.path.join(outputfolder,f"js_links.txt")
                with open(outputfile, "w") as f:
                    f.write("\n".join(jslinks))     
    with open(output+"subdomains.txt", "w") as f:
        f.write("\n".join(subdomains))              
             
def status_report():
    logging.info("The following are the current modules available:")
    for toolname in tools:
        online_count = state.queues[toolname].online_consumers_count
        pending=len(state.queues[toolname].pending_tasks)
        crached=len(state.queues[toolname].crashed_tasks)
        if online_count == 0:
            logging.info(f"\033[91mModule: {toolname}, Online Consumers: {online_count}, Pending Tasks: {pending}, Crashed Tasks: {crached}\033[0m")
        else:
            logging.info(f"\033[94mModule: {toolname}, Online Consumers: {online_count}, Pending Tasks: {pending}, Crashed Tasks: {crached}\033[0m")
def restart_stuck_tasks():
    logging.info("Checking for stuck tasks...")
    for toolname in tools:
        pending=state.queues[toolname].pending_tasks
        count=len(pending)                 
        for i in pending:
            status=i.status                    
            now = datetime.datetime.now()

            minutes_ago = (now.timestamp() - i.last_update) / 60

            if status =="TaskState.STARTED" and minutes_ago > 60:
                logging.info(f"Restarting stuck task: {i}")
                producer.backend.restart_task(i)
                
if __name__ == "__main__":
    main()


