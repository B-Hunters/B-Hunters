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

def get_files_names():
    """Retrieve all file names from the S3 'bhunters' bucket using pagination.

    This function handles large buckets by implementing S3's pagination mechanism
    through continuation tokens. It iteratively fetches all objects from the bucket
    until no more objects are available.

    :param None: This function doesn't take any parameters

    :type s3: boto3.client('s3')
    :param s3: boto3 S3 client instance for S3 operations

    :raises botocore.exceptions.ClientError: If there are issues accessing the S3 bucket
    :raises botocore.exceptions.BotoCoreError: If there are AWS configuration issues

    :return: A list of strings containing all file keys in the bucket
    :rtype: list

    Note:
        - This function assumes the existence of a global 's3' client object
        - The function may take a while to complete for buckets with many objects
        - Ensure proper AWS credentials and permissions are set up before calling
    """
    files = []
    bucket_name = "bhunters"
    params = {'Bucket': bucket_name}

    while True:
        response = s3.list_objects_v2(**params)

        if 'Contents' in response:
            files.extend(obj['Key'] for obj in response['Contents'])

        # Break if no more objects to fetch
        if not response.get('IsTruncated'):
            break

        # Update continuation token for next iteration
        params['ContinuationToken'] = response['NextContinuationToken']

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
            task.add_payload("scan_id", scan_id,persistent=True)
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

    def get_output_path(base_path):
        """
        Generate a unique output path by appending a timestamp if the path exists.

        Args:
            base_path (str): The desired output path

        Returns:
            str: A unique output path that doesn't exist
        """
        if not os.path.exists(base_path):
            return base_path

        # Get directory and basename
        dir_path = os.path.dirname(base_path.rstrip('/'))
        base_name = os.path.basename(base_path.rstrip('/'))

        # Add timestamp to create unique path
        timestamp = int(time.time())
        unique_path = os.path.join(dir_path, f"{base_name}_{timestamp}")

        return unique_path

    def save_json_data(data, output_path):
        """Save data as formatted JSON file."""
        with open(output_path, 'w') as f:
            json.dump(data, indent=4, fp=f)

    def save_text_data(data, output_path):
        """Save data as text file with newline separation."""
        with open(output_path, 'w') as f:
            f.write('\n'.join(data))

    def save_binary_data(data, output_path):
        """Save binary data to file."""
        with open(output_path, 'wb') as f:
            f.write(data)

    def process_paths_data(paths):
        """Extract URLs from paths data."""
        return [path.split(" ")[-1] for path in paths[0]]

    def process_paths403_data(paths403):
        """Extract pathurls from paths403 data."""
        return [path_url["pathurl"] for path in paths403 for path_url in path]

    def process_js_data(js_data):
        """
        Process JavaScript data to extract vulnerabilities and links.

        Args:
            js_data (list): List of JavaScript data entries

        Returns:
            dict: Dictionary containing processed JS vulnerabilities and links
        """
        js_vulns = [
            {"url": entry["url"], "Vulns": entry["Vulns"]}
            for entry in js_data
            if entry["Vulns"]
        ]
        js_links = [entry["url"] for entry in js_data]

        return {
            'vulns': js_vulns,
            'links': js_links
        }

    def save_document_data(document, outputfolder, domain=None, db=None):
        """Save document data according to predefined configuration.

        Processes and saves different types of data from the document according to
        the DATA_HANDLERS configuration. Handles various data types including tools data,
        JavaScript data, and general document data.

        :param document: The document containing various data types
        :type document: dict
        :param outputfolder: Base output directory path
        :type outputfolder: str
        :param domain: Domain name for JS data queries, defaults to None
        :type domain: str, optional
        :param db: MongoDB database instance for JS queries, defaults to None
        :type db: pymongo.database.Database, optional

        :raises OSError: If there are issues creating directories or writing files
        :raises ValueError: If required data fields are missing or malformed
        :raises TypeError: If input parameters are of incorrect type

        :return: None
        :rtype: None

        Note:
            - The function uses the global DATA_HANDLERS configuration dictionary
            - Directory structure is created automatically if it doesn't exist
            - Special handling is provided for tools data, JS data, and root-level files
        """
        for data_type, config in DATA_HANDLERS.items():
            # Handle tools data specially
            if config.get('is_tools_data'):
                tools_data = document.get('data', {})
                for tool_name, tool_data in tools_data.items():
                    output_path = os.path.join(outputfolder, f"{tool_name}.json")
                    save_json_data(tool_data, output_path)
                continue

            # Handle JavaScript data specially
            if config.get('is_js_data') and db and domain:
                js_collection = db[config['collection']]
                js_query = {config['query_field']: domain}
                js_data = list(js_collection.find(js_query))

                if js_data:
                    processed_data = process_js_data(js_data)

                    for file_config in config['files']:
                        # Handle files that should go in specific directories
                        if 'directory' in file_config:
                            dir_path = os.path.join(outputfolder, file_config['directory'])
                            os.makedirs(dir_path, exist_ok=True)
                            output_path = os.path.join(dir_path, file_config['filename'])
                        else:
                            output_path = os.path.join(outputfolder, file_config['filename'])

                        file_data = file_config['processor'](processed_data)
                        file_config['save_func'](file_data, output_path)
                continue

            # Handle root-level files (like subdomains.txt)
            if config.get('is_root_level'):
                data = document.get(data_type, [])
                if data:
                    output_path = os.path.join(os.path.dirname(outputfolder.rstrip('/')),
                                            config['filename'])
                    if config['processor']:
                        data = config['processor'](data)
                    config['save_func'](data, output_path)
                continue

            # Original handling for other data types
            data = document.get(data_type)
            if not data:
                continue

            if config.get('is_directory'):
                dir_path = os.path.join(outputfolder, config['directory'])
                os.makedirs(dir_path, exist_ok=True)

                for key in data.keys():
                    output_path = os.path.join(dir_path, f"{key}{config['extension']}")
                    config['save_func'](data[key], output_path)

            elif 'files' in config:
                for file_config in config['files']:
                    processed_data = data
                    if file_config['processor']:
                        processed_data = file_config['processor'](data)
                    output_path = os.path.join(outputfolder, file_config['filename'])
                    file_config['save_func'](processed_data, output_path)

            else:
                processed_data = data
                if config['processor']:
                    processed_data = config['processor'](data)
                output_path = os.path.join(outputfolder, config['filename'])
                config['save_func'](processed_data, output_path)

    # Configuration dictionary defining how to handle each data type
    DATA_HANDLERS = {
        'Ports': {
            'filename': 'ports.json',
            'save_func': save_json_data,
            'processor': None
        },
        'Technology': {
            'filename': 'technology.json',
            'save_func': save_json_data,
            'processor': None
        },
        'Vulns': {
            'directory': 'vulns',
            'extension': '.json',
            'save_func': save_json_data,
            'processor': None,
            'is_directory': True
        },
        'Paths': {
            'files': [
                {
                    'filename': 'dirsearch.json',
                    'save_func': save_json_data,
                    'processor': None
                },
                {
                    'filename': 'dirsearch.txt',
                    'save_func': save_text_data,
                    'processor': process_paths_data
                }
            ]
        },
        'Paths403': {
            'filename': 'paths403.txt',
            'save_func': save_text_data,
            'processor': process_paths403_data
        },
        'Screenshot': {
            'filename': 'screenshot.png',
            'save_func': save_binary_data,
            'processor': None
        },
        'ToolsData': {
            'is_tools_data': True,  # Special flag for tools data handling
            'save_func': save_json_data,
            'processor': None
        },
        'JavaScript': {
            'files': [
                {
                    'filename': 'js_vulns.json',
                    'save_func': save_json_data,
                    'processor': lambda x: x['vulns'],
                    'directory': 'vulns'  # Specify vulns directory for js vulns
                },
                {
                    'filename': 'js_links.txt',
                    'save_func': save_text_data,
                    'processor': lambda x: x['links']
                }
            ],
            'is_js_data': True,  # Special flag for JS data handling
            'collection': 'js',  # MongoDB collection name
            'query_field': 'domain'  # Field to query by
        },
        'Subdomains': {
            'filename': 'subdomains.txt',
            'save_func': save_text_data,
            'processor': None,
            'is_root_level': True  # Flag for root-level files
        }
    }

    domain = re.sub(r'^https?://', '', domain)
    domain = domain.rstrip('/')
    output = output if output else os.path.join("/tmp", f"{domain}_report")
    output = get_output_path(output)

    try:
        os.makedirs(output, exist_ok=True)
        logging.info(f"{Fore.YELLOW}Report will be saved to {output}")
    except OSError as e:
        logging.error(f"{Fore.RED}Error creating output directory: {e}")
        exit(1)

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
    files=get_files_names()
    subdomains=[]
    for document in documents:
        subdomains.append(document["Domain"])
        if document["active"]==True:

            domain=document["Domain"]
            logging.info(f"{Fore.MAGENTA}Creating report for domain {domain}")

            outputfolder=os.path.join(output, domain)
            if not os.path.exists(f"{outputfolder}"):
                os.makedirs(f"{outputfolder}")

            domain_files = [filename for filename in files if domain in filename]

            for i in domain_files:
                data=s3.get_object(Bucket="bhunters", Key=i)["Body"]
                foldername=i.split("_")[0]
                outputfoldertool=os.path.join(outputfolder,foldername)
                if not os.path.exists(f"{outputfoldertool}"):
                    os.makedirs(f"{outputfoldertool}")
                outputfile=os.path.join(outputfoldertool,"_".join(i.split("_")[1:])+".txt")
                with open(outputfile, "wb") as f:
                    f.write(data.read())

            save_document_data(document, outputfolder, domain=domain, db=db)

def status_report():
    """Display status information for all available system modules.

    This function generates a color-coded report of all modules in the system,
    showing their current operational status including online consumers,
    pending tasks, and crashed tasks. Modules are highlighted in different
    colors based on their operational status.

    :param None: This function doesn't take any parameters

    :type tools: list
    :param tools: List of available tool names
    :type state: KartonState
    :param state: Current state of the Karton system

    :raises AttributeError: If required global dependencies are not available
    :raises TypeError: If tools list contains non-string elements
    :raises KartonStateError: If there are issues accessing Karton system state

    :return: None
    :rtype: None

    Note:
        - Uses colorama for cross-platform color formatting
        - Red indicates modules with no online consumers
        - Blue indicates active modules with online consumers
    """
    logging.info("The following are the current modules available:")

    for toolname in tools:
        queue = state.queues[toolname]
        status = {
            'online_count': queue.online_consumers_count,
            'pending': len(queue.pending_tasks),
            'crashed': len(queue.crashed_tasks)
        }

        # Format the status message
        status_msg = (
            f"Module: {toolname}, "
            f"Online Consumers: {status['online_count']}, "
            f"Pending Tasks: {status['pending']}, "
            f"Crashed Tasks: {status['crashed']}"
        )

        # Use colorama's Fore for color selection
        color = Fore.RED if status['online_count'] == 0 else Fore.BLUE
        logging.info(f"{color}{status_msg}{Style.RESET_ALL}")

def restart_stuck_tasks():
    """
    Identify and restart stuck tasks in the task queue.

    This function checks all pending tasks across different tools and restarts them if they meet
    certain criteria for being considered "stuck". A task is considered stuck if either:

    1. No tasks are in "started" state and the task hasn't been updated for over 90 minutes
    2. The task is in "started" state and hasn't been updated for over 90 minutes

    Global Dependencies:
        tools (list): List of available tool names
        state (KartonState): The current state of the Karton system
        producer (Producer): The Karton producer instance

    Returns:
        None

    Note:
        - The function uses a 90-minute threshold to determine if a task is stuck
        - Tasks are restarted using the producer's backend restart_task method
        - The function logs information about restarted tasks
    """
    logging.info("Checking for stuck tasks...")
    # Define constant for timeout threshold
    STUCK_TASK_TIMEOUT_MINUTES = 90

    for toolname in tools:
        pending_tasks = state.queues[toolname].pending_tasks
        if not pending_tasks:
            continue

        # Count started tasks in a single pass
        started_tasks = sum(1 for task in pending_tasks
                          if "started" in str(task.status).lower())

        current_time = datetime.datetime.now().timestamp()

        for task in pending_tasks:
            minutes_inactive = (current_time - task.last_update) / 60
            is_started = "started" in str(task.status).lower()

            # Restart task if:
            # 1. No tasks are started and this task is stuck
            # 2. Task is in started state and stuck
            if ((started_tasks == 0 or is_started) and
                minutes_inactive > STUCK_TASK_TIMEOUT_MINUTES):
                logging.info(f"Restarting stuck task: {task.uid} for tool: {toolname}")
                producer.backend.restart_task(task)

if __name__ == "__main__":
    main()


