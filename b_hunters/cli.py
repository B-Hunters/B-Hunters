import argparse
import datetime
import json
import logging
import os
import re
import time

import pymongo
from colorama import Fore, Style, init
from karton.core import Config, Producer, Task
from karton.core.inspect import KartonState


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
        raise Exception("Mongo Connection Failed") from None

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
    banner = rf"""
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

    # --- platform commands ------------------------------------------------
    serve_parser = subparsers.add_parser('serve', help=f"{Fore.CYAN}Run the authenticated platform API and web UI")
    serve_parser.add_argument('--host', type=str, default=None, help=f"{Fore.YELLOW}Bind address")
    serve_parser.add_argument('--port', type=int, default=None, help=f"{Fore.YELLOW}Bind port")
    serve_parser.add_argument('--reload', action='store_true', help=f"{Fore.YELLOW}Enable auto-reload (development only)")

    admin_parser = subparsers.add_parser('admin', help=f"{Fore.CYAN}Platform administration")
    admin_sub = admin_parser.add_subparsers(dest='admin_command', required=True)
    bootstrap = admin_sub.add_parser('bootstrap', help=f"{Fore.YELLOW}Create the initial administrator account")
    bootstrap.add_argument('--username', type=str, default='admin')
    bootstrap.add_argument('--password', type=str, default=None, help=f"{Fore.YELLOW}Read the password from BHUNTERS_BOOTSTRAP_PASSWORD or prompt for it")
    add_user = admin_sub.add_parser('add-user', help=f"{Fore.YELLOW}Create a platform user")
    add_user.add_argument('--username', type=str, required=True)
    add_user.add_argument('--password', type=str, default=None)
    add_user.add_argument('--role', type=str, default='viewer', choices=['admin', 'operator', 'viewer'])
    admin_sub.add_parser('list-users', help=f"{Fore.YELLOW}List the platform users")
    admin_sub.add_parser('init-db', help=f"{Fore.YELLOW}Create the database indexes")
    admin_sub.add_parser('seed-roles', help=f"{Fore.YELLOW}Seed the built-in agent definitions")
    add_provider = admin_sub.add_parser('add-provider', help=f"{Fore.YELLOW}Configure a model provider")
    add_provider.add_argument('--name', type=str, required=True)
    add_provider.add_argument('--base-url', type=str, required=True, help=f"{Fore.YELLOW}The OpenAI-compatible base URL")
    add_provider.add_argument('--model', type=str, required=True)
    add_provider.add_argument('--api-key', type=str, default=None, help=f"{Fore.YELLOW}Read from BHUNTERS_LLM_API_KEY when omitted")
    add_provider.add_argument('--role-model', type=str, action='append', default=[], help=f"{Fore.YELLOW}Override the model for a role: role=model")
    add_provider.add_argument('--timeout', type=float, default=120.0)
    add_provider.add_argument('--max-retries', type=int, default=2)
    add_provider.add_argument('--concurrency', type=int, default=4)
    admin_sub.add_parser('list-providers', help=f"{Fore.YELLOW}List the configured model providers")
    admin_sub.add_parser('check-provider', help=f"{Fore.YELLOW}Check the connectivity of a provider").add_argument('name', type=str)

    bench_parser = subparsers.add_parser('bench', help=f"{Fore.CYAN}Vulnerable application benchmark laboratory")
    bench_sub = bench_parser.add_subparsers(dest='bench_command', required=True)
    bench_sub.add_parser('sync', help=f"{Fore.YELLOW}Load the benchmark manifests into the database")
    bench_lab = bench_sub.add_parser('lab', help=f"{Fore.YELLOW}Manage the vulnerable application laboratory")
    bench_lab.add_argument('action', choices=['up', 'down', 'status'])
    bench_lab.add_argument('--applications', type=str, default='', help=f"{Fore.YELLOW}Comma separated application slugs")
    bench_run = bench_sub.add_parser('run', help=f"{Fore.YELLOW}Run the benchmark suite")
    bench_run.add_argument('--applications', type=str, default='', help=f"{Fore.YELLOW}Comma separated application slugs")
    bench_run.add_argument('--provider', type=str, default='')
    bench_run.add_argument('--profile', type=str, default='standard')
    bench_run.add_argument('--start-lab', action='store_true')
    bench_sub.add_parser('scores', help=f"{Fore.YELLOW}Show the recorded benchmark scores")

    contracts_parser = subparsers.add_parser('contracts', help=f"{Fore.CYAN}Check the worker message contracts")
    contracts_parser.add_argument('--workers', type=str, default='', help=f"{Fore.YELLOW}Directory holding the worker repositories")
    contracts_parser.add_argument('--strict', action='store_true', help=f"{Fore.YELLOW}Exit non-zero on warnings as well as errors")

    # Parse the arguments
    args = parser.parse_args()

    # The platform commands do not need the legacy Karton/Mongo bootstrap.
    if args.command == 'serve':
        return _serve(args)
    if args.command == 'admin':
        return _admin(args)
    if args.command == 'bench':
        return _bench(args)
    if args.command == 'contracts':
        return _contracts(args)

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
        if document["active"]:

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





# ----------------------------------------------------------------------
# Platform commands
# ----------------------------------------------------------------------
def _platform_services():
    """Build the platform service container from the environment/INI file."""
    from b_hunters.platform.api.deps import Services
    from b_hunters.platform.db.client import Database
    from b_hunters.platform.settings import load_settings

    settings = load_settings()
    database = Database(settings)
    services = Services(database, settings)
    services.ensure_indexes()
    return services


def _serve(args):
    """Run the authenticated platform API and web UI."""
    import uvicorn

    from b_hunters.platform.api.app import create_app
    from b_hunters.platform.settings import load_settings

    settings = load_settings()
    host = args.host or settings.host
    port = args.port or settings.port
    logging.info(
        f"{Fore.GREEN}Starting the B-Hunters platform on http://{host}:{port} "
        f"(environment: {settings.environment})"
    )
    uvicorn.run(
        create_app(settings),
        host=host,
        port=port,
        reload=bool(args.reload),
        log_level=settings.log_level.lower(),
    )
    return 0


def _admin(args):
    """Platform administration commands."""
    from b_hunters.platform.security.passwords import validate_password_strength

    services = _platform_services()

    if args.admin_command == 'init-db':
        logging.info(f"{Fore.GREEN}Database indexes are up to date.")
        return 0

    if args.admin_command == 'seed-roles':
        from b_hunters.platform.agents.roles import default_role_definitions

        created = 0
        for definition in default_role_definitions():
            existing = services.agent_definitions.get_by_role_and_name(
                definition["name"], definition["role"]
            ) if hasattr(services.agent_definitions, "get_by_role_and_name") else None
            if existing is None:
                services.agent_definitions.create(definition)
                created += 1
        logging.info(f"{Fore.GREEN}Seeded {created} agent definition(s).")
        return 0

    if args.admin_command == 'add-provider':
        from b_hunters.platform.agents.provider import ProviderConfig

        api_key = args.api_key
        if api_key is None:
            api_key = os.environ.get("BHUNTERS_LLM_API_KEY", "")
        role_models: dict[str, str] = {}
        for entry in args.role_model or []:
            role, _, model = entry.partition("=")
            if role and model:
                role_models[role.strip()] = model.strip()
        document = {
            "name": args.name,
            "base_url": args.base_url,
            "api_key": api_key,
            "model": args.model,
            "role_models": role_models,
            "timeout_seconds": args.timeout,
            "max_retries": args.max_retries,
            "concurrency": args.concurrency,
            "enabled": True,
        }
        services.providers.upsert(document)
        services.audit.record(
            action="provider.upsert",
            actor="cli",
            target_type="provider",
            target_id=args.name,
            detail={"base_url": args.base_url, "model": args.model},
        )
        logging.info(
            f"{Fore.GREEN}Configured the provider '{args.name}' "
            f"({args.model} at {args.base_url})."
        )
        return 0

    if args.admin_command == 'list-providers':
        providers = services.providers.list()
        if not providers:
            logging.info(f"{Fore.YELLOW}No model provider is configured.")
            return 0
        for provider in providers:
            public = services.providers.public(provider)
            models = ", ".join(f"{k}={v}" for k, v in (public.get("role_models") or {}).items())
            logging.info(
                f"{Fore.CYAN}{public['name']:<20} {public.get('model',''):<24} "
                f"{public.get('base_url','')}"
                + (f"  roles: {models}" if models else "")
            )
        return 0

    if args.admin_command == 'check-provider':
        import asyncio

        from b_hunters.platform.agents.provider import Provider, ProviderConfig

        document = services.providers.get(args.name)
        if document is None:
            logging.error(f"{Fore.RED}The provider '{args.name}' is not configured.")
            return 1

        provider = Provider(
            ProviderConfig(
                name=document.get("name", args.name),
                base_url=document.get("base_url", ""),
                api_key=document.get("api_key", ""),
                model=document.get("model", ""),
                role_models=document.get("role_models", {}) or {},
                timeout_seconds=float(document.get("timeout_seconds", 30.0)),
            )
        )

        async def _check() -> int:
            try:
                health = await provider.health_check()
            finally:
                await provider.aclose()
            if health.get("reachable"):
                logging.info(
                    f"{Fore.GREEN}Reachable: {health.get('name')} "
                    f"(model available: {health.get('model_available')}, "
                    f"{health.get('latency_ms')} ms)"
                )
                return 0
            logging.error(f"{Fore.RED}Not reachable: {health.get('error')}")
            return 1

        return asyncio.run(_check())

    if args.admin_command == 'list-users':
        users = services.users.list_users()
        if not users:
            logging.info(f"{Fore.YELLOW}No users exist yet.")
            return 0
        for user in users:
            public = services.users.public(user)
            logging.info(
                f"{Fore.CYAN}{public['username']:<24} {public['role']:<10} "
                f"active={public['active']}"
            )
        return 0

    if args.admin_command in {'bootstrap', 'add-user'}:
        username = args.username
        password = args.password
        if not password:
            password = os.environ.get("BHUNTERS_BOOTSTRAP_PASSWORD")
        if not password:
            try:
                import getpass

                password = getpass.getpass(f"Password for '{username}': ")
            except (EOFError, KeyboardInterrupt):
                logging.error(f"{Fore.RED}No password supplied; aborting.")
                return 1
        problems = validate_password_strength(password)
        if problems:
            for problem in problems:
                logging.error(f"{Fore.RED}{problem}")
            return 1
        role = "admin" if args.admin_command == "bootstrap" else args.role
        try:
            user = services.users.create(
                username=username, password=password, role=role
            )
        except Exception as exc:
            logging.error(f"{Fore.RED}Could not create the user: {exc}")
            return 1
        services.audit.record(
            action="user.create",
            actor="cli",
            target_type="user",
            target_id=user["user_id"],
            detail={"username": user["username"], "role": role},
        )
        logging.info(
            f"{Fore.GREEN}Created {role} user '{username}'. "
            f"Change the password immediately after the first sign-in."
        )
        return 0

    return 1


def _bench(args):
    """Vulnerable application benchmark commands."""
    import json

    from b_hunters.platform.bench.lab import LabManager
    from b_hunters.platform.bench.manifest import default_manifests

    services = _platform_services()
    lab = LabManager()

    if args.bench_command == 'sync':
        for manifest in default_manifests():
            services.db.collection("platform_benchmarks").update_one(
                {"slug": manifest.slug}, {"$set": manifest.to_dict()}, upsert=True
            )
        logging.info(
            f"{Fore.GREEN}Synced {len(default_manifests())} benchmark manifest(s)."
        )
        return 0

    if args.bench_command == 'lab':
        applications = [a.strip() for a in args.applications.split(',') if a.strip()]
        if args.action == 'up':
            try:
                result = lab.up(applications or None)
            except Exception as exc:
                logging.error(f"{Fore.RED}{exc}")
                return 1
            logging.info(f"{Fore.GREEN}Laboratory started: {result}")
        elif args.action == 'down':
            logging.info(f"{Fore.GREEN}Laboratory stopped: {lab.down()}")
        else:
            status = lab.status()
            logging.info(f"{Fore.CYAN}Laboratory running: {status.running}")
            for application in status.applications:
                logging.info(
                    f"  {application.get('slug')}: {application.get('state')} {application.get('status','')}"
                )
        return 0

    if args.bench_command == 'run':
        import asyncio

        from b_hunters.platform.bench.runner import BenchmarkRunConfig, BenchmarkRunner

        applications = [a.strip() for a in args.applications.split(',') if a.strip()]
        if args.start_lab:
            try:
                lab.up(applications or None)
            except Exception as exc:
                logging.error(f"{Fore.RED}{exc}")
                return 1

        async def _run():
            from b_hunters.platform.api.routers.scans import _build_orchestrator

            # The real worker stack, when one is reachable.
            worker_collector = None
            worker_runner = _build_worker_runner(services)
            if worker_runner is not None:
                def collect(**kwargs):
                    return worker_runner.run(**kwargs)

                worker_collector = collect

            async def scan_creator(**kwargs):
                from bson import ObjectId

                targets = kwargs.get("targets", [])
                target = targets[0] if targets else ""
                # The host *with* the port: the subdomain payload and the
                # Domain field have to be the same string, or a worker that
                # derives the status from the URL writes to a document that
                # does not exist.
                host = target.split("://", 1)[-1].split("/", 1)[0]

                # The legacy documents the scanner workers write into,
                # exactly as subrecon creates them.  The legacy scan
                # identifier is also the platform's scan identifier, so the
                # orchestrator, the workers and the benchmark all
                # correlate on one value.
                legacy = services.db
                scan_oid = ObjectId()
                report_oid = ObjectId()
                legacy.collection("scans").insert_one(
                    {
                        "_id": scan_oid,
                        "Domain": host,
                        "Type": "single",
                        "Description": "benchmark run",
                    }
                )
                legacy.collection("reports").insert_one(
                    {
                        "_id": report_oid,
                        "Domain": host,
                        "Ports": [],
                        "Technology": {},
                        "Vulns": {},
                        "Paths": [],
                        "Paths403": [],
                        "Screenshot": "",
                        "data": {},
                    }
                )
                legacy.collection("domains").insert_one(
                    {
                        "Scanid": str(scan_oid),
                        "Domain": host,
                        "report_id": report_oid,
                        "resolve": True,
                        "active": True,
                        "status": {"processing": [], "finished": [], "failed": []},
                    }
                )

                record = services.scans.create(
                    {
                        "scan_id": str(scan_oid),
                        "name": kwargs.get("name", "benchmark"),
                        "status": "queued",
                        "created_by": "cli",
                        "definition": {
                            "targets": targets,
                            "profile": {"name": kwargs.get("profile", "standard")},
                            "benchmark": True,
                        },
                        "scope": {
                            "authorized_hosts": kwargs.get("authorized_hosts", []),
                            "allow_private_network": kwargs.get("allow_private_network", True),
                            "allow_state_changing": kwargs.get("allow_state_changing", False),
                        },
                    }
                )
                orchestrator = _build_orchestrator(services)
                from b_hunters.platform.agents.orchestrator import ScanContext, ScanProfile

                context = ScanContext(
                    scan_id=str(scan_oid),
                    name=record.name,
                    targets=list(kwargs.get("targets", [])),
                    authorized_hosts=list(kwargs.get("authorized_hosts", [])),
                    profile=ScanProfile.from_dict({"name": kwargs.get("profile", "standard")}),
                    allow_private_network=bool(kwargs.get("allow_private_network", True)),
                )
                services.orchestrators[str(scan_oid)] = orchestrator
                asyncio.create_task(orchestrator.run(context))
                return {"scan_id": str(scan_oid), "report_id": report_oid}

            runner = BenchmarkRunner(
                database=services.db,
                lab=lab,
                scan_creator=scan_creator,
                worker_collector=worker_collector,
            )
            return await runner.run(
                BenchmarkRunConfig(
                    applications=applications,
                    provider=args.provider,
                    profile=args.profile,
                )
            )

        try:
            outcome = asyncio.run(_run())
        except Exception as exc:
            logging.error(f"{Fore.RED}The benchmark run failed: {exc}")
            return 1

        from b_hunters.platform.bench.scoring import summarise_for_humans

        run_id = f"run-{int(time.time() * 1000)}"
        services.db.collection("platform_benchmark_runs").insert_one(
            {
                "run_id": run_id,
                "benchmark_id": "default",
                "status": "completed",
                "started_at": outcome["started_at"],
                "finished_at": outcome["finished_at"],
                "summary": outcome["summary"],
                "started_by": "cli",
            }
        )
        services.db.collection("platform_benchmark_results").insert_many(
            [dict(result, run_id=run_id) for result in outcome["results"]]
        )
        logging.info(f"{Fore.GREEN}{summarise_for_humans(outcome['summary'])}")
        print(json.dumps(outcome["summary"]["score"], indent=2))
        return 0

    if args.bench_command == 'scores':
        runs = list(
            services.db.collection("platform_benchmark_runs")
            .find({})
            .sort("started_at", -1)
            .limit(20)
        )
        if not runs:
            logging.info(f"{Fore.YELLOW}No benchmark runs have been recorded yet.")
            return 0
        from b_hunters.platform.bench.scoring import summarise_for_humans

        for run in runs:
            logging.info(
                f"{Fore.CYAN}run {run.get('run_id')} ({run.get('started_at')})"
            )
            logging.info(summarise_for_humans(run.get("summary", {})))
        return 0

    return 1




def _contracts(args):
    """Check that every worker agrees on the Karton message contract."""
    from pathlib import Path

    from b_hunters.platform.scanners.contracts import verify_repository_set

    root = Path(args.workers) if args.workers else Path(__file__).resolve().parents[2] / "repos"
    if not root.is_dir():
        logging.error(f"{Fore.RED}The worker directory {root} does not exist")
        return 1

    repositories = [
        directory
        for directory in sorted(root.iterdir())
        if directory.is_dir()
        and directory.name != "B-Hunters"
        and any(directory.glob("*/*.py"))
    ]
    contracts, findings = verify_repository_set(repositories)
    logging.info(f"{Fore.CYAN}Checked {len(contracts)} worker repositories")

    errors = [finding for finding in findings if finding.severity == "error"]
    warnings = [finding for finding in findings if finding.severity == "warning"]
    notes = [finding for finding in findings if finding.severity == "info"]

    for finding in errors:
        logging.error(f"{Fore.RED}{finding}")
    for finding in warnings:
        logging.info(f"{Fore.YELLOW}{finding}")
    for finding in notes:
        logging.info(f"{Fore.CYAN}{finding}")

    if errors:
        logging.error(f"{Fore.RED}{len(errors)} contract error(s)")
        return 1
    if warnings and args.strict:
        logging.error(f"{Fore.RED}{len(warnings)} contract warning(s)")
        return 1
    if not findings:
        logging.info(f"{Fore.GREEN}Every worker agrees on the message contract.")
    return 0




def _build_worker_runner(services):
    """Build the Karton worker collector, when the stack is reachable.

    The benchmark drives the workers that run as containers: the producer
    publishes the tasks, the workers pick them up and write their results
    into the report document, and the collector reads them back.
    """
    import os

    from karton.core import Config, Producer

    from b_hunters.platform.bench.workers import KartonWorkerRunner

    config_path = os.environ.get("BHUNTERS_HOST_CONFIG")
    if not config_path or not os.path.exists(config_path):
        return None
    try:
        producer = Producer(config=Config(path=config_path), identity="B-Hunters-Bench")
    except Exception as exc:
        logging.info(f"{Fore.YELLOW}The worker stack is not reachable: {exc}")
        return None
    return KartonWorkerRunner(
        producer=producer,
        mongo_database=services.db,
        wait_seconds=int(os.environ.get("BHUNTERS_BENCH_WORKER_WAIT", "240")),
    )


if __name__ == "__main__":
    main()
