# B-Hunters
```text
$$$$$$$\          $$\   $$\                      $$\                                   
$$  __$$\         $$ |  $$ |                     $$ |                                  
$$ |  $$ |        $$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\   $$$$$$$\ 
$$$$$$$\ |$$$$$$\ $$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ $$  _____|
$$  __$$\ \______|$$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|\$$$$$$\  
$$ |  $$ |        $$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |       \____$$\ 
$$$$$$$  |        $$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      $$$$$$$  |
\_______/         \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      \_______/ 
                                            0xBormaa - 2024                                            
```

**B-Hunters** is a bug bounty framework built on the [Karton](https://github.com/CERT-Polska/karton) framework. It leverages Docker to execute multiple tools and tasks across different machines, providing a powerful, modular, and scalable approach to reconnaissance and vulnerability scanning.

B-Hunters automates the entire recon process by utilizing multiprocessing and microservices to ensure efficiency, flexibility, and ease of integration.

Results can be integrated with discord webhooks to be sent once tool running finish or using the command line

---

# [B-hunters-playground](https://github.com/B-Hunters/B-Hunters-playground) Includes all tools and servers needed  to start using B-Hunters

## Tools Integrated

B-Hunters currently includes the following tools:
## Subdomains

1. **[Subfinder](https://github.com/projectdiscovery/subfinder)**  
   A fast passive subdomain enumeration tool that uses a wide range of sources.

2. **[Vita](https://github.com/vita-project/vita)**  
   A tool for vulnerability and information gathering during reconnaissance.

3. **[Findomain](https://github.com/findomain/findomain)**  
   A subdomain enumeration tool that integrates API keys for faster and more extensive discovery.

4. **[Sublist3r](https://github.com/aboul3la/Sublist3r)**  
   A tool designed to enumerate subdomains using multiple search engines.

5. **[Assetfinder](https://github.com/tomnomnom/assetfinder)**  
   Quickly finds domains and subdomains related to a target using various sources.

6. **[Chaos](https://github.com/projectdiscovery/chaos-client)**  
   Fetches subdomains from ProjectDiscovery's Chaos dataset.

---

### Crawling and Spidering

1. **[Gospider](https://github.com/jaeles-project/gospider)**  
   A fast web spider written in Go, designed for gathering URLs and data.

2. **[Dirsearch](https://github.com/maurosoria/dirsearch)**  
   A simple command-line tool designed to brute force directories and files in webservers.

3. **[GetJS](https://github.com/003random/getJS)**  
   Scrapes JavaScript files from web pages for further analysis.

4. **[Gowitness](https://github.com/sensepost/gowitness)**  
   A tool for taking screenshots of websites, collecting headers, and identifying technologies.

5. **[Katana](https://github.com/projectdiscovery/katana)**  
   A fast and lightweight web crawler built for information gathering.

6. **[ParamSpider](https://github.com/devanshbatham/ParamSpider)**  
   Finds parameters from web pages for use in parameter-based vulnerability testing.

7. **[Waymore](https://github.com/xnl-h4ck3r/waymore)**  
   Fetches URLs from various online services, including Wayback Machine and others.

8. **[Waybackurls](https://github.com/tomnomnom/waybackurls)**  
   Retrieves URLs for a domain from the Wayback Machine and similar services.

9. **[GAU (GetAllURLs)](https://github.com/lc/gau)**  
   Fetches known URLs from AlienVault's Open Threat Exchange, Wayback Machine, and more.

10. **[Wappalyzer-CLI](https://github.com/gokulapap/wappalyzer-cli.git)**  
   Identifies technologies used on websites via the command line.

---

### Vulnerability Checks

1. **[DalFox](https://github.com/hahwul/dalfox)**  
   A fast and powerful open-source tool for detecting and exploiting XSS vulnerabilities.

2. **[SSTImap](https://github.com/vladko312/SSTImap)**  
   Detects and maps Server-Side Template Injection (SSTI) vulnerabilities.

3. **[SQLMap](https://github.com/sqlmapproject/sqlmap)**  
   An automated SQL injection and database takeover tool.

4. **[Nuclei](https://github.com/projectdiscovery/nuclei)**  
   A fast tool for vulnerability scanning based on templates.

5. **[SecretFinder](https://github.com/m4ll0k/SecretFinder)**  
   Finds sensitive data in JavaScript files.

6. **NipeJS**   
   A JavaScript analysis tool for identifying vulnerabilities.

---
### Other

1. **uro**
2. **gf**
3. **qsreplace**
4. **Nmap**

---
## Features

- **Automation**: Automates recon and scanning tasks to save time and reduce manual effort.
- **Modularity**: Built on a microservices architecture, allowing easy customization and extension.
- **Scalability**: Handles large-scale tasks with multiprocessing and distributed workloads.
- **Integration**: Feeds the output of one tool seamlessly into another.
- **Dockerized**: Provides containerized environments for consistent and isolated tool execution.

---

## Why B-Hunters?

B-Hunters uses a microservices architecture to provide these features:

- **Isolation**: Each tool runs in its own container, ensuring no interference between tools.
- **Resilience**: Faults in one service do not affect others.
- **Scalability**: Allows horizontal scaling by distributing services across multiple machines.
- **Flexibility**: Enables you to easily replace or update individual components without disrupting the entire framework.
- **Parallelism**: Tasks are processed concurrently, significantly reducing recon time.

---

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/B-Hunters.git
   cd B-Hunters
   pip install .
   ```
2. **Install Using pip**:
    ```bash
    pip install b-hunters
    ```

## Config

You have first to update **b-hunters.example.ini** file with your **IP** and other configs if you want to edit. 
**Remember when you update settings when running tools use the same config file**
Config file by default should be in **/etc/b-hunters/b-hunters.ini"** if you want insomething else use **-c** flag when calling command

# Usage


The tool provides two main commands: `scan` and `report`. These commands allow you to perform scans on domains and generate reports. Below is a detailed explanation of each command and its options.

## General Options

| Option            | Description                                      | Default                               |
|--------------------|--------------------------------------------------|---------------------------------------|
| `--config`, `-c`  | Optional path to the configuration file.          | `/etc/b-hunters/b-hunters.ini`       |

---

## Commands

### 1. **Scan Command**

Run a scan operation on a specified domain.
#### **Options**

| **Option**            | **Description**                                  | **Required** |
|------------------------|--------------------------------------------------|--------------|
| `--domain`, `-d`      | Target domain for scanning.                      | Yes          |
| `--scantype`, `-t`    | Type of scan: `single` or `multi`.               | Yes          |
| `--description`       | Optional description for the scan.               | No           |
|


#### Usage:
```bash
b-hunters  [-c <config_path>] scan --domain <target_domain> --scantype <single or multi> [--description <description>]
```
For example to scan all subdomains in example.com

```bash
b-hunters scan -d example.com -t multi
```
### 2. Report Command

Generate a scan report for a specified domain.
#### **Options**

| **Option**            | **Description**                                  | **Required** |
|------------------------|--------------------------------------------------|--------------|
| `--domain`, `-d`      | Specify the domain for the report.               | Yes          |
| `--output`, `-o`      | Optional path to save the report output.         | No           |
|
#### **Usage**
```bash
b-hunters report --domain <target_domain> [--output <output_path>] 
```

Example to get report of domain example.com
```bash
b-hunters report -d example.com -o /tmp/example.com
```
# Future Plan

Here are the planned features and improvements for the tool:

-  **Create Web Interface**  
  Develop a user-friendly web interface to manage scans and reports.

-  **Integrate Discord Bot**  
  Integrate a Discord bot to scan or get full report.

- **Add More Tools**  
  Continuously expand the toolset by adding more scanning and vulnerability scanning tools.

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/bormaa)
