# Network Vulnerability Scanner Walkthrough

This script automates network vulnerability scanning using `nmap` and `metasploit-framework`.

## Prerequisites
-   Python 3
-   `nmap` installed and in PATH
-   `msfconsole` installed and in PATH (or provide path to directory)

## Usage

The script `vuln_scanner.py` has 5 modes. Run them in order.

### 1. Analyze
Analyzes the Metasploit directory to build a database of safe auxiliary modules.

```bash
# Standard analysis (filters unsafe/auth modules)
./vuln_scanner.py analyze --msf-path /path/to/msfconsole --format html --output modules.html

# Full analysis (include all modules)
./vuln_scanner.py analyze --full --format html --output modules.html
```
*   **Output**: `modules.html` (Interactive HTML report) or `modules.json`
*   **Console Output**: Lists modules skipped due to missing `RPORT` definition.
*   **Port 0**: Modules that don't target a specific network port (e.g., local exploits, file format, client-side, network spoofing) are grouped under **Port 0**.

### 2. Serve (Interactive Mode)
Hosts the HTML report and allows interactive configuration.
```bash
./vuln_scanner.py serve --port 8001 --html modules.html --config config.json
```
*   Open `http://localhost:8001` in your browser.
*   **New UI Features**:
    *   **Bootstrap 5 Interface**: Professional, responsive layout.
    *   **Dashboard Stats**: View total ports, modules, and selected count in the navbar.
    *   **External Links**: Quick access to Google Search and InfoSecMatter for module details.
    *   **Search**: Filter modules by name/description in the sidebar.
    *   **Syntax Highlighting**: Ruby code highlighting with Prism.js.
    *   **Real-time Config**: Select modules to update `config.json` instantly.

### 3. Init
Initializes the scan configuration for a specific target.

```bash
./vuln_scanner.py init --firm "MyFirm" --subnet "192.168.1.0/24" --type all
```
*   **Output**: `config.json`

### 3. Discovery
Runs `nmap` to discover open ports on the subnet.

```bash
./vuln_scanner.py discovery
```
*   **Output**: `nmap_scan.xml`, `inventory.json`
*   **Note**: Use `--dry-run` to see the command without executing.

### 4. Scan
Runs Metasploit auxiliary modules against the discovered targets.

```bash
./vuln_scanner.py scan
```
*   **Output**: `msf_results_*.txt`, `checkpoint.json`
*   **Features**:
    *   Resumable: Skips already completed modules if interrupted.
    *   Parallel: Uses `setg threads 25` in msfconsole.
    *   Safe: Only runs auxiliary modules (no exploits/DoS).
    *   Unauthenticated: Filters out modules that require credentials or sessions.

### 4. Custom Module Options
You can define custom options for specific modules in `config.json`. This is useful for setting required parameters like `VERSION`, `THREADS`, or specific credentials.

Example `config.json` snippet:
```json
```json
"module_options": {
    "auxiliary/scanner/snmp/snmp_login": {
        "VERSION": "ALL",
        "COMMUNITY": "public"
    },
    "auxiliary/scanner/redis/redis_login": [
        "setg --clear pass_file",
        "setg anonymous_login true",
        "setg blank_passwords true"
    ]
}
```
*   **Key-Value Pair**: Generates `set KEY VALUE`.
*   **List**: Injects raw commands directly (useful for `setg`, `--clear`, or specific ordering).

### 6. Multiple Subnets
You can specify multiple subnets in `config.json` by using a list of strings:
```json
"subnet": [
    "192.168.1.0/24",
    "10.0.0.0/8"
]
```
Alternatively, you can provide a file containing a list of subnets (one per line) to the `init` command:
`./vuln_scanner.py init --subnet subnets.txt ...`

### 7. Configurable Nmap Arguments
You can customize the Nmap arguments used during discovery by adding `nmap_args` to `config.json`:
```json
"nmap_args": "-sS -n -vvv -T4 --top-ports 1000",
"threads": 50
```
### 8. UDP Support and Split Scanning
The scanner automatically detects UDP modules and separates ports into `tcp_ports` and `udp_ports` in `config.json`.
The `discovery` command executes two separate Nmap scans:
1.  **TCP Scan**: `nmap -sS -p T:<tcp_ports> ...`
2.  **UDP Scan**: `nmap -sU -p U:<udp_ports> ...`

The results are merged into `inventory.json`, which tracks protocols per host:
```json
"192.168.1.10": {
    "tcp": [80, 443],
    "udp": [161]
}
```
The `scan` command then ensures that modules are only executed against ports with the matching protocol (e.g., `snmp_login` only runs on UDP 161).

### 9. Automatic Self-Exclusion
The `init` command automatically detects the local machine's IP addresses and adds them to `exclude_ips` in `config.json`.
These IPs are passed to Nmap using the `--exclude` flag to prevent the scanner from scanning itself.
-   `scanner_modules/`: Python modules for each mode.
-   `modules.json`: Database of MSF modules.
-   `config.json`: Scan configuration.
-   `inventory.json`: Discovered hosts and ports.
-   `checkpoint.json`: Scan progress tracking.
