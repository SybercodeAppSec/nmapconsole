import os
import re
import json

class ModuleAnalyzer:
    def __init__(self, msf_path):
        self.msf_path = msf_path
        self.aux_path = os.path.join(msf_path, 'auxiliary')
        self.unsafe_categories = ['dos', 'fuzzers', 'spoof', 'bnat', 'vsploit']
        self.modules = {}

    def parse_module(self, file_path, full_scan=False):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            if not full_scan:
                # Never include server/capture modules - they OPEN LISTENERS
                # on the given port (e.g. auxiliary/server/capture/vnc binds
                # 5900) and block the whole scan.
                rel = os.path.relpath(file_path, self.aux_path)
                if rel.split(os.sep)[0] == 'server':
                    return None

                # Check for authenticated mixins
                # If it's an SMB Authenticated module, we only allow it if it's also a Scanner.
                # Non-scanner authenticated modules (like gather/admin) usually require valid creds.
                if "Msf::Exploit::Remote::SMB::Client::Authenticated" in content:
                    if "Msf::Auxiliary::Scanner" not in content:
                        return None

                # Check for required authentication options
                # OptString.new('PASSWORD', [true, ...])
                # OptString.new('USERNAME', [true, ...])
                # OptInt.new('SESSION', [true, ...])
                
                # Regex to find required options: Opt*.new('NAME', [true
                # We look for specific sensitive option names
                sensitive_opts = ['PASSWORD', 'USERNAME', 'SMBUser', 'SMBPass', 'SESSION']
                for opt in sensitive_opts:
                    # Pattern: Opt\w+\.new\(['"]OPT['"],\s*\[\s*true
                    pattern = r"Opt\w+\.new\(['\"]" + opt + r"['\"],\s*\[\s*true"
                    if re.search(pattern, content, re.IGNORECASE):
                        return None

            # Extract Name
            name_match = re.search(r"'Name'\s*=>\s*['\"](.*?)['\"]", content)
            name = name_match.group(1) if name_match else "Unknown"

            # Extract Description
            desc_match = re.search(r"'Description'\s*=>\s*['\"](.*?)['\"]", content, re.DOTALL)
            description = desc_match.group(1) if desc_match else "No description"
            description = " ".join(description.split()) # Clean up whitespace

            # Extract RPORT
            rport_match = re.search(r"Opt::RPORT\((\d+)\)", content)
            rport = int(rport_match.group(1)) if rport_match else None
            
            # If no RPORT in Opt::RPORT, try to find register_options with 'RPORT'
            if not rport:
                 rport_match_alt = re.search(r"OptPort\.new\('RPORT',\s*\[\s*true,\s*'.*?',\s*(\d+)\s*\]\)", content)
                 if rport_match_alt:
                     rport = int(rport_match_alt.group(1))

            # If still no RPORT, infer from mixins
            if not rport:
                if "Msf::Exploit::Remote::SMB::Client" in content:
                    rport = 445
                elif "Msf::Exploit::Remote::HttpClient" in content:
                    rport = 80
                elif "Msf::Exploit::Remote::TNS" in content:
                    rport = 1521
                elif "Msf::Exploit::Remote::Postgres" in content:
                    rport = 5432
                elif "Msf::Exploit::Remote::MSSQL" in content:
                    rport = 1433
                elif "Msf::Exploit::Remote::MySQL" in content:
                    rport = 3306
                elif "Msf::Exploit::Remote::Smtp" in content:
                    rport = 25
                elif "Msf::Exploit::Remote::Ftp" in content:
                    rport = 21
                elif "Msf::Exploit::Remote::Telnet" in content:
                    rport = 23
                elif "Msf::Exploit::Remote::Ssh" in content:
                    rport = 22

            # If no RPORT, check for SRVPORT (Server Port for exploit/server modules)
            if not rport:
                srvport_match = re.search(r"OptPort\.new\('SRVPORT',\s*\[\s*true,\s*'.*?',\s*(\d+)\s*\]\)", content)
                if srvport_match:
                    rport = int(srvport_match.group(1))

            # If still no RPORT, infer from file path
            if not rport:
                path_based_ports = {
                    'http': 80, 'https': 443, 'ftp': 21, 'ssh': 22, 'telnet': 23, 
                    'smtp': 25, 'dns': 53, 'tftp': 69, 'kerberos': 88, 'pop3': 110, 
                    'ntp': 123, 'netbios': 137, 'imap': 143, 'snmp': 161, 'ldap': 389, 
                    'smb': 445, 'mssql': 1433, 'oracle': 1521, 'mysql': 3306, 
                    'rdp': 3389, 'postgres': 5432, 'vnc': 5900, 'winrm': 5985, 
                    'redis': 6379, 'sip': 5060, 'mqtt': 1883, 'mongodb': 27017,
                    'git': 9418, 'elasticsearch': 9200, 'memcached': 11211,
                    'sap': 3200, 'db2': 50000, 'printer': 9100, 'afp': 548,
                    'dhcp': 67, 'upnp': 1900, 'natpmp': 5351, 'jenkins': 8080,
                    'wordpress': 80, 'joomla': 80, 'drupal': 80, 'web': 80,
                    'tomcat': 8080, 'weblogic': 7001, 'jboss': 8080, 'glassfish': 4848,
                    'aws': 443, 'vmware': 443, 'ssl': 443, 'kerberoast': 88,
                    'cisco': 22, 'fortinet': 22, 'juniper': 22, 'f5': 443,
                    'sunrpc': 111, 'dcerpc': 135, 'nfs': 2049, 'x11': 6000,
                    'scada': 502, 'bacnet': 47808, 'citrix': 443, 'sccm': 80,
                    'browser': 80, 'android': 80, 'ios': 80, 'firefox': 80, 
                    'chrome': 80, 'safari': 80, 'ie': 80, 'webkit': 80, 'crawler': 80,
                    'foxit': 0, 'adobe': 0, 'office': 0, 'word': 0, 'excel': 0, 'pdf': 0,
                    'mdns': 5353, 'vxworks': 17185, 'tftp': 69, 'dhcp': 67,
                    'cups': 631, 'ibm_mq': 1414, 'rocketmq': 9876, 'llmnr': 5355,
                    'varnish': 6082, 'acpp': 5009, 'thinmanager': 2031, 'nuuo': 80,
                    'wpad': 80, 'shodan': 443, 'censys': 443
                }
                
                # Categories that map to Port 0 (Local/Client/Network/File)
                local_categories = [
                    'fileformat', 'analyze', 'crack', 'sniffer', 'spoof', 'capture', 
                    'discovery', 'portscan', 'udp', 'ipv6', 'admin/misc', 'parser',
                    'bnat', 'vsploit', 'client'
                ]

                # Check path segments and filename
                # file_path is absolute
                path_lower = file_path.lower()
                filename = os.path.basename(path_lower)
                
                # Check for local categories first
                for cat in local_categories:
                    if f"/{cat}/" in path_lower:
                        rport = 0
                        break
                
                if rport is None:
                    for service, port in path_based_ports.items():
                        # Check directory segments: /service/
                        if f"/{service}/" in path_lower or f"\\{service}\\" in path_lower:
                            rport = port
                            break
                # Check filename contains service
                        if service in filename:
                            rport = port
                            break

            # Detect Protocol (TCP/UDP)
            protocol = 'tcp' # Default
            if "Msf::Exploit::Remote::Udp" in content:
                protocol = 'udp'
            else:
                # Check for known UDP services
                udp_services = [
                    'snmp', 'tftp', 'ntp', 'dns', 'dhcp', 'netbios', 'isakmp', 
                    'udp', 'radius', 'syslog', 'ipmi', 'citrix', 'memcached', 
                    'openvpn', 'raknet', 'steam', 'teamspeak', 'wireguard'
                ]
                path_lower = file_path.lower()
                for service in udp_services:
                    if f"/{service}/" in path_lower or service in os.path.basename(path_lower):
                        protocol = 'udp'
                        break



            return {
                'name': name,
                'description': description,
                'rport': rport,
                'protocol': protocol
            }
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return None

    def analyze(self, full_scan=False):
        print(f"Analyzing modules in {self.aux_path}...")
        skipped_modules = []
        
        for root, dirs, files in os.walk(self.aux_path):
            # Skip unsafe categories unless full_scan is True
            parts = os.path.relpath(root, self.aux_path).split(os.sep)
            if not full_scan and any(part in self.unsafe_categories for part in parts):
                continue

            for file in files:
                if file.endswith('.rb'):
                    full_path = os.path.join(root, file)
                    # Construct module path (e.g., auxiliary/scanner/ssh/ssh_version)
                    rel_path = os.path.relpath(full_path, self.msf_path)
                    module_path = os.path.splitext(rel_path)[0]

                    module_info = self.parse_module(full_path, full_scan)
                    
                    if module_info and module_info['rport'] is not None:
                        port = module_info['rport']
                        if port not in self.modules:
                            self.modules[port] = []
                        
                        self.modules[port].append({
                            'path': module_path,
                            'info': module_info
                        })

                    else:
                        skipped_modules.append(module_path)
        
        if skipped_modules:
            print(f"\n[!] Skipped {len(skipped_modules)} modules due to missing RPORT:")
            for mod in skipped_modules:
                print(f"    - {mod}")
        
        return self.modules

    def save_to_file(self, output_file='modules.json'):
        with open(output_file, 'w') as f:
            json.dump(self.modules, f, indent=4)
        print(f"Analysis complete. Found modules for {len(self.modules)} ports. Saved to {output_file}")
