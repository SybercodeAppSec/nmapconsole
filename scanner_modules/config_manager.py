import socket
import json
import os

class ConfigManager:
    def __init__(self, modules_db_path='modules.json'):
        self.modules_db_path = modules_db_path
        self.modules_db = self._load_modules_db()

    def _load_modules_db(self):
        if not os.path.exists(self.modules_db_path):
            print(f"Warning: Module database {self.modules_db_path} not found. Please run 'analyze' first.")
            return {}
        with open(self.modules_db_path, 'r') as f:
            return json.load(f)

    def _get_local_ips(self):
        local_ips = []
        try:
            # Get hostname
            hostname = socket.gethostname()
            # Get all IP addresses associated with the hostname
            _, _, ips = socket.gethostbyname_ex(hostname)
            local_ips.extend(ips)
            
            # Also try to get the IP that connects to a public DNS (e.g. Google)
            # This helps if gethostbyname_ex returns 127.0.0.1 or misses an interface
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Doesn't actually connect
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
                if ip not in local_ips:
                    local_ips.append(ip)
            except Exception:
                pass
            finally:
                s.close()
                
        except Exception as e:
            print(f"Warning: Could not detect local IPs: {e}")
        
        # Filter out loopback if desired, but user said "exclude local IPs", so maybe keep them?
        # Usually we want to exclude the scanner machine itself from the scan.
        return sorted(list(set(local_ips)))

    def init_config(self, firm_name, subnet, scan_type, output_file='config.json', scan_engine='msfconsole,nmap'):
        # Auto-detect local IPs to exclude
        exclude_ips = self._get_local_ips()
        
        # Validate scan_type
        if scan_type == 'all':
            print("Error: 'all' is not a valid scan_type. Please specify 'tcp', 'udp', or 'tcp,udp'.")
            return

        valid_types = ['tcp', 'udp']
        for t in scan_type.split(','):
            if t.strip() not in valid_types:
                print(f"Error: Invalid scan_type '{t}'. Must be 'tcp' or 'udp'.")
                return
        
        # Handle subnet argument (string or file path)
        subnet_list = []
        if os.path.isfile(subnet):
            print(f"Reading subnets from file: {subnet}")
            try:
                with open(subnet, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            subnet_list.append(line)
            except Exception as e:
                print(f"Error reading subnet file: {e}")
                return
        else:
            # Treat as single subnet string
            subnet_list = [subnet]

        default_conf_path = 'default.conf'
        config = {}
        
        if os.path.exists(default_conf_path):
            print(f"Loading configuration from {default_conf_path}...")
            with open(default_conf_path, 'r') as f:
                config = json.load(f)
            
            # Update with instance-specific values
            config['firm_name'] = firm_name
            config['subnet'] = subnet_list
            config['scan_type'] = scan_type
            config['scan_engine'] = scan_engine
            config['exclude_ips'] = exclude_ips
            
            # Ensure required fields exist
            if 'tcp_ports' not in config: config['tcp_ports'] = []
            if 'udp_ports' not in config: config['udp_ports'] = []
            if 'modules' not in config: config['modules'] = {}
            if 'modules_nmap' not in config: config['modules_nmap'] = {}
            if 'threads' not in config: config['threads'] = 25
            if 'nmap_args' not in config: config['nmap_args'] = "-n -vv"
            
            tcp_ports = config['tcp_ports']
            udp_ports = config['udp_ports']
            
        else:
            print("Generating fresh configuration from module database...")
            config = {
                'firm_name': firm_name,
                'subnet': subnet_list,
                'scan_type': scan_type,
                'scan_engine': scan_engine,
                'threads': 25,
                'nmap_args': "-n -vv",
                'exclude_ips': exclude_ips,
                'tcp_ports': [],
                'udp_ports': [],
                'modules': {},
                'modules_nmap': {}
            }

            # Determine target ports based on available modules and scan type
            tcp_ports = set()
            udp_ports = set()

            # Select modules for each port
            for port_str, modules in self.modules_db.items():
                port = int(port_str)
                config['modules'][port_str] = []
                
                for module in modules:
                    # We can add filtering logic here if needed
                    config['modules'][port_str].append(module['path'])
                    
                    # Check protocol
                    if 'info' in module and 'protocol' in module['info']:
                        proto = module['info']['protocol']
                        if proto == 'udp':
                            udp_ports.add(port)
                        else:
                            tcp_ports.add(port)
                    else:
                        # Default to TCP if unknown
                        tcp_ports.add(port)

            config['tcp_ports'] = sorted(list(tcp_ports))
            config['udp_ports'] = sorted(list(udp_ports))

        # Enforce key order
        ordered_config = {
            'firm_name': firm_name,
            'username': "", # New field
            'password': "", # New field
            'domain': "", # New field
            'opsec_safe': False, # New field
            'subnet': subnet_list,
            'scan_type': scan_type,
            'scan_engine': scan_engine,
            'exclude_ips': exclude_ips
        }
        
        # Add remaining keys from config
        for k, v in config.items():
            if k not in ordered_config:
                ordered_config[k] = v
        
        config = ordered_config

        with open(output_file, 'w') as f:
            json.dump(config, f, indent=4)
        
        print(f"Configuration saved to {output_file}")
        print(f"Targeting {len(tcp_ports)} TCP ports and {len(udp_ports)} UDP ports.")
        print(f"Excluded local IPs: {', '.join(exclude_ips)}")

