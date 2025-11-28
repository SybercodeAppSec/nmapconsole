import json
import subprocess
import os
import xml.etree.ElementTree as ET
from .runner import fix_permissions

class DiscoveryManager:
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.config = self._load_config()

    def _load_config(self):
        with open(self.config_file, 'r') as f:
            return json.load(f)

    def run_discovery(self, output_base='nmap_scan', dry_run=False):
        subnet = self.config['subnet']
        base_output_dir = self.config.get('output_dir', 'scans')
        firm_name = self.config.get('firm_name', 'default')
        output_dir = os.path.join(base_output_dir, firm_name)
        
        if not dry_run:
            if not os.path.exists(base_output_dir):
                os.makedirs(base_output_dir)
                fix_permissions(base_output_dir)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                fix_permissions(output_dir)

        # Default arguments
        default_args = "-n -vvv -T5"
        nmap_args = self.config.get('nmap_args', default_args)
        if not nmap_args: # Handle empty string case
            nmap_args = default_args
        
        # Filter out scan flags from nmap_args to avoid conflicts
        args_list = nmap_args.split()
        filtered_args = [a for a in args_list if a not in ['-sS', '-sT', '-sU', '-p']]
        
        # Base command construction
        base_cmd = ["nmap"]
        base_cmd.extend(filtered_args)
        
        # Add exclusions
        if 'exclude_ips' in self.config and self.config['exclude_ips']:
            base_cmd.append("--exclude")
            base_cmd.append(",".join(self.config['exclude_ips']))

        if isinstance(subnet, list):
            base_cmd.extend(subnet)
        else:
            base_cmd.append(subnet)

        xml_files = []

        # 1. TCP Scan
        if 'tcp_ports' in self.config and self.config['tcp_ports']:
            print("Starting TCP Scan...")
            tcp_ports = ",".join(map(str, self.config['tcp_ports']))
            tcp_output = os.path.join(output_dir, f"{output_base}_tcp")
            
            cmd = ["nmap"]
            cmd.extend(filtered_args)
            cmd.append("-sS")
            cmd.append("-p")
            cmd.append(tcp_ports)
            cmd.extend(["-oA", tcp_output])
            
            if 'exclude_ips' in self.config and self.config['exclude_ips']:
                cmd.append("--exclude")
                cmd.append(",".join(self.config['exclude_ips']))
            
            if isinstance(subnet, list):
                cmd.extend(subnet)
            else:
                cmd.append(subnet)

            print(f"Running TCP discovery: {' '.join(cmd)}")
            
            if not dry_run:
                try:
                    subprocess.run(cmd, check=True)
                    xml_files.append(f"{tcp_output}.xml")
                    fix_permissions(f"{tcp_output}.xml")
                    fix_permissions(f"{tcp_output}.nmap")
                    fix_permissions(f"{tcp_output}.gnmap")
                except subprocess.CalledProcessError as e:
                    print(f"TCP scan failed: {e}")
            else:
                print("Dry run: Skipping TCP execution.")

        # 2. UDP Scan
        if 'udp_ports' in self.config and self.config['udp_ports']:
            print("Starting UDP Scan...")
            udp_ports = ",".join(map(str, self.config['udp_ports']))
            udp_output = os.path.join(output_dir, f"{output_base}_udp")
            
            cmd = ["nmap"]
            cmd.extend(filtered_args)
            cmd.append("-sU")
            cmd.append("-p")
            cmd.append(udp_ports)
            cmd.extend(["-oA", udp_output])
            
            if 'exclude_ips' in self.config and self.config['exclude_ips']:
                cmd.append("--exclude")
                cmd.append(",".join(self.config['exclude_ips']))
            
            if isinstance(subnet, list):
                cmd.extend(subnet)
            else:
                cmd.append(subnet)

            print(f"Running UDP discovery: {' '.join(cmd)}")
            
            if not dry_run:
                try:
                    subprocess.run(cmd, check=True)
                    xml_files.append(f"{udp_output}.xml")
                    fix_permissions(f"{udp_output}.xml")
                    fix_permissions(f"{udp_output}.nmap")
                    fix_permissions(f"{udp_output}.gnmap")
                except subprocess.CalledProcessError as e:
                    print(f"UDP scan failed: {e}")
            else:
                print("Dry run: Skipping UDP execution.")

        if not dry_run and xml_files:
            self.parse_nmap_xml(xml_files)

    def parse_nmap_xml(self, xml_files, output_file='inventory.json'):
        if isinstance(xml_files, str):
            xml_files = [xml_files]
            
        inventory = {}

        for xml_file in xml_files:
            if not os.path.exists(xml_file):
                print(f"Error: XML file {xml_file} not found.")
                continue

            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                # Try to detect protocol from scaninfo
                # <scaninfo type="syn" protocol="tcp" numservices="1000" services="..."/>
                # <scaninfo type="udp" protocol="udp" numservices="1000" services="..."/>
                scaninfo = root.find('scaninfo')
                protocol = 'tcp' # Default
                if scaninfo is not None:
                    protocol = scaninfo.get('protocol', 'tcp')
                
                # Fallback: check filename
                if 'udp' in xml_file.lower():
                    protocol = 'udp'
                elif 'tcp' in xml_file.lower():
                    protocol = 'tcp'

                for host in root.findall('host'):
                    status = host.find('status')
                    if status is None or status.get('state') != 'up':
                        continue
                    
                    address = host.find('address')
                    if address is None:
                        continue
                    ip = address.get('addr')
                    
                    if ip not in inventory:
                        inventory[ip] = {'tcp': [], 'udp': []}
                    
                    ports_element = host.find('ports')
                    if ports_element is None:
                        continue
                    
                    for port in ports_element.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            port_id = int(port.get('portid'))
                            # Port element also has protocol attribute usually
                            port_proto = port.get('protocol', protocol)
                            
                            if port_proto == 'tcp':
                                if port_id not in inventory[ip]['tcp']:
                                    inventory[ip]['tcp'].append(port_id)
                            elif port_proto == 'udp':
                                if port_id not in inventory[ip]['udp']:
                                    inventory[ip]['udp'].append(port_id)
            except Exception as e:
                print(f"Error parsing {xml_file}: {e}")

        # Clean up empty entries if any
        final_inventory = {}
        for ip, ports in inventory.items():
            if ports['tcp'] or ports['udp']:
                ports['tcp'].sort()
                ports['udp'].sort()
                final_inventory[ip] = ports

        with open(output_file, 'w') as f:
            json.dump(final_inventory, f, indent=4)
        fix_permissions(output_file)
        
        print(f"Discovery complete. Found {len(final_inventory)} hosts. Saved to {output_file}")
