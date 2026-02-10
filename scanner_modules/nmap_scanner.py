import json
import subprocess
import os
import time
from .runner import fix_permissions

class NmapRunner:
    def __init__(self, config_file='config.json', inventory_file='inventory.json', checkpoint_file='checkpoint.json'):
        self.config_file = config_file
        self.inventory_file = inventory_file
        self.checkpoint_file = checkpoint_file
        self.config = self._load_json(config_file)
        self.inventory = self._load_json(inventory_file)
        self.timeout = self.config.get('nmap_timeout', 0)
        self.checkpoint = self._load_checkpoint()

    def _load_json(self, path):
        if not os.path.exists(path):
            return {}
        with open(path, 'r') as f:
            return json.load(f)

    def _load_checkpoint(self):
        if not os.path.exists(self.checkpoint_file):
            return {'completed_scans': []}
        with open(self.checkpoint_file, 'r') as f:
            return json.load(f)

    def _save_checkpoint(self):
        with open(self.checkpoint_file, 'w') as f:
            json.dump(self.checkpoint, f, indent=4)
        fix_permissions(self.checkpoint_file)

    def run_scan(self, dry_run=False, force=False):
        # Group IPs by port AND protocol
        target_groups = {}
        
        for ip, protocols in self.inventory.items():
            if isinstance(protocols, dict):
                for proto, ports in protocols.items():
                    for port in ports:
                        if port not in target_groups:
                            target_groups[port] = {'tcp': [], 'udp': []}
                        if proto in target_groups[port]:
                            target_groups[port][proto].append(ip)

        # Iterate through ports in modules_nmap
        modules_nmap = self.config.get('modules_nmap', {})
        if not modules_nmap:
            print("No NSE modules configured (modules_nmap is empty).")
            return

        for port_str, scripts in modules_nmap.items():
            port = int(port_str)
            
            # Determine protocol (default to TCP, but check if we have UDP targets)
            # Since NSE scripts can be protocol specific, we ideally need to know.
            # For now, we'll run against both if targets exist, or maybe just TCP?
            # Nmap usually handles it if we specify -p U:123,T:123 but we are running per port.
            
            # Let's check which protocols have targets for this port
            protocols_to_scan = []
            if port in target_groups:
                if target_groups[port]['tcp']:
                    protocols_to_scan.append('tcp')
                if target_groups[port]['udp']:
                    protocols_to_scan.append('udp')
            
            if not protocols_to_scan:
                continue

            for proto in protocols_to_scan:
                ips = target_groups[port][proto]
                if not ips:
                    continue

                # Prepare scripts argument
                script_arg = ",".join(scripts)
                
                scan_id = f"nmap_nse:{port}:{proto}:{script_arg}"
                if scan_id in self.checkpoint['completed_scans'] and not force:
                    print(f"Skipping already completed NSE scan: {scan_id}")
                    continue

                print(f"Running NSE scripts for port {port} ({proto.upper()}) on {len(ips)} hosts...")
                
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

                target_file = os.path.join(output_dir, f"targets_nse_{port}_{proto}.txt")
                
                if not dry_run:
                    with open(target_file, 'w') as f:
                        for ip in ips:
                            f.write(f"{ip}\n")
                    fix_permissions(target_file)

                # Build Nmap command
                # nmap -p <port> --script <scripts> -iL <target_file> -oA <output> <nmap_args>
                
                output_base = os.path.join(output_dir, f"nmap_nse_{port}_{proto}")
                
                cmd = []
                if self.timeout > 0:
                    cmd.extend(["timeout", str(self.timeout)])
                
                cmd.append("nmap")
                
                # Protocol flag
                if proto == 'udp':
                    cmd.append("-sU")
                else:
                    cmd.append("-sS") # or -sT depending on needs, but -sS is standard
                
                cmd.extend(["-p", str(port)])
                cmd.extend(["--script", script_arg])
                cmd.extend(["-iL", target_file])
                cmd.extend(["-oA", output_base])
                
                # Add custom nmap args
                nmap_args = self.config.get('nmap_args', '')
                if nmap_args:
                    cmd.extend(nmap_args.split())
                
                # Add exclusions
                if 'exclude_ips' in self.config and self.config['exclude_ips']:
                    cmd.append("--exclude")
                    cmd.append(",".join(self.config['exclude_ips']))

                if dry_run:
                    print(f"Command: {' '.join(cmd)}")
                else:
                    try:
                        subprocess.run(cmd, check=True)
                        self.checkpoint['completed_scans'].append(scan_id)
                        self._save_checkpoint()
                        # Fix permissions for generated files (xml, nmap, gnmap)
                        # Easiest is to fix the whole output dir or specific files
                        fix_permissions(output_dir) 
                    except KeyboardInterrupt:
                        print(f"\n[!] Skipping current Nmap scan...")
                        continue
                    except subprocess.CalledProcessError as e:
                        print(f"NSE scan failed for port {port}: {e}")
                    except Exception as e:
                        print(f"An error occurred: {e}")

        print("NSE scan phase complete.")
