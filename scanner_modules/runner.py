import json
import subprocess
import os
import time
import pwd
import grp

def fix_permissions(path):
    """
    Changes the ownership of the file or directory at 'path' to the user
    who invoked sudo (SUDO_UID/SUDO_GID), if those environment variables exist.
    """
    sudo_uid = os.environ.get('SUDO_UID')
    sudo_gid = os.environ.get('SUDO_GID')

    if sudo_uid and sudo_gid:
        try:
            uid = int(sudo_uid)
            gid = int(sudo_gid)
            
            # Change ownership of the path itself
            if os.path.exists(path):
                os.chown(path, uid, gid)
            
            # If it's a directory, recursively change ownership of contents
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for d in dirs:
                        os.chown(os.path.join(root, d), uid, gid)
                    for f in files:
                        os.chown(os.path.join(root, f), uid, gid)
                        
        except Exception as e:
            print(f"Warning: Failed to fix permissions for {path}: {e}")

class ScanRunner:
    def __init__(self, config_file='config.json', inventory_file='inventory.json', checkpoint_file='checkpoint.json'):
        self.config_file = config_file
        self.inventory_file = inventory_file
        self.checkpoint_file = checkpoint_file
        self.config = self._load_json(config_file)
        self.inventory = self._load_json(inventory_file)
        self.timeout = self.config.get('msf_timeout', 0)
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

    def _get_module_protocol(self, port, module_path):
        # Determine protocol based on config ports
        if port in self.config.get('udp_ports', []):
            return 'udp'
        if port in self.config.get('tcp_ports', []):
            return 'tcp'
            
        # Fallback/Default
        return 'tcp'

    def run_scan(self, dry_run=False, timeout=600):
        # Group IPs by port AND protocol
        # target_groups[port][protocol] = [ips]
        target_groups = {}
        
        for ip, protocols in self.inventory.items():
            # Handle both old format (list of ports) and new format (dict of protocols)
            if isinstance(protocols, list):
                # Old format: assume TCP for all
                for port in protocols:
                    if port not in target_groups:
                        target_groups[port] = {'tcp': [], 'udp': []}
                    target_groups[port]['tcp'].append(ip)
            elif isinstance(protocols, dict):
                # New format
                for proto, ports in protocols.items():
                    for port in ports:
                        if port not in target_groups:
                            target_groups[port] = {'tcp': [], 'udp': []}
                        if proto in target_groups[port]:
                            target_groups[port][proto].append(ip)

        # Iterate through ports and run modules
        for port in sorted(target_groups.keys()):
            port_str = str(port)
            if port_str not in self.config['modules']:
                # print(f"No modules configured for port {port}. Skipping.")
                continue

            modules = self.config['modules'][port_str]
            
            # For each module, determine its protocol and get relevant IPs
            for module_path in modules:
                module_proto = self._get_module_protocol(port, module_path)
                
                # Get IPs that have this port open on this protocol
                ips = target_groups[port].get(module_proto, [])
                
                if not ips:
                    continue

                scan_id = f"{port}:{module_path}"
                
                if scan_id in self.checkpoint['completed_scans']:
                    print(f"Skipping already completed scan: {scan_id}")
                    continue

                print(f"Running {module_path} on port {port} ({module_proto.upper()}) ({len(ips)} hosts)...")
                
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

                target_file = os.path.join(output_dir, f"targets_{port}_{module_proto}.txt")
                
                # Create target file
                if not dry_run:
                    with open(target_file, 'w') as f:
                        for ip in ips:
                            f.write(f"{ip}\n")
                
                # Construct MSF command
                output_file = os.path.join(output_dir, f"msf_results_{port}_{module_path.replace('/', '_')}.txt")
                
                threads = self.config.get('threads', 25)
                
                msf_commands = [
                    f"use {module_path}",
                    f"spool {output_file}",
                    f"setg rhosts file:{target_file}",
                    f"setg threads {threads}",
                    f"setg RPORT {port}"
                ]

                # Apply custom options
                if 'module_options' in self.config and module_path in self.config['module_options']:
                    custom_opts = self.config['module_options'][module_path]
                    if isinstance(custom_opts, list):
                        msf_commands.extend(custom_opts)
                    elif isinstance(custom_opts, dict):
                        for opt, val in custom_opts.items():
                            msf_commands.append(f"set {opt} {val}")

                msf_commands.extend([
                    "options",
                    "run",
                    "spool off",
                    "exit"
                ])
                
                full_command = "; ".join(msf_commands)
                cmd = []
                if self.timeout > 0:
                    cmd.extend(["timeout", str(self.timeout)])
                
                cmd.extend(["msfconsole", "-qx", full_command])
                
                if dry_run:
                    print(f"Command: {' '.join(cmd)}")
                else:
                    try:
                        # We use the system 'timeout' command, so we don't need python's timeout here strictly,
                        # but keeping a python timeout slightly larger than the system timeout is good practice
                        # to ensure we catch it if the system timeout fails or hangs.
                        # However, user requested command structure modification.
                        subprocess.run(cmd, check=True)
                        self.checkpoint['completed_scans'].append(scan_id)
                        self._save_checkpoint()
                    except subprocess.TimeoutExpired:
                        print(f"Timeout expired for {scan_id}")
                    except subprocess.CalledProcessError as e:
                        print(f"Scan failed for {scan_id}: {e}")
                    except Exception as e:
                        print(f"An error occurred: {e}")

        print("Scan phase complete.")
