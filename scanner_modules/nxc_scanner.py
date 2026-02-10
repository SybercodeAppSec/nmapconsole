import json
import os
import subprocess
import time
from datetime import datetime
from .runner import fix_permissions

class NxcRunner:
    def __init__(self, config_file, inventory_file, checkpoint_file):
        self.config_file = config_file
        self.inventory_file = inventory_file
        self.checkpoint_file = checkpoint_file
        
        with open(config_file, 'r') as f:
            self.config = json.load(f)
            
        self.username = self.config.get('username', '')
        self.password = self.config.get('password', '')
        self.domain = self.config.get('domain', '')
        self.opsec_safe = self.config.get('opsec_safe', False)
        self.opsec_safe = self.config.get('opsec_safe', False)
        self.timeout = self.config.get('nxc_timeout', 0)
        
        base_output_dir = self.config.get('output_dir', 'scans')
        firm_name = self.config.get('firm_name', 'default')
        self.output_dir = os.path.join(base_output_dir, firm_name)
        
        if not os.path.exists(base_output_dir):
            os.makedirs(base_output_dir)
            fix_permissions(base_output_dir)

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            fix_permissions(self.output_dir)
            
        self.checkpoint = self._load_checkpoint()

    def _load_checkpoint(self):
        if not os.path.exists(self.checkpoint_file):
            return {'completed_scans': []}
        with open(self.checkpoint_file, 'r') as f:
            return json.load(f)

    def _save_checkpoint(self):
        with open(self.checkpoint_file, 'w') as f:
            json.dump(self.checkpoint, f, indent=4)
            fix_permissions(self.checkpoint_file)

    def _get_creds_string(self):
        creds = f"-u '{self.username}' -p '{self.password}'"
        if self.domain == 'local-auth' or self.domain == 'localauth':
            creds += " --local-auth"
        elif self.domain:
            creds += f" -d '{self.domain}'"
        return creds

    def run_command(self, command, log_file, dry_run=False):
        # Use log filename as unique ID for checkpoint
        scan_id = f"nxc:{os.path.basename(log_file)}"
        
        if scan_id in self.checkpoint.get('completed_scans', []):
            print(f"Skipping already completed scan: {scan_id}")
            return

        full_command = f"{command} --log {log_file}"
        
        if self.timeout > 0:
            full_command = f"timeout {self.timeout} {full_command}"

        print(f"Running: {full_command}")
        
        if dry_run:
            return

        try:
            subprocess.run(full_command, shell=True, check=False)
            fix_permissions(log_file)
            
            if 'completed_scans' not in self.checkpoint:
                self.checkpoint['completed_scans'] = []
            self.checkpoint['completed_scans'].append(scan_id)
            self._save_checkpoint()
            
        except KeyboardInterrupt:
            print(f"\n[!] Skipping current nxc command...")
            return
        except Exception as e:
            print(f"Error running command: {e}")

    def get_targets_for_port(self, port):
        targets = []
        if not os.path.exists(self.inventory_file):
            return targets
            
        with open(self.inventory_file, 'r') as f:
            inventory = json.load(f)
            
        for ip, info in inventory.items():
            tcp_ports = info.get('tcp', [])
            udp_ports = info.get('udp', [])
            if port in tcp_ports or port in udp_ports:
                targets.append(ip)
        return targets

    def is_dc(self, ip, inventory):
        info = inventory.get(ip, {})
        tcp_ports = info.get('tcp', [])
        # Check for 445, 88, 389
        return 445 in tcp_ports and 88 in tcp_ports and 389 in tcp_ports

    def run_scan(self, dry_run=False, force=False):
        print("Starting NetExec (nxc) Scan...")
        
        if not os.path.exists(self.inventory_file):
            print("Inventory file not found. Skipping nxc scan.")
            return

        with open(self.inventory_file, 'r') as f:
            inventory = json.load(f)

        # SMB (445)
        smb_targets = self.get_targets_for_port(445)
        if smb_targets:
            self.scan_smb(smb_targets, inventory, dry_run)

        # LDAP (389)
        ldap_targets = self.get_targets_for_port(389)
        if ldap_targets:
            self.scan_ldap(ldap_targets, dry_run)

        # WINRM (5985/5986)
        winrm_targets = self.get_targets_for_port(5985) + self.get_targets_for_port(5986)
        if winrm_targets:
            self.scan_protocol('winrm', list(set(winrm_targets)), dry_run)

        # MSSQL (1433)
        mssql_targets = self.get_targets_for_port(1433)
        if mssql_targets:
            self.scan_protocol('mssql', mssql_targets, dry_run)

        # SSH (22)
        ssh_targets = self.get_targets_for_port(22)
        if ssh_targets:
            self.scan_protocol('ssh', ssh_targets, dry_run, ignore_domain=True)

        # FTP (21)
        ftp_targets = self.get_targets_for_port(21)
        if ftp_targets:
            self.scan_protocol('ftp', ftp_targets, dry_run)

        # RDP (3389)
        rdp_targets = self.get_targets_for_port(3389)
        if rdp_targets:
            self.scan_protocol('rdp', rdp_targets, dry_run)

        # NFS (111)
        nfs_targets = self.get_targets_for_port(111)
        if nfs_targets:
            self.scan_protocol('nfs', nfs_targets, dry_run, ignore_domain=True)
            
        # WMI (135) - Special case for extended modules
        wmi_targets = self.get_targets_for_port(135)
        if wmi_targets:
            self.scan_protocol('wmi', wmi_targets, dry_run)

    def scan_smb(self, targets, inventory, dry_run):
        target_str = " ".join(targets)
        base_log = os.path.join(self.output_dir, "nxc_smb")
        
        # Auth Types
        # Empty Auth
        self.run_command(f"nxc smb {target_str} --users", f"{base_log}_empty_users.txt", dry_run)
        self.run_command(f"nxc smb {target_str} --groups", f"{base_log}_empty_groups.txt", dry_run)
        self.run_command(f"nxc smb {target_str} --shares", f"{base_log}_empty_shares.txt", dry_run)
        
        # Null Auth
        self.run_command(f"nxc smb {target_str} -u '' -p '' --users", f"{base_log}_null_users.txt", dry_run)
        self.run_command(f"nxc smb {target_str} -u '' -p '' --groups", f"{base_log}_null_groups.txt", dry_run)
        self.run_command(f"nxc smb {target_str} -u '' -p '' --shares", f"{base_log}_null_shares.txt", dry_run)

        # Guest Auth
        self.run_command(f"nxc smb {target_str} -u 'doesnotexist' -p '' --users", f"{base_log}_guest_users.txt", dry_run)
        self.run_command(f"nxc smb {target_str} -u 'doesnotexist' -p '' --groups", f"{base_log}_guest_groups.txt", dry_run)
        self.run_command(f"nxc smb {target_str} -u 'doesnotexist' -p '' --shares", f"{base_log}_guest_shares.txt", dry_run)

        # User Auth (if creds provided)
        if self.username:
            creds = self._get_creds_string()
            
            self.run_command(f"nxc smb {target_str} {creds} --users", f"{base_log}_user_users.txt", dry_run)
            self.run_command(f"nxc smb {target_str} {creds} --groups", f"{base_log}_user_groups.txt", dry_run)
            self.run_command(f"nxc smb {target_str} {creds} --shares", f"{base_log}_user_shares.txt", dry_run)

            # Extended Modules
            modules = [
                "enum_av", "enum_ca", "ioxidresolver", "ms17-010", "ntlm_reflection",
                "printnightmare", "remove-mic", "sccm-recon6", "smbghost", "spooler",
                "webdav", "aws-credentials", "timeroast"
            ]
            
            for module in modules:
                self.run_command(f"nxc smb {target_str} {creds} -M {module}", f"{base_log}_{module}.txt", dry_run)

            # DC Specific Modules
            dc_targets = [ip for ip in targets if self.is_dc(ip, inventory)]
            if dc_targets:
                dc_str = " ".join(dc_targets)
                dc_modules = [
                    "gpp_privileges", "nopac", "zerologon", "gpp_autologin", "gpp_password"
                ]
                for module in dc_modules:
                    self.run_command(f"nxc smb {dc_str} {creds} -M {module}", f"{base_log}_dc_{module}.txt", dry_run)

    def scan_ldap(self, targets, dry_run):
        if not self.username:
            return

        target_str = " ".join(targets)
        creds = self._get_creds_string()
            
        base_log = os.path.join(self.output_dir, "nxc_ldap")

        # Core Modules
        self.run_command(f"nxc ldap {target_str} {creds} --kerberoasting {base_log}_kerberoasting.txt", f"{base_log}_kerberoasting_log.txt", dry_run)
        self.run_command(f"nxc ldap {target_str} {creds} --asreproast {base_log}_asreproast.txt", f"{base_log}_asreproast_log.txt", dry_run)
        
        core_flags = [
            "--find-delegation", "--trusted-for-delegation", "--password-not-required",
            "--admin-count", "--dc-list", "--get-sid"
        ]
        
        for flag in core_flags:
            flag_name = flag.replace("--", "")
            self.run_command(f"nxc ldap {target_str} {creds} {flag}", f"{base_log}_{flag_name}.txt", dry_run)

        # Extended Modules
        modules = [
            "adcs", "enum_trusts", "find-computer", "get-desc-users", "get-network",
            "get-unixUserPassword", "get-userPassword", "groupmembership", "laps",
            "ldap-checker", "maq", "obsolete", "pre2k", "pso", "sccm", "subnets",
            "user-desc", "whoami"
        ]
        
        for module in modules:
            self.run_command(f"nxc ldap {target_str} {creds} -M {module}", f"{base_log}_{module}.txt", dry_run)

    def scan_protocol(self, protocol, targets, dry_run, ignore_domain=False):
        if not self.username:
            return
            
        target_str = " ".join(targets)
        
        if ignore_domain:
            creds = f"-u '{self.username}' -p '{self.password}'"
        else:
            creds = self._get_creds_string()
            
        base_log = os.path.join(self.output_dir, f"nxc_{protocol}")
        self.run_command(f"nxc {protocol} {target_str} {creds}", f"{base_log}_login.txt", dry_run)