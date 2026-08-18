import json
import os
import subprocess
from datetime import datetime
from .runner import fix_permissions

# NetExec >= 1.3.0 compatibility notes (tested against 1.5.1):
# - "nxc smb --users/--groups" REMOVED -> use "nxc ldap --users/--groups"
# - [REMOVED] modules and their replacements:
#     ntlm_reflection   -> enum_cve
#     dfscoerce         -> coerce_plus
#     petitpotam        -> coerce_plus
#     printerbug        -> coerce_plus
#     shadowcoerce      -> coerce_plus
#     efsr_spray        -> coerce_plus (activates EFS automatically)
#     ldap-checker      -> native (shown in LDAP banner)
#     enum_trusts       -> --dc-list flag
#     pso               -> --pso flag
#     group-mem         -> --groups "<GROUP>" flag

# SMB modules that can run without credentials (null session friendly)
SMB_ANON_MODULES = [
    "enum_ca",
    "enum_cve",
    "ioxidresolver",
    "smbghost",
    "spooler",
    "webdav",
]

# SMB modules that require credentials
SMB_AUTH_MODULES = [
    "aws-credentials",
    "enum_av",
    "ms17-010",
    "printnightmare",
    "remove-mic",
    "sccm-recon6",
    "timeroast",
]

# LDAP modules that often work unauthenticated (null session)
LDAP_ANON_MODULES = [
    "adcs",
    "get-desc-users",
    "get-network",
    "get-unixUserPassword",
    "get-userPassword",
    "maq",
    "obsolete",
    "sccm",
    "subnets",
    "user-desc",
]

# LDAP modules that require credentials
LDAP_AUTH_MODULES = [
    "laps",
    "pre2k",
]

# DC-only modules (run only against Domain Controllers, require credentials)
DC_MODULES = [
    "badsuccessor",        # DMSA takeover (CVE-2025-53319)
    "dump-computers",
    "gpp_autologin",
    "gpp_password",
    "gpp_privileges",
    "nopac",               # CVE-2021-42278/42287
    "resetnightmare",      # CVE-2026-27912
    "zerologon",           # CVE-2020-1472
]


# Modules that actively attack/modify targets - only run when opsec_safe=false
OPSEC_UNSAFE_MODULES = [
    "resetnightmare",   # resets account passwords (CVE-2026-27912)
    "zerologon",        # CVE-2020-1472 (check only, but very noisy)
    "timeroast",        # requests password hashes via NTP
    "pre2k",            # obtains TGTs for pre-created computers
    "nopac",            # CVE-2021-42278/42287 (check)
    "badsuccessor",     # DMSA takeover check
]


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
        self.timeout = self.config.get('nxc_timeout', 0)
        self.nxc_threads = self.config.get('nxc_threads', 100)

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

        full_command = f"{command} --log {log_file} -t {self.nxc_threads} --no-progress"

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
            print("\n[!] Skipping current nxc command...")
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
        # Heuristic: DCs expose SMB + Kerberos + LDAP
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

        # LDAP (389/636)
        ldap_targets = self.get_targets_for_port(389) + self.get_targets_for_port(636)
        if ldap_targets:
            self.scan_ldap(list(set(ldap_targets)), dry_run)

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

        # WMI (135)
        wmi_targets = self.get_targets_for_port(135)
        if wmi_targets:
            self.scan_protocol('wmi', wmi_targets, dry_run)

    def scan_smb(self, targets, inventory, dry_run):
        target_str = " ".join(targets)
        base_log = os.path.join(self.output_dir, "nxc_smb")

        # ---- 1. Anonymous / null session checks (no creds needed) ----
        self.run_command(f"nxc smb {target_str} --shares", f"{base_log}_anon_shares.txt", dry_run)
        self.run_command(f"nxc smb {target_str} --pass-pol", f"{base_log}_anon_passpol.txt", dry_run)
        self.run_command(f"nxc smb {target_str} --smb-sessions", f"{base_log}_anon_sessions.txt", dry_run)
        self.run_command(f"nxc smb {target_str} --gen-relay-list {base_log}_relay_list.txt", f"{base_log}_genrelaylist.txt", dry_run)

        for module in SMB_ANON_MODULES:
            self.run_command(f"nxc smb {target_str} -M {module}", f"{base_log}_anon_{module}.txt", dry_run)

        # ---- 2. Null session (empty user/pass) ----
        self.run_command(f"nxc smb {target_str} -u '' -p '' --shares", f"{base_log}_null_shares.txt", dry_run)
        self.run_command(f"nxc smb {target_str} -u '' -p '' --pass-pol", f"{base_log}_null_passpol.txt", dry_run)

        # ---- 3. Guest session ----
        self.run_command(f"nxc smb {target_str} -u 'doesnotexist' -p '' --shares", f"{base_log}_guest_shares.txt", dry_run)

        # NOTE: --users / --groups moved from SMB to LDAP in NetExec >= 1.3.0
        # (handled in scan_ldap below)

        if not self.username:
            return

        creds = self._get_creds_string()

        # ---- 4. Authenticated enumeration ----
        self.run_command(f"nxc smb {target_str} {creds} --shares", f"{base_log}_user_shares.txt", dry_run)
        self.run_command(f"nxc smb {target_str} {creds} --pass-pol", f"{base_log}_user_passpol.txt", dry_run)
        self.run_command(f"nxc smb {target_str} {creds} --smb-sessions", f"{base_log}_user_sessions.txt", dry_run)
        self.run_command(f"nxc smb {target_str} {creds} --loggedon-users", f"{base_log}_loggedon_users.txt", dry_run)
        self.run_command(f"nxc smb {target_str} {creds} --rid-brute 4000", f"{base_log}_ridbrute.txt", dry_run)
        self.run_command(f"nxc smb {target_str} {creds} --disks", f"{base_log}_disks.txt", dry_run)
        self.run_command(f"nxc smb {target_str} {creds} --interfaces", f"{base_log}_interfaces.txt", dry_run)

        for module in SMB_AUTH_MODULES:
            if self.opsec_safe and module in OPSEC_UNSAFE_MODULES:
                print(f"[opsec_safe] Skipping noisy module: {module}")
                continue
            self.run_command(f"nxc smb {target_str} {creds} -M {module}", f"{base_log}_{module}.txt", dry_run)

        # ---- 5. DC specific modules ----
        dc_targets = [ip for ip in targets if self.is_dc(ip, inventory)]
        if dc_targets:
            dc_str = " ".join(dc_targets)
            for module in DC_MODULES:
                if self.opsec_safe and module in OPSEC_UNSAFE_MODULES:
                    print(f"[opsec_safe] Skipping noisy module: {module}")
                    continue
                self.run_command(f"nxc smb {dc_str} {creds} -M {module}", f"{base_log}_dc_{module}.txt", dry_run)

    def scan_ldap(self, targets, dry_run):
        target_str = " ".join(targets)
        base_log = os.path.join(self.output_dir, "nxc_ldap")

        # ---- 1. Unauthenticated checks (work with null session) ----
        # LDAP signing / channel binding is now shown natively in the banner
        self.run_command(f"nxc ldap {target_str}", f"{base_log}_anon_banner.txt", dry_run)

        for module in LDAP_ANON_MODULES:
            self.run_command(f"nxc ldap {target_str} -M {module}", f"{base_log}_anon_{module}.txt", dry_run)

        if not self.username:
            return

        creds = self._get_creds_string()

        # ---- 2. Domain user/group enumeration (moved here from SMB) ----
        self.run_command(f"nxc ldap {target_str} {creds} --users", f"{base_log}_users.txt", dry_run)
        self.run_command(f"nxc ldap {target_str} {creds} --groups", f"{base_log}_groups.txt", dry_run)
        self.run_command(f"nxc ldap {target_str} {creds} --computers", f"{base_log}_computers.txt", dry_run)
        self.run_command(f"nxc ldap {target_str} {creds} --active-users", f"{base_log}_active_users.txt", dry_run)
        self.run_command(f"nxc ldap {target_str} {creds} --admin-count", f"{base_log}_admincount.txt", dry_run)
        self.run_command(f"nxc ldap {target_str} {creds} --dc-list", f"{base_log}_dclist.txt", dry_run)
        self.run_command(f"nxc ldap {target_str} {creds} --get-sid", f"{base_log}_getsid.txt", dry_run)
        self.run_command(f"nxc ldap {target_str} {creds} --find-delegation", f"{base_log}_finddelegation.txt", dry_run)
        self.run_command(f"nxc ldap {target_str} {creds} --trusted-for-delegation", f"{base_log}_trustedfordelegation.txt", dry_run)
        self.run_command(f"nxc ldap {target_str} {creds} --password-not-required", f"{base_log}_passwordnotrequired.txt", dry_run)
        self.run_command(f"nxc ldap {target_str} {creds} --pso", f"{base_log}_pso.txt", dry_run)

        # Kerberos attacks (hash output files)
        self.run_command(f"nxc ldap {target_str} {creds} --kerberoasting {base_log}_kerberoast.txt", f"{base_log}_kerberoasting_log.txt", dry_run)
        self.run_command(f"nxc ldap {target_str} {creds} --asreproast {base_log}_asreproast.txt", f"{base_log}_asreproast_log.txt", dry_run)

        # ---- 3. Authenticated modules ----
        for module in LDAP_AUTH_MODULES:
            if self.opsec_safe and module in OPSEC_UNSAFE_MODULES:
                print(f"[opsec_safe] Skipping noisy module: {module}")
                continue
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

        # MSSQL extra enumeration
        if protocol == 'mssql':
            modules = [
                "enum_logins",
                "enum_links",
                "mssql_cbt",
                "mssql_priv",
                "mssql_dumper",
            ]
            for module in modules:
                self.run_command(f"nxc mssql {target_str} {creds} -M {module}", f"{base_log}_{module}.txt", dry_run)

        # WinRM extra enumeration
        if protocol == 'winrm':
            self.run_command(f"nxc winrm {target_str} {creds} --wmi-query 'SELECT * FROM Win32_ComputerSystem'", f"{base_log}_compsys.txt", dry_run)

        print(f"NetExec {protocol} phase complete.")
