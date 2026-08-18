import os
import re
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import textwrap
from .runner import fix_permissions

class HTMLReporter:
    def __init__(self, output_dir='scans'):
        self.output_dir = output_dir
        self.data = {
            'scan_info': {
                'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'total_hosts': 0,
                'total_vulns': 0,
                'total_ports': 0
            },
            'hosts': {},  # IP -> {hostname, os, ports: [], findings: []}
            'vulns': [],  # List of {title, severity, description, hosts: []}
            'ports': {}   # Port -> {protocol, hosts: []}
        }
        
        self.SEVERITY_MAP = {
            'Critical': [
                # Nmap
                'ms-sql-empty-password', 'rdp-vuln-ms12-020', 'smb-vuln-cve-2017-7494', 
                'smb-vuln-cve2009-3103', 'smb-vuln-ms06-025', 'smb-vuln-ms07-029', 
                'smb-vuln-ms08-067', 'smb-vuln-ms10-054', 'smb-vuln-ms10-061', 
                'smb-vuln-ms17-010', 'smb-vuln-regsvc-dos', 'smb-double-pulsar-backdoor',
                'smb-vuln-webexec', 'smb-vuln-conficker',
                'mysql-vuln-cve2012-2122', 'supermicro-ipmi-conf',
                # MSF
                'auxiliary/scanner/mssql/mssql_login',
                'auxiliary/scanner/ftp/ftp_login',
                'auxiliary/scanner/ssh/juniper_backdoor',
                'auxiliary/scanner/ssh/libssh_auth_bypass',
                'auxiliary/scanner/ssh/fortinet_backdoor',
                'auxiliary/scanner/smb/smb_ms17_010',
                'auxiliary/scanner/rdp/cve_2019_0708_bluekeep',
                'auxiliary/scanner/rdp/ms12_020_check',
                'auxiliary/scanner/vnc/vnc_none_auth',
                'auxiliary/scanner/misc/dahua_dvr_auth_bypass',
                'auxiliary/scanner/mongodb/cve_2025_14847_mongobleed',
                # NetExec
                'smb/printnightmare',
                'smb/zerologon',
                'smb/badsuccessor',
                'smb/resetnightmare',
                'smb/dc_zerologon',
                'smb/dc_badsuccessor',
                'smb/dc_resetnightmare'
            ],
            'High': [
                # Nmap
                'smtp-vuln-cve2010-4344', 'smtp-vuln-cve2011-1720', 'smtp-vuln-cve2011-1764',
                'ftp-proftpd-backdoor', 'ftp-vsftpd-backdoor', 'ftp-vuln-cve2010-4221',
                'smb-enum-shares', 'smb-ls', 'realvnc-auth-bypass',
                'http-vuln-cve2010-2861', 'http-vuln-cve2017-1001000',
                'http-coldfusion-subzero', 'http-litespeed-sourcecode-download',
                'http-frontpage-login', 'http-awstatstotals-exec',
                'http-barracuda-dir-traversal', 'http-axis2-dir-traversal',
                'http-dlink-backdoor', 'http-huawei-hg5xx-vuln',
                'http-vuln-cve2013-7091', 'http-vuln-cve2015-1427',
                'http-vuln-cve2015-1635', 'http-vuln-cve2017-5638',
                'http-vuln-cve2017-5689', 'http-vuln-cve2017-8917',
                'http-vuln-cve2014-2129', 'http-vuln-wnr1000-creds',
                'http-vuln-misfortune-cookie', 'netbus-auth-bypass',
                'rsa-vuln-roca', 'samba-vuln-cve-2012-1182',
                # MSF
                'auxiliary/scanner/ftp/colorado_ftp_traversal',
                'auxiliary/gather/crushftp_fileread_cve_2024_4040',
                'auxiliary/gather/crushftp_authbypass_cve_2025_2825',
                'auxiliary/scanner/http/springcloud_traversal',
                'auxiliary/scanner/http/apache_nifi_login',
                'auxiliary/scanner/http/jupyter_login',
                'auxiliary/gather/splunk_raw_server_info',
                'auxiliary/gather/java_rmi_registry',
                'auxiliary/scanner/misc/java_jmx_server',
                'auxiliary/scanner/misc/java_rmi_server',
                'auxiliary/scanner/telnet/telnet_login',
                'auxiliary/scanner/telnet/telnet_encrypt_overflow',
                'auxiliary/scanner/smtp/smtp_relay',
                'auxiliary/admin/kerberos/ms14_068_kerberos_checksum',
                'auxiliary/scanner/afp/afp_login',
                'auxiliary/scanner/ipmi/ipmi_dumphashes',
                'auxiliary/admin/vnc/realvnc_41_bypass',
                'auxiliary/scanner/vnc/vnc_login',
                'auxiliary/scanner/vnc/ard_root_pw',
                'auxiliary/gather/adobe_coldfusion_fileread_cve_2023_26360',
                'auxiliary/gather/elasticsearch_enum',
                # NetExec
                'smb/remove-mic',
                'smb/empty_users',
                'smb/guest_users',
                'smb/user_users',
                'smb/null_users',
                'auxiliary/scanner/msmq/cve_2023_21554_queuejumper',
                'ldap/kerberoasting',
                'ldap/asreproast',
                'smb/ms17-010',
                'smb/nopac',
                'smb/gpp_autologin',
                'smb/gpp_password',
                'smb/gpp_privileges',
                'smb/dc_nopac',
                'smb/dc_gpp_autologin',
                'smb/dc_gpp_password',
                'smb/dc_gpp_privileges'
            ],
            'Medium': [
                # Nmap
                'sshv1', 'afp-path-vuln', 'http-git', 'http-iis-short-name-brute',
                'http-iis-webdav-vuln', 'http-shellshock', 'http-avaya-ipoffice-users',
                'http-dlink-backdoor', 'http-vmware-path-vuln', 'tls-ticketbleed',
                'ssl-heartbleed', 'rmi-vuln-classloader', 'ftp-anon', 'snmp-brute',
                'ipmi-cipher-zero', 'ssl-ccs-injection', 'ssl-poodle',
                'ssl-known-key', 'smb2-vuln-uptime', 'http-config-backup',
                'http-backup-finder', 'http-cors', 'nfs-showmount', 'nfs-ls',
                'mongodb-databases', 'redis-info', 'http-enum',
                # MSF
                'auxiliary/admin/http/webnms_cred_disclosure',
                'auxiliary/scanner/ftp/anonymous',
                'auxiliary/scanner/ftp/ftp_anonymous',
                'auxiliary/scanner/ssh/ssh_enum_git_keys',
                'auxiliary/scanner/snmp/snmp_login',
                'auxiliary/gather/windows_deployment_services_shares',
                'auxiliary/gather/asterisk_creds',
                'auxiliary/voip/asterisk_login',
                'auxiliary/scanner/nfs/nfsmount',
                'auxiliary/scanner/redis/redis_login',
                # NetExec
                'smb/guest_shares',
                'smb/user_shares',
                'smb/null_shares',
                'smb/smbghost',
                'smb/spooler',
                'smb/webdav',
                'smb/enum_av',
                'smb/enum_cve',
                'smb/coerce_plus',
                'ldap/adcs',
                'ldap/laps',
                'ldap/maq',
                'ldap/pre2k',
                'ldap/user-desc',
                'ldap/get-desc-users',
                'smb/ntlmv1'
            ],
            'Low': [
                # Nmap
                'http-default-accounts', 'http-slowloris-check', 'http-aspnet-debug',
                'smb-enum-domains', 'smb-enum-groups', 'ftp-syst', 'dns-recursion',
                'http-methods', 'http-headers', 'http-title', 'http-cakephp-version',
                'http-devframework', 'mongodb-info', 'snmp-info', 'mysql-info',
                'ms-sql-info', 'ms-sql-ntlm-info',
                # MSF
                'auxiliary/scanner/portmap/portmap_amp',
                'auxiliary/scanner/dcerpc/management',
                'auxiliary/scanner/dcerpc/hidden',
                'auxiliary/scanner/dcerpc/tcp_dcerpc_auditor',
                'auxiliary/scanner/dcerpc/endpoint_mapper',
                'auxiliary/scanner/memcached/memcached_amp',
                'auxiliary/scanner/chargen/chargen_probe',
                'auxiliary/scanner/dns/dns_amp',
                'auxiliary/scanner/gopher/gopher_gophermap',
                'auxiliary/scanner/oracle/tnspoison_checker',
                'auxiliary/scanner/mysql/mysql_version',
                'auxiliary/scanner/scada/modbusdetect',
                'auxiliary/scanner/ntp/ntp_readvar',
                'auxiliary/scanner/rsync/modules_list',
                'auxiliary/scanner/winrm/winrm_auth_methods'
            ],
            'Info': [
                'auxiliary/scanner/netbios/nbname',
                'auxiliary/scanner/ipmi/ipmi_version',
                'auxiliary/scanner/smtp/smtp_version',
                'auxiliary/scanner/telnet/telnet_version',
                'auxiliary/scanner/misc/sunrpc_portmapper',
                'auxiliary/scanner/smb/smb_version',
                'auxiliary/scanner/ftp/ftp_version',
                'vnc-info', 'redis-info', 'memcached-info',
                'ssh-auth-methods', 'ssh-hostkey', 'ssh2-enum-algos',
                'rdp-enum-encryption', 'rdp-ntlm-info', 'smb-os-discovery',
                'smb-security-mode', 'smb2-security-mode', 'ipmi-version',
                'snmp-sysdescr', 'snmp-interfaces', 'ftp-syst', 'telnet-encryption',
                'rtsp-methods', 'sip-methods', 'mqtt-subscribe', 'iscsi-info',
                'rpcinfo', 'msrpc-enum', 'nfs-statfs', 'rsync-list-modules',
                'upnp-info', 'dns-nsid', 'smtp-commands', 'pop3-capabilities',
                'imap-capabilities', 'ssl-enum-ciphers', 'ssl-cert-intaddr',
                'http-chrono', 'bjnp-info', 'modbus-discover'
            ]
        }

    def _get_severity(self, module_name, output=''):
        # Check explicit mappings
        for severity, modules in self.SEVERITY_MAP.items():
            if module_name in modules:
                return severity
            # Check if module_name (with underscores) matches a mapped item (with slashes)
            # This handles MSF modules where filename has underscores but map has slashes
            for m in modules:
                if m.replace('/', '_') == module_name:
                    return severity
        
        # Special case for vnc-info
        if module_name == 'vnc-info':
            out_lower = output.lower()
            if 'none (1)' in out_lower or 'authentication: none' in out_lower or 'does not require authentication' in out_lower:
                return 'Critical'
            return 'Info'

        # Default heuristics if not explicitly mapped
        if 'vuln' in module_name or 'cve' in module_name:
            return 'High'
            
        return None

    def parse_nmap_xml(self, xml_file):
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue
                
                addr_elem = host.find('address[@addrtype="ipv4"]')
                if addr_elem is None:
                    continue
                ip = addr_elem.get('addr')
                
                if ip not in self.data['hosts']:
                    self.data['hosts'][ip] = {
                        'hostname': '',
                        'os': 'Unknown',
                        'ports': [],
                        'findings': []
                    }
                    self.data['scan_info']['total_hosts'] += 1

                # Hostnames
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    for hn in hostnames.findall('hostname'):
                        name = hn.get('name')
                        if name:
                            self.data['hosts'][ip]['hostname'] = name
                            break
                
                # Ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        state = port.find('state')
                        service = port.find('service')
                        
                        if state is not None and state.get('state') == 'open':
                            service_name = service.get('name') if service is not None else 'unknown'
                            port_str = f"{port_id}/{protocol}"
                            
                            # Check if port already exists for this host
                            existing_port = False
                            for p in self.data['hosts'][ip]['ports']:
                                if p['id'] == port_id and p['protocol'] == protocol:
                                    existing_port = True
                                    # Update service if it was unknown and now we have a name?
                                    if p['service'] == 'unknown' and service_name != 'unknown':
                                        p['service'] = service_name
                                    break
                            
                            if not existing_port:
                                self.data['hosts'][ip]['ports'].append({
                                    'id': port_id,
                                    'protocol': protocol,
                                    'service': service_name
                                })
                            
                            if port_str not in self.data['ports']:
                                self.data['ports'][port_str] = {'protocol': protocol, 'hosts': []}
                                self.data['scan_info']['total_ports'] += 1
                            
                            if ip not in self.data['ports'][port_str]['hosts']:
                                self.data['ports'][port_str]['hosts'].append(ip)

                            # NSE Scripts
                            for script in port.findall('script'):
                                script_id = script.get('id')
                                raw_output = script.get('output', '')
                                script_output = textwrap.dedent(raw_output.expandtabs()).strip()
                                
                                # Filter out script execution errors
                                if script_output and "ERROR: Script execution failed" in script_output:
                                    continue

                                # Filter out explicit "NOT VULNERABLE" results
                                if "NOT VULNERABLE" in script_output:
                                    continue

                                # Filter out http-default-accounts with no valid credentials
                                if script_id == 'http-default-accounts' and '(no valid default credentials found)' in script_output:
                                    continue

                                # Filter out http-iis-webdav-vuln if WebDAV is disabled
                                if script_id == 'http-iis-webdav-vuln' and 'WebDAV is DISABLED' in script_output:
                                    continue

                                # Filter out smtp-open-relay if not an open relay
                                if script_id == 'smtp-open-relay' and "Server isn't an open relay" in script_output:
                                    continue

                                # Filter out http-php-version if unknown hash
                                if script_id == 'http-php-version' and 'unknown hash' in script_output.lower():
                                    continue

                                # Filter out ftp-anon if login failed or requires password
                                if script_id == 'ftp-anon':
                                    lower_output = script_output.lower()
                                    if 'failed' in lower_output or 'password' in lower_output:
                                        continue

                                # Filter out ms-sql-empty-password if password is not blank
                                if script_id == 'ms-sql-empty-password' and 'password is not blank' in script_output:
                                    continue

                                # Filter out ms-sql-dump-hashes if no login credentials or error
                                if script_id == 'ms-sql-dump-hashes' and ('ERROR' in script_output or 'No login' in script_output):
                                    continue
                                
                                severity = self._get_severity(script_id, script_output)
                                if severity is None:
                                    severity = 'Info'
                                
                                finding = {
                                    'source': 'Nmap NSE',
                                    'module': script_id,
                                    'severity': severity,
                                    'description': script_output,
                                    'description': script_output,
                                    'port': port_str
                                }
                                self._add_finding(ip, finding)

        except Exception as e:
            print(f"Error parsing Nmap XML {xml_file}: {e}")

    def parse_msf_output(self, txt_file):
        try:
            filename = os.path.basename(txt_file)
            # Try to extract info from filename: msf_results_<port>_<module>.txt
            parts = filename.replace('msf_results_', '').replace('.txt', '').split('_', 1)
            port = parts[0] if len(parts) > 0 else 'unknown'
            module = parts[1] if len(parts) > 1 else 'unknown'
            
            with open(txt_file, 'r', errors='ignore') as f:
                content = f.read()
                
            full_output = textwrap.dedent(content.expandtabs()).strip() # Added dedent and strip
            
            lines = full_output.splitlines() # Use full_output here
            current_host = None
            
            # Regex to find IPs in the output
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            
            # Simple heuristic: associate findings with the last seen IP, or if none, "Unknown"
            # Many MSF modules print the RHOST.
            
            for line in lines:
                # Check for IP
                ip_match = ip_pattern.search(line)
                if ip_match:
                    current_host = ip_match.group(0)
                    if current_host not in self.data['hosts']:
                         # We might discover hosts only via MSF if Nmap didn't run or failed
                         self.data['hosts'][current_host] = {
                            'hostname': '',
                            'os': 'Unknown',
                            'ports': [],
                            'findings': []
                        }
                         self.data['scan_info']['total_hosts'] += 1

                if '[+]' in line:
                    # Determine severity
                    # First check if module is in our map
                    severity = self._get_severity(module, line)
                    
                    # If it returned None (not mapped), let's refine based on MSF status
                    if severity is None:
                        if '[+]' in line:
                            severity = 'High' # Default to High for positive findings if not mapped
                        elif '[-]' in line:
                            severity = 'Low'
                        else:
                            severity = 'Info'
                    
                    # If user wants ALL results, we include them.
                    
                    finding = {
                        'source': 'Metasploit',
                        'module': module,
                        'severity': severity,
                        'description': line.strip(),
                        'port': port
                    }
                    
                    target_host = current_host if current_host else 'Unknown Host'
                    if target_host not in self.data['hosts']:
                         self.data['hosts'][target_host] = {
                            'hostname': '',
                            'os': 'Unknown',
                            'ports': [],
                            'findings': []
                        }
                    
                    self._add_finding(target_host, finding)

        except Exception as e:
            print(f"Error parsing MSF output {txt_file}: {e}")

    def parse_nxc_output(self, txt_file):
        try:
            filename = os.path.basename(txt_file)
            # Filename format: nxc_<protocol>_<module>.txt
            parts = filename.replace('nxc_', '', 1).replace('.txt', '').split('_', 1)
            protocol = parts[0]
            rest = parts[1] if len(parts) > 1 else 'general'
            # DC-specific logs (nxc_smb_dc_zerologon.txt) -> protocol=smb, module=dc_zerologon
            if protocol == 'smb' and rest.startswith('dc_'):
                module = rest
            else:
                module = rest
            
            with open(txt_file, 'r', errors='ignore') as f:
                content = f.read()
                
            full_output = textwrap.dedent(content.expandtabs()).strip()
            lines = full_output.splitlines()
            
            if not lines:
                return

            # 1. Extract command info from first line
            command_line = lines[0]
            lines = lines[1:]

            # Extract username from command line if present (-u username)
            target_username = None
            u_match = re.search(r'\s-u\s+([^\s]+)', command_line)
            if u_match:
                target_username = u_match.group(1)

            # Regex to find IPs in the output
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            
            # Group lines by Host
            host_lines = {} # IP -> [lines]

            for line in lines:
                # Skip empty lines
                if not line.strip():
                    continue

                # 2. Filter informational lines
                # "if protocol ... and smb.py ... and [*] ... skip"
                if protocol.lower() in line.lower() and '.py' in line and '[*]' in line:
                    continue

                # 3. Filter failed attempts and errors
                if '[-]' in line or 'ERROR' in line:
                    continue

                # 4. Filter specific SMB success with provided username or null user
                # "if protocol smb ... and smb.py ... and [+] ... and (\username: or \:) ... skip"
                if protocol.lower() == 'smb' and '.py' in line and '[+]' in line:
                    # Check for \username: pattern
                    if target_username and f"\\{target_username}:" in line:
                        continue
                    # Check for null user pattern (\:)
                    if "\\:" in line:
                        continue

                # 5. Filter other noise
                if 'Found NOTHING!' in line or '-Username-' in line or 'Starting' in line:
                    continue

                # 6. Filter Share Enumeration Noise
                # Header: Share Permissions Remark
                if 'Share' in line and 'Permissions' in line and 'Remark' in line:
                    continue
                # Separator: -----------
                if '-----------' in line:
                    continue
                # Default Shares: print$, IPC$, lp1-4
                # Check if any of these strings are in the line
                ignored_shares = ['print$', 'IPC$', 'lp1', 'lp2', 'lp3', 'lp4']
                if any(share in line for share in ignored_shares):
                    continue

                # Extract IP
                ip_match = ip_pattern.search(line)
                current_host = ip_match.group(0) if ip_match else 'Unknown Host'
                
                if current_host not in host_lines:
                    host_lines[current_host] = []
                
                host_lines[current_host].append(line)

            # 3. Create findings (Grouped)
            for host, h_lines in host_lines.items():
                if not h_lines:
                    continue
                
                # Join lines
                description = '\n'.join(h_lines)
                
                # Determine severity
                # DC-specific names keep 'smb/dc_' prefix so severity map matches
                severity = self._get_severity(f"{protocol}/{module}", description)
                if severity is None:
                    severity = 'Info'
                
                # Register Host if new
                if host != 'Unknown Host' and host not in self.data['hosts']:
                     self.data['hosts'][host] = {
                        'hostname': '',
                        'os': 'Unknown',
                        'ports': [],
                        'findings': []
                    }
                     self.data['scan_info']['total_hosts'] += 1

                finding = {
                    'source': 'NetExec',
                    'module': f"{protocol}/{module}",
                    'severity': severity,
                    'description': description,
                    'port': protocol 
                }
                
                # Map protocol to port
                proto_port_map = {
                    'smb': '445/tcp', 'ldap': '389/tcp', 'winrm': '5985/tcp', 'mssql': '1433/tcp',
                    'ssh': '22/tcp', 'ftp': '21/tcp', 'rdp': '3389/tcp', 'nfs': '111/tcp', 'wmi': '135/tcp'
                }
                if protocol in proto_port_map:
                    finding['port'] = proto_port_map[protocol]
                
                target_host = host if host != 'Unknown Host' else 'Unknown Host'
                
                # Only add if host is valid
                if target_host in self.data['hosts']:
                    self._add_finding(target_host, finding)
                    
                    # Ensure port is registered
                    if finding.get('port'):
                        port_str = finding['port']
                        if port_str not in self.data['ports']:
                            # Guess protocol from port string
                            proto = 'tcp'
                            if '/' in port_str:
                                proto = port_str.split('/')[1]
                            self.data['ports'][port_str] = {'protocol': proto, 'hosts': []}
                            self.data['scan_info']['total_ports'] += 1
                        
                        # Add host to port if not present
                        if target_host not in self.data['ports'][port_str]['hosts']:
                            self.data['ports'][port_str]['hosts'].append(target_host)



        except Exception as e:
            print(f"Error parsing NetExec output {txt_file}: {e}")

    def _add_finding(self, host_ip, finding):
        if host_ip not in self.data['hosts']:
            return

        existing_findings = self.data['hosts'][host_ip]['findings']
        for f in existing_findings:
            # Check if module and port match
            if f['module'] == finding['module'] and f['port'] == finding['port']:
                # Aggregate description if not already present
                if finding['description'] not in f['description']:
                    f['description'] += "\n" + finding['description']
                
                # Update severity if new finding is more severe
                severity_rank = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
                current_rank = severity_rank.get(f['severity'], 5)
                new_rank = severity_rank.get(finding['severity'], 5)
                
                if new_rank < current_rank:
                    f['severity'] = finding['severity']
                
                # Still add to global findings to ensure we track it there too
                self._add_global_finding(finding, host_ip)
                return

        # If no match found, add as new
        self.data['hosts'][host_ip]['findings'].append(finding)
        self._add_global_finding(finding, host_ip)

    def _add_global_finding(self, finding, host):
        # Construct host string with port if available
        host_str = host
        if finding.get('port') and finding['port'] != 'unknown':
             host_str = f"{host} - {finding['port']}"

        # 1. Find or create the vulnerability group by title
        group = None
        for g in self.data['vulns']:
            if g['title'] == finding['module']:
                group = g
                break
        
        if not group:
            group = {
                'title': finding['module'],
                'severity': finding['severity'],
                'findings': []
            }
            self.data['vulns'].append(group)
            # Count unique vulnerability titles? Or total findings?
            # User probably wants total unique vulnerabilities (groups)
            # But previously we counted total findings. Let's stick to total findings for the stats?
            # Actually, "Vulns" stat usually means unique vulnerability types found.
            # But let's keep it simple. If we group, maybe we should count groups?
            # Let's count groups for now as "Vulns".
            # Wait, if I add a new group, I increment.
            if finding['severity'] in ['High', 'Critical']:
                 self.data['scan_info']['total_vulns'] += 1

        # 2. Update group severity if this finding is more severe
        severity_rank = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        current_rank = severity_rank.get(group['severity'], 5)
        new_rank = severity_rank.get(finding['severity'], 5)
        
        if new_rank < current_rank:
            group['severity'] = finding['severity']

        # 3. Add the specific finding description to the group
        desc_entry = None
        for d in group['findings']:
            if d['description'] == finding['description']:
                desc_entry = d
                break
        
        if not desc_entry:
            desc_entry = {
                'description': finding['description'],
                'hosts': []
            }
            group['findings'].append(desc_entry)
            
        if host_str not in desc_entry['hosts']:
            desc_entry['hosts'].append(host_str)

    def generate_report(self, output_file='scan_report.html'):
        # 1. Parse all files in output_dir
        if not os.path.exists(self.output_dir):
            print(f"Output directory {self.output_dir} not found.")
            return

        for filename in os.listdir(self.output_dir):
            filepath = os.path.join(self.output_dir, filename)
            if filename.endswith('.xml'):
                self.parse_nmap_xml(filepath)
            elif filename.startswith('msf_results_') and filename.endswith('.txt'):
                self.parse_msf_output(filepath)
            elif filename.startswith('nxc_') and filename.endswith('.txt'):
                self.parse_nxc_output(filepath)

        # 1.5 Sort findings by severity
        severity_rank = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        
        # Sort host findings
        for ip in self.data['hosts']:
            self.data['hosts'][ip]['findings'].sort(key=lambda x: severity_rank.get(x['severity'], 5))
            
        # Sort global vulns
        self.data['vulns'].sort(key=lambda x: severity_rank.get(x['severity'], 5))

        # 1.6 Aggregate findings per port
        # Initialize findings list and counts for each port
        for port in self.data['ports']:
            self.data['ports'][port]['findings'] = []
            self.data['ports'][port]['severity_counts'] = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}

        # Iterate through all hosts and their findings
        for ip, host_data in self.data['hosts'].items():
            for finding in host_data['findings']:
                port_str = finding.get('port')
                if port_str and port_str in self.data['ports']:
                    # Add finding to port
                    # Avoid duplicates if multiple hosts have same finding? 
                    # Actually, for the port view, we probably want to see "Finding X on Host Y"
                    
                    # Create a display finding object
                    port_finding = finding.copy()
                    port_finding['host'] = ip
                    self.data['ports'][port_str]['findings'].append(port_finding)
                    
                    # Increment count
                    sev = finding.get('severity', 'Info')
                    if sev in self.data['ports'][port_str]['severity_counts']:
                        self.data['ports'][port_str]['severity_counts'][sev] += 1

        # Sort port findings
        for port in self.data['ports']:
             self.data['ports'][port]['findings'].sort(key=lambda x: severity_rank.get(x['severity'], 5))

        # 2. Generate HTML
        html_content = self._get_html_template()
        
        # Inject Data
        json_data = json.dumps(self.data)
        html_content = html_content.replace('/* DATA_placeholder */', f'const reportData = {json_data};')
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        fix_permissions(output_file)
        
        print(f"HTML Report generated: {output_file}")

    def _get_html_template(self):
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        :root {
            --primary: #2c3e50;
            --secondary: #34495e;
            --accent: #3498db;
            --light: #ecf0f1;
            --dark: #2c3e50;
            --danger: #e74c3c;
            --warning: #f1c40f;
            --success: #2ecc71;
            --info: #3498db;
            
            /* Severity Colors */
            --sev-critical: #8e44ad; /* Purple */
            --sev-high: #e74c3c;     /* Red */
            --sev-medium: #f1c40f;   /* Yellow */
            --sev-low: #3498db;      /* Blue */
            --sev-info: #2ecc71;     /* Green */
        }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background: #f4f7f6; color: #333; }
        header { background: var(--primary); color: white; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        h1 { margin: 0; font-size: 1.5rem; }
        .stats { display: flex; gap: 20px; font-size: 0.9rem; }
        .stat-item { background: rgba(255,255,255,0.1); padding: 5px 10px; border-radius: 4px; }
        
        .container { display: flex; height: calc(100vh - 60px); }
        .sidebar { width: 300px; background: white; border-right: 1px solid #ddd; overflow-y: auto; display: flex; flex-direction: column; }
        .sidebar-search { padding: 10px; border-bottom: 1px solid #eee; background: #f9f9f9; }
        .sidebar-search input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .main-content { flex: 1; padding: 20px; overflow-y: auto; }
        
        .tabs { display: flex; background: white; border-bottom: 1px solid #ddd; }
        .tab { padding: 15px 25px; cursor: pointer; border-bottom: 3px solid transparent; font-weight: 600; color: #777; }
        .tab.active { border-bottom-color: var(--accent); color: var(--accent); }
        .tab:hover { background: #f9f9f9; }
        
        .list-group-item { padding: 10px 15px; border-bottom: 1px solid #eee; cursor: pointer; transition: background 0.2s; display: flex; justify-content: space-between; align-items: center; }
        .list-group-item:hover, .list-group-item.active { background: var(--light); border-left: 4px solid var(--accent); }
        
        .badge { font-size: 0.8em; padding: 2px 6px; border-radius: 4px; color: white; font-weight: bold; }
        .list-group-item .badge { margin-left: 5px; }
        
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); padding: 20px; margin-bottom: 20px; }
        .card h2 { margin-top: 0; border-bottom: 1px solid #eee; padding-bottom: 10px; color: var(--primary); }
        
        .finding { border: 1px solid #eee; border-radius: 4px; margin-bottom: 10px; overflow: hidden; }
        .finding-header { padding: 10px 15px; background: #f9f9f9; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
        .finding-header:hover { background: #f0f0f0; }
        .finding-body { padding: 15px; display: none; border-top: 1px solid #eee; background: white; font-family: monospace; }
        .finding.open .finding-body { display: block; }
        
        .badge-Critical { background: var(--sev-critical); }
        .badge-High { background: var(--sev-high); }
        .badge-Medium { background: var(--sev-medium); color: #333; }
        .badge-Low { background: var(--sev-low); }
        .badge-Info { background: var(--sev-info); }
        
        .sev-counts { display: flex; gap: 5px; margin-top: 5px; font-size: 0.75em; }
        .sev-count { padding: 1px 5px; border-radius: 3px; color: white; min-width: 15px; text-align: center; }
        
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #eee; }
        th { background: #f9f9f9; font-weight: 600; }
        
        .hidden { display: none; }
    </style>
</head>
<body>

<header>
    <h1>🛡️ Vulnerability Scan Report</h1>
    <div class="stats" id="scanStats">
        <!-- Stats injected here -->
    </div>
    <label style="margin-left: 20px; display: flex; align-items: center; gap: 5px; cursor: pointer; color: white;">
        <input type="checkbox" id="collapseCheck" checked onchange="toggleAllFindings()"> Collapse All
    </label>
</header>

<div class="tabs">
    <div class="tab active" onclick="switchTab('hosts')">Hosts</div>
    <div class="tab" onclick="switchTab('vulns')">Vulnerabilities</div>
    <div class="tab" onclick="switchTab('ports')">Ports</div>
</div>

<div class="container">
    <div class="sidebar">
        <div class="sidebar-search">
            <input type="text" id="sidebarSearch" placeholder="Filter..." onkeyup="filterSidebar()">
        </div>
        <div id="sidebarList" style="flex: 1; overflow-y: auto;">
            <!-- List items injected here -->
        </div>
    </div>
    <div class="main-content" id="mainView">
        <div class="card">
            <h2>Select an item from the left to view details</h2>
            <p>Use the tabs above to switch between views.</p>
        </div>
    </div>
</div>

<script>
    /* DATA_placeholder */
    
    let currentTab = 'hosts';
    let selectedId = null;

    function init() {
        renderStats();
        switchTab('hosts');
    }

    function renderStats() {
        const stats = reportData.scan_info;
        document.getElementById('scanStats').innerHTML = `
            <div class="stat-item">Hosts: ${stats.total_hosts}</div>
            <div class="stat-item">Vulns: ${stats.total_vulns}</div>
            <div class="stat-item">Ports: ${stats.total_ports}</div>
            <div class="stat-item">Generated: ${stats.generated_at}</div>
        `;
    }

    function switchTab(tab) {
        currentTab = tab;
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelector(`.tab[onclick="switchTab('${tab}')"]`).classList.add('active');
        
        document.getElementById('sidebarSearch').value = '';
        renderSidebar();
        document.getElementById('mainView').innerHTML = '<div class="card"><h2>Select an item</h2></div>';
    }

    function filterSidebar() {
        const query = document.getElementById('sidebarSearch').value.toLowerCase();
        const items = document.querySelectorAll('.list-group-item');
        
        items.forEach(item => {
            const text = item.textContent.toLowerCase();
            if (text.includes(query)) {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
            }
        });
    }

    function renderSidebar() {
        const list = document.getElementById('sidebarList');
        list.innerHTML = '';
        
        if (currentTab === 'hosts') {
            Object.keys(reportData.hosts).forEach(ip => {
                const host = reportData.hosts[ip];
                
                // Calculate counts
                const counts = {Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0};
                host.findings.forEach(f => {
                    if (counts[f.severity] !== undefined) counts[f.severity]++;
                });

                let sevHtml = '<div class="sev-counts">';
                if (counts.Critical > 0) sevHtml += `<span class="sev-count badge-Critical">${counts.Critical}</span>`;
                if (counts.High > 0) sevHtml += `<span class="sev-count badge-High">${counts.High}</span>`;
                if (counts.Medium > 0) sevHtml += `<span class="sev-count badge-Medium">${counts.Medium}</span>`;
                if (counts.Low > 0) sevHtml += `<span class="sev-count badge-Low">${counts.Low}</span>`;
                if (counts.Info > 0) sevHtml += `<span class="sev-count badge-Info">${counts.Info}</span>`;
                sevHtml += '</div>';

                const item = document.createElement('div');
                item.className = 'list-group-item';
                item.innerHTML = `
                    <div style="width:100%">
                        <div style="display:flex; justify-content:space-between; align-items:center">
                            <div>${ip}</div>
                            <small style="color:#888">${host.hostname || ''}</small>
                        </div>
                        ${sevHtml}
                    </div>`;
                item.onclick = () => showHost(ip, item);
                list.appendChild(item);
            });
        } else if (currentTab === 'vulns') {
            reportData.vulns.forEach((vuln, idx) => {
                const item = document.createElement('div');
                item.className = 'list-group-item';
                item.innerHTML = `<div>${vuln.title}</div><span class="badge badge-${vuln.severity}">${vuln.severity}</span>`;
                item.onclick = () => showVuln(idx, item);
                list.appendChild(item);
            });
        } else if (currentTab === 'ports') {
            Object.keys(reportData.ports).sort().forEach(port => {
                const pData = reportData.ports[port];
                const item = document.createElement('div');
                item.className = 'list-group-item';
                
                // Build severity counts HTML
                let sevHtml = '<div class="sev-counts">';
                const counts = pData.severity_counts || {};
                if (counts.Critical > 0) sevHtml += `<span class="sev-count badge-Critical">${counts.Critical}</span>`;
                if (counts.High > 0) sevHtml += `<span class="sev-count badge-High">${counts.High}</span>`;
                if (counts.Medium > 0) sevHtml += `<span class="sev-count badge-Medium">${counts.Medium}</span>`;
                if (counts.Low > 0) sevHtml += `<span class="sev-count badge-Low">${counts.Low}</span>`;
                if (counts.Info > 0) sevHtml += `<span class="sev-count badge-Info">${counts.Info}</span>`;
                sevHtml += '</div>';
                
                // Wrap content to achieve: 
                // Line 1: Port (Left) ... Hosts (Right)
                // Line 2: Badges (Right)
                item.innerHTML = `
                    <div style="width: 100%;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div style="font-weight: 500;">${port}</div>
                            <small style="color: #666;">${pData.hosts.length} Hosts</small>
                        </div>
                        ${sevHtml}
                    </div>
                `;
                item.onclick = () => showPort(port, item);
                list.appendChild(item);
            });
        }
    }

    function setActiveItem(element) {
        document.querySelectorAll('.list-group-item').forEach(i => i.classList.remove('active'));
        if(element) element.classList.add('active');
    }

    function showHost(ip, element) {
        setActiveItem(element);
        const host = reportData.hosts[ip];
        const main = document.getElementById('mainView');
        
        let findingsHtml = '';
        const isCollapsed = document.getElementById('collapseCheck').checked;
        const openClass = isCollapsed ? '' : 'open';
        
        host.findings.forEach(f => {
            const portLabel = f.port ? `[${f.port}] ` : '';
            findingsHtml += `
                <div class="finding ${openClass}">
                    <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
                        <strong>${portLabel}[${f.source}] ${f.module}</strong>
                        <span class="badge badge-${f.severity}">${f.severity}</span>
                    </div>
                    <div class="finding-body"><div style="white-space: pre-wrap;">${escapeHtml(f.description)}</div></div>
                </div>
            `;
        });

        let portsHtml = '<table class="table"><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Findings</th></tr></thead><tbody>';
        host.ports.forEach(p => {
            const portStr = p.id + '/' + p.protocol;
            
            // Calculate severity counts for this port
            const counts = {Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0};
            let hasFindings = false;
            
            host.findings.forEach(f => {
                if (f.port === portStr) {
                    hasFindings = true;
                    if (counts[f.severity] !== undefined) {
                        counts[f.severity]++;
                    }
                }
            });
            
            let sevHtml = '<div class="sev-counts">';
            if (counts.Critical > 0) sevHtml += `<span class="sev-count badge-Critical">${counts.Critical}</span>`;
            if (counts.High > 0) sevHtml += `<span class="sev-count badge-High">${counts.High}</span>`;
            if (counts.Medium > 0) sevHtml += `<span class="sev-count badge-Medium">${counts.Medium}</span>`;
            if (counts.Low > 0) sevHtml += `<span class="sev-count badge-Low">${counts.Low}</span>`;
            if (counts.Info > 0) sevHtml += `<span class="sev-count badge-Info">${counts.Info}</span>`;
            sevHtml += '</div>';
            
            if (!hasFindings) sevHtml = '-';

            portsHtml += `<tr><td>${p.id}</td><td>${p.protocol}</td><td>${p.service}</td><td>${sevHtml}</td></tr>`;
        });
        portsHtml += '</tbody></table>';

        main.innerHTML = `
            <div class="card">
                <h2>${ip} ${host.hostname ? '('+host.hostname+')' : ''}</h2>
                <p><strong>OS:</strong> ${host.os}</p>
                
                <h3>Findings (${host.findings.length})</h3>
                ${findingsHtml || '<p>No findings recorded.</p>'}

                <h3>Open Ports (${host.ports.length})</h3>
                ${portsHtml}
            </div>
        `;
    }

    function showVuln(idx, element) {
        setActiveItem(element);
        const vuln = reportData.vulns[idx];
        const main = document.getElementById('mainView');
        
        const isCollapsed = document.getElementById('collapseCheck').checked;
        const openClass = isCollapsed ? '' : 'open';

        let findingsHtml = '';
        vuln.findings.forEach(f => {
            let hostsHtml = '<ul style="margin: 5px 0; padding-left: 20px;">';
            f.hosts.forEach(h => hostsHtml += `<li>${h}</li>`);
            hostsHtml += '</ul>';
            
            findingsHtml += `
                <div class="finding ${openClass}">
                    <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
                        <strong>Affected Hosts (${f.hosts.length})</strong>
                    </div>
                    <div class="finding-body">
                        <div style="margin-bottom: 15px; white-space: pre-wrap;">${escapeHtml(f.description)}</div>
                        <div style="border-top: 1px solid #eee; padding-top: 10px;">
                            <strong>Hosts:</strong>
                            ${hostsHtml}
                        </div>
                    </div>
                </div>
            `;
        });

        main.innerHTML = `
            <div class="card">
                <h2>${vuln.title} <span class="badge badge-${vuln.severity}">${vuln.severity}</span></h2>
                ${findingsHtml}
            </div>
        `;
    }

    function showPort(port, element) {
        setActiveItem(element);
        const pData = reportData.ports[port];
        const main = document.getElementById('mainView');
        
        let hostsHtml = '<ul>';
        pData.hosts.forEach(h => hostsHtml += `<li>${h}</li>`);
        hostsHtml += '</ul>';
        
        let findingsHtml = '';
        const isCollapsed = document.getElementById('collapseCheck').checked;
        const openClass = isCollapsed ? '' : 'open';

        if (pData.findings && pData.findings.length > 0) {
            pData.findings.forEach(f => {
                findingsHtml += `
                    <div class="finding ${openClass}">
                        <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
                            <strong>${f.host} - [${f.source}] ${f.module}</strong>
                            <span class="badge badge-${f.severity}">${f.severity}</span>
                        </div>
                        <div class="finding-body">${escapeHtml(f.description)}</div>
                    </div>
                `;
            });
        } else {
            findingsHtml = '<p>No findings recorded for this port.</p>';
        }

        main.innerHTML = `
            <div class="card">
                <h2>Port ${port}</h2>
                <p>Protocol: ${pData.protocol}</p>
                
                <h3>Findings (${pData.findings ? pData.findings.length : 0})</h3>
                ${findingsHtml}

                <h3>Open on Hosts (${pData.hosts.length})</h3>
                ${hostsHtml}
            </div>
        `;
    }

    function escapeHtml(text) {
        if (!text) return '';
        return text.replace(/&/g, "&amp;")
                   .replace(/</g, "&lt;")
                   .replace(/>/g, "&gt;")
                   .replace(/"/g, "&quot;")
                   .replace(/'/g, "&#039;");
    }

    function toggleAllFindings() {
        const isCollapsed = document.getElementById('collapseCheck').checked;
        document.querySelectorAll('.finding').forEach(f => {
            if (isCollapsed) {
                f.classList.remove('open');
            } else {
                f.classList.add('open');
            }
        });
    }

    init();
</script>
</body>
</html>
"""
