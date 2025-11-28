import argparse
import sys
import os
import json
from scanner_modules.analyzer import ModuleAnalyzer
from scanner_modules.config_manager import ConfigManager
from scanner_modules.discovery import DiscoveryManager
from scanner_modules.runner import ScanRunner
from scanner_modules.html_generator import HtmlGenerator
from scanner_modules.nmap_scanner import NmapRunner
from scanner_modules.nxc_scanner import NxcRunner

def validate_config(config):
    tcp_ports = set(config.get('tcp_ports', []))
    udp_ports = set(config.get('udp_ports', []))
    all_ports = tcp_ports.union(udp_ports)
    
    missing_ports = []
    
    # Check MSF modules
    if 'modules' in config:
        for port_str in config['modules']:
            port = int(port_str)
            if port not in all_ports:
                missing_ports.append(f"Port {port} (used in 'modules') is not in 'tcp_ports' or 'udp_ports'")

    # Check Nmap modules
    if 'modules_nmap' in config:
        for port_str in config['modules_nmap']:
            port = int(port_str)
            if port not in all_ports:
                missing_ports.append(f"Port {port} (used in 'modules_nmap') is not in 'tcp_ports' or 'udp_ports'")
    
    if missing_ports:
        print("\n" + "="*50)
        print("CONFIGURATION ERROR")
        print("="*50)
        for msg in missing_ports:
            print(f"- {msg}")
        print("="*50 + "\n")
        print("Please update 'tcp_ports' or 'udp_ports' in config.json to include these ports.")
        print("Or remove the unused modules configuration.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Analyze Command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze MSF modules')
    analyze_parser.add_argument('--msf-path', default='msfconsole', help='Path to msfconsole directory')
    analyze_parser.add_argument('--output', help='Output file (default: modules.json for json, modules.html for html)')
    analyze_parser.add_argument('--format', choices=['json', 'html'], default='json', help='Output format')
    analyze_parser.add_argument('--full', action='store_true', help='Include all modules (disable filtering)')

    # Init Command
    init_parser = subparsers.add_parser('init', help='Initialize scan configuration')
    init_parser.add_argument('--firm', required=True, help='Firm name')
    init_parser.add_argument('--subnet', required=True, help='Target subnet (CIDR)')
    init_parser.add_argument('--type', default='tcp,udp', help='Scan type (tcp, udp, tcp,udp)')
    init_parser.add_argument('--engine', default='msfconsole,nmap', help='Scan engine (msfconsole, nmap, or both)')
    init_parser.add_argument('--modules-db', default='modules.json', help='Path to modules database')
    init_parser.add_argument('--output', default='config.json', help='Output configuration file')

    # Discovery Command
    disc_parser = subparsers.add_parser('discovery', help='Run nmap discovery')
    disc_parser.add_argument('--config', default='config.json', help='Configuration file')
    disc_parser.add_argument('--output-base', default='nmap_scan', help='Base name for nmap output')
    disc_parser.add_argument('--dry-run', action='store_true', help='Print command without running')

    # Report Command
    report_parser = subparsers.add_parser('report', help='Generate report')
    report_parser.add_argument('--output', default='scan_report.html', help='Report file')
    report_parser.add_argument('--firm', help='Specific firm to report on')
    report_parser.add_argument('--all', action='store_true', help='Generate reports for all firms')
    report_parser.add_argument('--config', default='config.json', help='Configuration file')

    # Serve Command
    serve_parser = subparsers.add_parser('serve', help='Serve HTML report and API')
    serve_parser.add_argument('--port', type=int, default=8001, help='Port to serve on')
    serve_parser.add_argument('--config', default='config.json', help='Config file')
    serve_parser.add_argument('--html', default='modules.html', help='HTML report file')

    # Generate Config Command
    gen_config_parser = subparsers.add_parser('generateconfig', help='Generate default configuration from existing config')
    gen_config_parser.add_argument('--input', default='config.json', help='Input configuration file')
    gen_config_parser.add_argument('--output', default='default.conf', help='Output configuration file')

    # Scan Command
    scan_parser = subparsers.add_parser('scan', help='Run scans (MSF and/or Nmap NSE)')
    scan_parser.add_argument('--config', default='config.json', help='Configuration file')
    scan_parser.add_argument('--inventory', default='inventory.json', help='Inventory file')
    scan_parser.add_argument('--checkpoint', default='checkpoint.json', help='Checkpoint file')
    scan_parser.add_argument('--timeout', type=int, default=600, help='Timeout per module in seconds')
    scan_parser.add_argument('--dry-run', action='store_true', help='Print command without running')
    scan_parser.add_argument('--force', action='store_true', help='Force run even if already completed')

    args = parser.parse_args()

    if args.command == 'analyze':
        # Resolve absolute path if needed, but user provided relative path in prompt
        msf_path = os.path.abspath(args.msf_path)
        if not os.path.exists(msf_path):
            print(f"Error: Path {msf_path} does not exist.")
            sys.exit(1)
            
        analyzer = ModuleAnalyzer(msf_path)
        modules = analyzer.analyze(args.full)
        
        # Always save to modules.json for ConfigManager to use
        # But only if we are not about to overwrite it with HTML
        if args.format == 'html' and args.output == 'modules.json':
             print("Warning: You requested HTML output to modules.json. This will corrupt the module database.")
             print("Saving database to modules.json.bak instead.")
             analyzer.save_to_file('modules.json.bak')
        else:
             analyzer.save_to_file('modules.json')

        output_file = args.output
        if output_file is None:
            if args.format == 'json':
                output_file = 'modules.json'
            else:
                output_file = 'modules.html'

        if args.format == 'json':
            if output_file != 'modules.json':
                analyzer.save_to_file(output_file)
        elif args.format == 'html':
            html_gen = HtmlGenerator(msf_path) # HtmlGenerator needs msf_path for template loading
            html_gen.generate(modules, output_file)

    elif args.command == 'init':
        manager = ConfigManager(args.modules_db)
        manager.init_config(args.firm, args.subnet, args.type, args.output, args.engine)

    elif args.command == 'discovery':
        # Load config for validation
        with open(args.config, 'r') as f:
            config = json.load(f)
        validate_config(config)

        manager = DiscoveryManager(args.config)
        manager.run_discovery(args.output_base, args.dry_run)

    elif args.command == 'generateconfig':
        if not os.path.exists(args.input):
            print(f"Error: Input file {args.input} not found.")
            sys.exit(1)

        with open(args.input, 'r') as f:
            config = json.load(f)

        # Remove instance-specific fields
        if 'firm_name' in config:
            del config['firm_name']
        if 'subnet' in config:
            del config['subnet']
        if 'exclude_ips' in config:
            del config['exclude_ips']
        if 'scan_type' in config:
            del config['scan_type']

        with open(args.output, 'w') as f:
            json.dump(config, f, indent=4)
        
        print(f"Created {args.output} from {args.input}")

    elif args.command == 'scan':
        # Load config to check scan_engine
        with open(args.config, 'r') as f:
            config = json.load(f)
        
        # Validate config
        validate_config(config)
        
        engines = config.get('scan_engine', 'msfconsole,nmap').split(',')
        engines = [e.strip() for e in engines]
        
        if 'msfconsole' in engines or 'msf' in engines:
            print("Starting MSF Scan Engine...")
            runner = ScanRunner(args.config, args.inventory, args.checkpoint)
            runner.run_scan(args.dry_run, args.timeout)
        
        if 'nmap' in engines:
            print("Starting Nmap NSE Scan Engine...")
            nmap_runner = NmapRunner(args.config, args.inventory, args.checkpoint)
            nmap_runner.run_scan(args.dry_run, args.force)

        if 'nxc' in engines or 'netexec' in engines:
            print("Starting NetExec (nxc) Scan Engine...")
            nxc_runner = NxcRunner(args.config, args.inventory, args.checkpoint)
            nxc_runner.run_scan(args.dry_run, args.force)



    elif args.command == 'report':
        from scanner_modules.reporter import HTMLReporter
        
        # Load config to get base output dir
        with open(args.config, 'r') as f:
            config = json.load(f)
        base_output_dir = config.get('output_dir', 'scans')
        
        if args.all:
            if not os.path.exists(base_output_dir):
                print(f"Error: Output directory {base_output_dir} not found.")
                sys.exit(1)
                
            firms = [d for d in os.listdir(base_output_dir) if os.path.isdir(os.path.join(base_output_dir, d))]
            if not firms:
                print(f"No firm directories found in {base_output_dir}.")
                sys.exit(1)
                
            for firm in firms:
                firm_dir = os.path.join(base_output_dir, firm)
                output_file = f"scan_report_{firm}.html"
                print(f"Generating report for firm: {firm}...")
                reporter = HTMLReporter(output_dir=firm_dir)
                reporter.generate_report(output_file)
                
        elif args.firm:
            firm_dir = os.path.join(base_output_dir, args.firm)
            if not os.path.exists(firm_dir):
                print(f"Error: Directory for firm {args.firm} not found at {firm_dir}")
                sys.exit(1)
                
            output_file = args.output if args.output != 'scan_report.html' else f"scan_report_{args.firm}.html"
            print(f"Generating report for firm: {args.firm}...")
            reporter = HTMLReporter(output_dir=firm_dir)
            reporter.generate_report(output_file)
            
        else:
            # Default behavior: Generate reports for ALL firms found in scans directory
            if not os.path.exists(base_output_dir):
                print(f"Error: Output directory {base_output_dir} not found.")
                sys.exit(1)
                
            firms = [d for d in os.listdir(base_output_dir) if os.path.isdir(os.path.join(base_output_dir, d))]
            if not firms:
                print(f"No firm directories found in {base_output_dir}.")
                sys.exit(1)
                
            print(f"No firm specified. Generating reports for all {len(firms)} firms found in {base_output_dir}...")
            
            for firm in firms:
                firm_dir = os.path.join(base_output_dir, firm)
                output_file = f"scan_report_{firm}.html"
                print(f"Generating report for firm: {firm}...")
                reporter = HTMLReporter(output_dir=firm_dir)
                reporter.generate_report(output_file)

    elif args.command == 'serve':
        server = ConfigServer(args.port, args.config, args.html)
        server.run()

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
