import http.server
import socketserver
import json
import os
import shutil

class ConfigServer:
    def __init__(self, port=8001, config_file='config.json', html_file='modules.html'):
        self.port = port
        self.config_file = config_file
        self.html_file = html_file

    def run(self):
        # We need a custom handler to serve the HTML file at root and handle API requests
        config_file_path = os.path.abspath(self.config_file)
        html_file_path = os.path.abspath(self.html_file)

        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/' or self.path == '/index.html':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    with open(html_file_path, 'rb') as f:
                        self.copyfile(f, self.wfile)
                elif self.path == '/config':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    if os.path.exists(config_file_path):
                        with open(config_file_path, 'rb') as f:
                            self.copyfile(f, self.wfile)
                    else:
                        self.wfile.write(b'{}')
                else:
                    # Serve other files if needed, or 404
                    self.send_error(404)

            def do_POST(self):
                if self.path == '/config':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    data = json.loads(post_data)
                    
                    # data: { port: "80", module: "path/to/mod", selected: true/false }
                    self.update_config(data)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"status": "ok"}')
                else:
                    self.send_error(404)

            def update_config(self, data):
                port = str(data.get('port'))
                module = data.get('module')
                selected = data.get('selected')
                
                if not port or not module:
                    return

                try:
                    if os.path.exists(config_file_path):
                        with open(config_file_path, 'r') as f:
                            config = json.load(f)
                    else:
                        config = {
                            "firm_name": "Unknown",
                            "subnet": "0.0.0.0/0",
                            "scan_type": "all",
                            "tcp_ports": [],
                            "udp_ports": [],
                            "modules": {}
                        }

                    if 'modules' not in config: config['modules'] = {}
                    if 'tcp_ports' not in config: config['tcp_ports'] = []
                    if 'udp_ports' not in config: config['udp_ports'] = []
                    # Remove legacy target_ports if present
                    if 'target_ports' in config: del config['target_ports']

                    # Load modules DB to check protocol
                    modules_db_path = 'modules.json'
                    protocol = 'tcp'
                    if os.path.exists(modules_db_path):
                        with open(modules_db_path, 'r') as f:
                            modules_db = json.load(f)
                            if port in modules_db:
                                for mod in modules_db[port]:
                                    if mod['path'] == module:
                                        protocol = mod.get('info', {}).get('protocol', 'tcp')
                                        break

                    if selected:
                        # Add module
                        if port not in config['modules']:
                            config['modules'][port] = []
                        
                        if module not in config['modules'][port]:
                            config['modules'][port].append(module)
                            
                        # Add port to appropriate list
                        port_int = int(port)
                        if protocol == 'udp':
                            if port_int not in config['udp_ports']:
                                config['udp_ports'].append(port_int)
                                config['udp_ports'].sort()
                        else:
                            if port_int not in config['tcp_ports']:
                                config['tcp_ports'].append(port_int)
                                config['tcp_ports'].sort()
                    else:
                        # Remove module
                        if port in config['modules']:
                            if module in config['modules'][port]:
                                config['modules'][port].remove(module)
                            
                            # If no modules left for port, remove port from lists
                            if not config['modules'][port]:
                                del config['modules'][port]
                                port_int = int(port)
                                if port_int in config['tcp_ports']:
                                    config['tcp_ports'].remove(port_int)
                                if port_int in config['udp_ports']:
                                    config['udp_ports'].remove(port_int)

                    with open(config_file_path, 'w') as f:
                        json.dump(config, f, indent=4)
                        
                except Exception as e:
                    print(f"Error updating config: {e}")

        print(f"Serving {self.html_file} at http://localhost:{self.port}")
        with socketserver.TCPServer(("", self.port), Handler) as httpd:
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nServer stopped.")

