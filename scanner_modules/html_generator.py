import json
import os
import html
import base64

class HtmlGenerator:
    def __init__(self, msf_path):
        self.msf_path = msf_path

    def generate(self, modules_data, output_file='modules.html'):
        # Prepare data structure for frontend
        frontend_data = {}
        
        print("Generating HTML report data...")
        total_modules = sum(len(mods) for mods in modules_data.values())
        processed = 0
        
        for port, modules in modules_data.items():
            frontend_data[port] = []
            for module in modules:
                module_path = module['path']
                abs_path = os.path.join(self.msf_path, module_path + ".rb")
                code_content = ""
                try:
                    with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code_content = f.read()
                except Exception as e:
                    code_content = f"# Error reading file: {e}"

                frontend_data[port].append({
                    'name': module['info']['name'],
                    'path': module_path,
                    'description': module['info']['description'],
                    'code': code_content
                })
                processed += 1
                if processed % 50 == 0:
                    print(f"Processed {processed}/{total_modules} modules...")

        # Base64 encode the data to avoid HTML injection/syntax errors
        json_str = json.dumps(frontend_data)
        b64_data = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')

        # HTML Template with Bootstrap 5
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MSF Module Scanner</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Prism.js CSS (Okaidia Theme) -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-okaidia.min.css" rel="stylesheet">
    <style>
        body {{ height: 100vh; overflow: hidden; display: flex; flex-direction: column; }}
        #navbar {{ flex: 0 0 auto; z-index: 1000; }}
        #main-container {{ flex: 1; display: flex; overflow: hidden; }}
        
        #sidebar {{ width: 350px; background: #f8f9fa; border-right: 1px solid #dee2e6; display: flex; flex-direction: column; }}
        #sidebar-header {{ padding: 1rem; border-bottom: 1px solid #dee2e6; }}
        #portsAccordion {{ flex: 1; overflow-y: auto; }}
        
        #content-area {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; background: #fff; }}
        #module-header {{ padding: 1rem; border-bottom: 1px solid #dee2e6; background: #f8f9fa; }}
        #code-container {{ flex: 1; overflow: auto; position: relative; background: #272822; }}
        #code-container pre {{ margin: 0; padding: 1rem; height: 100%; box-sizing: border-box; }}
        
        .port-header {{ cursor: pointer; font-weight: 600; background: #e9ecef; }}
        .port-header:hover {{ background: #dee2e6; }}
        .module-item {{ cursor: pointer; font-size: 0.9rem; border-bottom: 1px solid #f1f1f1; padding: 8px 15px; }}
        .module-item:hover {{ background: #e9ecef; }}
        .module-item.active {{ background: #0d6efd; color: white; }}
        .module-item.module-selected {{ color: #198754; font-weight: bold; background-color: #f0fff4; }}
        .module-item.active.module-selected {{ color: white; background-color: #0d6efd; }} /* Keep white text when active */
        
        /* Scrollbar styling */
        ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
        ::-webkit-scrollbar-track {{ background: #f1f1f1; }}
        ::-webkit-scrollbar-thumb {{ background: #ccc; border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #aaa; }}
    </style>
</head>
<body>

<!-- Navbar -->
<nav id="navbar" class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container-fluid">
        <a class="navbar-brand" href="#">MSF Scanner</a>
        <div class="d-flex align-items-center">
             <div id="stats-container" class="me-3 text-light small" style="text-align: right; line-height: 1.2;">
                <div>Ports: <span id="stat-ports" class="fw-bold">0</span></div>
                <div>Modules: <span id="stat-modules" class="fw-bold">0</span></div>
                <div>Selected: <span id="stat-selected" class="text-warning fw-bold">0</span></div>
             </div>
             <span id="connection-status" class="badge bg-secondary me-3">Offline</span>
             <button class="btn btn-sm btn-outline-light" onclick="saveConfig()">Force Save</button>
        </div>
    </div>
</nav>

<div id="main-container">
    <!-- Sidebar -->
    <div id="sidebar">
        <div id="sidebar-header">
            <input type="text" id="search-input" class="form-control" placeholder="Search modules...">
        </div>
        <div id="portsAccordion" class="accordion accordion-flush">
            <!-- Ports will be injected here -->
        </div>
    </div>

    <!-- Main Content -->
    <div id="content-area">
        <div id="module-header">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h5 id="mod-title" class="mb-1">Select a module</h5>
                    <p id="mod-desc" class="text-muted mb-1 small">Description will appear here.</p>
                    <code id="mod-path" class="text-primary small"></code>
                    <div class="mt-2">
                        <a id="btn-google" href="#" target="_blank" class="btn btn-sm btn-outline-secondary me-1 disabled">Google Search</a>
                        <a id="btn-infosec" href="#" target="_blank" class="btn btn-sm btn-outline-info disabled">InfoSecMatter</a>
                    </div>
                </div>
                <div class="form-check form-switch">
                    <input class="form-check-input" type="checkbox" id="mod-checkbox" disabled>
                    <label class="form-check-label" for="mod-checkbox">Enable</label>
                </div>
            </div>
        </div>
        <div id="code-container">
            <pre><code id="code-block" class="language-ruby"># Select a module to view source code</code></pre>
        </div>
    </div>
</div>

<!-- Bootstrap JS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<!-- Prism JS -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-ruby.min.js"></script>

<script>
    // Decode Data
    const encodedData = "{b64_data}";
    const data = JSON.parse(atob(encodedData));
    const ports = Object.keys(data).sort((a, b) => parseInt(a) - parseInt(b));
    
    let configModules = {{}};
    let currentModule = null;
    let currentPort = null;

    // Elements
    const accordion = document.getElementById('portsAccordion');
    const searchInput = document.getElementById('search-input');
    const modTitle = document.getElementById('mod-title');
    const modDesc = document.getElementById('mod-desc');
    const modPath = document.getElementById('mod-path');
    const modCheckbox = document.getElementById('mod-checkbox');
    const codeBlock = document.getElementById('code-block');
    const statusBadge = document.getElementById('connection-status');

    // Initialize
    init();

    function init() {{
        fetchConfig();
        renderSidebar();
        updateGlobalStats();
        
        searchInput.addEventListener('input', (e) => {{
            filterModules(e.target.value.toLowerCase());
        }});
        
        modCheckbox.addEventListener('change', (e) => {{
            if (currentModule && currentPort) {{
                updateConfig(currentPort, currentModule.path, e.target.checked);
            }}
        }});
    }}

    function fetchConfig() {{
        fetch('/config')
            .then(res => res.json())
            .then(config => {{
                if (config.modules) {{
                    configModules = config.modules;
                    statusBadge.textContent = "Connected";
                    statusBadge.className = "badge bg-success me-3";
                    updateSidebarCounts();
                    updateCheckboxState();
                    updateGlobalStats();
                }}
            }})
            .catch(err => {{
                console.log("Offline mode");
                statusBadge.textContent = "Offline";
                statusBadge.className = "badge bg-danger me-3";
            }});
    }}

    function renderSidebar() {{
        accordion.innerHTML = '';
        ports.forEach((port, index) => {{
            const modules = data[port];
            const portId = `port-${{port}}`;
            const collapseId = `collapse-${{port}}`;
            
            const item = document.createElement('div');
            item.className = 'accordion-item';
            
            const header = document.createElement('h2');
            header.className = 'accordion-header';
            header.id = `heading-${{port}}`;
            
            const button = document.createElement('button');
            button.className = 'accordion-button collapsed port-header';
            button.type = 'button';
            button.setAttribute('data-bs-toggle', 'collapse');
            button.setAttribute('data-bs-target', `#${{collapseId}}`);
            button.innerHTML = `Port ${{port}} <span class="badge bg-secondary ms-2 count-badge" data-port="${{port}}">0/${{modules.length}}</span>`;
            
            header.appendChild(button);
            item.appendChild(header);
            
            const collapse = document.createElement('div');
            collapse.id = collapseId;
            collapse.className = 'accordion-collapse collapse';
            collapse.setAttribute('data-bs-parent', '#portsAccordion');
            
            const body = document.createElement('div');
            body.className = 'accordion-body p-0';
            
            modules.forEach(mod => {{
                const modDiv = document.createElement('div');
                modDiv.className = 'module-item';
                modDiv.textContent = mod.name;
                modDiv.setAttribute('data-name', mod.name.toLowerCase());
                modDiv.setAttribute('data-path', mod.path); // Add path for easy lookup
                modDiv.onclick = () => selectModule(port, mod, modDiv);
                body.appendChild(modDiv);
            }});
            
            collapse.appendChild(body);
            item.appendChild(collapse);
            accordion.appendChild(item);
        }});
        updateSidebarCounts();
    }}

    function selectModule(port, mod, element) {{
        // Highlight
        document.querySelectorAll('.module-item').forEach(el => el.classList.remove('active'));
        element.classList.add('active');
        
        currentModule = mod;
        currentPort = port;
        
        // Update Details
        modTitle.textContent = mod.name;
        modDesc.textContent = mod.description;
        modPath.textContent = mod.path;
        modCheckbox.disabled = false;
        
        // Update Buttons
        const btnGoogle = document.getElementById('btn-google');
        const btnInfosec = document.getElementById('btn-infosec');
        
        btnGoogle.href = `https://www.google.com/search?q=${{encodeURIComponent(mod.name + ' metasploit module')}}`;
        btnGoogle.classList.remove('disabled');
        
        btnInfosec.href = `https://www.infosecmatter.com/metasploit-module-library/?mm=${{mod.path}}`;
        btnInfosec.classList.remove('disabled');

        // Update Code
        codeBlock.textContent = mod.code;
        Prism.highlightElement(codeBlock);
        
        updateCheckboxState();
    }}

    function updateCheckboxState() {{
        if (currentModule && currentPort) {{
            const isSelected = configModules[currentPort] && configModules[currentPort].includes(currentModule.path);
            modCheckbox.checked = isSelected;
        }}
    }}

    function updateSidebarCounts() {{
        ports.forEach(port => {{
            const selectedModulesList = configModules[port] || [];
            const selectedCount = selectedModulesList.length;
            const total = data[port].length;
            
            // Update Badge
            const badge = document.querySelector(`.count-badge[data-port="${{port}}"]`);
            if (badge) {{
                badge.textContent = `${{selectedCount}}/${{total}}`;
                if (selectedCount > 0) {{
                    badge.className = 'badge bg-primary ms-2 count-badge';
                }} else {{
                    badge.className = 'badge bg-secondary ms-2 count-badge';
                }}
            }}
            
            // Update Module Items Highlighting
            const collapse = document.getElementById(`collapse-${{port}}`);
            if (collapse) {{
                const moduleItems = collapse.querySelectorAll('.module-item');
                moduleItems.forEach(item => {{
                    const path = item.getAttribute('data-path');
                    if (selectedModulesList.includes(path)) {{
                        item.classList.add('module-selected');
                    }} else {{
                        item.classList.remove('module-selected');
                    }}
                }});
            }}
        }});
    }}

    function updateGlobalStats() {{
        const totalPorts = ports.length;
        let totalModules = 0;
        let selectedModules = 0;

        ports.forEach(port => {{
            totalModules += data[port].length;
            if (configModules[port]) {{
                selectedModules += configModules[port].length;
            }}
        }});

        document.getElementById('stat-ports').textContent = totalPorts;
        document.getElementById('stat-modules').textContent = totalModules;
        document.getElementById('stat-selected').textContent = selectedModules;
    }}

    function updateConfig(port, modulePath, isSelected) {{
        // Optimistic update
        if (!configModules[port]) configModules[port] = [];
        
        if (isSelected) {{
            if (!configModules[port].includes(modulePath)) configModules[port].push(modulePath);
        }} else {{
            configModules[port] = configModules[port].filter(p => p !== modulePath);
        }}
        
        updateSidebarCounts();
        updateGlobalStats();
        
        fetch('/config', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ port, module: modulePath, selected: isSelected }})
        }}).then(res => res.json())
          .then(data => console.log('Saved'))
          .catch(err => console.error('Save failed', err));
    }}

    function filterModules(query) {{
        document.querySelectorAll('.module-item').forEach(item => {{
            const name = item.getAttribute('data-name');
            if (name.includes(query)) {{
                item.style.display = 'block';
            }} else {{
                item.style.display = 'none';
            }}
        }});
        
        // Open accordions that have matches
        document.querySelectorAll('.accordion-item').forEach(group => {{
            const hasVisible = group.querySelector('.module-item[style="display: block;"]');
            const collapse = group.querySelector('.accordion-collapse');
            if (query.length > 0 && hasVisible) {{
                collapse.classList.add('show');
            }} else if (query.length === 0) {{
                collapse.classList.remove('show');
            }}
        }});
    }}
    
    function saveConfig() {{
        // Just triggers a fetch to ensure connection
        fetchConfig();
    }}
</script>

</body>
</html>
"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"HTML report generated: {output_file}")
