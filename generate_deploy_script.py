import os
import base64

def main():
    # Exclude list
    excludes = {'.DS_Store', 'generate_deploy_script.py', '.git'}
    exclude_dirs = {'.git', '.ruby-lsp', '__pycache__', '.idea', '.vscode'}
    
    commands = []
    
    base_dir = os.getcwd()
    
    # First, collect all directories to create them upfront (optional, but cleaner)
    # But doing it inline is fine for a simple script.
    
    for root, dirs, files in os.walk(base_dir):
        # Filter dirs in-place
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            if file in excludes:
                continue
            if file.endswith('.pyc'):
                continue
                
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, base_dir)
            
            # Ensure directory exists
            dir_name = os.path.dirname(rel_path)
            if dir_name and dir_name != ".":
                # We use -p so it doesn't fail if it exists
                commands.append(f"mkdir -p '{dir_name}'")
            
            try:
                with open(full_path, "rb") as f:
                    content = f.read()
                    b64 = base64.b64encode(content).decode('utf-8')
                    
                # Construct command
                # echo '...' | base64 -d > '...'
                # Using printf might be safer for some shells but echo is standard enough for simple base64
                safe_rel_path = rel_path.replace("'", "'\\''")
                cmd = f"echo '{b64}' | base64 -d > '{safe_rel_path}'"
                commands.append(cmd)
            except Exception as e:
                pass
    
    # Join all commands
    # We use " && " to ensure sequential execution and stop on error
    # Wrap in specific shell invocation if needed, but raw string is requested
    print(" && ".join(commands))

if __name__ == "__main__":
    main()
