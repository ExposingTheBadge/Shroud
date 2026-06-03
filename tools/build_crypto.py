import os
import subprocess
import shutil

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    zig_dir = os.path.join(repo_root, 'zig')
    
    with open(os.path.join(repo_root, 'VERSION'), 'r') as f:
        version = f.read().strip()
        
    print(f"Building shroud_crypto.dll for version v{version}...")
    
    # Run zig build
    subprocess.run(["C:\\ProgramData\\chocolatey\\bin\\zig.exe", "build", "-Dtarget=x86_64-windows", "-Doptimize=ReleaseFast"], cwd=zig_dir, check=True)
    
    # Copy to releases
    dll_src = os.path.join(zig_dir, "zig-out", "bin", "shroud_crypto.dll")
    releases_dir = os.path.join(repo_root, "releases", f"v{version}")
    
    os.makedirs(releases_dir, exist_ok=True)
    
    dll_dest = os.path.join(releases_dir, f"shroud_crypto-v{version}.dll")
    shutil.copy2(dll_src, dll_dest)
    print(f"Successfully compiled and copied to: {dll_dest}")

if __name__ == '__main__':
    main()
