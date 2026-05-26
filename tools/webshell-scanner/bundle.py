import subprocess
import os
import shutil
import platform
import zipfile
import sys

def build_windows():
    print(">>> Building Windows binary...")
    # Use the venv if it exists
    python_exe = sys.executable
    if os.path.exists(".venv/Scripts/python.exe"):
        python_exe = os.path.abspath(".venv/Scripts/python.exe")
    
    pyinstaller_cmd = [
        python_exe, "-m", "PyInstaller", "build.spec", 
        "--clean", "--noconfirm", 
        "--distpath", "dist/windows"
    ]
    subprocess.run(pyinstaller_cmd, check=True)

def build_linux():
    print(">>> Building Linux binary via Docker...")
    dockerfile_content = """
FROM python:3.11-slim
RUN apt-get update && apt-get install -y binutils gcc libmagic1
WORKDIR /app
COPY . .
RUN pip install . pyinstaller
RUN pyinstaller build.spec --clean --noconfirm --distpath dist/linux
"""
    with open("Dockerfile.build", "w") as f:
        f.write(dockerfile_content)
    
    try:
        image_name = "webshell-scanner-build"
        container_name = "temp_scanner_build"
        
        subprocess.run(["docker", "build", "-t", image_name, "-f", "Dockerfile.build", "."], check=True)
        
        # Remove old container if exists
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        
        # Create container and copy files out
        subprocess.run(["docker", "create", "--name", container_name, image_name], check=True)
        
        if not os.path.exists("dist/linux"):
            os.makedirs("dist/linux")
            
        subprocess.run(["docker", "cp", f"{container_name}:/app/dist/linux/.", "dist/linux/"], check=True)
        subprocess.run(["docker", "rm", container_name], check=True)
    finally:
        if os.path.exists("Dockerfile.build"):
            os.remove("Dockerfile.build")

def create_bundle():
    print(">>> Creating cross-platform ZIP bundle...")
    bundle_path = "dist/webshell-scanner-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        # Add windows binary
        win_exe = "dist/windows/webshell-scanner.exe"
        if os.path.exists(win_exe):
            print(f"Adding {win_exe}")
            zipf.write(win_exe, "windows/webshell-scanner.exe")
        else:
            print("Warning: Windows binary not found.")
        
        # Add linux binary
        lin_exe = "dist/linux/webshell-scanner"
        if os.path.exists(lin_exe):
            print(f"Adding {lin_exe}")
            zipf.write(lin_exe, "linux/webshell-scanner")
        else:
            print("Warning: Linux binary not found.")
            
    print(f"SUCCESS: Bundle created at {os.path.abspath(bundle_path)}")

if __name__ == "__main__":
    # Change to the script's directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    if not os.path.exists("dist"):
        os.makedirs("dist")
    
    # Build for Windows if on Windows
    if platform.system() == "Windows":
        try:
            build_windows()
        except Exception as e:
            print(f"Failed to build Windows binary: {e}")
    
    # Build for Linux if Docker is available
    try:
        subprocess.run(["docker", "version"], capture_output=True, check=True)
        build_linux()
    except Exception as e:
        print(f"Docker not found or failed to build Linux binary: {e}")
    
    create_bundle()
