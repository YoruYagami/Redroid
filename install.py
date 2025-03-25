import os
import platform
import subprocess
import shutil
import requests
import sys
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

def download_latest_jadx():
    system = platform.system().lower()
    if system == "linux":
        # Check for specific Linux distributions
        try:
            distro_info = os.popen('cat /etc/*release 2>/dev/null || echo "Unknown"').read().lower()
            if 'debian' in distro_info or 'ubuntu' in distro_info or 'kali' in distro_info:
                print("Detected Debian-based system (e.g., Kali Linux)")
                os.system("sudo apt update && sudo apt install jadx -y")
                print("Jadx installed successfully via apt.")
            elif 'arch' in distro_info or 'blackarch' in distro_info:
                print("Detected Arch Linux or BlackArch")
                os.system("sudo pacman -Syu jadx --noconfirm")
                print("Jadx installed successfully via pacman.")
            else:
                print("Unsupported Linux distribution. Please install Jadx manually.")
        except Exception as e:
            print(f"Error detecting Linux distribution: {e}")
    elif system == "windows":
        try:
            print("Downloading Jadx for Windows...")
            response = requests.get("https://api.github.com/repos/skylot/jadx/releases/latest")
            response.raise_for_status()
            latest_release = response.json()
            assets = latest_release.get('assets', [])
            for asset in assets:
                if 'no-jre-win.exe' in asset['name']:
                    download_url = asset['browser_download_url']
                    local_filename = asset['name']

                    # Get the current directory path of the script
                    script_dir = os.path.dirname(os.path.abspath(__file__))
                    local_filepath = os.path.join(script_dir, "jadx-gui.exe")

                    print(f"Downloading {local_filename} from {download_url}")
                    with requests.get(download_url, stream=True) as r:
                        r.raise_for_status()
                        with open(local_filepath, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=8192):
                                f.write(chunk)
                    print(f"Downloaded and renamed {local_filename} to jadx-gui.exe in the script directory: {local_filepath}")
                    return
            print("No suitable Jadx executable found in the latest release.")
        except Exception as e:
            print(f"An error occurred while trying to download the latest version of Jadx: {str(e)}")
    else:
        print(f"Unsupported operating system: {system}. Please install Jadx manually.")

def get_latest_apktool_url():
    url = "https://bitbucket.org/iBotPeaches/apktool/downloads/"
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and href.endswith('.jar'):
                return f"https://bitbucket.org{href}"
        return None
    except Exception as e:
        print(f"Error fetching apktool URL: {e}")
        return None

def setup_apktool():
    try:
        system = platform.system().lower()
        if system == "linux":
            try:
                distro_info = os.popen('cat /etc/*release 2>/dev/null || echo "Unknown"').read().lower()
                if 'kali' in distro_info or 'debian' in distro_info or 'ubuntu' in distro_info:
                    os.system('sudo apt update && sudo apt install apktool -y')
                elif 'arch' in distro_info or 'manjaro' in distro_info or 'blackarch' in distro_info:
                    os.system('sudo pacman -Syu apktool --noconfirm')
                else:
                    print("Unsupported Linux distribution")
                    return
                print(Fore.GREEN + "✅ Apktool installed successfully." + Style.RESET_ALL)
            except Exception as e:
                print(f"Error detecting Linux distribution: {e}")
        elif system == "windows":
            bat_url = "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat"
            jar_url = get_latest_apktool_url()
            if not jar_url:
                print("Failed to find the latest apktool.jar")
                return

            # Get the current directory path of the script
            script_dir = os.path.dirname(os.path.abspath(__file__))

            # Download apktool.bat
            print(f"Downloading apktool.bat from {bat_url}")
            response = requests.get(bat_url)
            response.raise_for_status()
            bat_path = os.path.join(script_dir, "apktool.bat")
            with open(bat_path, "wb") as file:
                file.write(response.content)

            # Download apktool.jar
            print(f"Downloading apktool.jar from {jar_url}")
            response = requests.get(jar_url)
            response.raise_for_status()
            jar_path = os.path.join(script_dir, "apktool.jar")
            with open(jar_path, "wb") as file:
                file.write(response.content)

            print(f"apktool setup completed. Files downloaded to the script directory: {bat_path} and {jar_path}")
            print(Fore.YELLOW + "Note: To use apktool from any directory, add these files to a directory in your PATH or:" + Style.RESET_ALL)
            print("1. Copy both files to C:\\Windows (requires admin)")
            print("2. Or add the current directory to your PATH")
        else:
            print("Unsupported Operating System")
    except Exception as e:
        print(f"An error occurred while setting up apktool: {str(e)}")

def add_to_system_path(path):
    """Add a directory to the system PATH environment variable."""
    try:
        if platform.system().lower() == 'windows':
            # Update current session PATH
            os.environ['PATH'] = f"{os.environ['PATH']};{path}"
            # Persist the PATH change for future sessions (requires user to restart terminal)
            subprocess.run(f'setx PATH "%PATH%;{path}"', shell=True, check=True)
            print(f"Added {path} to system PATH. You may need to restart your terminal for changes to take effect.")
        else:
            # For Linux, update current session
            os.environ['PATH'] = f"{os.environ['PATH']}:{path}"
            
            # Update shell profile based on shell
            shell = os.environ.get('SHELL', '')
            profile_file = ''
            
            if 'bash' in shell:
                profile_file = os.path.expanduser('~/.bashrc')
            elif 'zsh' in shell:
                profile_file = os.path.expanduser('~/.zshrc')
            else:
                # Default to .profile if shell can't be determined
                profile_file = os.path.expanduser('~/.profile')
            
            # Add to shell profile if file exists and path not already in file
            if os.path.exists(profile_file):
                with open(profile_file, 'r') as f:
                    content = f.read()
                
                path_export = f'export PATH="$PATH:{path}"'
                if path_export not in content:
                    with open(profile_file, 'a') as f:
                        f.write(f'\n# Added by Redroid installer\n{path_export}\n')
                    
                    print(f"Added {path} to {profile_file}. Run 'source {profile_file}' to apply changes in this terminal.")
                else:
                    print(f"Path {path} already exists in {profile_file}.")
            else:
                print(f"Could not find profile file {profile_file}. Please add {path} to your PATH manually.")
        
        return True
    except Exception as e:
        print(Fore.RED + f"Error adding {path} to system PATH: {e}" + Style.RESET_ALL)
        return False

def check_nuclei_installed():
    """Check if Nuclei can be executed from the terminal."""
    try:
        subprocess.run(["nuclei", "-version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_nuclei():
    """Install Nuclei using Go and ensure it's executable from any terminal."""
    if not check_go_installed():
        print(Fore.YELLOW + "Go is not installed on your system. Please install Go and try again." + Style.RESET_ALL)
        return False

    try:
        print("Installing Nuclei...")
        subprocess.run("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", shell=True, check=True)
        print("Nuclei installed successfully.")

        if not check_nuclei_installed():
            go_bin_path = os.path.expanduser("~/go/bin")
            if add_to_system_path(go_bin_path):
                if not check_nuclei_installed():
                    print(Fore.YELLOW + "Nuclei is still not executable. You may need to restart your terminal." + Style.RESET_ALL)
                    print(f"Please check your PATH settings and ensure {go_bin_path} is included.")
                else:
                    print(Fore.GREEN + "✅ Nuclei is now executable from the terminal." + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "Failed to add Go binaries to PATH. Please add it manually." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "✅ Nuclei is executable from the terminal." + Style.RESET_ALL)
        
        return True
    except Exception as e:
        print(Fore.RED + f"An error occurred during Nuclei installation: {str(e)}" + Style.RESET_ALL)
        return False

def check_go_installed():
    """Check if Go is installed."""
    try:
        subprocess.run(["go", "version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_mobsf():
    """Install MobSF using Docker."""
    if not shutil.which("docker"):
        print(Fore.YELLOW + "Docker is not installed. Please install Docker first." + Style.RESET_ALL)
        return False
    
    print("Installing MobSF...")
    try:
        subprocess.run(["docker", "pull", "opensecurity/mobile-security-framework-mobsf:latest"], check=True)
        print(Fore.GREEN + "✅ MobSF Docker image installed successfully." + Style.RESET_ALL)
        print("To run MobSF, use: docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest")
        return True
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error installing MobSF: {e}" + Style.RESET_ALL)
        return False

def install_all_tools():
    """Install all tools and display a summary of what was installed."""
    init(autoreset=True)
    print(Fore.CYAN + "====== Redroid Tool Installer ======" + Style.RESET_ALL)
    
    tools_status = {
        "JADX": {"installed": False, "message": ""},
        "Apktool": {"installed": False, "message": ""},
        "Nuclei": {"installed": False, "message": ""},
        "MobSF": {"installed": False, "message": ""}
    }
    
    # Install JADX
    print("\n" + Fore.CYAN + "Installing JADX..." + Style.RESET_ALL)
    try:
        download_latest_jadx()
        tools_status["JADX"]["installed"] = True
        tools_status["JADX"]["message"] = "Successfully installed"
    except Exception as e:
        tools_status["JADX"]["message"] = f"Failed: {str(e)}"
    
    # Install APKTool
    print("\n" + Fore.CYAN + "Installing Apktool..." + Style.RESET_ALL)
    try:
        setup_apktool()
        tools_status["Apktool"]["installed"] = True
        tools_status["Apktool"]["message"] = "Successfully installed"
    except Exception as e:
        tools_status["Apktool"]["message"] = f"Failed: {str(e)}"
    
    # Install Nuclei
    print("\n" + Fore.CYAN + "Installing Nuclei..." + Style.RESET_ALL)
    try:
        if install_nuclei():
            tools_status["Nuclei"]["installed"] = True
            tools_status["Nuclei"]["message"] = "Successfully installed"
        else:
            tools_status["Nuclei"]["message"] = "Installation incomplete, see details above"
    except Exception as e:
        tools_status["Nuclei"]["message"] = f"Failed: {str(e)}"
    
    # Install MobSF
    print("\n" + Fore.CYAN + "Installing MobSF..." + Style.RESET_ALL)
    try:
        if install_mobsf():
            tools_status["MobSF"]["installed"] = True
            tools_status["MobSF"]["message"] = "Successfully installed"
        else:
            tools_status["MobSF"]["message"] = "Installation incomplete, Docker required"
    except Exception as e:
        tools_status["MobSF"]["message"] = f"Failed: {str(e)}"
    
    # Display summary
    print("\n" + Fore.CYAN + "====== Installation Summary ======" + Style.RESET_ALL)
    for tool, status in tools_status.items():
        if status["installed"]:
            print(f"{Fore.GREEN}✅ {tool}: {status['message']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ {tool}: {status['message']}{Style.RESET_ALL}")
    
    print("\n" + Fore.CYAN + "====== Installation Complete ======" + Style.RESET_ALL)
    print("Some tools may require you to restart your terminal or add paths to your environment.")

if __name__ == "__main__":
    install_all_tools()
