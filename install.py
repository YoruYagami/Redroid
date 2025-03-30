import os
import platform
import subprocess
import shutil
import requests
import sys
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

def check_java_installed():
    """Check if Java is installed and display its version."""
    try:
        output = subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT)
        version_info = output.decode().splitlines()[0]
        print(Fore.GREEN + f"Java installed: {version_info}" + Style.RESET_ALL)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(Fore.RED + "Java is not installed." + Style.RESET_ALL)
        return False

def check_android_studio_installed():
    """Check if Android Studio is installed by searching common installation paths."""
    found = False
    system = platform.system().lower()
    paths = []
    if system == "windows":
        paths = [
            r"C:\Program Files\Android\Android Studio\bin\studio64.exe",
            r"C:\Program Files (x86)\Android\Android Studio\bin\studio.exe"
        ]
    else:
        paths = [
            "/opt/android-studio/bin/studio.sh",
            os.path.join(os.path.expanduser("~"), "android-studio", "bin", "studio.sh")
        ]
    for p in paths:
        if os.path.exists(p):
            print(Fore.GREEN + f"Android Studio found: {p}" + Style.RESET_ALL)
            found = True
            break
    if not found:
        print(Fore.YELLOW + "Android Studio is not installed or not found in common paths." + Style.RESET_ALL)
    return found

def check_jadx_installed():
    """Check if JADX is already installed."""
    system = platform.system().lower()
    if system == "linux":
        if shutil.which("jadx") is not None:
            return True
        else:
            return False
    elif system == "windows":
        if os.path.exists(os.path.join(os.getcwd(), "jadx-gui.exe")):
            return True
        else:
            return False
    else:
        return False

def check_apktool_installed():
    """Check if Apktool is already installed."""
    system = platform.system().lower()
    if system == "linux":
        if shutil.which("apktool") is not None:
            return True
        else:
            return False
    elif system == "windows":
        script_dir = os.getcwd()
        if os.path.exists(os.path.join(script_dir, "apktool.jar")) and os.path.exists(os.path.join(script_dir, "apktool.bat")):
            return True
        else:
            return False
    else:
        return False

def check_nuclei_installed():
    """Check if Nuclei is executable from the terminal."""
    try:
        subprocess.run(["nuclei", "-version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def check_mobsf_installed():
    """Check if the MobSF Docker image is already present."""
    try:
        result = subprocess.check_output(["docker", "images", "-q", "opensecurity/mobile-security-framework-mobsf:latest"], text=True)
        if result.strip():
            print(Fore.GREEN + "MobSF Docker image is already present." + Style.RESET_ALL)
            return True
        else:
            return False
    except Exception as e:
        print(Fore.RED + f"Error checking MobSF: {e}" + Style.RESET_ALL)
        return False

def download_latest_jadx():
    """Install or download the latest JADX."""
    system = platform.system().lower()
    # On Windows, use the current directory for downloads
    script_dir = os.getcwd() if system == "windows" else os.path.dirname(os.path.abspath(__file__))
    
    if system == "linux":
        try:
            distro_info = subprocess.check_output("cat /etc/*release 2>/dev/null || echo 'Unknown'", shell=True).decode().lower()
            if any(x in distro_info for x in ['debian', 'ubuntu', 'kali']):
                print("Detected Debian-based system (e.g., Kali Linux)")
                subprocess.run(["sudo", "apt", "update"], check=True)
                subprocess.run(["sudo", "apt", "install", "jadx", "-y"], check=True)
                print("JADX installed successfully via apt.")
            elif any(x in distro_info for x in ['arch', 'blackarch']):
                print("Detected Arch Linux or BlackArch")
                subprocess.run(["sudo", "pacman", "-Syu", "jadx", "--noconfirm"], check=True)
                print("JADX installed successfully via pacman.")
            else:
                print("Unsupported Linux distribution. Please install JADX manually.")
        except Exception as e:
            print(f"Error detecting Linux distribution: {e}")
    elif system == "windows":
        try:
            print("Downloading JADX for Windows...")
            response = requests.get("https://api.github.com/repos/skylot/jadx/releases/latest")
            response.raise_for_status()
            latest_release = response.json()
            assets = latest_release.get('assets', [])
            for asset in assets:
                if 'no-jre-win.exe' in asset['name']:
                    download_url = asset['browser_download_url']
                    local_filename = asset['name']
                    local_filepath = os.path.join(script_dir, "jadx-gui.exe")
                    print(f"Downloading {local_filename} from {download_url}")
                    with requests.get(download_url, stream=True) as r:
                        r.raise_for_status()
                        with open(local_filepath, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=8192):
                                f.write(chunk)
                    print(f"Downloaded and renamed {local_filename} to jadx-gui.exe in: {local_filepath}")
                    return
            print("No suitable JADX executable found in the latest release.")
        except Exception as e:
            print(f"An error occurred while downloading the latest version of JADX: {e}")
    else:
        print(f"Unsupported operating system: {system}. Please install JADX manually.")

def get_latest_apktool_url():
    """Retrieve the URL for the latest apktool.jar from Bitbucket."""
    url = "https://bitbucket.org/iBotPeaches/apktool/downloads/"
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and href.endswith('.jar'):
                if not href.startswith('/'):
                    href = "/" + href
                return f"https://bitbucket.org{href}"
        return None
    except Exception as e:
        print(f"Error fetching apktool URL: {e}")
        return None

def setup_apktool():
    """Install Apktool (or download it on Windows)."""
    system = platform.system().lower()
    # On Windows, use the current directory for downloads
    script_dir = os.getcwd() if system == "windows" else os.path.dirname(os.path.abspath(__file__))
    
    if system == "linux":
        try:
            distro_info = subprocess.check_output("cat /etc/*release 2>/dev/null || echo 'Unknown'", shell=True).decode().lower()
            if any(x in distro_info for x in ['kali', 'debian', 'ubuntu']):
                subprocess.run(["sudo", "apt", "update"], check=True)
                subprocess.run(["sudo", "apt", "install", "apktool", "-y"], check=True)
            elif any(x in distro_info for x in ['arch', 'manjaro', 'blackarch']):
                subprocess.run(["sudo", "pacman", "-Syu", "apktool", "--noconfirm"], check=True)
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

        print(f"Downloading apktool.bat from {bat_url}")
        response = requests.get(bat_url)
        response.raise_for_status()
        bat_path = os.path.join(script_dir, "apktool.bat")
        with open(bat_path, "wb") as file:
            file.write(response.content)

        print(f"Downloading apktool.jar from {jar_url}")
        response = requests.get(jar_url)
        response.raise_for_status()
        jar_path = os.path.join(script_dir, "apktool.jar")
        with open(jar_path, "wb") as file:
            file.write(response.content)

        print(f"Apktool setup completed. Files downloaded to: {bat_path} and {jar_path}")
        print(Fore.YELLOW + "Note: To use Apktool from any directory, add these files to a directory in your PATH or:" + Style.RESET_ALL)
        print("1. Copy both files to C:\\Windows (requires admin)")
        print("2. Or add the current directory to your PATH")
    else:
        print("Unsupported Operating System")

def install_nuclei():
    """Install Nuclei via Go and verify its execution."""
    if not check_go_installed():
        print(Fore.YELLOW + "Go is not installed on your system. Please install Go and try again." + Style.RESET_ALL)
        return False

    try:
        print("Installing Nuclei...")
        subprocess.run("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", shell=True, check=True)
        print("Nuclei installed successfully.")

        if not check_nuclei_installed():
            go_bin_path = os.path.expanduser("~/go/bin")
            print(Fore.YELLOW + f"Nuclei is still not executable. Please ensure that {go_bin_path} is added to your PATH manually." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "✅ Nuclei is executable from the terminal." + Style.RESET_ALL)
        return True
    except Exception as e:
        print(Fore.RED + f"An error occurred during Nuclei installation: {e}" + Style.RESET_ALL)
        return False

def install_mobsf():
    """Install MobSF via Docker."""
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

def check_go_installed():
    """Check if Go is installed."""
    try:
        subprocess.run(["go", "version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_all_tools():
    """Install all tools with an initial check and display a summary."""
    init(autoreset=True)
    print(Fore.CYAN + "====== Redroid Tool Installer ======" + Style.RESET_ALL)
    
    # Check prerequisites
    print("\n" + Fore.CYAN + "Checking prerequisites..." + Style.RESET_ALL)
    java_installed = check_java_installed()
    android_studio_installed = check_android_studio_installed()
    
    tools_status = {
        "JADX": {"installed": False, "message": ""},
        "Apktool": {"installed": False, "message": ""},
        "Nuclei": {"installed": False, "message": ""},
        "MobSF": {"installed": False, "message": ""}
    }
    
    # Check and install JADX
    print("\n" + Fore.CYAN + "Checking for JADX..." + Style.RESET_ALL)
    if check_jadx_installed():
        tools_status["JADX"]["installed"] = True
        tools_status["JADX"]["message"] = "Already installed"
        print(Fore.GREEN + "JADX is already installed." + Style.RESET_ALL)
    else:
        print(Fore.CYAN + "Installing JADX..." + Style.RESET_ALL)
        try:
            download_latest_jadx()
            tools_status["JADX"]["installed"] = True
            tools_status["JADX"]["message"] = "Successfully installed"
        except Exception as e:
            tools_status["JADX"]["message"] = f"Failed: {e}"
    
    # Check and install Apktool
    print("\n" + Fore.CYAN + "Checking for Apktool..." + Style.RESET_ALL)
    if check_apktool_installed():
        tools_status["Apktool"]["installed"] = True
        tools_status["Apktool"]["message"] = "Already installed"
        print(Fore.GREEN + "Apktool is already installed." + Style.RESET_ALL)
    else:
        print(Fore.CYAN + "Installing Apktool..." + Style.RESET_ALL)
        try:
            setup_apktool()
            tools_status["Apktool"]["installed"] = True
            tools_status["Apktool"]["message"] = "Successfully installed"
        except Exception as e:
            tools_status["Apktool"]["message"] = f"Failed: {e}"
    
    # Check and install Nuclei
    print("\n" + Fore.CYAN + "Checking for Nuclei..." + Style.RESET_ALL)
    if check_nuclei_installed():
        tools_status["Nuclei"]["installed"] = True
        tools_status["Nuclei"]["message"] = "Already installed"
        print(Fore.GREEN + "Nuclei is already installed." + Style.RESET_ALL)
    else:
        print(Fore.CYAN + "Installing Nuclei..." + Style.RESET_ALL)
        try:
            if install_nuclei():
                tools_status["Nuclei"]["installed"] = True
                tools_status["Nuclei"]["message"] = "Successfully installed"
            else:
                tools_status["Nuclei"]["message"] = "Installation incomplete, see details above"
        except Exception as e:
            tools_status["Nuclei"]["message"] = f"Failed: {e}"
    
    # Check and install MobSF
    print("\n" + Fore.CYAN + "Checking for MobSF..." + Style.RESET_ALL)
    if check_mobsf_installed():
        tools_status["MobSF"]["installed"] = True
        tools_status["MobSF"]["message"] = "Already installed"
    else:
        print(Fore.CYAN + "Installing MobSF..." + Style.RESET_ALL)
        try:
            if install_mobsf():
                tools_status["MobSF"]["installed"] = True
                tools_status["MobSF"]["message"] = "Successfully installed"
            else:
                tools_status["MobSF"]["message"] = "Installation incomplete, Docker required"
        except Exception as e:
            tools_status["MobSF"]["message"] = f"Failed: {e}"
    
    # Display summary
    print("\n" + Fore.CYAN + "====== Installation Summary ======" + Style.RESET_ALL)
    for tool, status in tools_status.items():
        if status["installed"]:
            print(f"{Fore.GREEN}✅ {tool}: {status['message']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ {tool}: {status['message']}{Style.RESET_ALL}")
    
    print("\n" + Fore.CYAN + "====== Installation Complete ======" + Style.RESET_ALL)
    print("Some tools may require you to restart your terminal or add paths to your environment manually.")

if __name__ == "__main__":
    install_all_tools()
