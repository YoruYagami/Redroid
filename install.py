import os
import platform
import subprocess
import shutil
import requests
import sys
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

def install_tool(tool):
    try:
        subprocess.run(['pip', 'install', tool, '--break-system-packages'], check=True)
        print(Fore.GREEN + f"✅ {tool} installed successfully." + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error installing {tool}: {e}" + Style.RESET_ALL)

def download_latest_jadx():
    system = platform.system().lower()
    if system == "linux":
        # Check for specific Linux distributions
        distro_info = os.popen('cat /etc/*release').read().lower()
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
    elif system == "windows":
        try:
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
            distro_info = os.popen('cat /etc/*release').read().lower()
            if 'kali' in distro_info or 'debian' in distro_info or 'ubuntu' in distro_info:
                os.system('sudo apt update && sudo apt install apktool -y')
            elif 'arch' in distro_info or 'manjaro' in distro_info or 'blackarch' in distro_info:
                os.system('sudo pacman -Syu apktool --noconfirm')
            else:
                print("Unsupported Linux distribution")
                return
            print(Fore.GREEN + "✅ Apktool installed successfully." + Style.RESET_ALL)
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
            print("Please move apktool.bat and apktool.jar to the C:\\Windows folder manually.")
        else:
            print("Unsupported Operating System")
    except Exception as e:
        print(f"An error occurred while setting up apktool: {str(e)}")

def add_to_system_path(path):
    """Add a directory to the system PATH environment variable."""
    try:
        if platform.system() == 'Windows':
            subprocess.run(f'setx PATH "%PATH%;{path}"', shell=True, check=True)
        else:
            with open(os.path.expanduser('~/.bashrc'), 'a') as f:
                f.write(f'\nexport PATH="$PATH:{path}"\n')
            os.environ['PATH'] += f':{path}'
        print(f"Added {path} to the system PATH.")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error adding {path} to system PATH: {e}" + Style.RESET_ALL)

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
        print("Go is not installed on your system. Please install Go and try again.")
        return

    try:
        print("Installing Nuclei...")
        subprocess.run("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", shell=True, check=True)
        print("Nuclei installed successfully.")

        if not check_nuclei_installed():
            go_bin_path = os.path.expanduser("~/go/bin")
            add_to_system_path(go_bin_path)

            if not check_nuclei_installed():
                print("Nuclei is still not executable. Please check your PATH settings manually.")
            else:
                print("Nuclei is now executable from the terminal.")
        else:
            print("Nuclei is already executable from the terminal.")

    except Exception as e:
        print(f"An error occurred during Nuclei installation: {str(e)}")

def check_go_installed():
    """Check if Go is installed."""
    try:
        subprocess.run(["go", "version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_mob_fs():
    if shutil.which("docker"):
        print("Installing MobSF...")
        try:
            subprocess.run(["docker", "pull", "opensecurity/mobile-security-framework-mobsf:latest"], check=True)
            print("MobSF installed successfully.")
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"Error installing MobSF: {e}" + Style.RESET_ALL)
    else:
        print("Docker is not installed. Please install Docker first.")

def is_apkleaks_installed():
    try:
        subprocess.run(['apkleaks', '-h'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_all_tools():
    init(autoreset=True)

    print(Fore.GREEN + "Starting installation of all tools..." + Style.RESET_ALL)

    # Install Frida
    print("\nInstalling Frida...")
    install_tool("frida-tools")

    # Install Objection
    print("\nInstalling Objection...")
    install_tool("objection")

    # Install reFlutter
    print("\nInstalling reFlutter...")
    install_tool("reFlutter")

    # Install Jadx
    print("\nInstalling Jadx...")
    download_latest_jadx()

    # Install APKTool
    print("\nInstalling APKTool...")
    setup_apktool()

    # Install Nuclei
    print("\nInstalling Nuclei...")
    install_nuclei()

    # Install MobSF
    print("\nInstalling MobSF...")
    install_mob_fs()

    # Install apkleaks
    print("\nInstalling apkleaks...")
    install_tool("apkleaks")

    print(Fore.GREEN + "\nAll tools have been installed successfully!" + Style.RESET_ALL)

if __name__ == "__main__":
    install_all_tools()
