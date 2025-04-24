import os
import platform
import subprocess
import shutil
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init(autoreset=True)

# --- Checks ---
def check_go_installed():
    """Check if Go is installed."""
    try:
        subprocess.run(["go", "version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def check_nuclei_installed():
    """Verify if Nuclei is executable from the terminal."""
    try:
        subprocess.run(["nuclei", "-version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def check_apktool_installed():
    """Check if Apktool is already installed."""
    system = platform.system().lower()
    if system == "linux":
        return shutil.which("apktool") is not None
    elif system == "windows":
        script_dir = os.getcwd()
        jar = os.path.join(script_dir, "apktool.jar")
        bat = os.path.join(script_dir, "apktool.bat")
        return os.path.exists(jar) and os.path.exists(bat)
    return False


# --- Apktool Setup ---
def get_latest_apktool_url():
    """Retrieve the URL for the latest apktool.jar release."""
    url = "https://bitbucket.org/iBotPeaches/apktool/downloads/"
    try:
        resp = requests.get(url)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.endswith('.jar'):
                if not href.startswith('/'):
                    href = '/' + href
                return f"https://bitbucket.org{href}"
    except Exception as e:
        print(Fore.RED + f"Error fetching apktool URL: {e}" + Style.RESET_ALL)
    return None


def setup_apktool():
    """Install or download Apktool depending on the OS."""
    system = platform.system().lower()
    script_dir = os.getcwd() if system == "windows" else os.path.dirname(os.path.abspath(__file__))

    if system == "linux":
        try:
            distro = subprocess.check_output("cat /etc/*release 2>/dev/null || echo 'Unknown'", shell=True).decode().lower()
            if any(x in distro for x in ['debian', 'ubuntu', 'kali']):
                subprocess.run(["sudo", "apt", "update"], check=True)
                subprocess.run(["sudo", "apt", "install", "apktool", "-y"], check=True)
            elif any(x in distro for x in ['arch', 'manjaro', 'blackarch']):
                subprocess.run(["sudo", "pacman", "-Syu", "apktool", "--noconfirm"], check=True)
            else:
                print(Fore.YELLOW + "Unsupported Linux distribution. Please install Apktool manually." + Style.RESET_ALL)
                return
            print(Fore.GREEN + "✅ Apktool installed successfully." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"Error installing Apktool: {e}" + Style.RESET_ALL)

    elif system == "windows":
        bat_url = "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat"
        jar_url = get_latest_apktool_url()
        if not jar_url:
            print(Fore.RED + "Failed to locate latest apktool.jar" + Style.RESET_ALL)
            return

        try:
            print(f"Downloading apktool.bat from {bat_url}")
            r1 = requests.get(bat_url)
            r1.raise_for_status()
            bat_path = os.path.join(script_dir, "apktool.bat")
            with open(bat_path, 'wb') as f:
                f.write(r1.content)

            print(f"Downloading apktool.jar from {jar_url}")
            r2 = requests.get(jar_url)
            r2.raise_for_status()
            jar_path = os.path.join(script_dir, "apktool.jar")
            with open(jar_path, 'wb') as f:
                f.write(r2.content)

            print(Fore.GREEN + f"✅ Apktool setup completed: {bat_path}, {jar_path}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"Error downloading Apktool: {e}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "Unsupported OS. Please install Apktool manually." + Style.RESET_ALL)


# --- Nuclei Installation ---
def install_nuclei():
    """Install Nuclei via Go and verify its execution."""
    if not check_go_installed():
        print(Fore.YELLOW + "Go is not installed. Please install Go and try again." + Style.RESET_ALL)
        return False

    try:
        print("Installing Nuclei...")
        subprocess.run("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", shell=True, check=True)
        if check_nuclei_installed():
            print(Fore.GREEN + "✅ Nuclei is executable from the terminal." + Style.RESET_ALL)
        else:
            go_bin = os.path.expanduser("~/go/bin")
            print(Fore.YELLOW + f"Nuclei not in PATH. Add {go_bin} to your PATH." + Style.RESET_ALL)
        return True
    except Exception as e:
        print(Fore.RED + f"Error installing Nuclei: {e}" + Style.RESET_ALL)
        return False


# --- Main ---
def main():
    print(Fore.CYAN + "--- Tool Installer: Apktool & Nuclei ---" + Style.RESET_ALL)

    # Apktool
    print(Fore.CYAN + "\n[1] Checking Apktool..." + Style.RESET_ALL)
    if not check_apktool_installed():
        print(Fore.CYAN + "Installing Apktool..." + Style.RESET_ALL)
        setup_apktool()
    else:
        print(Fore.GREEN + "Apktool is already installed." + Style.RESET_ALL)

    # Nuclei
    print(Fore.CYAN + "\n[2] Checking Nuclei..." + Style.RESET_ALL)
    if not check_nuclei_installed():
        print(Fore.CYAN + "Installing Nuclei..." + Style.RESET_ALL)
        install_nuclei()
    else:
        print(Fore.GREEN + "Nuclei is already installed." + Style.RESET_ALL)


if __name__ == "__main__":
    main()
