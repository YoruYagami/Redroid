#!/usr/bin/env python3
import os
import subprocess
import platform
import socket
import re
import shutil
import lzma
import sys
import shlex
import ctypes
import time
from platform import system

# Attempt to import external libraries
try:
    import psutil
    import requests
    from requests.exceptions import ConnectionError
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Style
except ImportError as e:
    print(f"ImportError: {e}. Ensure all dependencies are installed and available.")
    sys.exit(1)

# Initialize colorama (if ANSI colors are supported; on Android you may wish to disable these)
init(autoreset=True)

# Global variables
emulator_type = None
emulator_installation_path = None
adb_command = None
device_serial = None

def detect_emulator():
    """Detect whether Nox or Genymotion emulator is running.
       When running on Android, this function is bypassed.
    """
    global emulator_type, emulator_installation_path
    # If running on Android, disable desktop emulator detection.
    if 'ANDROID_ARGUMENT' in os.environ:
        print(Fore.YELLOW + "⚠️ Running on Android device; emulator detection is disabled." + Style.RESET_ALL)
        emulator_type = None
        emulator_installation_path = None
        return None, None

    for process in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            name = process.info.get('name')
            cmdline = process.info.get('cmdline', [])
            exe_path = process.info.get('exe', '')
            if not exe_path:
                continue  # Skip if no executable path
            if name and 'Nox.exe' in name:
                emulator_type = 'Nox'
                emulator_installation_path = os.path.dirname(exe_path)
                break
            elif name and 'player.exe' in name and any('Genymotion' in arg for arg in cmdline):
                emulator_type = 'Genymotion'
                emulator_installation_path = os.path.dirname(exe_path)
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return emulator_type, emulator_installation_path

def get_adb_command(emulator_type, emulator_installation_path):
    """Return the adb command path based on the emulator type.
       On Android, return None.
    """
    if os.environ.get('ANDROID_ARGUMENT'):
        # When running on an Android device, ADB is not used.
        return None

    if emulator_type == 'Nox':
        adb_executable = 'nox_adb.exe'
        adb_command_path = os.path.join(emulator_installation_path, adb_executable)
        if os.path.exists(adb_command_path):
            return f'"{adb_command_path}"'
        else:
            print(Fore.RED + f"❌ {adb_executable} not found in {emulator_installation_path}." + Style.RESET_ALL)
            return 'adb'  # fallback to system adb
    elif emulator_type == 'Genymotion':
        adb_executable = 'adb.exe'
        adb_command_path = os.path.join(emulator_installation_path, 'tools', adb_executable)
        if os.path.exists(adb_command_path):
            return f'"{adb_command_path}"'
        else:
            print(Fore.YELLOW + "⚠️ Genymotion adb not found. Using system adb." + Style.RESET_ALL)
            return 'adb'
    else:
        return 'adb'

def get_connected_devices(adb_command):
    """Retrieve a list of connected devices via adb. Returns an empty list on Android."""
    if adb_command is None:
        return []
    try:
        result = subprocess.run(f'{adb_command} devices', shell=True, capture_output=True, text=True, check=True)
        devices = []
        # Skip the header line
        for line in result.stdout.strip().split('\n')[1:]:
            if line.strip():
                device_serial = line.split()[0]
                devices.append(device_serial)
        return devices
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error executing adb: {e}" + Style.RESET_ALL)
        return []

def run_adb_command(command):
    """Run an adb command for the selected device."""
    global device_serial, adb_command
    if adb_command is None or not device_serial:
        print(Fore.RED + "❗ ADB command cannot run: either not on desktop or no device selected." + Style.RESET_ALL)
        return None
    full_command = f'{adb_command} -s {device_serial} {command}'
    try:
        result = subprocess.run(full_command, shell=True, text=True, capture_output=True, check=True)
        return result
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ adb command failed: {e}" + Style.RESET_ALL)
        return None

def get_local_ipv4_addresses():
    """Retrieve local IPv4 addresses."""
    ip_dict = {}
    for iface_name, iface_addresses in psutil.net_if_addrs().items():
        for addr in iface_addresses:
            if addr.family == socket.AF_INET:
                ip_dict[iface_name] = addr.address
    return ip_dict

def try_download_certificate(ip, port):
    """Attempt to download and install Burp Suite certificate from a given IP and port.
       Instead of using OpenSSL to convert the certificate, simply download the file and rename it.
    """
    cert_url = f"http://{ip}:{port}/cert"
    input_der_file = "cacert.der"
    output_file = "9a5ba575.0"

    try:
        response = requests.get(cert_url, timeout=10)
        if response.status_code == 200:
            with open(input_der_file, "wb") as certificate_file:
                certificate_file.write(response.content)
            print(Fore.GREEN + f"✅ Burp Suite certificate downloaded successfully from {cert_url}." + Style.RESET_ALL)

            # Instead of converting using OpenSSL, simply rename the file
            os.rename(input_der_file, output_file)
            print(Fore.GREEN + f"✅ Renamed {input_der_file} to {output_file}." + Style.RESET_ALL)

            # Push the certificate to the emulator via adb (desktop only)
            result_root = run_adb_command('root')
            if result_root is None:
                print(Fore.RED + "❌ Failed to switch adb to root mode." + Style.RESET_ALL)
                return False

            result_remount = run_adb_command('remount')
            if result_remount is None:
                print(Fore.RED + "❌ Failed to remount the /system partition as read-write." + Style.RESET_ALL)
                return False

            push_result = run_adb_command(f'push {output_file} /system/etc/security/cacerts/')
            if push_result is None:
                print(Fore.RED + "❌ Failed to push the certificate to the system cacerts directory." + Style.RESET_ALL)
                return False

            chmod_result = run_adb_command(f'shell chmod 644 /system/etc/security/cacerts/{output_file}')
            if chmod_result is None:
                print(Fore.RED + "❌ Failed to set permissions on the certificate." + Style.RESET_ALL)
                return False

            print(Fore.GREEN + "✅ Burp Suite Certificate Installed Successfully in the emulator." + Style.RESET_ALL)
            os.remove(output_file)
            return True
        else:
            print(Fore.RED + f"❌ Unable to download the certificate from {cert_url}. Status code: {response.status_code}" + Style.RESET_ALL)
            return False

    except ConnectionError:
        print(Fore.RED + f"❌ Burp Suite is not running or the proxy server is not on {ip}:{port}." + Style.RESET_ALL)
        return False
    except Exception as e:
        print(Fore.RED + f"❌ An unexpected error occurred: {str(e)}" + Style.RESET_ALL)
        return False

def install_burpsuite_certificate(port):
    """Install Burp Suite certificate into the emulator."""
    print(Fore.CYAN + "🔍 Attempting to download the Burp Suite certificate from localhost..." + Style.RESET_ALL)
    if try_download_certificate('127.0.0.1', port):
        print(Fore.GREEN + "✅ Successfully downloaded and installed the Burp Suite certificate from localhost." + Style.RESET_ALL)
        return

    print(Fore.CYAN + "🔍 Checking other local IP addresses for Burp Suite certificate..." + Style.RESET_ALL)
    ipv4_addresses = get_local_ipv4_addresses()
    for ip in ipv4_addresses.values():
        if ip != '127.0.0.1' and try_download_certificate(ip, port):
            print(Fore.GREEN + f"✅ Successfully downloaded and installed the Burp Suite certificate from {ip}." + Style.RESET_ALL)
            return

    print(Fore.RED + "❌ Failed to download the Burp Suite certificate from any local IP address." + Style.RESET_ALL)

def install_tool(tool):
    """Install a Python tool using pip."""
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', tool, '--break-system-packages'], check=True)
        print(Fore.GREEN + f"✅ {tool} installed successfully." + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error installing {tool}: {e}" + Style.RESET_ALL)

def download_latest_jadx():
    """Download the latest version of Jadx based on the operating system."""
    system = platform.system().lower()
    if system == "linux":
        if os.path.exists("/etc/debian_version"):
            print("Detected Debian-based system (e.g., Kali Linux)")
            os.system("sudo apt update && sudo apt install jadx -y")
            print("Jadx installed successfully via apt.")
        elif os.path.exists("/etc/arch-release"):
            print("Detected Arch Linux")
            os.system("sudo pacman -Syu jadx --noconfirm")
            print("Jadx installed successfully via pacman.")
        else:
            print("⚠️ Unsupported Linux distribution. Please install Jadx manually.")
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
                    script_dir = os.path.dirname(os.path.abspath(__file__))
                    local_filepath = os.path.join(script_dir, "jadx-gui.exe")
                    print(f"Downloading {local_filename} from {download_url}")
                    with requests.get(download_url, stream=True) as r:
                        r.raise_for_status()
                        with open(local_filepath, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=8192):
                                f.write(chunk)
                    print(f"Downloaded and renamed {local_filename} to jadx-gui.exe in: {local_filepath}")
                    return
            print("❌ No suitable Jadx executable found in the latest release.")
        except Exception as e:
            print(Fore.RED + f"❌ An error occurred while trying to download Jadx: {str(e)}" + Style.RESET_ALL)
    else:
        print(f"❌ Unsupported operating system: {system}. Please install Jadx manually.")

def get_latest_apktool_url():
    """Retrieve the latest apktool.jar download URL from the official repository."""
    url = "https://bitbucket.org/iBotPeaches/apktool/downloads/"
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and href.endswith('.jar'):
                return f"https://bitbucket.org{href}"
    except Exception as e:
        print(Fore.RED + f"❌ Error fetching apktool URL: {e}" + Style.RESET_ALL)
    return None

def setup_apktool():
    """Set up apktool on the system."""
    try:
        system = platform.system().lower()
        if system == "linux":
            distro_info = os.popen('cat /etc/*release').read().lower()
            if 'kali' in distro_info or 'debian' in distro_info or 'ubuntu' in distro_info:
                os.system('sudo apt update && sudo apt install apktool -y')
                print("✅ Apktool installed successfully via apt.")
            elif 'arch' in distro_info or 'manjaro' in distro_info:
                os.system('sudo pacman -Syu apktool --noconfirm')
                print("✅ Apktool installed successfully via pacman.")
            else:
                print("⚠️ Unsupported Linux distribution. Please install Apktool manually.")
        elif system == "windows":
            bat_url = "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat"
            jar_url = get_latest_apktool_url()
            if not jar_url:
                print("❌ Failed to find the latest apktool.jar.")
                return

            script_dir = os.path.dirname(os.path.abspath(__file__))
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
            print(f"✅ Apktool setup completed. Files downloaded to: {bat_path} and {jar_path}")
            print("⚠️ Please move apktool.bat and apktool.jar to a directory in your PATH (e.g., C:\\Windows).")
        else:
            print("❌ Unsupported Operating System. Please install Apktool manually.")
    except Exception as e:
        print(Fore.RED + f"❌ An error occurred while setting up Apktool: {str(e)}" + Style.RESET_ALL)

def check_nuclei_installed():
    """Check if Nuclei can be executed from the terminal."""
    try:
        subprocess.run(["nuclei", "-version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def check_go_installed():
    """Check if Go is installed."""
    try:
        subprocess.run(["go", "version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_nuclei():
    """Install Nuclei using Go and ensure it's executable from any terminal."""
    if not check_go_installed():
        print(Fore.RED + "❌ Go is not installed on your system. Please install Go and try again." + Style.RESET_ALL)
        return
    try:
        print("✅ Installing Nuclei...")
        subprocess.run("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", shell=True, check=True)
        print(Fore.GREEN + "✅ Nuclei installed successfully." + Style.RESET_ALL)
        if not shutil.which("nuclei"):
            print(Fore.YELLOW + "⚠️ Nuclei is not executable. Please ensure the installation directory is in your PATH." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "✅ Nuclei is executable from the terminal." + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error during Nuclei installation: {e}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"❌ An unexpected error occurred during Nuclei installation: {str(e)}" + Style.RESET_ALL)

def remove_ads_and_bloatware():
    """Remove ads and bloatware from the emulator."""
    if not emulator_type:
        print(Fore.RED + "❗ No emulator detected. Please start an emulator and try again." + Style.RESET_ALL)
        return
    if not device_serial:
        print(Fore.RED + "❗ No device selected. Please connect to an emulator and try again." + Style.RESET_ALL)
        return
    print(Fore.CYAN + "🧹 Removing Bloatware and Ads from the emulator..." + Style.RESET_ALL)
    run_adb_command('root')
    run_adb_command('remount')
    bloatware_apps = [
        'AmazeFileManager', 'AppStore', 'CtsShimPrebuilt', 'EasterEgg', 'Facebook',
        'Helper', 'LiveWallpapersPicker', 'PrintRecommendationService', 'PrintSpooler',
        'WallpaperBackup', 'newAppNameEn'
    ]
    for app in bloatware_apps:
        print(Fore.YELLOW + f"🚮 Removing {app}..." + Style.RESET_ALL)
        run_adb_command(f'shell rm -rf /system/app/{app}')
    print(Fore.GREEN + "✅ Bloatware removed successfully." + Style.RESET_ALL)
    print(Fore.CYAN + "🔄 Rebooting the emulator..." + Style.RESET_ALL)
    run_adb_command("shell su -c 'setprop ctl.restart zygote'")
    print(Fore.GREEN + "✅ After successful reboot, configure your settings as needed." + Style.RESET_ALL)

def is_apkleaks_installed():
    """Check if apkleaks is installed."""
    try:
        subprocess.run(['apkleaks', '-h'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def run_apkleaks():
    """Run apkleaks on a specified APK file and automatically save the output."""
    if not is_apkleaks_installed():
        print(Fore.RED + "❌ apkleaks is not installed or not found in your PATH. Please install it using 'pip install apkleaks'." + Style.RESET_ALL)
        return
    apk_path = input("📝 Enter the path to the APK file: ").strip()
    if not os.path.isfile(apk_path):
        print(Fore.RED + f"❌ Error: The file '{apk_path}' does not exist or is not valid." + Style.RESET_ALL)
        return
    print(Fore.CYAN + f"\n🔍 Running apkleaks on '{apk_path}'..." + Style.RESET_ALL)
    try:
        output_filename = f"{os.path.splitext(os.path.basename(apk_path))[0]}_apkleaks_output.txt"
        output_path = os.path.join(os.getcwd(), output_filename)
        command = ['apkleaks', '-f', apk_path, '-o', output_path]
        subprocess.run(command, check=True)
        print(Fore.GREEN + f"✅ apkleaks output saved to '{output_path}'." + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error running apkleaks: {e}" + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + "❌ apkleaks is not installed. Please install it using 'pip install apkleaks'." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"❌ An unexpected error occurred: {str(e)}" + Style.RESET_ALL)

def is_frida_server_running():
    """Check if a Frida-Server process is currently running on the device."""
    global adb_command, device_serial
    if adb_command is None or not device_serial:
        return False
    try:
        # Run the pgrep command. pgrep returns non-zero if no match is found.
        result = subprocess.run(f'{adb_command} -s {device_serial} shell pgrep -f frida-server',
                                  shell=True, capture_output=True, text=True)
        if result.stdout.strip():
            return True
        else:
            return False
    except Exception:
        return False

def install_frida_server():
    """
    Checks if Frida-Server is already running on the device.
    If not running, downloads the Frida-Server binary matching the installed Frida version
    and the device CPU architecture, then installs it on the device using:
      adb root && sleep 2 && adb remount
      adb push frida-server /data/local/tmp/
      adb shell "chmod 755 /data/local/tmp/frida-server"
    """
    global adb_command, device_serial

    if adb_command is None or not device_serial:
        print(Fore.RED + "❌ ADB command unavailable or no device selected. Cannot install Frida-Server." + Style.RESET_ALL)
        return

    # Initial check: if Frida-Server is already running, we skip installation.
    if is_frida_server_running():
        print(Fore.GREEN + "✅ Frida-Server is already running on the device." + Style.RESET_ALL)
        return

    # Step 1: Get the installed Frida-Tools version.
    try:
        frida_version_output = subprocess.check_output("frida --version", shell=True, stderr=subprocess.STDOUT, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(Fore.RED + "❌ Frida Tools is not installed on this system. Please install Frida Tools first." + Style.RESET_ALL)
        return

    version_match = re.search(r'(\d+\.\d+\.\d+)', frida_version_output)
    if not version_match:
        print(Fore.RED + "❌ Unable to determine Frida Tools version." + Style.RESET_ALL)
        return
    frida_version = version_match.group(1)
    print(Fore.GREEN + f"✅ Frida-Tools Version: {frida_version}" + Style.RESET_ALL)

    # Step 2: Get the device's CPU architecture.
    arch_result = run_adb_command('shell getprop ro.product.cpu.abi')
    if arch_result and arch_result.stdout.strip():
        emulator_arch = arch_result.stdout.strip()
        print(Fore.GREEN + f"✅ Device CPU Architecture: {emulator_arch}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Unable to determine device CPU architecture." + Style.RESET_ALL)
        return

    # Step 3: Construct the download URL for the matching frida-server binary.
    frida_server_url = f"https://github.com/frida/frida/releases/download/{frida_version}/frida-server-{frida_version}-android-{emulator_arch}.xz"
    print(Fore.CYAN + f"🔗 Downloading Frida-Server from: {frida_server_url}" + Style.RESET_ALL)

    try:
        response = requests.get(frida_server_url, stream=True, timeout=15)
        response.raise_for_status()
        with open("frida-server.xz", "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(Fore.GREEN + "✅ Frida-Server downloaded successfully." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"❌ Failed to download Frida-Server: {e}" + Style.RESET_ALL)
        return

    # Step 4: Decompress the downloaded file using lzma.
    try:
        with lzma.open("frida-server.xz") as compressed_file:
            with open("frida-server", "wb") as out_file:
                shutil.copyfileobj(compressed_file, out_file)
        os.remove("frida-server.xz")
        print(Fore.GREEN + "✅ Frida-Server decompressed successfully." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"❌ Failed to decompress Frida-Server: {e}" + Style.RESET_ALL)
        return

    # Step 5: Install Frida-Server on the device.
    try:
        print(Fore.CYAN + "🔧 Setting device to root mode and remounting system partition..." + Style.RESET_ALL)
        subprocess.run(f'{adb_command} -s {device_serial} root', shell=True, check=True)
        # Use Python's sleep instead of an external sleep command.
        time.sleep(2)
        subprocess.run(f'{adb_command} -s {device_serial} remount', shell=True, check=True)
        print(Fore.GREEN + "✅ Device is in root mode and system partition is remounted." + Style.RESET_ALL)

        print(Fore.CYAN + "📦 Pushing Frida-Server to /data/local/tmp/..." + Style.RESET_ALL)
        subprocess.run(f'{adb_command} -s {device_serial} push frida-server /data/local/tmp/', shell=True, check=True)
        print(Fore.GREEN + "✅ Frida-Server pushed successfully." + Style.RESET_ALL)

        print(Fore.CYAN + "🔧 Setting executable permissions on Frida-Server..." + Style.RESET_ALL)
        subprocess.run(f'{adb_command} -s {device_serial} shell "chmod 755 /data/local/tmp/frida-server"', shell=True, check=True)
        print(Fore.GREEN + "✅ Permissions set: Frida-Server is ready." + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error during Frida-Server installation: {e}" + Style.RESET_ALL)
        return

    # Optionally remove the local frida-server binary file if it's no longer needed.
    try:
        os.remove("frida-server")
    except Exception:
        pass

def run_frida_server():
    """Start Frida-Server without pre-checks and ignore bind errors if port is in use."""
    global adb_command, device_serial
    if adb_command is None or not device_serial:
        print(Fore.RED + "❌ ADB command cannot run: either not on desktop or no device selected." + Style.RESET_ALL)
        return

    command = f'shell "/data/local/tmp/frida-server &"'
    full_command = f'{adb_command} -s {device_serial} {command}'

    try:
        result = subprocess.run(full_command, shell=True, capture_output=True, check=True, text=True)
        if "Error binding to address" in result.stderr:
            print(Fore.YELLOW + result.stderr.strip() + Style.RESET_ALL)
        print(Fore.GREEN + "✅ Frida-Server started." + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Failed to start Frida-Server: {e}" + Style.RESET_ALL)



def list_installed_applications():
    """List installed applications on the emulator using Frida."""
    if not is_frida_server_running():
        print(Fore.YELLOW + "⚠️ Frida-Server is not running. Attempting to start it..." + Style.RESET_ALL)
        run_frida_server()
        if not is_frida_server_running():
            print(Fore.RED + "❌ Frida-Server is not running. Cannot list applications." + Style.RESET_ALL)
            return
    print(Fore.CYAN + "📜 Listing installed applications on the emulator..." + Style.RESET_ALL)
    try:
        result = subprocess.run(['frida-ps', '-Uai'], capture_output=True, text=True, check=True)
        print(Fore.GREEN + result.stdout + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error listing applications: {e}" + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + "❌ Frida is not installed or not found in your PATH. Please install Frida." + Style.RESET_ALL)

def run_ssl_pinning_bypass():
    """Run SSL Pinning Bypass using Frida."""
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frida-scripts', 'ssl-pinning-bypass.js')
    if not os.path.exists(script_path):
        print(Fore.RED + f"❌ Script not found at {script_path}. Ensure the script is in the 'frida-scripts' directory." + Style.RESET_ALL)
        return
    if not is_frida_server_running():
        print(Fore.YELLOW + "⚠️ Frida-Server is not running. Attempting to start it..." + Style.RESET_ALL)
        run_frida_server()
        if not is_frida_server_running():
            print(Fore.RED + "❌ Frida-Server is not running. Cannot proceed with SSL Pinning Bypass." + Style.RESET_ALL)
            return
    list_installed_applications()
    app_package = input("📱 Enter the app package name to run the SSL pinning bypass on: ").strip()
    if app_package:
        cmd = f'frida -U -f {app_package} -l "{script_path}" --no-pause'
        print(Fore.CYAN + f"🚀 Running SSL Pinning Bypass on {app_package}..." + Style.RESET_ALL)
        open_new_terminal(cmd)
    else:
        print(Fore.RED + "❌ Invalid package name. Please enter a valid app package name." + Style.RESET_ALL)

def run_root_check_bypass():
    """Run Root Check Bypass using Frida."""
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frida-scripts', 'root-check-bypass.js')
    if not os.path.exists(script_path):
        print(Fore.RED + f"❌ Script not found at {script_path}. Ensure the script is in the 'frida-scripts' directory." + Style.RESET_ALL)
        return
    if not is_frida_server_running():
        print(Fore.YELLOW + "⚠️ Frida-Server is not running. Attempting to start it..." + Style.RESET_ALL)
        run_frida_server()
        if not is_frida_server_running():
            print(Fore.RED + "❌ Frida-Server is not running. Cannot proceed with Root Check Bypass." + Style.RESET_ALL)
            return
    list_installed_applications()
    app_package = input("📱 Enter the app package name to run the Root Check Bypass on: ").strip()
    if app_package:
        cmd = f'frida -U -f {app_package} -l "{script_path}" --no-pause'
        print(Fore.CYAN + f"🚀 Running Root Check Bypass on {app_package}..." + Style.RESET_ALL)
        open_new_terminal(cmd)
    else:
        print(Fore.RED + "❌ Invalid package name. Please enter a valid app package name." + Style.RESET_ALL)

def android_biometric_bypass():
    """Run Android Biometric Bypass using Frida."""
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frida-scripts', 'android-biometric-bypass.js')
    if not os.path.exists(script_path):
        print(Fore.RED + f"❌ Script not found at {script_path}. Ensure the script is in the 'frida-scripts' directory." + Style.RESET_ALL)
        return
    if not is_frida_server_running():
        print(Fore.YELLOW + "⚠️ Frida-Server is not running. Attempting to start it..." + Style.RESET_ALL)
        run_frida_server()
        if not is_frida_server_running():
            print(Fore.RED + "❌ Frida-Server is not running. Cannot proceed with Android Biometric Bypass." + Style.RESET_ALL)
            return
    list_installed_applications()
    app_package = input("📱 Enter the app package name to run the Android Biometric Bypass on: ").strip()
    if app_package:
        cmd = f'frida -U -f {app_package} -l "{script_path}" --no-pause'
        print(Fore.CYAN + f"🚀 Running Android Biometric Bypass on {app_package}..." + Style.RESET_ALL)
        open_new_terminal(cmd)
    else:
        print(Fore.RED + "❌ Invalid package name. Please enter a valid app package name." + Style.RESET_ALL)

def run_custom_frida_script():
    """Run a custom Frida script provided by the user."""
    frida_scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frida-scripts')
    known_scripts = {
        'ssl-pinning-bypass.js',
        'root-check-bypass.js',
        'android-biometric-bypass.js'
    }
    if not os.path.exists(frida_scripts_dir):
        print(Fore.RED + f"❌ 'frida-scripts' directory does not exist at {frida_scripts_dir}." + Style.RESET_ALL)
        return

    all_scripts = {f for f in os.listdir(frida_scripts_dir) if f.endswith('.js')}
    unknown_scripts = all_scripts - known_scripts
    script_path = None

    if unknown_scripts:
        print(Fore.CYAN + "\n🔍 Detected custom scripts in 'frida-scripts':" + Style.RESET_ALL)
        unknown_scripts_list = list(unknown_scripts)
        for idx, script in enumerate(unknown_scripts_list, 1):
            print(f"{Fore.YELLOW}{idx}. {script}{Style.RESET_ALL}")
        use_existing = input(Fore.CYAN + "✨ Execute one of these custom scripts? (y/n): " + Style.RESET_ALL).strip().lower()
        if use_existing in ['y', 'yes']:
            script_choice = input(f"🎯 Enter the number (1-{len(unknown_scripts_list)}): ").strip()
            if script_choice.isdigit() and 1 <= int(script_choice) <= len(unknown_scripts_list):
                script_path = os.path.join(frida_scripts_dir, unknown_scripts_list[int(script_choice) - 1])
            else:
                print(Fore.RED + "❌ Invalid choice. Exiting." + Style.RESET_ALL)
                return
        else:
            print(Fore.YELLOW + "⚠️ It is recommended to place your custom script in 'frida-scripts'." + Style.RESET_ALL)
            script_path = input(Fore.CYAN + "📝 Enter the full path to your custom Frida script: " + Style.RESET_ALL).strip()
    else:
        print(Fore.YELLOW + "⚠️ No custom scripts detected in 'frida-scripts'." + Style.RESET_ALL)
        print(Fore.YELLOW + "⚠️ It is recommended to place your script in 'frida-scripts'." + Style.RESET_ALL)
        script_path = input(Fore.CYAN + "📝 Enter the full path to your custom Frida script: " + Style.RESET_ALL).strip()

    if not os.path.isfile(script_path):
        print(Fore.RED + f"❌ The script '{script_path}' does not exist or is invalid." + Style.RESET_ALL)
        return
    if not is_frida_server_running():
        print(Fore.YELLOW + "⚠️ Frida-Server is not running. Attempting to start it..." + Style.RESET_ALL)
        run_frida_server()
        if not is_frida_server_running():
            print(Fore.RED + "❌ Frida-Server is not running. Cannot proceed with the custom script." + Style.RESET_ALL)
            return
    list_installed_applications()
    app_package = input(Fore.CYAN + "📱 Enter the app package name for the custom script: " + Style.RESET_ALL).strip()
    if app_package:
        cmd = f'frida -U -f {app_package} -l "{script_path}" --no-pause'
        print(Fore.CYAN + f"🚀 Running custom Frida script on {app_package}..." + Style.RESET_ALL)
        open_new_terminal(cmd)
    else:
        print(Fore.RED + "❌ Invalid package name. Exiting." + Style.RESET_ALL)

def install_mob_fs():
    """Install MobSF using Docker."""
    if shutil.which("docker"):
        print(Fore.CYAN + "🔄 Pulling the latest MobSF Docker image..." + Style.RESET_ALL)
        try:
            subprocess.run("docker pull opensecurity/mobile-security-framework-mobsf:latest", shell=True, check=True)
            print(Fore.GREEN + "✅ MobSF Docker image pulled successfully." + Style.RESET_ALL)
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"❌ Failed to pull MobSF Docker image: {e}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Docker is not installed. Please install Docker first." + Style.RESET_ALL)

def get_emulator_ip():
    """Retrieve emulator's IP address."""
    if not device_serial:
        print(Fore.RED + "❗ No device selected. Cannot get emulator IP." + Style.RESET_ALL)
        return None
    result = run_adb_command('shell getprop dhcp.eth0.ipaddress')
    if result and result.stdout.strip():
        ip_address = result.stdout.strip()
        print(Fore.GREEN + f"✅ Emulator IP Address: {ip_address}" + Style.RESET_ALL)
        return ip_address
    else:
        result = run_adb_command('shell ip -f inet addr show eth0')
        if result and result.stdout.strip():
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/\d+', result.stdout)
            if match:
                ip_address = match.group(1)
                print(Fore.GREEN + f"✅ Emulator IP Address: {ip_address}" + Style.RESET_ALL)
                return ip_address
    print(Fore.RED + "❗ Could not get emulator IP address." + Style.RESET_ALL)
    return None

def run_command_in_background(cmd):
    """Run a command in the background."""
    if platform.system() == "Windows":
        subprocess.Popen(f'start /B {cmd}', shell=True)
    else:
        subprocess.Popen(f'{cmd} &', shell=True)

def open_new_terminal(cmd):
    """Open a new terminal and execute the given command.
       On Android, simply prints the command.
    """
    if os.environ.get('ANDROID_ARGUMENT'):
        print(Fore.YELLOW + "⚠️ open_new_terminal is not supported on Android. Run this command manually:" + Style.RESET_ALL)
        print(Fore.YELLOW + cmd + Style.RESET_ALL)
        return
    try:
        if platform.system() == "Windows":
            subprocess.Popen(f'start cmd /k "{cmd}"', shell=True)
        elif platform.system() == "Darwin":
            apple_script = f'''
            tell application "Terminal"
                do script "{cmd}"
                activate
            end tell
            '''
            subprocess.Popen(['osascript', '-e', apple_script])
        else:
            terminal_emulators = ['gnome-terminal', 'konsole', 'xterm', 'lxterminal', 'xfce4-terminal', 'mate-terminal', 'terminator', 'urxvt']
            for term in terminal_emulators:
                if shutil.which(term):
                    subprocess.Popen([term, '-e', cmd])
                    break
            else:
                print(Fore.RED + "❌ No supported terminal emulator found. Run this command manually:" + Style.RESET_ALL)
                print(Fore.YELLOW + cmd + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"❌ Failed to open a new terminal: {e}" + Style.RESET_ALL)

def run_mob_fs():
    """Run MobSF using Docker."""
    if shutil.which("docker"):
        if not device_serial:
            print(Fore.CYAN + "🔄 Running MobSF without MOBSF_ANALYZER_IDENTIFIER..." + Style.RESET_ALL)
            cmd = "docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"
        else:
            if device_serial.startswith('emulator-'):
                port = device_serial.split('-')[1]
            elif re.match(r'^\d+\.\d+\.\d+\.\d+:\d+$', device_serial):
                port = device_serial.split(':')[1]
            else:
                print(Fore.YELLOW + "⚠️ Connected device is not an emulator. Running MobSF without identifier..." + Style.RESET_ALL)
                cmd = "docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"
                open_new_terminal(cmd)
                return
            emulator_ip = get_emulator_ip()
            if emulator_ip is None:
                print(Fore.YELLOW + "⚠️ Could not get emulator IP. Running MobSF without identifier..." + Style.RESET_ALL)
                cmd = "docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"
            else:
                mobsf_analyzer_identifier = f"{emulator_ip}:{port}"
                print(Fore.CYAN + f"🔧 Running MobSF with MOBSF_ANALYZER_IDENTIFIER='{mobsf_analyzer_identifier}'..." + Style.RESET_ALL)
                cmd = f"docker run -it --rm -e MOBSF_ANALYZER_IDENTIFIER='{mobsf_analyzer_identifier}' --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"
        open_new_terminal(cmd)
    else:
        print(Fore.RED + "❌ Docker is not installed. Please install Docker first." + Style.RESET_ALL)

def run_nuclei_against_apk():
    """Decompiles an APK, runs nuclei with templates, and saves output optionally.
       Handles paths with single/double quotes and spaces.
    """

    while True:
        apk_path_input = input("Enter the path to the APK file: ").strip()
        apk_path = apk_path_input.strip("'").strip('"')

        if os.path.exists(apk_path):
            break
        else:
            print(f"Error: The file {apk_path_input} (or {apk_path} after quote removal) does not exist.")

    script_dir = os.getcwd()
    output_dir = os.path.join(script_dir, os.path.splitext(os.path.basename(apk_path))[0])

    if os.path.exists(output_dir):
        print(f"\n⚠️ The directory \"{output_dir}\" already exists.")
        print("What would you like to do?")
        print("1. Scan directly using the existing Apktool output")
        print("2. Overwrite the output with a fresh decompilation")

        action_choice = input("\nEnter your choice (1 or 2): ").strip()

        if action_choice not in ['1', '2']:
            print("\n❌ Invalid choice. Operation cancelled.\n")
            return

    apktool_command = "apktool" if system().lower() != "windows" else "apktool.bat"
    try:
        subprocess.run(shlex.split(f"{apktool_command} d \"{apk_path}\" -o \"{output_dir}\""), check=True)
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error: Failed to decompile APK. {e}\n")
        return
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}. Ensure apktool is installed and accessible.")
        return

    user_home = os.path.expanduser("~")
    android_template_path = os.path.join(user_home, "nuclei-templates", "file", "android")
    keys_template_path = os.path.join(user_home, "nuclei-templates", "file", "keys")

    print("\nPlease choose which templates to use:")
    print("1. Android Templates")
    print("2. Keys Templates")
    print("3. Both (Android + Keys)")
    template_choice = input("Enter the number of your choice: ").strip()

    templates_paths = []
    if template_choice == '1':
        templates_paths.append(android_template_path)
    elif template_choice == '2':
        templates_paths.append(keys_template_path)
    elif template_choice == '3':
        templates_paths.extend([android_template_path, keys_template_path])
    else:
        print("Invalid choice. Exiting.")
        return

    for path in templates_paths:
        if not os.path.exists(path):
            print(f"Templates directory not found at {path}.")
            return

    nuclei_command = ["nuclei", "-target", output_dir, "-file"]
    for template_path in templates_paths:
        nuclei_command.extend(["-t", template_path])

    print("Nuclei command:", nuclei_command)  # Debugging print
    print("Template paths:", templates_paths) # Debugging print

    try:
        result = subprocess.run(nuclei_command, check=True, capture_output=True, text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to run nuclei. {e}")
        print(f"Stderr: {e.stderr}") # Print stderr for more details
        return

    save_output = input("Do you want to save the output? (y/n): ").strip().lower()
    if save_output in ['y', 'yes']:
        output_file = os.path.join(script_dir, f"{os.path.splitext(os.path.basename(output_dir))[0]}_nuclei_output.txt")
        with open(output_file, "w") as file:
            file.write(result.stdout)
        print(f"Output saved to {output_file}")

    print("Analysis complete.")

def is_go_installed():
    """Check if Go is installed."""
    try:
        subprocess.run(["go", "version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_nuclei_wrapper():
    """Wrapper function for installing nuclei."""
    if not check_go_installed():
        print(Fore.RED + "❌ Go is not installed on your system. Please install Go and try again." + Style.RESET_ALL)
        return
    try:
        print("✅ Installing Nuclei...")
        subprocess.run("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", shell=True, check=True)
        print(Fore.GREEN + "✅ Nuclei installed successfully." + Style.RESET_ALL)
        if not check_nuclei_installed():
            go_bin_path = os.path.expanduser("~\\go\\bin") if platform.system().lower() == "windows" else os.path.expanduser("~/go/bin")
            add_to_system_path(go_bin_path)
            if not check_nuclei_installed():
                print(Fore.YELLOW + "⚠️ Nuclei is still not executable. Attempting to add to PATH with administrative privileges..." + Style.RESET_ALL)
                if is_admin():
                    add_to_system_path(go_bin_path)
                else:
                    print("🔄 Requesting administrative privileges...")
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
                    return
            if not check_nuclei_installed():
                print(Fore.RED + "❌ Nuclei is still not executable. Please check your PATH settings manually." + Style.RESET_ALL)
            else:
                print(Fore.GREEN + "✅ Nuclei is now executable from the terminal." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "✅ Nuclei is already executable from the terminal." + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error during Nuclei installation: {e}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"❌ An unexpected error occurred during Nuclei installation: {str(e)}" + Style.RESET_ALL)

def add_to_system_path(new_path):
    """Stub for adding a directory to system PATH.
       Implementation will vary by OS and permissions.
    """
    print(Fore.YELLOW + f"Attempting to add {new_path} to system PATH..." + Style.RESET_ALL)
    # Placeholder – actual implementation depends on OS.
    pass

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def show_main_menu():
    """Display the main menu.
       On Android, consider replacing with UI elements.
    """
    print(Fore.CYAN + r"""
    __________       ________               .__    .___
    \______   \ ____ \______ \_______  ____ |__| __| _/
     |       _// __ \ |    |  \_  __ \/  _ \|  |/ __ | 
     |    |   \  ___/ |       \  | \(  <_> )  / /_/ | 
     |____|_  /\___  >_______  /__|   \____/|__\____ | 
            \/     \/        \/                     \/ 
    """ + Style.RESET_ALL)
    print(Fore.GREEN + "Welcome to the Redroid Tool!" + Style.RESET_ALL)
    print("=" * 50)
    print("1. 🛠️  Install Tools")
    print("2. 🚀  Run Tools")
    print("3. 🎮  Emulator Options")
    print("4. 🕵️  Frida")
    print("5. ❌  Exit")

def show_install_tools_menu():
    """Display the Install Tools submenu."""
    print("\n" + "=" * 50)
    print(f"{'Install Tools':^50}")
    print("=" * 50)
    print("1. 🧩  Frida")
    print("2. 🔐  Objection")
    print("3. 🛠️  reFlutter")
    print("4. 🖥️  Jadx")
    print("5. 🗃️  APKTool")
    print("6. 🔎  Nuclei")
    print("7. 📦  MobSF (docker)")
    print("8. 🔍  apkleaks")
    print("9. ↩️  Back")

def show_run_tools_menu():
    """Display the Run Tools submenu."""
    print("\n" + "=" * 50)
    print(f"{'Run Tools':^50}")
    print("=" * 50)
    print("1. 🛡️  Run MobSF (docker)")
    print("2. 🔍  Run nuclei against APK")
    print("3. 🕵️  Run apkleaks against APK")
    print("4. ↩️  Back")

def show_emulator_options_menu():
    """Display the Emulator Options submenu."""
    print("\n" + "=" * 50)
    print(f"{'Emulator Options':^50}")
    print("=" * 50)
    print("1. 🧹  Remove Ads and Bloatware from Nox Emulator")
    print("2. 🛡️  Install Burp Certificate")
    print("3. 💻  Open ADB shell")
    print("4. 🌐  Print proxy status")
    print("5. ⚙️  Set up/modify proxy")
    print("6. ❌  Remove proxy")
    print("7. ↩️  Back")

def show_frida_menu():
    """Display the Frida submenu."""
    print("\n" + "=" * 50)
    print(f"{'Frida':^50}")
    print("=" * 50)
    print("1. 🧩  Install Frida Server")
    print("2. ▶️  Run Frida Server")
    print("3. 📜  List installed applications")
    print("4. 🔓  Run SSL Pinning Bypass")
    print("5. 🛡️  Run Root Check Bypass")
    print("6. 🔑  Android Biometric Bypass")
    print("7. 📝  Run Custom Script")
    print("8. ↩️  Back")

def main():
    """Main function to run the tool."""
    global emulator_type, emulator_installation_path, adb_command, device_serial

    # Detect emulator (desktop only)
    emulator_type, emulator_installation_path = detect_emulator()
    if emulator_type:
        print(Fore.GREEN + f"✅ Emulator detected: {emulator_type}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "⚠️ Emulator not detected or running on Android." + Style.RESET_ALL)

    adb_command = get_adb_command(emulator_type, emulator_installation_path)
    devices = get_connected_devices(adb_command)
    if not devices:
        print(Fore.YELLOW + "⚠️ No devices connected via adb." + Style.RESET_ALL)
        device_serial = None
    elif len(devices) == 1:
        device_serial = devices[0]
        print(Fore.GREEN + f"✅ Device connected: {device_serial}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "⚠️ Multiple devices connected:" + Style.RESET_ALL)
        for idx, dev in enumerate(devices, 1):
            print(f"{idx}. {dev}")
        choice = input("🔢 Select a device by number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(devices):
            device_serial = devices[int(choice) - 1]
            print(Fore.GREEN + f"✅ Device selected: {device_serial}" + Style.RESET_ALL)
        else:
            print(Fore.RED + "❌ Invalid choice. No device selected." + Style.RESET_ALL)
            device_serial = None

    # Main loop. Replace with Android UI interactions as needed.
    while True:
        show_main_menu()
        main_choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()

        if main_choice == '1':
            # Install Tools menu
            while True:
                show_install_tools_menu()
                tools_choice = input(Fore.CYAN + "🛠️ Enter your choice: " + Style.RESET_ALL).strip()
                if tools_choice == '1':
                    install_tool("frida-tools")
                elif tools_choice == '2':
                    install_tool("objection")
                elif tools_choice == '3':
                    install_tool("reFlutter")
                elif tools_choice == '4':
                    download_latest_jadx()
                elif tools_choice == '5':
                    setup_apktool()
                elif tools_choice == '6':
                    install_nuclei()
                elif tools_choice == '7':
                    install_mob_fs()
                elif tools_choice == '8':
                    install_tool("apkleaks")
                elif tools_choice == '9':
                    break
                else:
                    print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)
        elif main_choice == '2':
            # Run Tools menu
            while True:
                show_run_tools_menu()
                run_tools_choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()
                if run_tools_choice == '1':
                    run_mob_fs()
                elif run_tools_choice == '2':
                    run_nuclei_against_apk()
                elif run_tools_choice == '3':
                    run_apkleaks()
                elif run_tools_choice == '4':
                    break
                else:
                    print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)
        elif main_choice == '3':
            # Emulator Options menu
            while True:
                show_emulator_options_menu()
                emulator_choice = input(Fore.CYAN + "🕹️ Enter your choice: " + Style.RESET_ALL).strip()
                if emulator_choice == '1':
                    remove_ads_and_bloatware()
                elif emulator_choice == '2':
                    port = input(Fore.CYAN + "📝 Enter the port Burp Suite is using: " + Style.RESET_ALL).strip()
                    if port.isdigit():
                        install_burpsuite_certificate(int(port))
                    else:
                        print(Fore.RED + "❌ Invalid port. Enter a valid port number." + Style.RESET_ALL)
                elif emulator_choice == '3':
                    if adb_command:
                        subprocess.run(f'{adb_command} -s {device_serial} shell', shell=True)
                    else:
                        print(Fore.RED + "❌ ADB shell not available on this device." + Style.RESET_ALL)
                elif emulator_choice == '4':
                    result = run_adb_command('shell settings get global http_proxy')
                    if result and result.stdout.strip():
                        print(Fore.CYAN + "🌐 Current proxy: " + Fore.GREEN + result.stdout.strip() + Style.RESET_ALL)
                    else:
                        print(Fore.YELLOW + "⚠️ No proxy is currently set." + Style.RESET_ALL)
                elif emulator_choice == '5':
                    ipv4_addresses = get_local_ipv4_addresses()
                    print("\n" + "{:<30} {:<15}".format("Interface", "IP Address"))
                    print("-" * 45)
                    for iface, ip in ipv4_addresses.items():
                        print(f"{iface:<30} {ip:<15}")
                    ip = input(Fore.CYAN + "📝 Enter the proxy IP address: " + Style.RESET_ALL).strip()
                    port = input(Fore.CYAN + "📝 Enter the proxy port: " + Style.RESET_ALL).strip()
                    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip) and port.isdigit():
                        subprocess.run(f'{adb_command} -s {device_serial} shell settings put global http_proxy {ip}:{port}', shell=True)
                        print(Fore.GREEN + f"✅ Proxy set to {ip}:{port} on the emulator." + Style.RESET_ALL)
                    else:
                        print(Fore.RED + "❌ Invalid IP address or port number." + Style.RESET_ALL)
                elif emulator_choice == '6':
                    subprocess.run(f'{adb_command} -s {device_serial} shell settings put global http_proxy :0', shell=True)
                    print(Fore.GREEN + "✅ Proxy removed from the emulator." + Style.RESET_ALL)
                elif emulator_choice == '7':
                    break
                else:
                    print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)
        elif main_choice == '4':
            # Frida Options menu
            while True:
                show_frida_menu()
                frida_choice = input(Fore.CYAN + "🕵️ Enter your choice: " + Style.RESET_ALL).strip()
                if frida_choice == '1':
                    install_frida_server()
                elif frida_choice == '2':
                    run_frida_server()
                elif frida_choice == '3':
                    list_installed_applications()
                elif frida_choice == '4':
                    run_ssl_pinning_bypass()
                elif frida_choice == '5':
                    run_root_check_bypass()
                elif frida_choice == '6':
                    android_biometric_bypass()
                elif frida_choice == '7':
                    run_custom_frida_script()
                elif frida_choice == '8':
                    break
                else:
                    print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)
        elif main_choice == '5':
            print(Fore.GREEN + "👋 Exiting... Have a great day!" + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)

if __name__ == "__main__":
    main()