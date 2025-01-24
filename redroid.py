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
import frida
import json

# External libraries
try:
    import psutil
    import requests
    from requests.exceptions import ConnectionError
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Style
except ImportError as e:
    print(f"ImportError: {e}. Ensure all dependencies are installed and available.")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

# Global variables
emulator_type = None
emulator_installation_path = None
adb_command = None
device_serial = None

def detect_emulator():
    """Detect whether Nox, Genymotion, or Android Studio emulator is running.
       When running on Android, this function is bypassed.
    """
    global emulator_type, emulator_installation_path
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
                continue
            if name and 'Nox.exe' in name:
                emulator_type = 'Nox'
                emulator_installation_path = os.path.dirname(exe_path)
                break
            elif name and 'player.exe' in name and any('Genymotion' in arg for arg in cmdline):
                emulator_type = 'Genymotion'
                emulator_installation_path = os.path.dirname(exe_path)
                break
            # Check for Android Studio Emulator processes:
            elif name and ("emulator" in name.lower() or "qemu-system" in name.lower()):
                emulator_type = 'AndroidStudio'
                emulator_installation_path = os.path.dirname(exe_path)
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return emulator_type, emulator_installation_path

def connect_nox_adb_ports(adb_cmd):
    """
    NEW FUNCTION:
    Automatically attempt to connect the local ADB to Nox 
    on localhost ports [62001, 62025, 62026].
    """
    ip = '127.0.0.1'
    ports = [62001, 62025, 62026]
    for port in ports:
        cmd = f'{adb_cmd} connect {ip}:{port}'
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(Fore.GREEN + f"✅ Attempted adb connect to {ip}:{port}. Output:" + Style.RESET_ALL)
                print(Fore.GREEN + result.stdout.strip() + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + f"⚠️ Could not connect to {ip}:{port}. Error:" + Style.RESET_ALL)
                print(Fore.YELLOW + result.stderr.strip() + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"❌ Exception connecting to Nox at {ip}:{port}: {str(e)}" + Style.RESET_ALL)

def get_adb_command(emulator_type, emulator_installation_path):
    """Return the adb command path based on the emulator type.
       On Android, return None.
    """
    if os.environ.get('ANDROID_ARGUMENT'):
        return None

    if emulator_type == 'Nox':
        adb_executable = 'nox_adb.exe'
        adb_command_path = os.path.join(emulator_installation_path, adb_executable)
        if os.path.exists(adb_command_path):
            return f'"{adb_command_path}"'
        else:
            print(Fore.RED + f"❌ {adb_executable} not found in {emulator_installation_path}." + Style.RESET_ALL)
            return 'adb'
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
    """Download the certificate from a given URL (using the provided IP and port)
    and install it on the device via adb.

    If the certificate file (renamed) already exists in the current directory,
    skip the remote download and proceed directly to the push phase.

    If pushing the certificate fails due to the filesystem being read-only,
    the script automatically executes 'adb root' and 'adb remount' (waiting 5 seconds),
    then retries. If the issue persists, the user is asked whether to reboot the device.
    """
    input_der_file = "cacert.der"
    output_file = "9a5ba575.0"

    # Check if the certificate (already renamed) exists locally
    if os.path.exists(output_file):
        print(Fore.GREEN + f"✅ Found local certificate '{output_file}', skipping remote download." + Style.RESET_ALL)
    else:
        cert_url = f"http://{ip}:{port}/cert"
        try:
            response = requests.get(cert_url, timeout=10)
            if response.status_code == 200:
                with open(input_der_file, "wb") as certificate_file:
                    certificate_file.write(response.content)
                print(Fore.GREEN + f"✅ Certificate downloaded successfully from {cert_url}." + Style.RESET_ALL)

                # Rename the file (no OpenSSL conversion is used)
                os.rename(input_der_file, output_file)
                print(Fore.GREEN + f"✅ Renamed {input_der_file} to {output_file}." + Style.RESET_ALL)
            else:
                print(Fore.RED + f"❌ Unable to download the certificate from {cert_url}. Status code: {response.status_code}" + Style.RESET_ALL)
                return False
        except ConnectionError:
            print(Fore.RED + f"❌ Burp Suite is not running or the proxy is not available at {ip}:{port}." + Style.RESET_ALL)
            return False
        except Exception as e:
            print(Fore.RED + f"❌ An unexpected error occurred during download: {str(e)}" + Style.RESET_ALL)
            return False

    # Attempt to push the certificate to the device
    push_result = run_adb_command(f'push {output_file} /system/etc/security/cacerts/')
    if push_result is None or (push_result.stderr and "read-only" in push_result.stderr.lower()):
        print(Fore.YELLOW + "⚠️ Error: File system is read-only. Retrying with adb root and remount." + Style.RESET_ALL)
        # Execute adb root and wait
        result_root = run_adb_command('root')
        if result_root is None:
            print(Fore.RED + "❌ Unable to obtain root privileges via adb." + Style.RESET_ALL)
            return False
        time.sleep(5)  # Wait 5 seconds
        result_remount = run_adb_command('remount')
        if result_remount is None:
            print(Fore.RED + "❌ Unable to remount the partition as writable." + Style.RESET_ALL)
            return False

        # Retry pushing the certificate
        push_result = run_adb_command(f'push {output_file} /system/etc/security/cacerts/')
        if push_result is None or (push_result.stderr and "read-only" in push_result.stderr.lower()):
            print(Fore.RED + "❌ The partition is still read-only." + Style.RESET_ALL)
            # Ask the user if they want to reboot the device
            user_choice = input(Fore.YELLOW + "Would you like to reboot the device now? (y/n): " + Style.RESET_ALL).strip().lower()
            if user_choice in ['y', 'yes']:
                reboot_result = run_adb_command('reboot')
                if reboot_result is None:
                    print(Fore.RED + "❌ Failed to reboot the device. Please reboot manually." + Style.RESET_ALL)
                else:
                    print(Fore.GREEN + "✅ Device reboot initiated. Please try installing the certificate again after the device restarts." + Style.RESET_ALL)
                return False
            else:
                print(Fore.RED + "❌ Certificate installation failed due to read-only partition." + Style.RESET_ALL)
                return False

    # Set permissions on the certificate
    chmod_result = run_adb_command(f'shell chmod 644 /system/etc/security/cacerts/{output_file}')
    if chmod_result is None:
        print(Fore.RED + "❌ Failed to set permissions on the certificate." + Style.RESET_ALL)
        return False

    print(Fore.GREEN + "✅ Burp Suite certificate installed successfully on the device." + Style.RESET_ALL)
    # Remove the local file if it is no longer needed
    try:
        os.remove(output_file)
    except Exception as e:
        print(Fore.YELLOW + f"⚠️ Unable to remove local file {output_file}: {str(e)}" + Style.RESET_ALL)
    return True

def install_burpsuite_certificate(port):
    """Install the Burp Suite certificate onto the device using
    the provided IP and port.
    """
    ip = input(Fore.CYAN + "📝 Enter the IP (e.g., 127.0.0.1): " + Style.RESET_ALL).strip()
    if not ip:
        print(Fore.RED + "❌ Invalid IP." + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"🔍 Attempting to download the certificate from {ip}:{port}..." + Style.RESET_ALL)
    if try_download_certificate(ip, port):
        print(Fore.GREEN + "✅ Certificate installation completed." + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Certificate installation failed." + Style.RESET_ALL)

def install_tool(tool):
    """Install a Python tool using pip."""
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', tool, '--break-system-packages'], check=True)
        print(Fore.GREEN + f"✅ {tool} installed successfully." + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error installing {tool}: {e}" + Style.RESET_ALL)

def download_latest_jadx():
    """Download the latest version of Jadx based on the operating system."""
    system_name = platform.system().lower()
    if system_name == "linux":
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
    elif system_name == "windows":
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
        print(f"❌ Unsupported operating system: {system_name}. Please install Jadx manually.")

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
        system_name = platform.system().lower()
        if system_name == "linux":
            distro_info = os.popen('cat /etc/*release').read().lower()
            if 'kali' in distro_info or 'debian' in distro_info or 'ubuntu' in distro_info:
                os.system('sudo apt update && sudo apt install apktool -y')
                print("✅ Apktool installed successfully via apt.")
            elif 'arch' in distro_info or 'manjaro' in distro_info:
                os.system('sudo pacman -Syu apktool --noconfirm')
                print("✅ Apktool installed successfully via pacman.")
            else:
                print("⚠️ Unsupported Linux distribution. Please install Apktool manually.")
        elif system_name == "windows":
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
            print(Fore.YELLOW + "⚠️ Nuclei is not executable. Please ensure the Go bin directory is in your PATH." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "✅ Nuclei is executable from the terminal." + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error during Nuclei installation: {e}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"❌ An unexpected error occurred during Nuclei installation: {str(e)}" + Style.RESET_ALL)

def install_mob_sf():
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

def run_mobfs():
    """
    1) Checks if this is an Android Studio emulator (emulator_type=='AndroidStudio') and if device_serial is set.
    2) Verifies if Docker is installed.
    3) Prints local IP addresses and asks the user for the Burp proxy IP and port.
    4) Asks whether to configure the global proxy as HTTP or HTTPS.
    5) Removes any pre-existing 'mobsf' container.
    6) Runs 'docker run' (MobSF) in a new terminal, providing the necessary environment variables for proxy configuration.
    7) Sets the chosen proxy (http_proxy or https_proxy) on the emulator.
    """
    global emulator_type, device_serial

    # 1) Check if we're on an Android Studio emulator and have a valid device_serial
    if emulator_type != 'AndroidStudio' or not device_serial:
        print(Fore.RED + "❌ No active Android Studio emulator detected, or missing device_serial." + Style.RESET_ALL)
        return
    print(Fore.GREEN + f"✅ Android Studio emulator detected, device_serial: {device_serial}" + Style.RESET_ALL)

    # 2) Verify Docker installation
    if not shutil.which("docker"):
        print(Fore.RED + "❌ Docker is not installed or not in the PATH." + Style.RESET_ALL)
        return

    # 3) Print local IP addresses and ask for the proxy settings
    print("\n" + Fore.GREEN + "===== Local IP Addresses =====" + Style.RESET_ALL)
    ip_dict = get_local_ipv4_addresses()
    print("{:<20} {:<15}".format("Interface", "IP Address"))
    print("-" * 35)
    for iface, ip_addr in ip_dict.items():
        print("{:<20} {:<15}".format(iface, ip_addr))

    user_ip = input(Fore.CYAN + "\n📝 Enter the proxy IP (e.g., 192.168.0.100): " + Style.RESET_ALL).strip()
    user_port = input(Fore.CYAN + "📝 Enter the proxy port (e.g., 8080): " + Style.RESET_ALL).strip()
    if not user_ip or not user_port.isdigit():
        print(Fore.RED + "❌ Invalid IP or port. Aborting configuration." + Style.RESET_ALL)
        return

    # 4) Ask if user wants HTTP or HTTPS as global proxy
    proxy_type = input(Fore.CYAN + "\nDo you want to configure 'http' or 'https' as the global emulator proxy? (default: http): " + Style.RESET_ALL).strip().lower()
    if proxy_type not in ["http", "https"]:
        proxy_type = "http"

    # 5) Remove any existing 'mobsf' container
    print(Fore.YELLOW + "🔄 Removing any existing 'mobsf' container..." + Style.RESET_ALL)
    subprocess.run("docker rm -f mobsf", shell=True, capture_output=True)

    # 6) Launch docker run in a new terminal
    docker_cmd = (
        f'docker run -it --name mobsf '
        f'-p 8000:8000 -p 1337:1337 '
        f'-e MOBSF_ANALYZER_IDENTIFIER="{device_serial}" '
        f'-e MOBSF_PROXY_IP="{user_ip}" '
        f'-e MOBSF_PROXY_PORT="{user_port}" '
        f'opensecurity/mobile-security-framework-mobsf:latest'
    )
    print(Fore.CYAN + "\n🔄 Launching MobSF (docker run) in a new terminal:\n" + Style.RESET_ALL + docker_cmd)
    open_new_terminal(docker_cmd)

    # 7) Set the global proxy on the emulator
    settings_key = "http_proxy" if proxy_type == "http" else "https_proxy"
    print(Fore.CYAN + f"\n🔗 Setting global {settings_key}: {user_ip}:{user_port}" + Style.RESET_ALL)
    adb_cmd = f'adb -s {device_serial} shell settings put global {settings_key} {user_ip}:{user_port}'

    try:
        subprocess.run(adb_cmd, shell=True, check=True)
        print(Fore.GREEN + f"✅ {settings_key} configured on emulator: {user_ip}:{user_port}" + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Failed to set {settings_key} on emulator. Error: {e}" + Style.RESET_ALL)

    print(Fore.GREEN + "\n✅ Setup complete! The MobSF container is starting in a separate window." + Style.RESET_ALL)
    print(Fore.GREEN + f"The emulator now uses {settings_key} = {user_ip}:{user_port} (if supported by your Android image)." + Style.RESET_ALL)
    print(Fore.GREEN + "To stop MobSF, close the new terminal window or run: docker stop mobsf.\n" + Style.RESET_ALL)


def run_nuclei_against_apk():
    """Decompiles an APK, runs nuclei with templates, and optionally saves output.
    Handles paths with quotes and spaces, and allows specifying a custom nuclei templates path.
    """
    # Get valid APK path from user
    while True:
        apk_path_input = input("Enter the path to the APK file: ").strip()
        apk_path = apk_path_input.strip("'").strip('"')
        if os.path.exists(apk_path):
            break
        else:
            print(f"Error: The file {apk_path_input} does not exist.")

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
        if action_choice == '2':
            # Overwrite scenario: remove existing folder first
            shutil.rmtree(output_dir)

    # Decompiling APK with apktool
    apktool_command = "apktool" if system().lower() != "windows" else "apktool.bat"
    try:
        subprocess.run(shlex.split(f"{apktool_command} d \"{apk_path}\" -o \"{output_dir}\""), check=True)
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error: Failed to decompile APK. {e}\n")
        return
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}. Ensure apktool is installed and accessible.")
        return

    # Define built-in templates paths based on user's home directory
    user_home = os.path.expanduser("~")
    android_template_path = os.path.join(user_home, "nuclei-templates", "file", "android")
    keys_template_path = os.path.join(user_home, "nuclei-templates", "file", "keys")

    # Ask user for which templates to use, including an option for custom templates
    print("\nPlease choose which templates to use:")
    print("1. Android Templates")
    print("2. Keys Templates")
    print("3. Both (Android + Keys)")
    print("4. Custom Templates (provide your own template path)")
    template_choice = input("Enter the number of your choice: ").strip()
    templates_paths = []

    if template_choice == '1':
        templates_paths.append(android_template_path)
    elif template_choice == '2':
        templates_paths.append(keys_template_path)
    elif template_choice == '3':
        templates_paths.extend([android_template_path, keys_template_path])
    elif template_choice == '4':
        custom_path = input("Enter the full path to your nuclei templates: ").strip()
        custom_path = custom_path.strip("'").strip('"')
        templates_paths.append(custom_path)
    else:
        print("Invalid choice. Exiting.")
        return

    # Validate each template directory exists
    for path in templates_paths:
        if not os.path.exists(path):
            print(f"Templates directory not found at {path}.")
            return

    # Construct the nuclei command including the "-file" flag
    nuclei_command = ["nuclei", "-target", output_dir, "-file"]
    for template_path in templates_paths:
        nuclei_command.extend(["-t", template_path])
    
    print("Nuclei command:", nuclei_command)
    try:
        result = subprocess.run(nuclei_command, check=True, capture_output=True, text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to run nuclei. {e}")
        print(f"Stderr: {e.stderr}")
        return

    # Ask user if they want to save the output
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
            print(Fore.YELLOW + "⚠️ Nuclei is not executable. Please ensure the Go bin directory is added to your PATH manually." + Style.RESET_ALL)
            if not check_nuclei_installed():
                print(Fore.RED + "❌ Nuclei is still not executable. Please check your PATH settings." + Style.RESET_ALL)
            else:
                print(Fore.GREEN + "✅ Nuclei is now executable from the terminal." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "✅ Nuclei is already executable from the terminal." + Style.RESET_ALL)
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

    apk_path_input = input("📝 Enter the path to the APK file: ").strip()
    
    # Remove all quotes from the input
    apk_path = apk_path_input.replace('"', '').replace("'", '')

    # Normalize the path (handles backslashes on Windows)
    apk_path = os.path.normpath(apk_path)

    if not os.path.isfile(apk_path):
        print(Fore.RED + f"❌ Error: The file '{apk_path}' does not exist or is not valid." + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n🔍 Running apkleaks on '{apk_path}'..." + Style.RESET_ALL)
    try:
        output_filename = f"{os.path.splitext(os.path.basename(apk_path))[0]}_apkleaks_output.txt"
        output_path = os.path.join(os.getcwd(), output_filename)
        command = ['apkleaks', '-f', apk_path, '-o', output_path]
        
        # Execute the command
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        
        print(Fore.GREEN + f"✅ apkleaks output saved to '{output_path}'." + Style.RESET_ALL)
        print(Fore.GREEN + f"📄 Output:\n{result.stdout}" + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error running apkleaks: {e.stderr}" + Style.RESET_ALL)
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
    Check if Frida-Server is already running on the device.
    If not, download the matching Frida-Server binary, decompress, push it to the device,
    set the executable permission, and clean up.
    """
    global adb_command, device_serial

    if adb_command is None or not device_serial:
        print(Fore.RED + "❌ ADB command unavailable or no device selected. Cannot install Frida-Server." + Style.RESET_ALL)
        return

    if is_frida_server_running():
        print(Fore.GREEN + "✅ Frida-Server is already running on the device." + Style.RESET_ALL)
        return

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

    arch_result = run_adb_command('shell getprop ro.product.cpu.abi')
    if arch_result and arch_result.stdout.strip():
        emulator_arch = arch_result.stdout.strip()
        print(Fore.GREEN + f"✅ Device CPU Architecture: {emulator_arch}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Unable to determine device CPU architecture." + Style.RESET_ALL)
        return

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

    try:
        with lzma.open("frida-server.xz") as compressed_file:
            with open("frida-server", "wb") as out_file:
                shutil.copyfileobj(compressed_file, out_file)
        os.remove("frida-server.xz")
        print(Fore.GREEN + "✅ Frida-Server decompressed successfully." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"❌ Failed to decompress Frida-Server: {e}" + Style.RESET_ALL)
        return

    try:
        print(Fore.CYAN + "🔧 Setting device to root mode and remounting system partition..." + Style.RESET_ALL)
        subprocess.run(f'{adb_command} -s {device_serial} root', shell=True, check=True)
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
        cmd = f'frida -U -f {app_package} -l "{script_path}"'
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
        cmd = f'frida -U -f {app_package} -l "{script_path}"'
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
        cmd = f'frida -U -f {app_package} -l "{script_path}"'
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
        cmd = f'frida -U -f {app_package} -l "{script_path}"'
        print(Fore.CYAN + f"🚀 Running custom Frida script on {app_package}..." + Style.RESET_ALL)
        open_new_terminal(cmd)
    else:
        print(Fore.RED + "❌ Invalid package name. Exiting." + Style.RESET_ALL)

def auto_fridump():
    """
    Automatically dumps the memory of a specified process using Frida.
    Utilizes 'frida-ps -Uia' to list applications and select a PID.
    """
    SESSION_FILE = "fridump_session.json"

    # ---------------------
    # Session Management
    # ---------------------
    def load_session(filepath):
        if not os.path.isfile(filepath):
            return {"dumped_ranges": {}, "skipped_ranges": {}}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or "dumped_ranges" not in data or "skipped_ranges" not in data:
                return {"dumped_ranges": {}, "skipped_ranges": {}}
            return data
        except:
            return {"dumped_ranges": {}, "skipped_ranges": {}}

    def save_session(filepath, dumped, skipped):
        data = {"dumped_ranges": dumped, "skipped_ranges": skipped}
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving session: {e}")

    # ---------------------
    # Utility Functions
    # ---------------------
    def print_progress(current, total, prefix='Progress:', bar_length=50):
        filled_length = int(bar_length * current // total)
        bar = '#' * filled_length + '-' * (bar_length - filled_length)
        print(f'\r{prefix} |{bar}| {current}/{total}', end='\r')
        if current == total:
            print()

    def run_strings(directory, min_len=4):
        strings_path = os.path.join(directory, "strings.txt")
        with open(strings_path, "w", encoding='utf-8') as st:
            for filename in os.listdir(directory):
                if filename.endswith(".data"):
                    filepath = os.path.join(directory, filename)
                    try:
                        with open(filepath, 'rb') as f:
                            content = f.read().decode('latin-1', errors='ignore')
                            strings = re.findall(r"[A-Za-z0-9/\-:;.,_$%'!()\[\]<>#]+", content)
                            for s in strings:
                                if len(s) >= min_len:
                                    st.write(s + "\n")
                    except:
                        continue

    def get_emulator_ip():
        try:
            output = subprocess.check_output(["adb", "shell", "ip", "addr"], universal_newlines=True)
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', output)
            if match:
                return match.group(1)
        except subprocess.CalledProcessError:
            pass
        return None

    def adb_forward():
        try:
            subprocess.check_call(["adb", "forward", "tcp:27042", "tcp:27042"])
            print(Fore.GREEN + "[*] ADB port forwarding set up: tcp:27042 -> tcp:27042" + Style.RESET_ALL)
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"[-] Error setting up ADB port forwarding: {e}" + Style.RESET_ALL)
            sys.exit(1)

    def run_frida_ps():
        """
        Runs 'frida-ps -Uia' to list all applications and returns a list of (PID, App Name) tuples.
        """
        try:
            result = subprocess.run(["frida-ps", "-Uia"], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            apps = []
            for line in lines[1:]:  # Skip header
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[0].isdigit():
                    pid = int(parts[0])
                    app_name = parts[1].strip()
                    apps.append((pid, app_name))
            return apps
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"[-] Error running 'frida-ps -Uia': {e}" + Style.RESET_ALL)
            sys.exit(1)
        except FileNotFoundError:
            print(Fore.RED + "[-] 'frida-ps' not found. Please ensure Frida is installed and added to PATH." + Style.RESET_ALL)
            sys.exit(1)

    # ---------------------
    # Memory Dump Functions
    # ---------------------
    def dump_memory(agent, base, size, directory, max_size=20971520):
        def dump_to_file(addr, sz, fname):
            data = agent.readmemory(addr, sz)
            with open(os.path.join(directory, fname), 'wb') as f:
                f.write(data)

        if size > max_size:
            for i in range(0, size, max_size):
                chunk_size = min(max_size, size - i)
                dump_to_file(base + i, chunk_size, f"{hex(base + i)}_dump.data")
        else:
            dump_to_file(base, size, f"{hex(base)}_dump.data")

    # ---------------------
    # Automatic Memory Dump Process
    # ---------------------
    def run_auto_dump():
        # Load session data
        session = load_session(SESSION_FILE)
        dumped = session["dumped_ranges"]
        skipped = session["skipped_ranges"]

        # Get emulator IP
        ip = get_emulator_ip()
        if not ip:
            print(Fore.RED + "[-] Unable to obtain emulator IP via ADB." + Style.RESET_ALL)
            sys.exit(1)
        print(Fore.GREEN + f"[*] Detected emulator IP: {ip}" + Style.RESET_ALL)

        # Set up ADB port forwarding
        adb_forward()

        # Connect to remote device
        host = "127.0.0.1:27042"
        try:
            device_manager = frida.get_device_manager()
            device = device_manager.add_remote_device(host)
            print(Fore.GREEN + f"[*] Connected to remote device: {host}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[-] Error connecting to remote device: {e}" + Style.RESET_ALL)
            sys.exit(1)

        # Enumerate running processes using 'frida-ps -Uia'
        apps = run_frida_ps()
        if not apps:
            print(Fore.YELLOW + "⚠️ No applications found." + Style.RESET_ALL)
            sys.exit(0)

        print(Fore.GREEN + "\n[*] Running applications:" + Style.RESET_ALL)
        print("{:<10} {}".format("PID", "Application"))
        print("-" * 40)
        for pid, app in apps:
            print("{:<10} {}".format(pid, app))

        # User input for PID
        try:
            pid_input = input(Fore.CYAN + "\nEnter the PID of the process to dump: " + Style.RESET_ALL).strip()
            pid = int(pid_input)
            if pid not in [app[0] for app in apps]:
                print(Fore.RED + "[-] PID not found in the list of running applications." + Style.RESET_ALL)
                sys.exit(1)
        except ValueError:
            print(Fore.RED + "[-] PID must be an integer." + Style.RESET_ALL)
            sys.exit(1)

        # User input for memory permissions
        perms = input(Fore.CYAN + "Enter memory permissions to dump (default 'rw-'): " + Style.RESET_ALL).strip()
        if not perms:
            perms = "rw-"
        perms_list = [p.strip() for p in perms.split(',')]

        # User input for running 'strings'
        strings_flag = input(Fore.CYAN + "Do you want to run 'strings' on dumped files? (y/n, default n): " + Style.RESET_ALL).strip().lower() == 'y'

        # Set output directory
        output_dir = os.path.join(os.getcwd(), "dump")
        os.makedirs(output_dir, exist_ok=True)
        print(Fore.GREEN + f"[*] Output directory: {output_dir}" + Style.RESET_ALL)

        # Attach to the target process
        try:
            session_frida = device.attach(pid)
            print(Fore.GREEN + f"[*] Attached to process PID: {pid}" + Style.RESET_ALL)
        except frida.ProcessNotFoundError:
            print(Fore.RED + f"[-] Process with PID '{pid}' not found." + Style.RESET_ALL)
            sys.exit(1)
        except frida.TransportError as e:
            print(Fore.RED + f"[-] Transport error: {e}" + Style.RESET_ALL)
            sys.exit(1)
        except Exception as e:
            print(Fore.RED + f"[-] Unexpected error: {e}" + Style.RESET_ALL)
            sys.exit(1)

        # Load Frida script
        script_code = """
        'use strict';
        rpc.exports = {
          enumerateranges: function (prot) {
            return Process.enumerateRangesSync(prot);
          },
          readmemory: function (address, size) {
            return Memory.readByteArray(ptr(address), size);
          }
        };
        """
        try:
            script = session_frida.create_script(script_code)
            script.load()
            agent = script.exports_sync
            print(Fore.GREEN + "[*] Frida script loaded successfully." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[-] Error loading Frida script: {e}" + Style.RESET_ALL)
            sys.exit(1)

        # Enumerate memory regions
        all_ranges = []
        for p in perms_list:
            try:
                ranges = agent.enumerateranges(p)
                print(Fore.GREEN + f"[*] Found {len(ranges)} regions with permissions '{p}'" + Style.RESET_ALL)
                all_ranges.extend(ranges)
            except Exception as e:
                print(Fore.RED + f"[-] Error enumerating regions for '{p}': {e}" + Style.RESET_ALL)

        if not all_ranges:
            print(Fore.YELLOW + "⚠️ No memory regions found with the specified permissions." + Style.RESET_ALL)
            sys.exit(0)

        # Remove duplicate regions and sort
        unique_ranges = {r['base']: r for r in all_ranges}.values()
        sorted_ranges = sorted(unique_ranges, key=lambda x: x['base'])

        print(Fore.GREEN + f"[*] Total unique memory regions to dump: {len(sorted_ranges)}" + Style.RESET_ALL)

        # Start memory dumping
        for idx, region in enumerate(sorted_ranges, 1):
            base = region['base']
            size = region['size']

            # Ensure base is an integer
            if isinstance(base, str):
                try:
                    base_int = int(base, 16)
                except ValueError:
                    print(Fore.RED + f"[-] Invalid base address format: {base}" + Style.RESET_ALL)
                    skipped[base] = True
                    save_session(SESSION_FILE, dumped, skipped)
                    print_progress(idx, len(sorted_ranges))
                    continue
            elif isinstance(base, int):
                base_int = base
            else:
                print(Fore.RED + f"[-] Unexpected base address type: {type(base)} for base {base}" + Style.RESET_ALL)
                skipped[str(base)] = True
                save_session(SESSION_FILE, dumped, skipped)
                print_progress(idx, len(sorted_ranges))
                continue

            base_str = hex(base_int)

            if base_str in dumped or base_str in skipped:
                print_progress(idx, len(sorted_ranges))
                continue

            try:
                dump_memory(agent, base_int, size, output_dir)
                dumped[base_str] = True
                save_session(SESSION_FILE, dumped, skipped)
                print(Fore.GREEN + f"[+] Dumped region {base_str} (size={size} bytes)." + Style.RESET_ALL)
            except Exception as e:
                skipped[base_str] = True
                save_session(SESSION_FILE, dumped, skipped)
                print(Fore.RED + f"[-] Error dumping region {base_str}: {e}" + Style.RESET_ALL)
            print_progress(idx, len(sorted_ranges))

        # Run 'strings' if requested
        if strings_flag:
            print(Fore.GREEN + "[*] Running 'strings' on dumped files..." + Style.RESET_ALL)
            run_strings(output_dir)
            print(Fore.GREEN + "[*] 'strings' extraction completed." + Style.RESET_ALL)

        print(Fore.GREEN + "[*] Memory dump completed." + Style.RESET_ALL)
        print(Fore.GREEN + f"[*] Session data saved in '{SESSION_FILE}'." + Style.RESET_ALL)

def install_mob_sf_wrapper():
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

def install_drozer_agent():
    """
    Download the latest Drozer Agent APK from GitHub and install it automatically
    on the connected emulator/device via adb.
    """
    global adb_command, device_serial
    if adb_command is None or not device_serial:
        print(Fore.RED + "❌ ADB command unavailable or no device selected. Cannot install Drozer Agent." + Style.RESET_ALL)
        return

    # Retrieve the latest release info from GitHub
    print(Fore.CYAN + "🔎 Checking latest Drozer Agent release..." + Style.RESET_ALL)
    try:
        response = requests.get("https://api.github.com/repos/WithSecureLabs/drozer-agent/releases/latest", timeout=15)
        response.raise_for_status()
        release_data = response.json()
        assets = release_data.get("assets", [])
        apk_url = None

        # Find an asset that looks like an .apk
        for asset in assets:
            if asset["browser_download_url"].endswith(".apk"):
                apk_url = asset["browser_download_url"]
                break

        if not apk_url:
            print(Fore.RED + "❌ Could not find an .apk asset in the latest Drozer release." + Style.RESET_ALL)
            return

        print(Fore.CYAN + f"🔗 Downloading Drozer Agent from: {apk_url}" + Style.RESET_ALL)
        apk_filename = "drozer-agent-latest.apk"
        with requests.get(apk_url, stream=True) as r:
            r.raise_for_status()
            with open(apk_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(Fore.GREEN + "✅ Drozer Agent APK downloaded successfully." + Style.RESET_ALL)

        # Now install the APK using adb
        install_command = f'install -r "{apk_filename}"'
        print(Fore.CYAN + "📦 Installing Drozer Agent APK on the device..." + Style.RESET_ALL)
        result = run_adb_command(install_command)
        if result and result.returncode == 0:
            print(Fore.GREEN + "✅ Drozer Agent installed successfully." + Style.RESET_ALL)
        else:
            print(Fore.RED + "❌ Installation failed. Check adb logs for details." + Style.RESET_ALL)

        # Cleanup local file if desired
        try:
            os.remove(apk_filename)
        except Exception:
            pass

    except Exception as e:
        print(Fore.RED + f"❌ An error occurred while downloading or installing Drozer Agent: {e}" + Style.RESET_ALL)

def start_drozer_forwarding():
    """
    Forward port 31415 on the local machine to port 31415 on the device/emulator
    (i.e., adb forward tcp:31415 tcp:31415).
    """
    global adb_command, device_serial
    if adb_command is None or not device_serial:
        print(Fore.RED + "❌ ADB command unavailable or no device selected. Cannot forward Drozer port." + Style.RESET_ALL)
        return

    # Perform the forwarding
    result = run_adb_command("forward tcp:31415 tcp:31415")
    if result and result.returncode == 0:
        print(Fore.GREEN + "✅ ADB forward set up: 31415 -> 31415" + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Failed to set up port forwarding. Check adb logs for details." + Style.RESET_ALL)

def show_drozer_menu():
    """Display the Drozer menu."""
    print("\n" + "=" * 50)
    print(f"{'Drozer':^50}")
    print("=" * 50)
    print("1. 🏹  Install Drozer Agent")
    print("2. 🚀  Start port forwarding (31415 -> 31415)")
    print("3. ↩️  Back")

def drozer_menu_loop():
    """Loop for the Drozer menu."""
    while True:
        show_drozer_menu()
        choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()
        if choice == '1':
            install_drozer_agent()
        elif choice == '2':
            start_drozer_forwarding()
        elif choice == '3':
            break
        else:
            print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)

def show_main_menu():
    """Display the main menu."""
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
    print("5. 🏹  Drozer")
    print("6. ❌  Exit")

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
    print("4. 🧠  Dump memory of an application")
    print("4. 🔓  Run SSL Pinning Bypass")
    print("5. 🛡️  Run Root Check Bypass")
    print("6. 🔑  Android Biometric Bypass")
    print("7. 📝  Run Custom Script")
    print("8. ↩️  Back")

def main():
    """Main function to run the tool."""
    global emulator_type, emulator_installation_path, adb_command, device_serial

    emulator_type, emulator_installation_path = detect_emulator()
    if emulator_type:
        print(Fore.GREEN + f"✅ Emulator detected: {emulator_type}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "⚠️ Emulator not detected or running on Android." + Style.RESET_ALL)

    adb_command = get_adb_command(emulator_type, emulator_installation_path)

    # -------------------------------
    if emulator_type == 'Nox' and adb_command:
        connect_nox_adb_ports(adb_command)
    # -------------------------------

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

    while True:
        show_main_menu()
        main_choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()
        if main_choice == '1':
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
                    install_mob_sf()
                elif tools_choice == '8':
                    install_tool("apkleaks")
                elif tools_choice == '9':
                    break
                else:
                    print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)

        elif main_choice == '2':
            while True:
                show_run_tools_menu()
                run_tools_choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()
                if run_tools_choice == '1':
                    run_mobfs()
                elif run_tools_choice == '2':
                    run_nuclei_against_apk()
                elif run_tools_choice == '3':
                    run_apkleaks()
                elif run_tools_choice == '4':
                    break
                else:
                    print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)

        elif main_choice == '3':
            while True:
                show_emulator_options_menu()
                emulator_choice = input(Fore.CYAN + "🕹️ Enter your choice: " + Style.RESET_ALL).strip()
                if emulator_choice == '1':
                    remove_ads_and_bloatware()
                elif emulator_choice == '2':
                    port = input(Fore.CYAN + "📝 Enter the Burp Suite port: " + Style.RESET_ALL).strip()
                    if port.isdigit():
                        install_burpsuite_certificate(int(port))
                    else:
                        print(Fore.RED + "❌ Invalid port. Enter a valid port number." + Style.RESET_ALL)
                elif emulator_choice == '3':
                    if adb_command and device_serial:
                        subprocess.run(f'{adb_command} -s {device_serial} shell', shell=True)
                    else:
                        print(Fore.RED + "❌ ADB shell not available (no device selected or on Android)." + Style.RESET_ALL)
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
                    auto_fridump()
                elif frida_choice == '5':
                    run_ssl_pinning_bypass()
                elif frida_choice == '6':
                    run_root_check_bypass()
                elif frida_choice == '7':
                    android_biometric_bypass()
                elif frida_choise == '8':
                    run_custom_frida_script() 
                elif frida_choice == '9':
                    break
                else:
                    print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)

        elif main_choice == '5':
            # Drozer menu
            drozer_menu_loop()

        elif main_choice == '6':
            print(Fore.GREEN + "👋 Exiting... Have a great day!" + Style.RESET_ALL)
            break

        else:
            print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n❌ Graceful shutdown initiated. Goodbye! 🚪" + Style.RESET_ALL)
        sys.exit(0)