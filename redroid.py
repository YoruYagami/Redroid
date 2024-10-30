import os
import subprocess
import platform
import psutil
import requests
import socket
import re
import shutil
import lzma
from OpenSSL import crypto
from requests.exceptions import ConnectionError
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import ctypes
import sys

# Initialize colorama
init(autoreset=True)

def detect_emulator():
    """Detect whether Nox, Genymotion, or Android Studio emulator is running."""
    emulator_type = None
    emulator_installation_path = None
    for process in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            name = process.info['name']
            cmdline = process.info.get('cmdline', [])
            exe_path = process.info.get('exe', '')
            if not exe_path:
                continue  # Skip processes without an exe path
            if name and 'Nox.exe' in name:
                emulator_type = 'Nox'
                emulator_installation_path = os.path.dirname(exe_path)
                break
            elif name and 'player.exe' in name and any('Genymotion' in arg for arg in cmdline):
                emulator_type = 'Genymotion'
                emulator_installation_path = os.path.dirname(exe_path)
                break
            elif name and ('emulator.exe' in name or 'qemu-system' in name):
                if any('android' in arg.lower() or 'emulator' in arg.lower() for arg in cmdline):
                    emulator_type = 'AndroidStudio'
                    emulator_installation_path = os.path.dirname(exe_path)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return emulator_type, emulator_installation_path

def get_adb_command():
    """Get the adb command path, checking in PATH and common locations."""
    adb_executable = 'adb.exe' if platform.system() == 'Windows' else 'adb'

    # First, try if adb is in PATH
    if shutil.which(adb_executable):
        return adb_executable

    # Next, try to find adb in common locations
    possible_adb_locations = []

    if platform.system() == 'Windows':
        # Use environment variables
        possible_adb_locations.extend([
            os.path.join(os.environ.get('ANDROID_HOME', ''), 'platform-tools', 'adb.exe'),
            os.path.join(os.environ.get('ANDROID_SDK_ROOT', ''), 'platform-tools', 'adb.exe'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Android', 'Sdk', 'platform-tools', 'adb.exe'),
        ])
        # Check common installation paths
        possible_adb_locations.extend([
            r'C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe',
            r'C:\Program Files\Android\android-sdk\platform-tools\adb.exe',
            r'C:\Android\Sdk\platform-tools\adb.exe',
            os.path.join(os.environ.get('ProgramFiles', ''), 'Android', 'Android Studio', 'platform-tools', 'adb.exe'),
            os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'Android', 'Android Studio', 'platform-tools', 'adb.exe'),
        ])
    else:
        # For macOS and Linux
        possible_adb_locations.extend([
            os.path.join(os.environ.get('ANDROID_HOME', ''), 'platform-tools', 'adb'),
            os.path.join(os.environ.get('ANDROID_SDK_ROOT', ''), 'platform-tools', 'adb'),
            os.path.expanduser('~/Library/Android/sdk/platform-tools/adb'),  # macOS default
            os.path.expanduser('~/Android/Sdk/platform-tools/adb'),  # Linux default
            '/usr/local/share/android-sdk/platform-tools/adb',
            '/usr/local/share/android-studio/platform-tools/adb',
            '/opt/android-sdk/platform-tools/adb',
            '/opt/android/platform-tools/adb',
        ])

    for adb_path in possible_adb_locations:
        if os.path.exists(adb_path):
            return adb_path

    # If not found, return None
    return None

def is_adb_available(adb_command):
    """Check if ADB is installed and available."""
    if adb_command is None:
        return False
    try:
        subprocess.run([adb_command, 'version'], capture_output=True, text=True, check=True)
        return True
    except FileNotFoundError:
        return False
    except subprocess.CalledProcessError:
        return False

# Detect emulator
emulator_type, emulator_installation_path = detect_emulator()
if emulator_type:
    print(Fore.GREEN + f"✅ Emulator detected: {emulator_type}" + Style.RESET_ALL)
else:
    print(Fore.YELLOW + "⚠️ Emulator not detected. Proceeding without emulator-specific optimizations." + Style.RESET_ALL)

adb_command = get_adb_command()

# Check if adb is available
if not is_adb_available(adb_command):
    print(Fore.YELLOW + f"⚠️ 'adb' not found in PATH or common directories." + Style.RESET_ALL)
    print(Fore.RED + "❌ 'adb' command not found. Please ensure that Android Debug Bridge (ADB) is installed." + Style.RESET_ALL)
    # Proceeding without ADB, but some functions will not work
    adb_command = None
else:
    print(Fore.GREEN + f"✅ 'adb' command found: {adb_command}" + Style.RESET_ALL)

def run_adb_command(command_list):
    if not adb_command:
        print(Fore.RED + "❗ 'adb' command is not available. Cannot execute adb commands." + Style.RESET_ALL)
        return None
    if not device_serial:
        print(Fore.RED + "❗ No device selected. This command requires a connected device or emulator." + Style.RESET_ALL)
        return None
    full_command = [adb_command, '-s', device_serial] + command_list
    try:
        result = subprocess.run(full_command, text=True, capture_output=True, check=True)
        return result
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error running adb command: {e}" + Style.RESET_ALL)
        return None
    except FileNotFoundError:
        print(Fore.RED + "❌ Error: 'adb' command not found. Please ensure that ADB is installed." + Style.RESET_ALL)
        return None

def get_connected_devices():
    if not adb_command:
        print(Fore.RED + "❗ 'adb' command is not available. Cannot list connected devices." + Style.RESET_ALL)
        return []
    try:
        result = subprocess.run([adb_command, 'devices'], capture_output=True, text=True, check=True)
        devices = []
        for line in result.stdout.strip().split('\n')[1:]:
            if line.strip() and 'device' in line:
                device_serial = line.split()[0]
                devices.append(device_serial)
        return devices
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error executing adb: {e}" + Style.RESET_ALL)
        return []

devices = get_connected_devices()
device_serial = None
if not devices:
    print(Fore.YELLOW + "⚠️ No devices connected via adb." + Style.RESET_ALL)
else:
    # List connected devices
    print(Fore.GREEN + "Connected devices via adb:")
    for idx, dev in enumerate(devices):
        print(f"{idx+1}. {dev}")
    if len(devices) == 1:
        device_serial = devices[0]
    else:
        while True:
            choice = input("Select a device by number: ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(devices):
                device_serial = devices[int(choice)-1]
                break
            else:
                print("Invalid choice. Please try again.")

    # Infer emulator type from device serial if not detected
    def infer_emulator_type_from_device_serial(device_serial):
        if device_serial.startswith('emulator-'):
            return 'AndroidStudio'
        elif 'nox' in device_serial.lower():
            return 'Nox'
        elif 'genymotion' in device_serial.lower() or 'vbox' in device_serial.lower():
            return 'Genymotion'
        else:
            return None

    if not emulator_type and device_serial:
        emulator_type = infer_emulator_type_from_device_serial(device_serial)

    if emulator_type:
        print(Fore.GREEN + f"✅ Emulator detected: {emulator_type}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "⚠️ Emulator type could not be determined, but a device is connected." + Style.RESET_ALL)

    # Display emulator IP address
    def get_emulator_ip():
        if not device_serial:
            print(Fore.RED + "❗ No device selected. Cannot get emulator IP." + Style.RESET_ALL)
            return None
        # Get all network interfaces and their IP addresses
        result = run_adb_command(['shell', 'ip', '-f', 'inet', 'addr', 'show'])
        if result and result.stdout.strip():
            interfaces = re.findall(r'\d+: (\w+):.*\n\s+inet (\d+\.\d+\.\d+\.\d+)/\d+', result.stdout)
            if interfaces:
                for interface, ip_address in interfaces:
                    if ip_address != '127.0.0.1':
                        return ip_address
        print(Fore.RED + "❗ Could not get emulator IP address." + Style.RESET_ALL)
        return None

    emulator_ip = get_emulator_ip()
    if emulator_ip:
        print(Fore.CYAN + f"🌐 Emulator IP Address: {emulator_ip}" + Style.RESET_ALL)

def run_emulator_specific_function():
    if not device_serial:
        print(Fore.RED + "❗ This function requires a connected device or emulator." + Style.RESET_ALL)
        return False
    if not adb_command:
        print(Fore.RED + "❗ 'adb' command is not available. Cannot execute adb commands." + Style.RESET_ALL)
        return False
    return True

def get_emulator_proxy_status():
    if not run_emulator_specific_function():
        return
    result = run_adb_command(['shell', 'settings', 'get', 'global', 'http_proxy'])
    if result and result.stdout.strip():
        print(Fore.CYAN + "🌐 Current proxy: " + Fore.GREEN + f"{result.stdout.strip()}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "⚠️ No proxy is currently set." + Style.RESET_ALL)

def set_emulator_proxy(ip, port):
    if not run_emulator_specific_function():
        return
    run_adb_command(['shell', 'settings', 'put', 'global', 'http_proxy', f'{ip}:{port}'])
    print(Fore.GREEN + f"✅ Proxy set to {ip}:{port} on the emulator." + Style.RESET_ALL)

def remove_emulator_proxy():
    if not run_emulator_specific_function():
        return
    run_adb_command(['shell', 'settings', 'delete', 'global', 'http_proxy'])
    print(Fore.GREEN + "✅ Proxy removed from the emulator." + Style.RESET_ALL)

def open_adb_shell():
    if not run_emulator_specific_function():
        return
    print("Opening ADB Shell. Type 'exit' to return to the main menu.")
    try:
        subprocess.run([adb_command, '-s', device_serial, 'shell'])
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error opening ADB shell: {e}" + Style.RESET_ALL)

def get_local_ipv4_addresses():
    ip_dict = {}
    for iface_name, iface_addresses in psutil.net_if_addrs().items():
        for addr in iface_addresses:
            if addr.family == socket.AF_INET:
                ip_dict[iface_name] = addr.address
    return ip_dict

def try_download_certificate(ip, port):
    cert_url = f"http://{ip}:{port}/cert"
    input_der_file = "cacert.der"
    output_pem_file = "9a5ba575.0"

    try:
        response = requests.get(cert_url, timeout=10)

        if response.status_code == 200:
            with open(input_der_file, "wb") as certificate_file:
                certificate_file.write(response.content)
            print(f"Burp Suite certificate downloaded successfully from {cert_url}.")

            with open(input_der_file, "rb") as der_file:
                der_data = der_file.read()
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_data)

            with open(output_pem_file, "wb") as pem_file:
                pem_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
                pem_file.write(pem_data)

            run_adb_command(['root'])
            run_adb_command(['remount'])
            run_adb_command(['push', output_pem_file, '/system/etc/security/cacerts/'])
            run_adb_command(['shell', 'chmod', '644', f'/system/etc/security/cacerts/{output_pem_file}'])
            print("Burp Suite Certificate Installed Successfully in the emulator")
            os.remove(input_der_file)
            os.remove(output_pem_file)
            return True
        else:
            print(f"Error: Unable to download the certificate from {cert_url}. Status code: {response.status_code}")
            return False

    except ConnectionError:
        print(f"Error: Burp Suite is not running or the proxy server is not on {ip}:{port}.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return False

def install_burpsuite_certificate(port):
    print(Fore.CYAN + "🔍 Attempting to download the Burp Suite certificate from localhost..." + Style.RESET_ALL)

    # Check localhost first
    if try_download_certificate('127.0.0.1', port):
        print(Fore.GREEN + "✅ Successfully downloaded and installed the Burp Suite certificate from localhost." + Style.RESET_ALL)
        return

    # Check other local IP addresses
    print(Fore.CYAN + "🔍 Checking other local IP addresses for Burp Suite certificate..." + Style.RESET_ALL)
    ipv4_addresses = get_local_ipv4_addresses()

    for ip in ipv4_addresses.values():
        if ip != '127.0.0.1' and try_download_certificate(ip, port):
            print(Fore.GREEN + f"✅ Successfully downloaded and installed the Burp Suite certificate from {ip}." + Style.RESET_ALL)
            return

    print(Fore.RED + "❌ Failed to download the Burp Suite certificate from any local IP address." + Style.RESET_ALL)

def install_tool(tool):
    try:
        subprocess.run(['pip', 'install', tool, '--break-system-packages'], check=True)
        print(Fore.GREEN + f"✅ {tool} installed successfully." + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error installing {tool}: {e}" + Style.RESET_ALL)

    # Step 1: Ensure we are in root mode
    result = run_adb_command(['root'])
    if result is None or result.returncode != 0:
        print(Fore.RED + "❌ Failed to switch adb to root mode." + Style.RESET_ALL)
        return

    # Step 2: Remount the /system partition in read-write mode
    result = run_adb_command(['remount'])
    if result is None or result.returncode != 0:
        print(Fore.RED + "❌ Failed to remount the /system partition as read-write." + Style.RESET_ALL)
        return

    # Step 3: Push the certificate to /system/etc/security/cacerts/
    result = run_adb_command(['push', cert_filename, '/system/etc/security/cacerts/'])
    if result is None or result.returncode != 0:
        print(Fore.RED + "❌ Failed to push the certificate to the system cacerts directory." + Style.RESET_ALL)
        return

    # Calculate the hash of the certificate
    import hashlib
    with open(cert_filename, 'rb') as f:
        cert_data = f.read()
    cert_hash = hashlib.md5(cert_data).hexdigest()

    # Use openssl to get the subject hash
    try:
        openssl_output = subprocess.check_output(['openssl', 'x509', '-inform', 'DER', '-subject_hash_old', '-in', cert_filename])
        hash_line = openssl_output.decode().splitlines()[0]
        cert_hash = hash_line.strip()
    except Exception as e:
        print(Fore.RED + f"❌ Failed to calculate the certificate hash: {e}" + Style.RESET_ALL)
        return

    # Rename the certificate on the device
    result = run_adb_command(['shell', 'mv', f'/system/etc/security/cacerts/{cert_filename}', f'/system/etc/security/cacerts/{cert_hash}.0'])
    if result is None or result.returncode != 0:
        print(Fore.RED + "❌ Failed to rename the certificate on the device." + Style.RESET_ALL)
        return

    # Set the correct permissions
    result = run_adb_command(['shell', 'chmod', '644', f'/system/etc/security/cacerts/{cert_hash}.0'])
    if result is None or result.returncode != 0:
        print(Fore.RED + "❌ Failed to set permissions on the certificate." + Style.RESET_ALL)
        return

    # Step 5: Reboot the emulator
    print(Fore.CYAN + "🔄 Rebooting the emulator to apply changes..." + Style.RESET_ALL)
    result = run_adb_command(['reboot'])
    if result is None or result.returncode != 0:
        print(Fore.RED + "❌ Failed to reboot the emulator." + Style.RESET_ALL)
        return

    print(Fore.GREEN + "✅ Burp Suite certificate installed successfully into the system store." + Style.RESET_ALL)
    print(Fore.GREEN + "Please wait for the emulator to reboot." + Style.RESET_ALL)

def remove_ads_and_bloatware():
    if emulator_type != 'Nox':
        print(Fore.RED + "❗ This function is specific to the Nox emulator." + Style.RESET_ALL)
        return
    if not run_emulator_specific_function():
        return
    print(Fore.CYAN + "🧹 Removing Bloatware and Ads from Nox emulator..." + Style.RESET_ALL)

    run_adb_command(['root'])
    run_adb_command(['remount'])

    bloatware_apps = [
        'AmazeFileManager', 'AppStore', 'CtsShimPrebuilt', 'EasterEgg', 'Facebook',
        'Helper', 'LiveWallpapersPicker', 'PrintRecommendationService', 'PrintSpooler',
        'WallpaperBackup', 'newAppNameEn'
    ]

    for app in bloatware_apps:
        print(Fore.YELLOW + f"🚮 Removing {app}..." + Style.RESET_ALL)
        run_adb_command(['shell', 'rm', '-rf', f'/system/app/{app}'])

    print(Fore.GREEN + "✅ Bloatware removed successfully." + Style.RESET_ALL)

    print(Fore.CYAN + "🔄 Rebooting the emulator..." + Style.RESET_ALL)
    run_adb_command(['shell', 'su', '-c', 'setprop', 'ctl.restart', 'zygote'])

    print(Fore.GREEN + "✅ After successful reboot, configure your settings as needed." + Style.RESET_ALL)

def run_apkleaks():
    """Run apkleaks on a specified APK file and automatically save the output."""
    if not is_apkleaks_installed():
        print(Fore.RED + "❌ apkleaks is not installed or not found in your PATH. Please install it using 'pip install apkleaks'." + Style.RESET_ALL)
        return

    apk_path = input("📝 Enter the path to the APK file: ").strip()

    if not os.path.isfile(apk_path):
        print(Fore.RED + f"❌ Error: The file '{apk_path}' does not exist or is not a valid file." + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n🔍 Running apkleaks on '{apk_path}'..." + Style.RESET_ALL)

    try:
        # Define the output filename
        output_filename = f"{os.path.splitext(os.path.basename(apk_path))[0]}_apkleaks_output.txt"
        output_path = os.path.join(os.getcwd(), output_filename)

        # Run apkleaks with the -o flag to specify the output file
        command = ['apkleaks', '-f', apk_path, '-o', output_path]
        subprocess.run(command, check=True)

        print(Fore.GREEN + f"✅ apkleaks has analyzed the APK and saved the output to '{output_path}'." + Style.RESET_ALL)

    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error running apkleaks: {e}" + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + "❌ apkleaks is not installed or not found in your PATH. Please install it using 'pip install apkleaks'." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"❌ An unexpected error occurred: {str(e)}" + Style.RESET_ALL)

def is_apkleaks_installed():
    try:
        subprocess.run(['apkleaks', '-h'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def run_nuclei_against_apk():
    # Get the path to the APK file
    apk_path = input("Enter the path to the APK file: ").strip()
    if not os.path.exists(apk_path):
        print(f"Error: The file {apk_path} does not exist.")
        return

    # Set the output directory to the current directory
    script_dir = os.getcwd()
    output_dir = os.path.join(script_dir, os.path.splitext(os.path.basename(apk_path))[0])  # Remove the .apk extension

    apktool_command = "apktool" if platform.system().lower() != "windows" else "apktool.bat"

    if os.path.exists(output_dir):
        print(f"\n⚠️  The directory \"{output_dir}\" already exists.")
        print("What would you like to do?")
        print("1. 🕵️  Scan directly using the existing Apktool output")
        print("2. 🔄  Overwrite the output with a fresh decompilation")

        action_choice = input("\nEnter your choice (1 or 2): ").strip()

        if action_choice == '1':
            print("\n✅ Proceeding with the existing Apktool output...\n")
        elif action_choice == '2':
            try:
                subprocess.run([apktool_command, "d", apk_path, "-o", output_dir, "-f"], check=True)
                print("\n🔄 Apktool output has been overwritten with a fresh decompilation.\n")
            except subprocess.CalledProcessError as e:
                print(f"\n❌ Error: Failed to decompile APK. {e}\n")
                return
            except FileNotFoundError as e:
                print(f"\n❌ Error: {e}. Ensure apktool is installed and in your PATH.\n")
                return
        else:
            print("\n❌ Invalid choice. Operation cancelled.\n")
            return
    else:
        try:
            subprocess.run([apktool_command, "d", apk_path, "-o", output_dir], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to decompile APK. {e}")
            return
        except FileNotFoundError as e:
            print(f"Error: {e}. Ensure apktool is installed and in your PATH.")
            return

    # Determine the default template path based on the OS
    user_home = os.path.expanduser("~")
    android_template_path = os.path.join(user_home, "nuclei-templates", "file", "android")
    keys_template_path = os.path.join(user_home, "nuclei-templates", "file", "keys")

    # Template selection menu
    print("\nPlease choose which templates to use:")
    print("1. Android Templates")
    print("2. Keys Templates")
    print("3. Both (Android + Keys)")
    print("4. Custom Template Path")
    template_choice = input("Enter the number of your choice: ").strip()

    # Process template choice
    templates_paths = []
    if template_choice == '1':
        templates_paths = [android_template_path]
    elif template_choice == '2':
        templates_paths = [keys_template_path]
    elif template_choice == '3':
        templates_paths = [android_template_path, keys_template_path]
    elif template_choice == '4':
        custom_path = input("Enter the full path to your custom nuclei templates: ").strip()
        if os.path.exists(custom_path):
            templates_paths = [custom_path]
        else:
            print(f"Error: The path '{custom_path}' does not exist.")
            return
    else:
        print("Invalid choice. Exiting.")
        return

    # Check if the selected template paths exist
    for path in templates_paths:
        if not os.path.exists(path):
            print(f"Templates directory not found at {path}.")
            return

    # Prepare nuclei command
    nuclei_command = ["nuclei", "-target", output_dir]

    # Add template paths to the nuclei command
    for template_path in templates_paths:
        nuclei_command.extend(["-t", template_path])

    # Run nuclei and capture the output
    try:
        result = subprocess.run(nuclei_command, check=True, capture_output=True, text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to run nuclei. {e}")
        return

    # Ask the user if they want to save the output
    save_output = input("Do you want to save the output? (y/n): ").strip().lower()
    if save_output in ['y', 'yes']:
        output_file = os.path.join(script_dir, f"{os.path.splitext(os.path.basename(output_dir))[0]}_nuclei_output.txt")
        with open(output_file, "w") as file:
            file.write(result.stdout)

        print(f"Output saved to {output_file}")

    print("Analysis complete.")

def run_mob_fs():
    if shutil.which("docker"):
        if device_serial is None:
            print("No emulator/device detected. Running MobSF without MOBSF_ANALYZER_IDENTIFIER...")
            cmd = "docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"
        else:
            # Get the IP and port
            # For emulator, device_serial will be like 'emulator-5554'
            if device_serial.startswith('emulator-'):
                # Extract the port
                port = device_serial.split('-')[1]
            elif re.match(r'^\d+\.\d+\.\d+\.\d+:\d+$', device_serial):
                # Device serial is in the form '127.0.0.1:5555'
                port = device_serial.split(':')[1]
            else:
                print("Connected device is not an emulator. Running MobSF without MOBSF_ANALYZER_IDENTIFIER...")
                cmd = "docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"
                open_new_terminal(cmd)
                return

            # Get the IP address of the emulator
            emulator_ip = get_emulator_ip()
            if emulator_ip is None:
                print("Could not get emulator IP. Running MobSF without MOBSF_ANALYZER_IDENTIFIER...")
                cmd = "docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"
            else:
                # Set the environment variable MOBSF_ANALYZER_IDENTIFIER
                mobsf_analyzer_identifier = f"{emulator_ip}:{port}"
                print(f"Running MobSF with MOBSF_ANALYZER_IDENTIFIER='{mobsf_analyzer_identifier}'...")
                cmd = f"docker run -it --rm -e MOBSF_ANALYZER_IDENTIFIER='{mobsf_analyzer_identifier}' --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"

        open_new_terminal(cmd)
    else:
        print("Docker is not installed. Please install Docker first.")


def init_colorama():
    init(autoreset=True)

def print_header(title):
    print("\n" + "="*50)
    print(f"{title:^50}")
    print("="*50)

def show_main_menu():
    print(Fore.CYAN + r"""
    __________       ________               .__    .___
    \______   \ ____ \______ \_______  ____ |__| __| _/
     |       _// __ \ |    |  \_  __ \/  _ \|  |/ __ | 
     |    |   \  ___/ |       \  | \(  <_> )  / /_/ | 
     |____|_  /\___  >_______  /__|   \____/|__\____ | 
            \/     \/        \/                     \/ 
    """)
    print(Fore.GREEN + "Welcome to the Redroid Tool!")
    print("="*50)
    print("1. 🚀  Run Tools")
    print("2. 🎮  Emulator Options")
    print("3. 🕵️  Frida")
    print("4. ❌  Exit")

def show_run_tools_menu():
    print_header("Run Tools")
    print("1. 🛡️  Run MobSF (docker)")
    print("2. 🔍  Run nuclei against APK")
    print("3. 🕵️  Run apkleaks against APK")
    print("4. ↩️  Back")

def show_emulator_options_menu():
    print_header("Emulator Options")
    print("1. 🧹  Remove Ads and Bloatware from Nox")
    print("2. 🛡️  Install Burp Certificate")
    print("3. 💻  Open ADB shell")
    print("4. 🌐  Print proxy status")
    print("5. ⚙️  Set up/modify proxy")
    print("6. ❌  Remove proxy")
    print("7. ↩️  Back")

def show_frida_menu():
    print_header("Frida")
    print("1. 🧩  Install Frida Server")
    print("2. ▶️  Run Frida Server")
    print("3. 📜  List installed applications")
    print("4. 🔓  Run SSL Pinning Bypass")
    print("5. 🛡️  Run Root Check Bypass")
    print("6. 🔑  Android Biometric Bypass")
    print("7. 📝  Run Custom Script")
    print("8. ↩️  Back")

def main():
    init_colorama()
    while True:
        show_main_menu()
        main_choice = input("Enter your choice: ").strip()

        if main_choice == '1':
            while True:
                show_run_tools_menu()
                run_tools_choice = input("📌 Enter your choice: ").strip()

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

        elif main_choice == '2':
            # Emulator options
            while True:
                show_emulator_options_menu()
                emulator_choice = input("Enter your choice: ").strip()

                if emulator_choice == '1':
                    remove_ads_and_bloatware()
                elif emulator_choice == '2':
                    port = input("Enter the port Burp Suite is using to intercept requests: ").strip()
                    if port.isdigit():
                        install_burpsuite_certificate(int(port))
                    else:
                        print(Fore.RED + "❗ Invalid port. Please enter a valid port number." + Style.RESET_ALL)
                elif emulator_choice == '3':
                    open_adb_shell()
                elif emulator_choice == '4':
                    get_emulator_proxy_status()
                elif emulator_choice == '5':
                    ipv4_addresses = get_local_ipv4_addresses()
                    print("\nLocal IPv4 addresses:")
                    print("{:<30} {:<15}".format("Interface", "IP Address"))
                    print("-" * 45)
                    for iface, ip in ipv4_addresses.items():
                        print(f"{iface:<30} {ip:<15}")
                    ip = input("Enter the proxy IP address: ").strip()
                    port = input("Enter the proxy port: ").strip()
                    set_emulator_proxy(ip, port)
                elif emulator_choice == '6':
                    remove_emulator_proxy()
                elif emulator_choice == '7':
                    break
                else:
                    print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)

        elif main_choice == '3':
            # Frida options
            while True:
                show_frida_menu()
                frida_choice = input("Enter your choice: ").strip()

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

        elif main_choice == '4':
            print(Fore.GREEN + "👋 Exiting... Have a great day!")
            break
        else:
            print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
