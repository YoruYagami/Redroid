import os
import subprocess
import platform
import psutil
import requests
import socket
import re
import shutil
import lzma
from zipfile import ZipFile
from OpenSSL import crypto
from requests.exceptions import ConnectionError
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import shlex

def find_nox_installation_path():
    for process in psutil.process_iter(['pid', 'name', 'exe']):
        if 'Nox.exe' in process.info['name']:
            return os.path.dirname(process.info['exe'])
    return None

nox_installation_path = find_nox_installation_path()

def connect_to_nox_adb(ip='127.0.0.1', port=62001):
    if nox_installation_path:
        adb_command = f'\"{nox_installation_path}\\nox_adb.exe\" connect {ip}:{port}'
        result = subprocess.run(adb_command, shell=True, text=True, capture_output=True)
        return result.stdout.strip()
    else:
        return "Nox player not installed."

def open_adb_shell_from_nox():
    if nox_installation_path:
        adb_shell_command = f'\"{nox_installation_path}\\nox_adb.exe\" shell -t su'
        print("Opening ADB Shell. Type 'exit' to return to the main menu.")
        subprocess.run(adb_shell_command, shell=True)
    else:
        print("Nox player not installed.")

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
        response = requests.get(cert_url)

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

            os.system(f'\"{nox_installation_path}\\nox_adb.exe\" root')
            os.system(f'\"{nox_installation_path}\\nox_adb.exe\" remount')
            os.system(f'\"{nox_installation_path}\\nox_adb.exe\" push {output_pem_file} /system/etc/security/cacerts/')
            os.system(f'\"{nox_installation_path}\\nox_adb.exe\" shell chmod 644 /system/etc/security/cacerts/{output_pem_file}')
            print("BurpSuite Certificate Installed Successfully in Nox Player")
            return True
        else:
            print(f"Error: Unable to download the certificate from {cert_url}.")
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
    subprocess.run(['pip', 'install', tool])

def download_latest_jadx():
    system = platform.system().lower()
    if system == "linux":
        # Check for specific Linux distributions
        if os.path.exists("/etc/debian_version"):  # Debian
            print("Detected Debian-based system (e.g., Kali Linux)")
            os.system("sudo apt update && sudo apt install jadx -y")
            print("Jadx installed successfully via apt.")
        elif os.path.exists("/etc/arch-release"):  # Arch
            print("Detected Arch Linux")
            os.system("sudo pacman -Sy jadx --noconfirm")
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
    response = requests.get(url)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, 'html.parser')
    for link in soup.find_all('a'):
        href = link.get('href')
        if href and href.endswith('.jar'):
            return f"https://bitbucket.org{href}"
    return None

def setup_apktool():
    try:
        system = platform.system().lower()
        if system == "linux":
            distro_info = os.popen('cat /etc/*release').read().lower()
            if 'kali' in distro_info or 'debian' in distro_info or 'ubuntu' in distro_info:
                os.system('sudo apt update && sudo apt install apktool -y')
            elif 'arch' in distro_info or 'manjaro' in distro_info:
                os.system('sudo pacman -Syu apktool --noconfirm')
            else:
                print("Unsupported Linux distribution")
                return
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



def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def add_to_system_path(path):
    """Add a directory to the system PATH environment variable."""
    subprocess.run(f'setx /M PATH "%PATH%;{path}"', shell=True)
    print(f"Added {path} to the system PATH.")

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
            go_bin_path = os.path.expanduser("~\\go\\bin")
            add_to_system_path(go_bin_path)
            
            if not check_nuclei_installed():
                print("Running with elevated privileges to add Nuclei to PATH...")
                if is_admin():
                    add_to_system_path(go_bin_path)
                else:
                    # Elevate to admin only for modifying the PATH
                    print("Requesting administrative privileges to modify PATH...")
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, "elevate", 1)
                    return  # Exit after elevating to avoid re-running as admin
            
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

def get_nox_proxy_status():
    if nox_installation_path:
        adb_shell_command = f'\"{nox_installation_path}\\nox_adb.exe\" shell settings get global http_proxy'
        result = subprocess.run(adb_shell_command, shell=True, text=True, capture_output=True)
        if result.stdout.strip():
            print(Fore.CYAN + "🌐 Current proxy: " + Fore.GREEN + f"{result.stdout.strip()}" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "⚠️ No proxy is currently set." + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Nox player not installed." + Style.RESET_ALL)

def set_nox_proxy(ip, port):
    if nox_installation_path:
        adb_shell_command = f'\"{nox_installation_path}\\nox_adb.exe\" shell settings put global http_proxy {ip}:{port}'
        subprocess.run(adb_shell_command, shell=True, text=True)
        print(Fore.GREEN + f"✅ Proxy set to {ip}:{port} on Nox Emulator." + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Nox player not installed." + Style.RESET_ALL)

def remove_nox_proxy():
    if nox_installation_path:
        adb_shell_command = f'\"{nox_installation_path}\\nox_adb.exe\" shell settings delete global http_proxy'
        subprocess.run(adb_shell_command, shell=True, text=True)
        print(Fore.GREEN + "✅ Proxy removed from Nox Emulator." + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Nox player not installed." + Style.RESET_ALL)

def remove_ads_and_bloatware():
    print(Fore.CYAN + "🧹 Removing Bloatware and Ads from Nox Emulator..." + Style.RESET_ALL)
    
    debloatroot = f'\"{nox_installation_path}\\nox_adb.exe\" root'
    os.system(debloatroot)
    
    debloatremount = f'\"{nox_installation_path}\\nox_adb.exe\" remount'
    os.system(debloatremount)
    
    bloatware_apps = [
        'AmazeFileManager', 'AppStore', 'CtsShimPrebuilt', 'EasterEgg', 'Facebook',
        'Helper', 'LiveWallpapersPicker', 'PrintRecommendationService', 'PrintSpooler',
        'WallpaperBackup', 'newAppNameEn'
    ]
    
    for app in bloatware_apps:
        print(Fore.YELLOW + f"🚮 Removing {app}..." + Style.RESET_ALL)
        os.system(f'\"{nox_installation_path}\\nox_adb.exe\" shell rm -rf /system/app/{app}')
    
    print(Fore.GREEN + "✅ Bloatware removed successfully." + Style.RESET_ALL)

    print(Fore.CYAN + "🔄 Rebooting the Nox Emulator..." + Style.RESET_ALL)
    os.system(f'\"{nox_installation_path}\\nox_adb.exe\" shell su -c \'setprop ctl.restart zygote\'')
    
    print(Fore.GREEN + "✅ After successful reboot, configure your settings as needed." + Style.RESET_ALL)


def install_frida_server():
    print("Checking Installed Frida-Tools Version")
    frida_version_output = subprocess.check_output("frida --version 2>&1", shell=True, stderr=subprocess.STDOUT, text=True)
    if re.search(r'(\d+\.\d+\.\d+)', frida_version_output):
        frida_version = re.search(r'(\d+\.\d+\.\d+)', frida_version_output).group(1)
        print(f"Frida-Tools Version: {frida_version}")
        
        noxarch = f'\"{nox_installation_path}\\nox_adb.exe\"  shell getprop ro.product.cpu.abi'
        noxarchre = subprocess.run(noxarch, shell=True, text=True, check=True, capture_output=True)
        noxarchresult = noxarchre.stdout.strip()
        print(f"CPU Architecture of Nox Emulator: {noxarchresult}")
        
        print("Downloading Frida-Server With Same Version")
        frida_server_url = f"https://github.com/frida/frida/releases/download/{frida_version}/frida-server-{frida_version}-android-{noxarchresult}.xz"
        
        response = requests.get(frida_server_url)
        with open("frida-server.xz", "wb") as f:
            f.write(response.content)
        
        with lzma.open("frida-server.xz") as f:
            with open("frida-server", "wb") as out_f:
                out_f.write(f.read())
        
        os.remove("frida-server.xz")
        
        os.system(f'\"{nox_installation_path}\\nox_adb.exe\" push frida-server /data/local/tmp/')
        os.remove("frida-server")
        
        chmodfridaserver = f'\"{nox_installation_path}\\nox_adb.exe\"  shell chmod +x /data/local/tmp/frida-server'
        os.system(chmodfridaserver)
        print("Provided executable permissions to Frida Server.")
        print("Frida Server setup completely on Nox Emulator.")
        print()
    else:
        print("Frida Tools is not installed on this system.")

def is_frida_server_running():
    try:
        check_command = [os.path.join(nox_installation_path, "nox_adb.exe"), "shell", "pgrep", "-f", "frida-server"]
        result = subprocess.run(check_command, capture_output=True, text=True)
        return result.returncode == 0  # Returncode 0 means the process is running
    except Exception as e:
        print(f"Error checking if Frida server is running: {str(e)}")
        return False

def run_frida_server():
    if nox_installation_path:
        if is_frida_server_running():
            print("Frida server is already running.")
            return

        print("Starting Frida Server in the background...")

        command = [os.path.join(nox_installation_path, "nox_adb.exe"), "shell", "/data/local/tmp/frida-server"]
        
        try:
            if platform.system().lower() == 'windows':
                subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_CONSOLE)
            else:  # Linux and macOS
                subprocess.Popen(command)
            
            print("Frida Server should be running in the background.")
        except Exception as e:
            print(f"Failed to start Frida server: {str(e)}")
    else:
        print("Nox player not installed or Frida server not started on the Nox Player.")

def list_installed_applications():
    print("Listing installed applications on Nox Emulator...")
    os.system("frida-ps -Uai")

def list_running_apps():
    try:
        result = subprocess.run(['frida-ps', '-U', '-a'], capture_output=True, text=True)
        print("Currently running applications:")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to list running applications. {e}")

def run_ssl_pinning_bypass():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frida-scripts', 'ssl-pinning-bypass.js')
    if os.path.exists(script_path):
        list_running_apps()
        app_package = input("Enter the app package name to run the SSL pinning bypass on: ").strip()
        
        # Check if Frida Gadget is embedded and the app is running
        try:
            # Start the app and attach Frida
            subprocess.run(['frida', '-U', '-f', app_package, '-l', script_path])
            print("SSL pinning bypass script executed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to execute SSL pinning bypass script. {e}")
    else:
        print(f"Error: Script not found at {script_path}. Please ensure the script is in the 'frida-scripts' directory.")

def run_root_check_bypass():
    if not is_frida_server_running():
        run_frida_server()
        if not is_frida_server_running():
            print("Error: Frida server is not running. Cannot proceed with root check bypass.")
            return
    
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frida-scripts', 'root-check-bypass.js')
    if os.path.exists(script_path):
        list_running_apps()
        app_package = input("Enter the app package name to run the root check bypass on: ").strip()
        
        # Check if Frida Gadget is embedded and the app is running
        try:
            # Start the app and attach Frida
            subprocess.run(['frida', '-U', '-f', app_package, '-l', script_path])
            print("Root check bypass script executed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to execute root check bypass script. {e}")
    else:
        print(f"Error: Script not found at {script_path}. Please ensure the script is in the 'frida-scripts' directory.")

def android_biometric_bypass():
    list_running_apps()  # List currently running apps
    app_package = input("Enter the app package name to run the Android Biometric Bypass on: ").strip()

    if app_package:
        command = f"frida --codeshare ax/universal-android-biometric-bypass -n {app_package}"
        print(Fore.GREEN + "Running Android Biometric Bypass...")
        os.system(command)
    else:
        print(Fore.RED + "❗ Invalid package name. Please enter a valid app package name.")

def run_custom_frida_script():
    frida_scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frida-scripts')
    
    # List existing known scripts
    known_scripts = {
        'ssl-pinning-bypass.js',
        'root-check-bypass.js',
        'android-biometric-bypass.js'
    }
    
    # Find any new/unknown JS scripts in the frida-scripts directory
    all_scripts = {f for f in os.listdir(frida_scripts_dir) if f.endswith('.js')}
    unknown_scripts = all_scripts - known_scripts

    # If there are any unknown scripts, list them and allow the user to choose one
    if unknown_scripts:
        print(Fore.CYAN + "\n🔍 Detected custom scripts in the 'frida-scripts' directory:" + Style.RESET_ALL)
        unknown_scripts_list = list(unknown_scripts)
        for idx, script in enumerate(unknown_scripts_list, 1):
            print(f"{Fore.YELLOW}{idx}. {script}{Style.RESET_ALL}")

        use_existing = input(Fore.CYAN + "✨ Do you want to execute one of these custom scripts? (y/n): " + Style.RESET_ALL).strip().lower()
        if use_existing in ['y', 'yes']:
            script_choice = input(f"🎯 Enter the number of the script you want to execute (1-{len(unknown_scripts_list)}): ").strip()
            if script_choice.isdigit() and 1 <= int(script_choice) <= len(unknown_scripts_list):
                script_path = os.path.join(frida_scripts_dir, unknown_scripts_list[int(script_choice) - 1])
            else:
                print(Fore.RED + "❌ Invalid choice. Exiting." + Style.RESET_ALL)
                return
        else:
            # Prompt the user to enter the full path to their custom script
            print(Fore.YELLOW + "⚠️ It is recommended to place your custom script in the 'frida-scripts' folder for easier access." + Style.RESET_ALL)
            script_path = input(Fore.CYAN + "📝 Please provide the full path to your custom Frida script: " + Style.RESET_ALL).strip()
    else:
        # No unknown scripts found, ask the user to provide a path to a custom script
        print(Fore.YELLOW + "⚠️ No custom scripts detected in the 'frida-scripts' directory." + Style.RESET_ALL)
        print(Fore.YELLOW + "⚠️ It is recommended to place your custom script in the 'frida-scripts' folder for easier access." + Style.RESET_ALL)
        script_path = input(Fore.CYAN + "📝 Please provide the full path to your custom Frida script: " + Style.RESET_ALL).strip()

    # Ensure Frida server is running
    if not is_frida_server_running():
        run_frida_server()
        if not is_frida_server_running():
            print(Fore.RED + "❌ Error: Frida server is not running. Cannot proceed with the custom script." + Style.RESET_ALL)
            return

    # List running apps and select the target app
    list_running_apps()
    app_package = input(Fore.CYAN + "📱 Enter the app package name to run the custom script on: " + Style.RESET_ALL).strip()

    # Run the custom script with Frida
    if app_package:
        try:
            print(Fore.GREEN + "🚀 Running custom script..." + Style.RESET_ALL)
            subprocess.run(['frida', '-U', '-f', app_package, '-l', script_path])
            print(Fore.GREEN + "✅ Custom script executed successfully." + Style.RESET_ALL)
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"❌ Error: Failed to execute custom script. {e}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Invalid package name. Please enter a valid app package name." + Style.RESET_ALL)

def install_mob_fs():
    if shutil.which("docker"):
        print("Installing Mob-FS...")
        os.system("docker pull opensecurity/mobile-security-framework-mobsf:latest")
        print("Mob-FS installed successfully.")
    else:
        print("Docker is not installed. Please install Docker first.")

def run_mob_fs():
    if shutil.which("docker"):
        print("Running Mob-FS...")
        os.system("docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest")
    else:
        print("Docker is not installed. Please install Docker first.")

def run_nuclei_against_apk():
    # Get the path to the APK file
    apk_path = input("Enter the path to the APK file: ").strip()
    if not os.path.exists(apk_path):
        print(f"Error: The file {apk_path} does not exist.")
        return
    
    # Set the output directory to the current directory
    script_dir = os.getcwd()
    output_dir = os.path.join(script_dir, apk_path.rsplit('.', 1)[0])  # Remove the .apk extension
    
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
    if platform.system().lower() == "windows":
        user_home = os.path.expanduser("~")
        default_templates_path = os.path.join(user_home, "nuclei-templates")
    else:  # Assuming Linux
        user_home = os.path.expanduser("~")
        default_templates_path = os.path.join(user_home, "nuclei-templates")

    # Template selection menu
    print("\nPlease choose the template option you want to use:")
    print(f"1. Default Nuclei Templates (Path: {default_templates_path})")
    print("2. Custom (Specify your own path)")
    template_choice = input("Enter the number of your choice: ").strip()

    # Process template choice
    if template_choice == '1':
        templates_path = default_templates_path
        if not os.path.exists(templates_path):
            print(f"Default templates directory not found at {templates_path}.")
            return
    elif template_choice == '2':
        templates_path = input("Enter the path to your custom Nuclei templates: ").strip()
        if not os.path.exists(templates_path):
            print(f"Error: The directory {templates_path} does not exist.")
            return
    else:
        print("Invalid choice. Exiting.")
        return

    # Ask the user for the severity level
    severity_level = input("Enter the severity level (low, medium, high, critical) you want to use (leave blank for none): ").strip().lower()
    
    nuclei_command = ["nuclei", "-target", output_dir, "-t", templates_path]
    
    if severity_level:
        nuclei_command.extend(["-severity", severity_level])

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
        output_file = os.path.join(script_dir, f"{os.path.basename(output_dir)}_nuclei_output.txt")
        with open(output_file, "w") as file:
            file.write(result.stdout)
        
        print(f"Output saved to {output_file}")

    print("Analysis complete.")

# Initialize colorama
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
     |    |   \  ___/ |    `   \  | \(  <_> )  / /_/ | 
     |____|_  /\___  >_______  /__|   \____/|__\____ | 
            \/     \/        \/                     \/ 
    """)
    print(Fore.GREEN + "Welcome to the Redroid Tool!")
    print("="*50)
    print("1. 🛠️  Install Tools")
    print("2. 🚀  Run Tools")
    print("3. 🎮  NOX Player Options")
    print("4.  🕵️  Frida")
    print("5. ❌  Exit")

def show_install_tools_menu():
    print_header("Install Tools")
    print("1. 🧩  Frida")
    print("2. 🔐  Objection")
    print("3. 🛠️  reFlutter")
    print("4. 🖥️  Jadx")
    print("5. 🗃️  APKTool")
    print("6. 🔎  Nuclei")
    print("7. 📦  Mob-FS (docker)")
    print("8. 🔍  apkleaks")
    print("9. ↩️  Back")

def show_run_tools_menu():
    print_header("Run Tools")
    print("1. 🛡️  Run Mob-FS (docker)")
    print("2. 🔍  Run nuclei against APK")
    print("3. ↩️  Back")

def show_nox_player_options_menu():
    print_header("NOX Player Options")
    print("1. 🧹  Remove Ads From Nox emulator")
    print("2. 🛡️  Install Burp Certificate")
    print("3. 💻  Open ADB shell")
    print("4. 🌐  Print proxy status")
    print("5. ⚙️  Set up/modify proxy")
    print("6. ❌  Remove proxy")
    print("7. ↩️  Back")

def show_frida_menu():
    print("\nFrida")
    print("1. 🧩  Install Frida Server")
    print("2. ▶️  Run Frida Server")
    print("3. 📜  List installed applications")
    print("4. 🔓  Run SSL Pinning Bypass")
    print("5. 🛡️  Run Root Check Bypass")
    print("6. 🔑  Android Biometric Bypass")
    print("7. 📝  Run Custom Script")
    print("8. ↩️  Back")


def main():
    while True:
        show_main_menu()
        main_choice = input("Enter your choice: ").strip()

        if main_choice == '1':
            while True:
                show_install_tools_menu()
                tools_choice = input("Enter your choice: ").strip()

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
                    print(Fore.RED + "❗ Invalid choice, please try again.")

        elif main_choice == '2':
            while True:
                show_run_tools_menu()
                run_tools_choice = input("Enter your choice: ").strip()

                if run_tools_choice == '1':
                    run_mob_fs()
                elif run_tools_choice == '2':
                    run_nuclei_against_apk()
                elif run_tools_choice == '3':
                    break
                else:
                    print(Fore.RED + "❗ Invalid choice, please try again.")

        elif main_choice == '3':
            if nox_installation_path:
                connection_result = connect_to_nox_adb()
                print(connection_result)
                if "connected" in connection_result.lower():
                    while True:
                        show_nox_player_options_menu()
                        nox_choice = input("Enter your choice: ").strip()

                        if nox_choice == '1':
                            remove_ads_and_bloatware()
                        elif nox_choice == '2':
                            port = input("Enter the port Burp Suite is using to intercept requests: ").strip()
                            if port.isdigit():
                                install_burpsuite_certificate(int(port))
                            else:
                                print(Fore.RED + "❗ Invalid port. Please enter a valid port number.")
                        elif nox_choice == '3':
                            open_adb_shell_from_nox()
                        elif nox_choice == '4':
                            get_nox_proxy_status()
                        elif nox_choice == '5':
                            ipv4_addresses = get_local_ipv4_addresses()
                            print("\nLocal IPv4 addresses:")
                            print("{:<30} {:<15}".format("Interface", "IP Address"))
                            print("-" * 45)
                            for iface, ip in ipv4_addresses.items():
                                print(f"{iface:<30} {ip:<15}")
                            ip = input("Enter the proxy IP address: ").strip()
                            port = input("Enter the proxy port: ").strip()
                            set_nox_proxy(ip, port)
                        elif nox_choice == '6':
                            remove_nox_proxy()
                        elif nox_choice == '7':
                            break
                        else:
                            print(Fore.RED + "❗ Invalid choice, please try again.")
                else:
                    print(Fore.RED + "❗ Unable to connect to Nox emulator. Please check if it is running and try again.")
            else:
                print(Fore.RED + "❗ Nox player not installed or not running.")

        elif main_choice == '4':
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
                    print(Fore.RED + "❗ Invalid choice, please try again.")

        elif main_choice == '5':
            print(Fore.GREEN + "👋 Exiting... Have a great day!")
            break
        else:
            print(Fore.RED + "❗ Invalid choice, please try again.")

if __name__ == "__main__":
    main()