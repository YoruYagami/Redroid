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
    # Check localhost first
    if try_download_certificate('127.0.0.1', port):
        return

    # Check other local IP addresses
    ipv4_addresses = get_local_ipv4_addresses()
    for ip in ipv4_addresses.values():
        if ip != '127.0.0.1' and try_download_certificate(ip, port):
            return

    print("Failed to download the Burp Suite certificate from any local IP address.")

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
                    
                    # Get the desktop path of the current user
                    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop', 'Redroid')
                    os.makedirs(desktop_path, exist_ok=True)
                    local_filepath = os.path.join(desktop_path, "jadx-gui.exe")
                    
                    print(f"Downloading {local_filename} from {download_url}")
                    with requests.get(download_url, stream=True) as r:
                        r.raise_for_status()
                        with open(local_filepath, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=8192):
                                f.write(chunk)
                    print(f"Downloaded and renamed {local_filename} to jadx-gui.exe in your Redroid folder on desktop: {local_filepath}")
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
            
            # Get the desktop path of the current user
            desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop', 'Redroid')
            os.makedirs(desktop_path, exist_ok=True)
            
            # Download apktool.bat
            print(f"Downloading apktool.bat from {bat_url}")
            response = requests.get(bat_url)
            response.raise_for_status()
            bat_path = os.path.join(desktop_path, "apktool.bat")
            with open(bat_path, "wb") as file:
                file.write(response.content)
            
            # Download apktool.jar
            print(f"Downloading apktool.jar from {jar_url}")
            response = requests.get(jar_url)
            response.raise_for_status()
            jar_path = os.path.join(desktop_path, "apktool.jar")
            with open(jar_path, "wb") as file:
                file.write(response.content)
            
            print(f"apktool setup completed. Files downloaded to your Redroid folder on desktop: {bat_path} and {jar_path}")
            print("Please move apktool.bat and apktool.jar to the C:\\Windows folder manually.")
        else:
            print("Unsupported Operating System")
    except Exception as e:
        print(f"An error occurred while setting up apktool: {str(e)}")

def download_latest_nuclei():
    try:
        latest_release_url = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
        response = requests.get(latest_release_url)
        response.raise_for_status()
        latest_release = response.json()

        system = platform.system().lower()
        if system == "linux":
            os.system('go install github.com/projectdiscovery/nuclei/cmd/nuclei@latest')
            print("Nuclei installed successfully using go install.")
        elif system == "windows":
            for asset in latest_release['assets']:
                if 'windows_amd64.zip' in asset['name']:
                    download_url = asset['browser_download_url']
                    local_filename = asset['name']
                    
                    # Get the desktop path of the current user
                    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop', 'Redroid')
                    os.makedirs(desktop_path, exist_ok=True)
                    local_filepath = os.path.join(desktop_path, local_filename)
                    
                    print(f"Downloading {local_filename} from {download_url}")
                    with requests.get(download_url, stream=True) as r:
                        r.raise_for_status()
                        with open(local_filepath, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=8192):
                                f.write(chunk)
                    
                    # Extract the zip file
                    with ZipFile(local_filepath, 'r') as zip_ref:
                        zip_ref.extractall(desktop_path)
                    os.remove(local_filepath)
                    
                    # Move Nuclei to a location in PATH
                    nuclei_path = os.path.join(desktop_path, "nuclei.exe")
                    destination_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Programs', 'nuclei.exe')
                    shutil.move(nuclei_path, destination_path)
                    
                    # Remove README and LICENSE files
                    for file_name in os.listdir(desktop_path):
                        if file_name.lower().startswith('readme') or file_name.lower() == 'license':
                            os.remove(os.path.join(desktop_path, file_name))
                    
                    print(f"Downloaded and installed Nuclei. You can run it from anywhere using the terminal.")
                    
                    # Add the directory to PATH
                    add_to_path(os.path.dirname(destination_path))
                    return
            print("No suitable Nuclei executable found in the latest release.")
        else:
            print("Unsupported Operating System")
    except Exception as e:
        print(f"An error occurred while trying to download the latest version of Nuclei: {str(e)}")

def add_to_path(new_path):
    command = f'setx PATH "%PATH%;{new_path}"'
    os.system(command)

def get_nox_proxy_status():
    if nox_installation_path:
        adb_shell_command = f'\"{nox_installation_path}\\nox_adb.exe\" shell settings get global http_proxy'
        result = subprocess.run(adb_shell_command, shell=True, text=True, capture_output=True)
        if result.stdout.strip():
            print(f"Current proxy: {result.stdout.strip()}")
        else:
            print("No proxy is currently set.")
    else:
        print("Nox player not installed.")

def set_nox_proxy(ip, port):
    if nox_installation_path:
        adb_shell_command = f'\"{nox_installation_path}\\nox_adb.exe\" shell settings put global http_proxy {ip}:{port}'
        subprocess.run(adb_shell_command, shell=True, text=True)
        print(f"Proxy set to {ip}:{port} on Nox Emulator.")
    else:
        print("Nox player not installed.")

def remove_nox_proxy():
    if nox_installation_path:
        adb_shell_command = f'\"{nox_installation_path}\\nox_adb.exe\" shell settings delete global http_proxy'
        subprocess.run(adb_shell_command, shell=True, text=True)
        print("Proxy removed from Nox Emulator.")
    else:
        print("Nox player not installed.")

def remove_ads_and_bloatware():
    print("Removing Bloatware and Ads from Nox Emulator...")
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
        os.system(f'\"{nox_installation_path}\\nox_adb.exe\" shell rm -rf /system/app/{app}')
    print("Bloatware removed successfully.")

    print("Rebooting the Nox Emulator...")
    os.system(f'\"{nox_installation_path}\\nox_adb.exe\" shell su -c \'setprop ctl.restart zygote\'')
    print("After successful reboot, configure your settings as needed.")

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

def run_frida_server():
    if nox_installation_path:
        print("Frida Server is running...")
        print("Below Some Useful commands of Frida-Tools")
        print("List installed applications: frida-ps -Uai")
        runfridaserver = f'\"{nox_installation_path}\\nox_adb.exe\"  shell /data/local/tmp/frida-server'
        os.system(runfridaserver)        
    else:
        print("Frida server not started on the Nox Player.")

def list_installed_applications():
    print("Listing installed applications on Nox Emulator...")
    os.system("frida-ps -Uai")

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
        overwrite = input(f"The directory {output_dir} already exists. Do you want to overwrite it? (y/n): ").strip().lower()
        if overwrite not in ['y', 'yes']:
            print("Operation cancelled.")
            return
        else:
            try:
                subprocess.run([apktool_command, "d", apk_path, "-o", output_dir, "-f"], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error: Failed to decompile APK. {e}")
                return
            except FileNotFoundError as e:
                print(f"Error: {e}. Ensure apktool is installed and in your PATH.")
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
    
    # Get the path to the Nuclei templates directory
    templates_path = input("Enter the path to the nuclei templates you want to use: ").strip()
    if not os.path.exists(templates_path):
        print(f"Error: The directory {templates_path} does not exist.")
        return

    # Run nuclei and capture the output
    try:
        result = subprocess.run(["nuclei", "-target", output_dir, "-t", templates_path], check=True, capture_output=True, text=True)
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

def show_main_menu():
    print("\nMain Menu")
    print("1. Install Tools")
    print("2. Run Tools")
    print("3. NOX Player Options")
    print("4. Frida")
    print("5. Exit")

def show_install_tools_menu():
    print("\nInstall Tools")
    print("1. Frida")
    print("2. Objection")
    print("3. reFlutter")
    print("4. Jadx")
    print("5. apktool")
    print("6. Nuclei")
    print("7. Mob-FS (docker)")
    print("8. apkleaks")
    print("9. Back")

def show_run_tools_menu():
    print("\nRun Tools")
    print("1. Run Mob-FS (docker)")
    print("2. Run nuclei against apk")
    print("3. Back")

def show_nox_player_options_menu():
    print("\nNOX Player Options")
    print("1. Remove Ads From Nox emulator")
    print("2. Install Burp Certificate")
    print("3. Install Frida Server")
    print("4. Get ADB shell")
    print("5. Print proxy status")
    print("6. Set up/modify proxy")
    print("7. Remove proxy")
    print("8. Back")

def show_frida_menu():
    print("\nFrida")
    print("1. List installed applications")
    print("2. Run Frida Server")
    print("3. Back")

def main():
    while True:
        show_main_menu()
        main_choice = input("Enter your choice: ")

        if main_choice == '1':
            while True:
                show_install_tools_menu()
                tools_choice = input("Enter your choice: ")
                
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
                    download_latest_nuclei()
                elif tools_choice == '7':
                    install_mob_fs()
                elif tools_choice == '8':
                    install_tool("apkleaks")
                elif tools_choice == '9':
                    break
                else:
                    print("Invalid choice, please try again.")

        elif main_choice == '2':
            while True:
                show_run_tools_menu()
                run_tools_choice = input("Enter your choice: ")
                
                if run_tools_choice == '1':
                    run_mob_fs()
                elif run_tools_choice == '2':
                    run_nuclei_against_apk()
                elif run_tools_choice == '3':
                    break
                else:
                    print("Invalid choice, please try again.")

        elif main_choice == '3':
            if nox_installation_path:
                connection_result = connect_to_nox_adb()
                print(connection_result)
                if "connected" in connection_result.lower():
                    while True:
                        show_nox_player_options_menu()
                        nox_choice = input("Enter your choice: ")

                        if nox_choice == '1':
                            remove_ads_and_bloatware()
                        elif nox_choice == '2':
                            port = input("Enter the port Burp Suite is using to intercept requests: ")
                            if port.isdigit():
                                install_burpsuite_certificate(int(port))
                            else:
                                print("Invalid port. Please enter a valid port number.")
                        elif nox_choice == '3':
                            install_frida_server()
                        elif nox_choice == '4':
                            open_adb_shell_from_nox()
                        elif nox_choice == '5':
                            get_nox_proxy_status()
                        elif nox_choice == '6':
                            ipv4_addresses = get_local_ipv4_addresses()
                            print("\nLocal IPv4 addresses:")
                            print("{:<30} {:<15}".format("Interface", "IP Address"))
                            print("-" * 45)
                            for iface, ip in ipv4_addresses.items():
                                print("{:<30} {:<15}".format(iface, ip))
                            print()
                            ip = input("Enter the proxy IP address: ")
                            port = input("Enter the proxy port: ")
                            set_nox_proxy(ip, port)
                        elif nox_choice == '7':
                            remove_nox_proxy()
                        elif nox_choice == '8':
                            break
                        else:
                            print("Invalid choice, please try again.")
                else:
                    print("Unable to connect to Nox emulator. Please check if it is running and try again.")
            else:
                print("Nox player not installed or not running.")

        elif main_choice == '4':
            while True:
                show_frida_menu()
                frida_choice = input("Enter your choice: ")

                if frida_choice == '1':
                    list_installed_applications()
                elif frida_choice == '2':
                    run_frida_server()
                elif frida_choice == '3':
                    break
                else:
                    print("Invalid choice, please try again.")

        elif main_choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
