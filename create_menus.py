#!/usr/bin/env python3
import os

# Run Tools Menu
run_tools = '''#!/usr/bin/env python3
"""
Run Tools Menu
"""

from colorama import Fore, Style
from redroid.modules.tools.mobsf import run_mobsf
from redroid.modules.tools.nuclei import run_nuclei_against_apk
from redroid.modules.tools.apkleaks import run_apkleaks
from redroid.modules.tools.trufflehog import run_trufflehog_against_apk
from redroid.modules.tools.android_studio import run_android_studio_emulator


def show_run_tools_menu():
    print("\\n" + "=" * 50)
    print(f"{'Run Tools':^50}")
    print("=" * 50)
    print("1. 🛡️  Run MobSF (docker)")
    print("2. 🔍  Run nuclei against APK")
    print("3. 🕵️  Run apkleaks against APK")
    print("4. 🐷  Run TruffleHog against APK")
    print("5. 🚀  Run Android Studio Emulator")
    print("6. ↩️  Back")


def run_tools_menu_loop():
    while True:
        show_run_tools_menu()
        choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()
        if choice == '1':
            run_mobsf()
        elif choice == '2':
            run_nuclei_against_apk()
        elif choice == '3':
            run_apkleaks()
        elif choice == '4':
            run_trufflehog_against_apk()
        elif choice == '5':
            run_android_studio_emulator()
        elif choice == '6':
            break
        else:
            print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)
'''

# Emulator Menu
emulator = '''#!/usr/bin/env python3
"""
Emulator Options Menu
"""

import subprocess
from colorama import Fore, Style
import redroid.config as config
from redroid.modules.emulator.certificate import install_burpsuite_certificate
from redroid.modules.emulator.logcat import start_smart_logcat
from redroid.core.adb import run_adb_command


def show_emulator_options_menu():
    print("\\n" + "=" * 50)
    print(f"{'Emulator Options':^50}")
    print("=" * 50)
    print("1. 🧹  Remove Ads and Bloatware (Not implemented)")
    print("2. 🛡️  Install Burp Certificate")
    print("3. 💻  Open ADB shell")
    print("4. 📱  Start Smart ADB Logcat")
    print("5. 🌐  Print proxy status")
    print("6. ⚙️  Set up/modify proxy")
    print("7. ❌  Remove proxy")
    print("8. ↩️  Back")


def emulator_menu_loop():
    while True:
        show_emulator_options_menu()
        choice = input(Fore.CYAN + "🕹️ Enter your choice: " + Style.RESET_ALL).strip()
        if choice == '1':
            print(Fore.YELLOW + "Remove Ads and Bloatware functionality not implemented." + Style.RESET_ALL)
        elif choice == '2':
            port = input(Fore.CYAN + "📝 Enter the Burp Suite port: " + Style.RESET_ALL).strip()
            if port.isdigit():
                install_burpsuite_certificate(int(port))
            else:
                print(Fore.RED + "❌ Invalid port. Enter a valid port number." + Style.RESET_ALL)
        elif choice == '3':
            if config.adb_command and config.device_serial:
                subprocess.run(f'{config.adb_command} -s {config.device_serial} shell', shell=True)
            else:
                print(Fore.RED + "❌ ADB shell not available (no device selected or on Android)." + Style.RESET_ALL)
        elif choice == '4':
            start_smart_logcat()
        elif choice == '5':
            result = run_adb_command('shell settings get global http_proxy')
            if result and result.stdout.strip():
                print(Fore.CYAN + "🌐 Current proxy: " + Fore.GREEN + result.stdout.strip() + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "⚠️ No proxy is currently set." + Style.RESET_ALL)
        elif choice == '6':
            print(Fore.CYAN + "Setting up/modifying proxy..." + Style.RESET_ALL)
            print(Fore.YELLOW + "⚠️ Proxy setup functionality not yet implemented in modular version." + Style.RESET_ALL)
        elif choice == '7':
            run_adb_command('shell settings put global http_proxy :0')
            print(Fore.GREEN + "✅ Proxy removed." + Style.RESET_ALL)
        elif choice == '8':
            break
        else:
            print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)
'''

# Frida Menu
frida = '''#!/usr/bin/env python3
"""
Frida Menu
"""

from colorama import Fore, Style
from redroid.modules.frida.server import install_frida_server, run_frida_server
from redroid.modules.frida.ssl_bypass import run_ssl_pinning_bypass
from redroid.modules.frida.root_bypass import run_root_check_bypass
from redroid.modules.frida.biometric_bypass import android_biometric_bypass
from redroid.modules.frida.custom_script import run_custom_frida_script
from redroid.modules.frida.memory_dump import auto_fridump
from redroid.modules.target.target_app import list_relevant_apps


def show_frida_menu():
    print("\\n" + "=" * 50)
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


def frida_menu_loop():
    while True:
        show_frida_menu()
        choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()
        if choice == '1':
            install_frida_server()
        elif choice == '2':
            run_frida_server()
        elif choice == '3':
            apps = list_relevant_apps(include_system_apps=False)
            if apps:
                print("\\n" + Fore.GREEN + "Installed applications:" + Style.RESET_ALL)
                for idx, app in enumerate(apps, 1):
                    print(f"{idx}. {app}")
            else:
                print(Fore.YELLOW + "⚠️ No applications found." + Style.RESET_ALL)
        elif choice == '4':
            auto_fridump()
        elif choice == '5':
            run_ssl_pinning_bypass()
        elif choice == '6':
            run_root_check_bypass()
        elif choice == '7':
            android_biometric_bypass()
        elif choice == '8':
            run_custom_frida_script()
        elif choice == '9':
            break
        else:
            print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)
'''

# Drozer Menu
drozer = '''#!/usr/bin/env python3
"""
Drozer Menu
"""

from colorama import Fore, Style
from redroid.modules.drozer.agent import install_drozer_agent
from redroid.modules.drozer.forward import start_drozer_forwarding
from redroid.modules.drozer.vulnscan import drozer_vulnscan


def show_drozer_menu():
    print("\\n" + "=" * 50)
    print(f"{'Drozer':^50}")
    print("=" * 50)
    print("1. 🏹  Install Drozer Agent")
    print("2. 🚀  Forward Port Locally (31415)")
    print("3. 🐞  Perform Vulnerability Scan")
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
'''

# Exploits Menu
exploits = '''#!/usr/bin/env python3
"""
Exploits Menu
"""

from colorama import Fore, Style
from redroid.modules.exploits.tapjacking import tapjacking_apk_builder
from redroid.modules.exploits.task_hijacking import task_hijacking_apk_builder


def show_exploits_menu():
    print("\\n" + "=" * 50)
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
'''

# API Keys Menu
api_keys = '''#!/usr/bin/env python3
"""
API Keys Testing Menu
"""

from colorama import Fore, Style
from redroid.modules.api_keys.google_maps import scan_gmaps


def show_api_keys_testing_menu():
    print("\\n" + "=" * 50)
    print(f"{'API Keys Testing':^50}")
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
'''

# Write all menus
menus = {
    'redroid/menus/run_tools_menu.py': run_tools,
    'redroid/menus/emulator_menu.py': emulator,
    'redroid/menus/frida_menu.py': frida,
    'redroid/menus/drozer_menu.py': drozer,
    'redroid/menus/exploits_menu.py': exploits,
    'redroid/menus/api_keys_menu.py': api_keys,
}

for path, content in menus.items():
    with open(path, 'w') as f:
        f.write(content)
    print(f"✅ Created {path}")

print(f"\\n✅ Created {len(menus)} menu files!")
