#!/usr/bin/env python3
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
    print("\n" + "=" * 50)
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
