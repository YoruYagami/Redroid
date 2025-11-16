#!/usr/bin/env python3
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
                print("\n" + Fore.GREEN + "Installed applications:" + Style.RESET_ALL)
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
