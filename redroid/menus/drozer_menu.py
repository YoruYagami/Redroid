#!/usr/bin/env python3
"""
Drozer Menu
"""

from colorama import Fore, Style
from redroid.modules.drozer.agent import install_drozer_agent
from redroid.modules.drozer.forward import start_drozer_forwarding
from redroid.modules.drozer.vulnscan import drozer_vulnscan


def show_drozer_menu():
    print("\n" + "=" * 50)
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
