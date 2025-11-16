#!/usr/bin/env python3
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
    print("\n" + "=" * 50)
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
