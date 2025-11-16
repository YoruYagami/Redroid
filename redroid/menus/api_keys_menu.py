#!/usr/bin/env python3
"""
API Keys Testing Menu
"""

from colorama import Fore, Style
from redroid.modules.api_keys.google_maps import scan_gmaps


def show_api_keys_testing_menu():
    print("\n" + "=" * 50)
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
