#!/usr/bin/env python3
"""
Redroid - Main Entry Point (Modular Version)
Complete modular refactoring - fully independent from redroid.py
"""

import sys
import argparse
from colorama import Fore, Style

# Core imports
import redroid.config as config
from redroid.core.device import detect_emulator, get_input_with_device_switch_check
from redroid.core.adb import get_adb_command, connect_nox_adb_ports, get_connected_devices

# Menu imports
from redroid.menus.main_menu import show_main_menu
from redroid.menus.run_tools_menu import run_tools_menu_loop
from redroid.menus.emulator_menu import emulator_menu_loop
from redroid.menus.frida_menu import frida_menu_loop
from redroid.menus.drozer_menu import drozer_menu_loop
from redroid.menus.exploits_menu import exploits_menu_loop
from redroid.menus.api_keys_menu import api_keys_testing_menu_loop

# Module imports
from redroid.modules.target.target_app import set_target_app
from redroid.modules.emulator.logcat import run_inline_logcat


def handle_logcat_mode():
    """Handle logcat mode command line arguments"""
    parser = argparse.ArgumentParser(description='Redroid Smart Logcat')
    parser.add_argument('--logcat-mode', action='store_true', help='Run in logcat mode')
    parser.add_argument('--device', required=True, help='Device serial')
    parser.add_argument('--adb-command', required=True, help='ADB command path')
    parser.add_argument('--highlight', help='Highlight strings (comma-separated)')
    parser.add_argument('--process-filter', help='Process filter')

    args = parser.parse_args()

    config.device_serial = args.device
    config.adb_command = args.adb_command

    run_inline_logcat(args.highlight, args.process_filter)


def init_device():
    """Initialize device connection"""
    config.emulator_type, config.emulator_installation_path = detect_emulator()
    if config.emulator_type:
        print(Fore.GREEN + f"✅ Emulator detected: {config.emulator_type}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "⚠️ Emulator not detected or running on Android." + Style.RESET_ALL)

    config.adb_command = get_adb_command(config.emulator_type, config.emulator_installation_path)

    if config.emulator_type == 'Nox' and config.adb_command:
        connect_nox_adb_ports(config.adb_command)

    devices = get_connected_devices(config.adb_command)
    if not devices:
        print(Fore.YELLOW + "⚠️ No devices connected via adb." + Style.RESET_ALL)
        config.device_serial = None
    elif len(devices) == 1:
        config.device_serial = devices[0]
        print(Fore.GREEN + f"✅ Device connected: {config.device_serial}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "⚠️ Multiple devices connected:" + Style.RESET_ALL)
        for idx, dev in enumerate(devices, 1):
            print(f"{idx}. {dev}")
        choice = input("🔢 Select a device by number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(devices):
            config.device_serial = devices[int(choice) - 1]
            print(Fore.GREEN + f"✅ Device selected: {config.device_serial}" + Style.RESET_ALL)
        else:
            print(Fore.RED + "❌ Invalid choice. No device selected." + Style.RESET_ALL)
            config.device_serial = None


def main():
    """Main entry point"""
    # Check if running in logcat mode
    if len(sys.argv) > 1 and "--logcat-mode" in sys.argv:
        handle_logcat_mode()
        return

    # Initialize device
    init_device()

    # Main menu loop
    while True:
        show_main_menu()
        main_choice = get_input_with_device_switch_check(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()

        if main_choice == '1':
            set_target_app()
        elif main_choice == '2':
            run_tools_menu_loop()
        elif main_choice == '3':
            emulator_menu_loop()
        elif main_choice == '4':
            frida_menu_loop()
        elif main_choice == '5':
            drozer_menu_loop()
        elif main_choice == '6':
            exploits_menu_loop()
        elif main_choice == '7':
            api_keys_testing_menu_loop()
        elif main_choice == '8':
            print(Fore.GREEN + "👋 Goodbye!" + Style.RESET_ALL)
            sys.exit(0)
        else:
            print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)


if __name__ == '__main__':
    main()
