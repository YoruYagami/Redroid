#!/usr/bin/env python3
"""
Main entry point for Redroid - Modular Version
This is a hybrid version that uses the new modular structure
where available and falls back to the original redroid.py
"""

import sys
import argparse
from colorama import Fore, Style

# Import from new modular structure
import redroid.config as config
from redroid.core.device import detect_emulator
from redroid.core.adb import get_adb_command, connect_nox_adb_ports, get_connected_devices
from redroid.menus.main_menu import show_main_menu

# Temporary imports from original file (to be migrated)
sys.path.insert(0, '.')
import redroid as old_redroid


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

    # Use function from original file (will be migrated)
    old_redroid.run_inline_logcat(args.highlight, args.process_filter)


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


def handle_menu_choice(choice):
    """Handle main menu selections"""
    # Sync config with old module
    old_redroid.device_serial = config.device_serial
    old_redroid.adb_command = config.adb_command
    old_redroid.emulator_type = config.emulator_type
    old_redroid.target_app = config.target_app

    if choice == '1':
        old_redroid.set_target_app()
        config.target_app = old_redroid.target_app
    elif choice == '2':
        # Run Tools Menu
        while True:
            old_redroid.show_run_tools_menu()
            tools_choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()
            if tools_choice == '1':
                old_redroid.run_mobsf()
            elif tools_choice == '2':
                old_redroid.run_nuclei_against_apk()
            elif tools_choice == '3':
                old_redroid.run_apkleaks()
            elif tools_choice == '4':
                old_redroid.run_trufflehog_against_apk()
            elif tools_choice == '5':
                old_redroid.run_android_studio_emulator()
            elif tools_choice == '6':
                break
            else:
                print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)
    elif choice == '3':
        # Emulator Options Menu
        while True:
            old_redroid.show_emulator_options_menu()
            emu_choice = input(Fore.CYAN + "🕹️ Enter your choice: " + Style.RESET_ALL).strip()
            if emu_choice == '1':
                print(Fore.YELLOW + "Remove Ads and Bloatware functionality not implemented." + Style.RESET_ALL)
            elif emu_choice == '2':
                port = input(Fore.CYAN + "📝 Enter the Burp Suite port: " + Style.RESET_ALL).strip()
                if port.isdigit():
                    old_redroid.install_burpsuite_certificate(int(port))
                else:
                    print(Fore.RED + "❌ Invalid port. Enter a valid port number." + Style.RESET_ALL)
            elif emu_choice == '3':
                if config.adb_command and config.device_serial:
                    import subprocess
                    subprocess.run(f'{config.adb_command} -s {config.device_serial} shell', shell=True)
                else:
                    print(Fore.RED + "❌ ADB shell not available (no device selected or on Android)." + Style.RESET_ALL)
            elif emu_choice == '4':
                old_redroid.start_smart_logcat()
            elif emu_choice == '5':
                result = old_redroid.run_adb_command('shell settings get global http_proxy')
                if result and result.stdout.strip():
                    print(Fore.CYAN + "🌐 Current proxy: " + Fore.GREEN + result.stdout.strip() + Style.RESET_ALL)
                else:
                    print(Fore.YELLOW + "⚠️ No proxy is currently set." + Style.RESET_ALL)
            elif emu_choice == '6':
                print(Fore.CYAN + "Setting up/modifying proxy..." + Style.RESET_ALL)
                # Proxy setup logic here
            elif emu_choice == '7':
                old_redroid.run_adb_command('shell settings put global http_proxy :0')
                print(Fore.GREEN + "✅ Proxy removed." + Style.RESET_ALL)
            elif emu_choice == '8':
                break
            else:
                print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)
    elif choice == '4':
        # Frida Menu
        while True:
            old_redroid.show_frida_menu()
            frida_choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()
            if frida_choice == '1':
                old_redroid.download_and_install_frida_server()
            elif frida_choice == '2':
                old_redroid.run_frida_server()
            elif frida_choice == '3':
                apps = old_redroid.list_relevant_apps(include_system_apps=False)
                if apps:
                    for idx, app in enumerate(apps, 1):
                        print(f"{idx}. {app}")
            elif frida_choice == '4':
                old_redroid.auto_fridump()
            elif frida_choice == '5':
                old_redroid.run_ssl_pinning_bypass()
            elif frida_choice == '6':
                old_redroid.run_root_check_bypass()
            elif frida_choice == '7':
                old_redroid.run_android_biometric_bypass()
            elif frida_choice == '8':
                old_redroid.run_custom_frida_script()
            elif frida_choice == '9':
                break
            else:
                print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)
    elif choice == '5':
        old_redroid.drozer_menu_loop()
    elif choice == '6':
        old_redroid.exploits_menu_loop()
    elif choice == '7':
        old_redroid.api_keys_testing_menu_loop()
    elif choice == '8':
        print(Fore.GREEN + "👋 Goodbye!" + Style.RESET_ALL)
        sys.exit(0)
    else:
        print(Fore.RED + "❗ Invalid choice, please try again." + Style.RESET_ALL)


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
        main_choice = input(Fore.CYAN + "📌 Enter your choice: " + Style.RESET_ALL).strip()
        handle_menu_choice(main_choice)


if __name__ == '__main__':
    main()
