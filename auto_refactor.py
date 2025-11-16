#!/usr/bin/env python3
"""
Automated Redroid refactoring script
This will read redroid.py and split it into a modular structure
"""

import os
import re
import shutil


# File header template
def get_header(description):
    return f'''#!/usr/bin/env python3
"""
{description}
"""

'''


# Import templates
COMMON_IMPORTS = '''import os
import sys
import subprocess
import re
import time
import shutil
from colorama import Fore, Style
'''


def extract_section(content, start_pattern, end_pattern=None):
    """Extract a section of code between start and end patterns."""
    lines = content.split('\n')
    result = []
    capturing = False
    indent_level = None

    for i, line in enumerate(lines):
        if re.search(start_pattern, line):
            capturing = True
            indent_level = len(line) - len(line.lstrip())
            result.append(line)
            continue

        if capturing:
            # If we hit a line at the same or lower indentation level that starts a new definition
            current_indent = len(line) - len(line.lstrip()) if line.strip() else float('inf')

            if line.strip() and current_indent <= indent_level:
                if line.strip().startswith('def ') or line.strip().startswith('class '):
                    break

            result.append(line)

    return '\n'.join(result) if result else ''


def create_file(path, content):
    """Create a file with the given content."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✅ Created: {path}")


def main():
    print("🔧 Starting automated refactoring of redroid.py...")

    if not os.path.exists('redroid.py'):
        print("❌ redroid.py not found!")
        return

    # Read original file
    with open('redroid.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # Extract all function blocks using regex
    functions = {}
    pattern = r'^(def\s+(\w+)\s*\([^)]*\):.*?)(?=^def\s+|\Z)'
    matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)

    for match in matches:
        func_code = match.group(1)
        func_name = match.group(2)
        functions[func_name] = func_code

    print(f"📝 Found {len(functions)} functions")

    # Mapping of functions to modules (based on menu structure and functionality)
    MODULE_MAP = {
        # CORE
        'redroid/core/device.py': ['detect_emulator', 'switch_device', 'setup_ctrl_d_handler',
                                    'safe_shutdown', 'check_and_handle_device_switch',
                                    'get_input_with_device_switch_check'],

        'redroid/core/adb.py': ['connect_nox_adb_ports', 'get_adb_command', 'get_connected_devices',
                                 'run_adb_command'],

        'redroid/core/utils.py': ['get_local_ipv4_addresses', 'try_download_certificate',
                                   'get_emulator_ip', 'run_command_in_background', 'open_new_terminal'],

        # TARGET
        'redroid/modules/target/target_app.py': ['list_relevant_apps', 'set_target_app'],

        # TOOLS
        'redroid/modules/tools/mobsf.py': ['run_mobsf'],
        'redroid/modules/tools/nuclei.py': ['run_nuclei_against_apk'],
        'redroid/modules/tools/apkleaks.py': ['run_apkleaks'],
        'redroid/modules/tools/trufflehog.py': ['run_trufflehog_against_apk'],
        'redroid/modules/tools/android_studio.py': ['run_android_studio_emulator'],

        # EMULATOR
        'redroid/modules/emulator/certificate.py': ['install_burpsuite_certificate'],
        'redroid/modules/emulator/logcat.py': ['start_smart_logcat', 'run_inline_logcat',
                                                 'run_separate_terminal_logcat'],

        # FRIDA
        'redroid/modules/frida/server.py': ['download_and_install_frida_server', 'is_frida_server_running',
                                              'run_frida_server'],
        'redroid/modules/frida/ssl_bypass.py': ['run_ssl_pinning_bypass'],
        'redroid/modules/frida/root_bypass.py': ['run_root_check_bypass'],
        'redroid/modules/frida/biometric_bypass.py': ['run_android_biometric_bypass'],
        'redroid/modules/frida/custom_script.py': ['run_custom_frida_script'],
        'redroid/modules/frida/memory_dump.py': ['auto_fridump'],

        # DROZER
        'redroid/modules/drozer/agent.py': ['install_drozer_agent'],
        'redroid/modules/drozer/forward.py': ['start_drozer_forwarding'],
        'redroid/modules/drozer/vulnscan.py': ['drozer_vulnscan'],

        # EXPLOITS
        'redroid/modules/exploits/apk_utils.py': ['sign_apk'],
        'redroid/modules/exploits/tapjacking.py': ['tapjacking_apk_builder'],
        'redroid/modules/exploits/task_hijacking.py': ['task_hijacking_apk_builder'],

        # API KEYS
        'redroid/modules/api_keys/google_maps.py': ['scan_gmaps'],

        # MENUS
        'redroid/menus/main_menu.py': ['show_main_menu'],
        'redroid/menus/run_tools_menu.py': ['show_run_tools_menu'],
        'redroid/menus/emulator_menu.py': ['show_emulator_options_menu'],
        'redroid/menus/frida_menu.py': ['show_frida_menu'],
        'redroid/menus/drozer_menu.py': ['show_drozer_menu', 'drozer_menu_loop'],
        'redroid/menus/exploits_menu.py': ['show_exploits_menu', 'exploits_menu_loop'],
        'redroid/menus/api_keys_menu.py': ['show_api_keys_testing_menu', 'api_keys_testing_menu_loop'],
    }

    # Create module files
    for module_path, func_names in MODULE_MAP.items():
        module_content = get_header(f"Module: {module_path}")
        module_content += COMMON_IMPORTS
        module_content += "import redroid.config as config\n\n"

        # Add module-specific imports
        if 'frida' in module_path:
            module_content += "import frida\nimport json\n\n"
        if 'mobsf' in module_path or 'certificate' in module_path or 'google_maps' in module_path:
            module_content += "import requests\nfrom bs4 import BeautifulSoup\n\n"
        if 'device' in module_path or 'utils' in module_path:
            module_content += "import psutil\nimport socket\n\n"
        if 'logcat' in module_path:
            module_content += "import signal\nimport threading\n\n"

        # Add functions
        for func_name in func_names:
            if func_name in functions:
                module_content += functions[func_name] + "\n\n"
                print(f"  ➕ Added {func_name} to {module_path}")
            else:
                print(f"  ⚠️  Function {func_name} not found")

        create_file(module_path, module_content)

    # Create main.py
    main_content = get_header("Main entry point for Redroid")
    main_content += '''import sys
import argparse
from colorama import Fore, Style

import redroid.config as config
from redroid.core.device import detect_emulator
from redroid.core.adb import get_adb_command, connect_nox_adb_ports, get_connected_devices
from redroid.menus.main_menu import show_main_menu
from redroid.modules.target.target_app import set_target_app
from redroid.modules.emulator.logcat import run_inline_logcat


def main():
    """Main entry point"""
    # Check if running in logcat mode
    if len(sys.argv) > 1 and "--logcat-mode" in sys.argv:
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
        return

    # Normal mode
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

    # Import menu handlers
    from redroid.menus.run_tools_menu import run_tools_menu_loop
    from redroid.menus.emulator_menu import emulator_menu_loop
    from redroid.menus.frida_menu import frida_menu_loop
    from redroid.menus.drozer_menu import drozer_menu_loop
    from redroid.menus.exploits_menu import exploits_menu_loop
    from redroid.menus.api_keys_menu import api_keys_testing_menu_loop

    # Main menu loop
    while True:
        show_main_menu()
        from redroid.core.device import get_input_with_device_switch_check
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
'''

    create_file('redroid/main.py', main_content)

    print("\n✅ Automated refactoring complete!")
    print(f"\n📊 Summary:")
    print(f"   - Created {len(MODULE_MAP)} module files")
    print(f"   - Distributed {sum(len(v) for v in MODULE_MAP.values())} functions")
    print(f"\n🚀 Run with: python3 -m redroid.main")


if __name__ == '__main__':
    main()
