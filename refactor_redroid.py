#!/usr/bin/env python3
"""
Automatic refactoring script for Redroid
This script analyzes redroid.py and creates a modular structure
"""

import os
import re
import ast


# Module mapping: function name -> destination module
FUNCTION_TO_MODULE = {
    # Core - Device
    'detect_emulator': 'redroid/core/device.py',
    'switch_device': 'redroid/core/device.py',
    'setup_ctrl_d_handler': 'redroid/core/device.py',
    'safe_shutdown': 'redroid/core/device.py',
    'check_and_handle_device_switch': 'redroid/core/device.py',
    'get_input_with_device_switch_check': 'redroid/core/device.py',

    # Core - ADB
    'connect_nox_adb_ports': 'redroid/core/adb.py',
    'get_adb_command': 'redroid/core/adb.py',
    'get_connected_devices': 'redroid/core/adb.py',
    'run_adb_command': 'redroid/core/adb.py',

    # Core - Utils
    'get_local_ipv4_addresses': 'redroid/core/utils.py',
    'try_download_certificate': 'redroid/core/utils.py',
    'run_command_in_background': 'redroid/core/utils.py',
    'open_new_terminal': 'redroid/core/utils.py',
    'get_emulator_ip': 'redroid/core/utils.py',

    # Target
    'list_relevant_apps': 'redroid/modules/target/target_app.py',
    'set_target_app': 'redroid/modules/target/target_app.py',

    # Tools
    'run_mobsf': 'redroid/modules/tools/mobsf.py',
    'run_nuclei_against_apk': 'redroid/modules/tools/nuclei.py',
    'run_apkleaks': 'redroid/modules/tools/apkleaks.py',
    'run_trufflehog_against_apk': 'redroid/modules/tools/trufflehog.py',
    'run_android_studio_emulator': 'redroid/modules/tools/android_studio.py',

    # Emulator
    'install_burpsuite_certificate': 'redroid/modules/emulator/certificate.py',
    'start_smart_logcat': 'redroid/modules/emulator/logcat.py',
    'run_inline_logcat': 'redroid/modules/emulator/logcat.py',
    'run_separate_terminal_logcat': 'redroid/modules/emulator/logcat.py',

    # Frida
    'download_and_install_frida_server': 'redroid/modules/frida/server.py',
    'is_frida_server_running': 'redroid/modules/frida/server.py',
    'run_frida_server': 'redroid/modules/frida/server.py',
    'run_ssl_pinning_bypass': 'redroid/modules/frida/ssl_bypass.py',
    'run_root_check_bypass': 'redroid/modules/frida/root_bypass.py',
    'run_android_biometric_bypass': 'redroid/modules/frida/biometric_bypass.py',
    'run_custom_frida_script': 'redroid/modules/frida/custom_script.py',
    'auto_fridump': 'redroid/modules/frida/memory_dump.py',

    # Drozer
    'install_drozer_agent': 'redroid/modules/drozer/agent.py',
    'start_drozer_forwarding': 'redroid/modules/drozer/forward.py',
    'drozer_vulnscan': 'redroid/modules/drozer/vulnscan.py',

    # Exploits
    'sign_apk': 'redroid/modules/exploits/apk_utils.py',
    'tapjacking_apk_builder': 'redroid/modules/exploits/tapjacking.py',
    'task_hijacking_apk_builder': 'redroid/modules/exploits/task_hijacking.py',

    # API Keys
    'scan_gmaps': 'redroid/modules/api_keys/google_maps.py',

    # Menus
    'show_main_menu': 'redroid/menus/main_menu.py',
    'show_run_tools_menu': 'redroid/menus/run_tools_menu.py',
    'show_emulator_options_menu': 'redroid/menus/emulator_menu.py',
    'show_frida_menu': 'redroid/menus/frida_menu.py',
    'show_drozer_menu': 'redroid/menus/drozer_menu.py',
    'show_exploits_menu': 'redroid/menus/exploits_menu.py',
    'show_api_keys_testing_menu': 'redroid/menus/api_keys_menu.py',
    'exploits_menu_loop': 'redroid/menus/exploits_menu.py',
    'api_keys_testing_menu_loop': 'redroid/menus/api_keys_menu.py',
    'drozer_menu_loop': 'redroid/menus/drozer_menu.py',
}


def extract_imports_from_file(filepath):
    """Extract all import statements from a Python file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    imports = []
    for line in content.split('\n'):
        stripped = line.strip()
        if stripped.startswith('import ') or stripped.startswith('from '):
            imports.append(line)

    return imports


def extract_function_code(content, function_name):
    """Extract the complete code of a function from the file content."""
    lines = content.split('\n')
    function_lines = []
    in_function = False
    indent_level = None

    for i, line in enumerate(lines):
        # Check if this is the start of our function
        if re.match(rf'^def\s+{re.escape(function_name)}\s*\(', line):
            in_function = True
            indent_level = len(line) - len(line.lstrip())
            function_lines.append(line)
            continue

        if in_function:
            # Check if we've reached the end of the function
            if line.strip() and not line.startswith(' ') and not line.startswith('\t'):
                # Found a non-indented line, function ended
                break

            # Check if we've reached another function definition at the same level
            if line.strip().startswith('def ') and len(line) - len(line.lstrip()) == indent_level:
                break

            function_lines.append(line)

    return '\n'.join(function_lines)


def create_module_file(filepath, functions_code, imports):
    """Create a module file with the given functions and imports."""
    # Ensure directory exists
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    # Create file header
    header = '''#!/usr/bin/env python3
"""
Auto-generated module from redroid.py refactoring
"""

'''

    # Add necessary imports
    imports_section = '\n'.join(imports) + '\n'
    imports_section += 'import redroid.config as config\n'
    imports_section += 'from colorama import Fore, Style\n\n'

    # Combine everything
    content = header + imports_section + '\n'.join(functions_code)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"✅ Created: {filepath}")


def main():
    print("🔧 Starting Redroid refactoring...")

    # Read original file
    with open('redroid.py', 'r', encoding='utf-8') as f:
        original_content = f.read()

    # Extract base imports
    base_imports = extract_imports_from_file('redroid.py')

    # Group functions by module
    modules = {}
    for func_name, module_path in FUNCTION_TO_MODULE.items():
        if module_path not in modules:
            modules[module_path] = []

        # Extract function code
        func_code = extract_function_code(original_content, func_name)
        if func_code:
            modules[module_path].append(func_code)
            print(f"📝 Extracted: {func_name} -> {module_path}")
        else:
            print(f"⚠️  Could not find: {func_name}")

    # Create module files
    for module_path, functions_code in modules.items():
        create_module_file(module_path, functions_code, base_imports)

    print("\n✅ Refactoring complete!")
    print("📁 New structure created in ./redroid/ directory")


if __name__ == '__main__':
    main()
