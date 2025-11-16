#!/usr/bin/env python3
"""
Complete refactoring script - extracts all functions from redroid.py
and distributes them into the proper modular structure
"""

import re
import os


def read_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def extract_function(content, func_name):
    """Extract a complete function from the source code"""
    pattern = rf'^(def {re.escape(func_name)}\([^)]*\):.*?)(?=^def\s+|\Z)'
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    if match:
        return match.group(1).rstrip() + '\n'
    return None


def write_module(path, header, imports, functions_dict, source_content):
    """Write a complete module file"""
    os.makedirs(os.path.dirname(path), exist_ok=True)

    content = f'''#!/usr/bin/env python3
"""
{header}
"""

{imports}

'''

    # Add each function
    for func_name in functions_dict:
        func_code = extract_function(source_content, func_name)
        if func_code:
            # Replace global variable references with config.variable
            func_code = func_code.replace('global adb_command', '# global adb_command')
            func_code = func_code.replace('global device_serial', '# global device_serial')
            func_code = func_code.replace('global target_app', '# global target_app')
            func_code = func_code.replace('global emulator_type', '# global emulator_type')
            func_code = func_code.replace(' adb_command ', ' config.adb_command ')
            func_code = func_code.replace(' device_serial', ' config.device_serial')
            func_code = func_code.replace('device_serial ', 'config.device_serial ')
            func_code = func_code.replace('(device_serial', '(config.device_serial')
            func_code = func_code.replace(' target_app', ' config.target_app')
            func_code = func_code.replace('target_app ', 'config.target_app ')
            func_code = func_code.replace('(target_app', '(config.target_app')
            func_code = func_code.replace(' emulator_type', ' config.emulator_type')

            content += func_code + '\n\n'
        else:
            print(f"⚠️  Function '{func_name}' not found")

    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"✅ Created: {path}")


def main():
    print("🔧 Starting complete refactoring...")

    source = read_file('redroid.py')

    # Define all modules and their functions
    modules = {
        # Don't recreate these - already done
        # 'redroid/core/device.py': ...,
        # 'redroid/core/adb.py': ...,
        # 'redroid/core/utils.py': ...,
        # 'redroid/modules/target/target_app.py': ...,

        # TOOLS
        'redroid/modules/tools/mobsf.py': {
            'header': 'MobSF integration',
            'imports': '''import os
import subprocess
import shutil
import requests
from colorama import Fore, Style
import redroid.config as config
from redroid.core.adb import run_adb_command
from redroid.core.utils import get_local_ipv4_addresses''',
            'functions': ['run_mobsf']
        },

        'redroid/modules/tools/nuclei.py': {
            'header': 'Nuclei integration for APK scanning',
            'imports': '''import os
import subprocess
import shutil
from colorama import Fore, Style''',
            'functions': ['run_nuclei_against_apk']
        },

        'redroid/modules/tools/apkleaks.py': {
            'header': 'APKLeaks integration',
            'imports': '''import os
import subprocess
import shutil
from colorama import Fore, Style''',
            'functions': ['run_apkleaks']
        },

        'redroid/modules/tools/trufflehog.py': {
            'header': 'TruffleHog integration',
            'imports': '''import os
import subprocess
import shutil
from colorama import Fore, Style''',
            'functions': ['run_trufflehog_against_apk']
        },

        'redroid/modules/tools/android_studio.py': {
            'header': 'Android Studio Emulator',
            'imports': '''import os
import subprocess
import shutil
from colorama import Fore, Style
import redroid.config as config''',
            'functions': ['run_android_studio_emulator']
        },

        # EMULATOR
        'redroid/modules/emulator/certificate.py': {
            'header': 'Certificate management',
            'imports': '''import os
from colorama import Fore, Style
import redroid.config as config
from redroid.core.utils import try_download_certificate''',
            'functions': ['install_burpsuite_certificate']
        },

        'redroid/modules/emulator/logcat.py': {
            'header': 'Smart logcat functionality',
            'imports': '''import os
import sys
import subprocess
import re
import signal
import threading
import time
from colorama import Fore, Style
import redroid.config as config
from redroid.core.adb import run_adb_command
from redroid.core.utils import open_new_terminal
from redroid.modules.target.target_app import list_relevant_apps''',
            'functions': ['start_smart_logcat', 'run_inline_logcat', 'run_separate_terminal_logcat']
        },

        # FRIDA
        'redroid/modules/frida/server.py': {
            'header': 'Frida server management',
            'imports': '''import os
import subprocess
import time
import shutil
import lzma
import platform
import requests
from colorama import Fore, Style
import redroid.config as config
from redroid.core.adb import run_adb_command''',
            'functions': ['download_and_install_frida_server', 'is_frida_server_running', 'run_frida_server']
        },

        'redroid/modules/frida/ssl_bypass.py': {
            'header': 'Frida SSL Pinning Bypass',
            'imports': '''import subprocess
import frida
from colorama import Fore, Style
import redroid.config as config
from redroid.modules.target.target_app import list_relevant_apps''',
            'functions': ['run_ssl_pinning_bypass']
        },

        'redroid/modules/frida/root_bypass.py': {
            'header': 'Frida Root Check Bypass',
            'imports': '''import subprocess
import frida
from colorama import Fore, Style
import redroid.config as config
from redroid.modules.target.target_app import list_relevant_apps''',
            'functions': ['run_root_check_bypass']
        },

        'redroid/modules/frida/biometric_bypass.py': {
            'header': 'Frida Biometric Bypass',
            'imports': '''import subprocess
import frida
from colorama import Fore, Style
import redroid.config as config
from redroid.modules.target.target_app import list_relevant_apps''',
            'functions': ['run_android_biometric_bypass']
        },

        'redroid/modules/frida/custom_script.py': {
            'header': 'Frida Custom Script',
            'imports': '''import subprocess
import os
import frida
from colorama import Fore, Style
import redroid.config as config
from redroid.modules.target.target_app import list_relevant_apps''',
            'functions': ['run_custom_frida_script']
        },

        'redroid/modules/frida/memory_dump.py': {
            'header': 'Frida Memory Dump (Fridump)',
            'imports': '''import os
import subprocess
import shutil
from colorama import Fore, Style
import redroid.config as config
from redroid.modules.target.target_app import list_relevant_apps''',
            'functions': ['auto_fridump']
        },

        # DROZER
        'redroid/modules/drozer/agent.py': {
            'header': 'Drozer Agent Installation',
            'imports': '''import os
import subprocess
import requests
from colorama import Fore, Style
import redroid.config as config
from redroid.core.adb import run_adb_command''',
            'functions': ['install_drozer_agent']
        },

        'redroid/modules/drozer/forward.py': {
            'header': 'Drozer Port Forwarding',
            'imports': '''from colorama import Fore, Style
import redroid.config as config
from redroid.core.adb import run_adb_command''',
            'functions': ['start_drozer_forwarding']
        },

        'redroid/modules/drozer/vulnscan.py': {
            'header': 'Drozer Vulnerability Scanning',
            'imports': '''import os
import subprocess
import datetime
from colorama import Fore, Style
import redroid.config as config''',
            'functions': ['drozer_vulnscan']
        },

        # EXPLOITS
        'redroid/modules/exploits/apk_utils.py': {
            'header': 'APK utilities (signing)',
            'imports': '''import os
import subprocess
import requests
from colorama import Fore, Style''',
            'functions': ['sign_apk']
        },

        'redroid/modules/exploits/tapjacking.py': {
            'header': 'Tapjacking APK Builder',
            'imports': '''import os
import subprocess
import shutil
from colorama import Fore, Style
import redroid.config as config
from redroid.modules.target.target_app import set_target_app
from redroid.modules.exploits.apk_utils import sign_apk
from redroid.core.adb import run_adb_command''',
            'functions': ['tapjacking_apk_builder']
        },

        'redroid/modules/exploits/task_hijacking.py': {
            'header': 'Task Hijacking APK Builder',
            'imports': '''import os
import subprocess
import shutil
from colorama import Fore, Style
import redroid.config as config
from redroid.modules/target.target_app import set_target_app
from redroid.modules.exploits.apk_utils import sign_apk
from redroid.core.adb import run_adb_command''',
            'functions': ['task_hijacking_apk_builder']
        },

        # API KEYS
        'redroid/modules/api_keys/google_maps.py': {
            'header': 'Google Maps API Key Testing',
            'imports': '''import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style''',
            'functions': ['scan_gmaps']
        },
    }

    # Create all modules
    for module_path, module_info in modules.items():
        write_module(
            module_path,
            module_info['header'],
            module_info['imports'],
            module_info['functions'],
            source
        )

    print("\n✅ Complete refactoring finished!")
    print(f"Created {len(modules)} module files")


if __name__ == '__main__':
    main()
