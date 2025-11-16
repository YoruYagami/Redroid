#!/usr/bin/env python3
"""
Frida Biometric Bypass
"""

import subprocess
import frida
from colorama import Fore, Style
import redroid.config as config
from redroid.modules.target.target_app import list_relevant_apps


def android_biometric_bypass():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frida-scripts', 'android-biometric-bypass.js')
    if not os.path.exists(script_path):
        print(Fore.RED + f"❌ Script not found at {script_path}. Ensure the script is in the 'frida-scripts' directory." + Style.RESET_ALL)
        return
    if not is_frida_server_running():
        print(Fore.YELLOW + "⚠️ Frida-Server is not running. Attempting to start it..." + Style.RESET_ALL)
        run_frida_server()
        if not is_frida_server_running():
            print(Fore.RED + "❌ Frida-Server is not running. Cannot proceed with Android Biometric Bypass." + Style.RESET_ALL)
            return
    
    if not config.target_app:
        print(Fore.YELLOW + "No target set. Please select a target application:" + Style.RESET_ALL)
        set_target_app()
        if not config.target_app:
            print(Fore.RED + "No target set. Aborting operation." + Style.RESET_ALL)
            return
    app_package = config.target_app
    print(Fore.GREEN + f"Using target application: {app_package}" + Style.RESET_ALL)
    cmd = f'frida -U -f {app_package} -l "{script_path}"'
    print(Fore.CYAN + f"🚀 Running Android Biometric Bypass on {app_package}..." + Style.RESET_ALL)
    open_new_terminal(cmd)

