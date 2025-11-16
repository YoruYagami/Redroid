#!/usr/bin/env python3
"""
Android Studio Emulator
"""

import os
import subprocess
import shutil
from colorama import Fore, Style
import redroid.config as config

def run_android_studio_emulator():
    try:
        # On Linux, emulator is typically in ~/Android/Sdk/emulator/
        home_dir = os.path.expanduser("~")
        emulator_dir = os.path.join(home_dir, "Android", "Sdk", "emulator")
        emulator_exe = os.path.join(emulator_dir, "emulator")
        
        if not os.path.exists(emulator_exe):
            # Try alternative location
            emulator_exe = shutil.which("emulator")
            if not emulator_exe:
                print(Fore.RED + f"❌ Emulator not found. Please ensure Android SDK is installed." + Style.RESET_ALL)
                return
            emulator_dir = os.path.dirname(emulator_exe)
        
        list_command = f'{emulator_exe} -list-avds'
        output = subprocess.check_output(list_command, shell=True, universal_newlines=True)
        avds = [line.strip() for line in output.strip().splitlines() if line.strip()]
        if not avds:
            print(Fore.RED + "❌ No AVD found." + Style.RESET_ALL)
            return
        print(Fore.GREEN + "Available AVDs:" + Style.RESET_ALL)
        for idx, avd in enumerate(avds, 1):
            print(f"{idx}. {avd}")
        choice = input(Fore.CYAN + "Enter the number of the AVD to launch: " + Style.RESET_ALL).strip()
        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(avds):
            print(Fore.RED + "❌ Invalid selection." + Style.RESET_ALL)
            return
        selected_avd = avds[int(choice) - 1]
        launch_command = f'cd {emulator_dir} && ./emulator -avd {selected_avd} -no-snapshot -writable-system &'
        print(Fore.CYAN + f"Launching emulator in background: {launch_command}" + Style.RESET_ALL)
        subprocess.Popen(launch_command, shell=True)
    except Exception as e:
        print(Fore.RED + f"❌ Error launching emulator: {e}" + Style.RESET_ALL)


