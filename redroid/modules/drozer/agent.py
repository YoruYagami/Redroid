#!/usr/bin/env python3
"""
Drozer Agent Installation
"""

import os
import subprocess
import requests
from colorama import Fore, Style
import redroid.config as config
from redroid.core.adb import run_adb_command

def install_drozer_agent():
    # global adb_command, config.device_serial
    if config.adb_command is None or not config.device_serial:
        print(Fore.RED + "❌ ADB command unavailable or no device selected. Cannot install Drozer Agent." + Style.RESET_ALL)
        return

    print(Fore.CYAN + "🔎 Checking latest Drozer Agent release..." + Style.RESET_ALL)
    try:
        response = requests.get("https://api.github.com/repos/WithSecureLabs/drozer-agent/releases/latest", timeout=15)
        response.raise_for_status()
        release_data = response.json()
        assets = release_data.get("assets", [])
        apk_url = None

        for asset in assets:
            if asset["browser_download_url"].endswith(".apk"):
                apk_url = asset["browser_download_url"]
                break

        if not apk_url:
            print(Fore.RED + "❌ Could not find an .apk asset in the latest Drozer release." + Style.RESET_ALL)
            return

        print(Fore.CYAN + f"🔗 Downloading Drozer Agent from: {apk_url}" + Style.RESET_ALL)
        apk_filename = "drozer-agent-latest.apk"
        with requests.get(apk_url, stream=True) as r:
            r.raise_for_status()
            with open(apk_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(Fore.GREEN + "✅ Drozer Agent APK downloaded successfully." + Style.RESET_ALL)

        install_command = f'install -r "{apk_filename}"'
        print(Fore.CYAN + "📦 Installing Drozer Agent APK on the device..." + Style.RESET_ALL)
        result = run_adb_command(install_command)
        if result and result.returncode == 0:
            print(Fore.GREEN + "✅ Drozer Agent installed successfully." + Style.RESET_ALL)
        else:
            print(Fore.RED + "❌ Installation failed. Check adb logs for details." + Style.RESET_ALL)

        try:
            os.remove(apk_filename)
        except Exception:
            pass

    except Exception as e:
        print(Fore.RED + f"❌ An error occurred while downloading or installing Drozer Agent: {e}" + Style.RESET_ALL)


