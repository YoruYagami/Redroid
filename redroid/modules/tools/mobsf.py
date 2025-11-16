#!/usr/bin/env python3
"""
MobSF integration
"""

import os
import subprocess
import shutil
import requests
from colorama import Fore, Style
import redroid.config as config
from redroid.core.adb import run_adb_command
from redroid.core.utils import get_local_ipv4_addresses

def run_mobsf():
    # global config.emulator_type, config.device_serial, adb_command

    if not shutil.which("docker"):
        print(Fore.RED + "❌ Docker is not installed or not in the PATH." + Style.RESET_ALL)
        return

    print("\n" + "=" * 50)
    print(f"{Fore.MAGENTA}=== MobSF Setup ==={Style.RESET_ALL}")
    print("=" * 50)

    # Show currently connected device
    if config.device_serial:
        print(f"{Fore.GREEN}✅ Currently connected device: {device_serial}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}⚠️ No device currently selected{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Do you want to connect MobSF to an emulator?{Style.RESET_ALL}")
    print(f"1. Use currently connected device ({config.device_serial if config.config.device_serial else 'None'})")
    print("2. Specify a custom device ID (e.g., emulator-5554 or adb_ip:adb_port)")
    print("3. Do not use any emulator")
    emu_choice = input("Enter your choice (1/2/3): ").strip()

    mobsf_device = None
    if emu_choice == "1":
        if config.device_serial:
            mobsf_device = config.device_serial
            print(f"{Fore.GREEN}✅ Using currently connected device: {device_serial}{Style.RESET_ALL}")
        else:
            print(Fore.RED + "❌ No device currently connected. Please choose option 2 or 3." + Style.RESET_ALL)
            return
    elif emu_choice == "2":
        custom_id = input("Enter the custom device ID (e.g., emulator-5554): ").strip()
        if custom_id:
            mobsf_device = custom_id
            print(f"{Fore.GREEN}✅ Using custom device: {custom_id}{Style.RESET_ALL}")
        else:
            print(Fore.RED + "❌ Invalid device ID. Aborting." + Style.RESET_ALL)
            return
    elif emu_choice == "3":
        mobsf_device = None
        print(Fore.GREEN + "Proceeding without connecting to an emulator." + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Invalid choice. Aborting." + Style.RESET_ALL)
        return

    custom_proxy_choice = input(f"\n{Fore.CYAN}Do you want to use a custom proxy for MobSF? (y/n): {Style.RESET_ALL}").strip().lower()
    if custom_proxy_choice in ["y", "yes"]:
        print("\n" + Fore.GREEN + "===== Local IP Addresses =====" + Style.RESET_ALL)
        ip_dict = get_local_ipv4_addresses()
        header = f"{'Interface':<30} {'IP Address':<20}"
        print(header)
        print("-" * len(header))
        for iface, ip_addr in ip_dict.items():
            print(f"{iface:<30} {ip_addr:<20}")
        user_ip = input(f"\n{Fore.CYAN}Enter the proxy IP (e.g., 192.168.0.100): {Style.RESET_ALL}").strip()
        user_port = input(f"{Fore.CYAN}Enter the proxy port (e.g., 8080): {Style.RESET_ALL}").strip()
        if not user_ip or not user_port.isdigit():
            print(Fore.RED + "❌ Invalid proxy IP or port. Aborting configuration." + Style.RESET_ALL)
            return
        use_proxy = True
        if config.device_serial:
            proxy_type = input(f"{Fore.CYAN}Configure global proxy on emulator as 'http' or 'https'? (default: http): {Style.RESET_ALL}").strip().lower()
            if proxy_type not in ["http", "https"]:
                proxy_type = "http"
    else:
        use_proxy = False

    print(f"\n{Fore.YELLOW}Checking for existing 'mobsf' container...{Style.RESET_ALL}")
    result = subprocess.run('docker ps -a --filter name=^/mobsf$ --format "{{.Status}}"', shell=True, capture_output=True, text=True)
    container_status = result.stdout.strip()

    if container_status:
        if container_status.lower().startswith("up"):
            print(Fore.GREEN + "✅ 'mobsf' container is already running." + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "⚠️ 'mobsf' container exists but is not running. Starting it..." + Style.RESET_ALL)
            subprocess.run("docker start mobsf", shell=True)
            print(Fore.GREEN + "✅ 'mobsf' container started." + Style.RESET_ALL)
    else:
        docker_cmd = 'docker run -it --name mobsf -p 8000:8000 -p 1337:1337 '
        if mobsf_device:
            docker_cmd += f'-e MOBSF_ANALYZER_IDENTIFIER="{mobsf_device}" '
        if use_proxy:
            docker_cmd += f'-e MOBSF_PROXY_IP="{user_ip}" -e MOBSF_PROXY_PORT="{user_port}" '
        docker_cmd += 'opensecurity/mobile-security-framework-mobsf:latest'

        print(f"\n{Fore.CYAN}Launching MobSF container with the following command:{Style.RESET_ALL}")
        print(docker_cmd)
        open_new_terminal(docker_cmd)

    if mobsf_device and use_proxy:
        settings_key = "http_proxy" if proxy_type == "http" else "https_proxy"
        result = run_adb_command(f'shell settings put global {settings_key} {user_ip}:{user_port}')
        if result and result.returncode == 0:
            print(Fore.GREEN + f"✅ Global {settings_key} set to {user_ip}:{user_port} on emulator {device_serial}." + Style.RESET_ALL)
        else:
            print(Fore.RED + f"❌ Failed to set global {settings_key} on emulator." + Style.RESET_ALL)

    print(Fore.GREEN + "\n✅ Setup complete! The MobSF container is starting in a separate window." + Style.RESET_ALL)


