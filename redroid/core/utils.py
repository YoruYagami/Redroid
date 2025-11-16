#!/usr/bin/env python3
"""
Utility functions for Redroid
"""

import os
import sys
import subprocess
import socket
import shutil
import re
import time
import psutil
import requests
from colorama import Fore, Style
from requests.exceptions import ConnectionError
import redroid.config as config


def get_local_ipv4_addresses():
    """Retrieve local IPv4 addresses."""
    ip_dict = {}
    for iface_name, iface_addresses in psutil.net_if_addrs().items():
        for addr in iface_addresses:
            if addr.family == socket.AF_INET:
                ip_dict[iface_name] = addr.address
    return ip_dict


def get_emulator_ip():
    """Retrieve emulator's IP address."""
    from redroid.core.adb import run_adb_command

    if not config.device_serial:
        print(Fore.RED + "❗ No device selected. Cannot get emulator IP." + Style.RESET_ALL)
        return None
    result = run_adb_command('shell getprop dhcp.eth0.ipaddress')
    if result and result.stdout.strip():
        ip_address = result.stdout.strip()
        print(Fore.GREEN + f"✅ Emulator IP Address: {ip_address}" + Style.RESET_ALL)
        return ip_address
    else:
        result = run_adb_command('shell ip -f inet addr show eth0')
        if result and result.stdout.strip():
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/\d+', result.stdout)
            if match:
                ip_address = match.group(1)
                print(Fore.GREEN + f"✅ Emulator IP Address: {ip_address}" + Style.RESET_ALL)
                return ip_address
    print(Fore.RED + "❗ Could not get emulator IP address." + Style.RESET_ALL)
    return None


def run_command_in_background(cmd):
    """Run a command in the background."""
    subprocess.Popen(f'{cmd} &', shell=True)


def open_new_terminal(cmd):
    """Open a new terminal and execute the given command.
       On Android, simply prints the command.
    """
    if os.environ.get('ANDROID_ARGUMENT'):
        print(Fore.YELLOW + "⚠️ open_new_terminal is not supported on Android. Run this command manually:" + Style.RESET_ALL)
        print(Fore.YELLOW + cmd + Style.RESET_ALL)
        return
    try:
        # Try common Linux terminal emulators
        terminal_emulators = [
            ('gnome-terminal', ['gnome-terminal', '--', 'bash', '-c', f'{cmd}; exec bash']),
            ('konsole', ['konsole', '-e', f'bash -c "{cmd}; exec bash"']),
            ('xfce4-terminal', ['xfce4-terminal', '-e', f'bash -c "{cmd}; exec bash"']),
            ('xterm', ['xterm', '-e', f'bash -c "{cmd}; exec bash"']),
            ('lxterminal', ['lxterminal', '-e', f'bash -c "{cmd}; exec bash"']),
            ('mate-terminal', ['mate-terminal', '-e', f'bash -c "{cmd}; exec bash"']),
            ('terminator', ['terminator', '-e', f'bash -c "{cmd}; exec bash"']),
            ('urxvt', ['urxvt', '-e', 'bash', '-c', f'{cmd}; exec bash'])
        ]

        for term_name, term_cmd in terminal_emulators:
            if shutil.which(term_name):
                subprocess.Popen(term_cmd)
                return

        print(Fore.RED + "❌ No supported terminal emulator found. Run this command manually:" + Style.RESET_ALL)
        print(Fore.YELLOW + cmd + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"❌ Failed to open a new terminal: {e}" + Style.RESET_ALL)


def try_download_certificate(ip, port):
    """Download certificate from Burp Suite proxy"""
    from redroid.core.adb import run_adb_command

    input_der_file = "cacert.der"
    output_file = "9a5ba575.0"

    if os.path.exists(output_file):
        print(Fore.GREEN + f"✅ Found local certificate '{output_file}', skipping remote download." + Style.RESET_ALL)
    else:
        cert_url = f"http://{ip}:{port}/cert"
        try:
            response = requests.get(cert_url, timeout=10)
            if response.status_code == 200:
                with open(input_der_file, "wb") as certificate_file:
                    certificate_file.write(response.content)
                print(Fore.GREEN + f"✅ Certificate downloaded successfully from {cert_url}." + Style.RESET_ALL)
                os.rename(input_der_file, output_file)
                print(Fore.GREEN + f"✅ Renamed {input_der_file} to {output_file}." + Style.RESET_ALL)
            else:
                print(Fore.RED + f"❌ Unable to download the certificate from {cert_url}. Status code: {response.status_code}" + Style.RESET_ALL)
                return False
        except ConnectionError:
            print(Fore.RED + f"❌ Burp Suite is not running or the proxy is not available at {ip}:{port}." + Style.RESET_ALL)
            return False
        except Exception as e:
            print(Fore.RED + f"❌ An unexpected error occurred during download: {str(e)}" + Style.RESET_ALL)
            return False

    push_result = run_adb_command(f'push {output_file} /system/etc/security/cacerts/')
    if push_result is None or (push_result.stderr and "read-only" in push_result.stderr.lower()):
        print(Fore.YELLOW + "⚠️ Error: File system is read-only. Retrying with adb root and remount." + Style.RESET_ALL)
        result_root = run_adb_command('root')
        if result_root is None:
            print(Fore.RED + "❌ Unable to obtain root privileges via adb." + Style.RESET_ALL)
            return False
        time.sleep(5)
        result_remount = run_adb_command('remount')
        if result_remount is None:
            print(Fore.RED + "❌ Unable to remount the partition as writable." + Style.RESET_ALL)
            return False
        push_result = run_adb_command(f'push {output_file} /system/etc/security/cacerts/')
        if push_result is None or (push_result.stderr and "read-only" in push_result.stderr.lower()):
            print(Fore.RED + "❌ The partition is still read-only." + Style.RESET_ALL)
            user_choice = input(Fore.YELLOW + "Would you like to reboot the device now? (y/n): " + Style.RESET_ALL).strip().lower()
            if user_choice in ['y', 'yes']:
                reboot_result = run_adb_command('reboot')
                if reboot_result is None:
                    print(Fore.RED + "❌ Failed to reboot the device. Please reboot manually." + Style.RESET_ALL)
                else:
                    print(Fore.GREEN + "✅ Device reboot initiated. Please try installing the certificate again after the device restarts." + Style.RESET_ALL)
                return False
            else:
                print(Fore.RED + "❌ Certificate installation failed due to read-only partition." + Style.RESET_ALL)
                return False

    chmod_result = run_adb_command(f'shell chmod 644 /system/etc/security/cacerts/{output_file}')
    if chmod_result is None:
        print(Fore.RED + "❌ Failed to set permissions on the certificate." + Style.RESET_ALL)
        return False

    print(Fore.GREEN + "✅ Burp Suite certificate installed successfully on the device." + Style.RESET_ALL)
    try:
        os.remove(output_file)
    except Exception as e:
        print(Fore.YELLOW + f"⚠️ Unable to remove local file {output_file}: {str(e)}" + Style.RESET_ALL)
    return True
