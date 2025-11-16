#!/usr/bin/env python3
"""
Frida Memory Dump (Fridump)
"""

import os
import subprocess
import shutil
from colorama import Fore, Style
import redroid.config as config
from redroid.modules.target.target_app import list_relevant_apps

def auto_fridump():
    SESSION_FILE = "fridump_session.json"

    def load_session(filepath):
        if not os.path.isfile(filepath):
            return {"dumped_ranges": {}, "skipped_ranges": {}}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or "dumped_ranges" not in data or "skipped_ranges" not in data:
                return {"dumped_ranges": {}, "skipped_ranges": {}}
            return data
        except:
            return {"dumped_ranges": {}, "skipped_ranges": {}}

    def save_session(filepath, dumped, skipped):
        data = {"dumped_ranges": dumped, "skipped_ranges": skipped}
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving session: {e}")

    def print_progress(current, total, prefix='Progress:', bar_length=50):
        filled_length = int(bar_length * current // total)
        bar = '#' * filled_length + '-' * (bar_length - filled_length)
        print(f'\r{prefix} |{bar}| {current}/{total}', end='\r')
        if current == total:
            print()

    def run_strings(directory, min_len=4):
        strings_path = os.path.join(directory, "strings.txt")
        with open(strings_path, "w", encoding='utf-8') as st:
            for filename in os.listdir(directory):
                if filename.endswith(".data"):
                    filepath = os.path.join(directory, filename)
                    try:
                        with open(filepath, 'rb') as f:
                            content = f.read().decode('latin-1', errors='ignore')
                            strings = re.findall(r"[A-Za-z0-9/\-:;.,_$%'!()\[\]<>#]+", content)
                            for s in strings:
                                if len(s) >= min_len:
                                    st.write(s + "\n")
                    except:
                        continue

    def get_emulator_ip_inner():
        try:
            output = subprocess.check_output(["adb", "shell", "ip", "addr"], universal_newlines=True)
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', output)
            if match:
                return match.group(1)
        except subprocess.CalledProcessError:
            pass
        return None

    def adb_forward():
        try:
            subprocess.check_call(["adb", "forward", "tcp:27042", "tcp:27042"])
            print(Fore.GREEN + "[*] ADB port forwarding set up: tcp:27042 -> tcp:27042" + Style.RESET_ALL)
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"[-] Error setting up ADB port forwarding: {e}" + Style.RESET_ALL)
            sys.exit(1)

    def run_frida_ps():
        try:
            result = subprocess.run(["frida-ps", "-Uia"], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            apps = []
            for line in lines[1:]:
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[0].isdigit():
                    pid = int(parts[0])
                    app_name = parts[1].strip()
                    apps.append((pid, app_name))
            return apps
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"[-] Error running 'frida-ps -Uia': {e}" + Style.RESET_ALL)
            sys.exit(1)
        except FileNotFoundError:
            print(Fore.RED + "[-] 'frida-ps' not found. Please ensure Frida is installed and added to PATH." + Style.RESET_ALL)
            sys.exit(1)

    def dump_memory(agent, base, size, directory, max_size=20971520):
        def dump_to_file(addr, sz, fname):
            data = agent.readmemory(addr, sz)
            with open(os.path.join(directory, fname), 'wb') as f:
                f.write(data)
        if size > max_size:
            for i in range(0, size, max_size):
                chunk_size = min(max_size, size - i)
                dump_to_file(base + i, chunk_size, f"{hex(base + i)}_dump.data")
        else:
            dump_to_file(base, size, f"{hex(base)}_dump.data")

    def run_auto_dump():
        session = load_session(SESSION_FILE)
        dumped = session["dumped_ranges"]
        skipped = session["skipped_ranges"]

        ip = get_emulator_ip_inner()
        if not ip:
            print(Fore.RED + "[-] Unable to obtain emulator IP via ADB." + Style.RESET_ALL)
            sys.exit(1)
        print(Fore.GREEN + f"[*] Detected emulator IP: {ip}" + Style.RESET_ALL)

        adb_forward()

        host = "127.0.0.1:27042"
        try:
            device_manager = frida.get_device_manager()
            device = device_manager.add_remote_device(host)
            print(Fore.GREEN + f"[*] Connected to remote device: {host}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[-] Error connecting to remote device: {e}" + Style.RESET_ALL)
            sys.exit(1)

        apps = run_frida_ps()
        if not apps:
            print(Fore.YELLOW + "⚠️ No applications found." + Style.RESET_ALL)
            sys.exit(0)

        print(Fore.GREEN + "\n[*] Running applications:" + Style.RESET_ALL)
        print("{:<10} {}".format("PID", "Application"))
        print("-" * 40)
        for pid, app in apps:
            print("{:<10} {}".format(pid, app))

        try:
            pid_input = input(Fore.CYAN + "\nEnter the PID of the process to dump: " + Style.RESET_ALL).strip()
            pid = int(pid_input)
            if pid not in [app[0] for app in apps]:
                print(Fore.RED + "[-] PID not found in the list of running applications." + Style.RESET_ALL)
                sys.exit(1)
        except ValueError:
            print(Fore.RED + "[-] PID must be an integer." + Style.RESET_ALL)
            sys.exit(1)

        perms = input(Fore.CYAN + "Enter memory permissions to dump (default 'rw-'): " + Style.RESET_ALL).strip()
        if not perms:
            perms = "rw-"
        perms_list = [p.strip() for p in perms.split(',')]

        strings_flag = input(Fore.CYAN + "Do you want to run 'strings' on dumped files? (y/n, default n): " + Style.RESET_ALL).strip().lower() == 'y'

        output_dir = os.path.join(os.getcwd(), "dump")
        os.makedirs(output_dir, exist_ok=True)
        print(Fore.GREEN + f"[*] Output directory: {output_dir}" + Style.RESET_ALL)

        try:
            session_frida = device.attach(pid)
            print(Fore.GREEN + f"[*] Attached to process PID: {pid}" + Style.RESET_ALL)
        except frida.ProcessNotFoundError:
            print(Fore.RED + f"[-] Process with PID '{pid}' not found." + Style.RESET_ALL)
            sys.exit(1)
        except frida.TransportError as e:
            print(Fore.RED + f"[-] Transport error: {e}" + Style.RESET_ALL)
            sys.exit(1)
        except Exception as e:
            print(Fore.RED + f"[-] Unexpected error: {e}" + Style.RESET_ALL)
            sys.exit(1)

        script_code = """
        'use strict';
        rpc.exports = {
          enumerateranges: function (prot) {
            return Process.enumerateRangesSync(prot);
          },
          readmemory: function (address, size) {
            return Memory.readByteArray(ptr(address), size);
          }
        };
        """
        try:
            script = session_frida.create_script(script_code)
            script.load()
            agent = script.exports_sync
            print(Fore.GREEN + "[*] Frida script loaded successfully." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[-] Error loading Frida script: {e}" + Style.RESET_ALL)
            sys.exit(1)

        all_ranges = []
        for p in perms_list:
            try:
                ranges = agent.enumerateranges(p)
                print(Fore.GREEN + f"[*] Found {len(ranges)} regions with permissions '{p}'" + Style.RESET_ALL)
                all_ranges.extend(ranges)
            except Exception as e:
                print(Fore.RED + f"[-] Error enumerating regions for '{p}': {e}" + Style.RESET_ALL)

        if not all_ranges:
            print(Fore.YELLOW + "⚠️ No memory regions found with the specified permissions." + Style.RESET_ALL)
            sys.exit(0)

        unique_ranges = {r['base']: r for r in all_ranges}.values()
        sorted_ranges = sorted(unique_ranges, key=lambda x: x['base'])

        print(Fore.GREEN + f"[*] Total unique memory regions to dump: {len(sorted_ranges)}" + Style.RESET_ALL)

        for idx, region in enumerate(sorted_ranges, 1):
            base = region['base']
            size = region['size']

            if isinstance(base, str):
                try:
                    base_int = int(base, 16)
                except ValueError:
                    print(Fore.RED + f"[-] Invalid base address format: {base}" + Style.RESET_ALL)
                    skipped[base] = True
                    save_session(SESSION_FILE, dumped, skipped)
                    print_progress(idx, len(sorted_ranges))
                    continue
            elif isinstance(base, int):
                base_int = base
            else:
                print(Fore.RED + f"[-] Unexpected base address type: {type(base)} for base {base}" + Style.RESET_ALL)
                skipped[str(base)] = True
                save_session(SESSION_FILE, dumped, skipped)
                print_progress(idx, len(sorted_ranges))
                continue

            base_str = hex(base_int)

            if base_str in dumped or base_str in skipped:
                print_progress(idx, len(sorted_ranges))
                continue

            try:
                dump_memory(agent, base_int, size, output_dir)
                dumped[base_str] = True
                save_session(SESSION_FILE, dumped, skipped)
                print(Fore.GREEN + f"[+] Dumped region {base_str} (size={size} bytes)." + Style.RESET_ALL)
            except Exception as e:
                skipped[base_str] = True
                save_session(SESSION_FILE, dumped, skipped)
                print(Fore.RED + f"[-] Error dumping region {base_str}: {e}" + Style.RESET_ALL)
            print_progress(idx, len(sorted_ranges))

        if strings_flag:
            print(Fore.GREEN + "[*] Running 'strings' on dumped files..." + Style.RESET_ALL)
            run_strings(output_dir)
            print(Fore.GREEN + "[*] 'strings' extraction completed." + Style.RESET_ALL)

        print(Fore.GREEN + "[*] Memory dump completed." + Style.RESET_ALL)
        print(Fore.GREEN + f"[*] Session data saved in '{SESSION_FILE}'." + Style.RESET_ALL)

    run_auto_dump()


