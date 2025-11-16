#!/usr/bin/env python3
"""
Smart logcat functionality
"""

import os
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
from redroid.modules.target.target_app import list_relevant_apps

def start_smart_logcat():
    """Start an intelligent ADB logcat with string highlighting."""
    # global adb_command, config.device_serial, config.target_app
    
    if config.adb_command is None or not config.device_serial:
        print(Fore.RED + "❌ ADB command unavailable or no device selected. Cannot start logcat." + Style.RESET_ALL)
        return
    
    print(Fore.CYAN + "📱 Starting Smart ADB Logcat..." + Style.RESET_ALL)
    print(Fore.YELLOW + "💡 You can specify strings to highlight (separated by commas)" + Style.RESET_ALL)
    print(Fore.YELLOW + "💡 Example: user_1,password_1,login,error" + Style.RESET_ALL)
    
    highlight_strings = input(Fore.CYAN + "Enter strings to highlight (comma-separated, or press Enter for none): " + Style.RESET_ALL).strip()
    
    # Check if target app is already set
    process_filter = None
    if config.target_app:
        process_filter = config.target_app
        print(f"\n{Fore.GREEN}✅ Target app already set: {target_app}{Style.RESET_ALL}")
        print(Fore.GREEN + f"✅ Using target app for monitoring: {process_filter}" + Style.RESET_ALL)
    else:
        print(f"\n{Fore.CYAN}📋 Select a process to monitor:{Style.RESET_ALL}")
    
    # If no process filter set yet, show selection menu
    if process_filter is None:
        # Get list of running processes
        apps = list_relevant_apps(include_system_apps=False)
        
        if not apps:
            print(Fore.YELLOW + "⚠️ No relevant running applications found." + Style.RESET_ALL)
            include_system = input(Fore.CYAN + "Would you like to include system apps? (y/n): " + Style.RESET_ALL).strip().lower()
            if include_system in ['y', 'yes']:
                apps = list_relevant_apps(include_system_apps=True)
                if not apps:
                    print(Fore.RED + "❌ No applications found even with system apps included." + Style.RESET_ALL)
                    return
            else:
                print(Fore.RED + "❌ No processes available for monitoring." + Style.RESET_ALL)
                return
        
        # Show available processes
        print(f"\n{Fore.GREEN}Available processes:{Style.RESET_ALL}")
        for idx, app in enumerate(apps, 1):
            current_indicator = " (current target)" if app == config.config.target_app else ""
            print(f"{idx}. {app}{current_indicator}")
        
        print(f"{len(apps) + 1}. Enter process name manually")
        print(f"{len(apps) + 2}. Monitor all processes (no filter)")
        
        # Get user choice
        choice = input(Fore.CYAN + f"Enter your choice (1-{len(apps) + 2}): " + Style.RESET_ALL).strip()
        
        if choice.isdigit():
            choice_num = int(choice)
            if 1 <= choice_num <= len(apps):
                process_filter = apps[choice_num - 1]
                print(Fore.GREEN + f"✅ Selected process: {process_filter}" + Style.RESET_ALL)
            elif choice_num == len(apps) + 1:
                # Manual entry
                process_filter = input(Fore.CYAN + "Enter process name or package to filter: " + Style.RESET_ALL).strip()
                if process_filter:
                    print(Fore.GREEN + f"✅ Manual process filter: {process_filter}" + Style.RESET_ALL)
                else:
                    print(Fore.YELLOW + "⚠️ No process specified, monitoring all processes." + Style.RESET_ALL)
            elif choice_num == len(apps) + 2:
                # No filter
                process_filter = None
                print(Fore.GREEN + "✅ Monitoring all processes (no filter)" + Style.RESET_ALL)
            else:
                print(Fore.RED + "❌ Invalid choice. Monitoring all processes." + Style.RESET_ALL)
                process_filter = None
        else:
            print(Fore.RED + "❌ Invalid choice. Monitoring all processes." + Style.RESET_ALL)
            process_filter = None
    
    # Ask user where to run logcat
    print(f"\n{Fore.CYAN}Where do you want to run the logcat?{Style.RESET_ALL}")
    print("1. Current window (inline)")
    print("2. Separate terminal window")
    
    window_choice = input(Fore.CYAN + "Enter your choice (1/2): " + Style.RESET_ALL).strip()
    
    if window_choice == "1":
        # Run inline in current window
        run_inline_logcat(highlight_strings, process_filter)
    elif window_choice == "2":
        # Run in separate terminal
        run_separate_terminal_logcat(highlight_strings, process_filter)
    else:
        print(Fore.RED + "❌ Invalid choice. Defaulting to current window." + Style.RESET_ALL)
        run_inline_logcat(highlight_strings, process_filter)


def run_inline_logcat(highlight_strings, process_filter=None):
    """Run logcat directly in the current terminal with highlighting and optional process filtering."""
    # global adb_command, config.device_serial
    
    # Color mapping for different highlight strings
    colors = [
        Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN,
        Fore.LIGHTRED_EX, Fore.LIGHTGREEN_EX, Fore.LIGHTYELLOW_EX, 
        Fore.LIGHTBLUE_EX, Fore.LIGHTMAGENTA_EX, Fore.LIGHTCYAN_EX
    ]
    
    def highlight_line(line):
        """Apply highlighting to a log line based on configured strings."""
        if not highlight_strings:
            return line
        
        search_strings = [s.strip() for s in highlight_strings.split(',') if s.strip()]
        
        # Check if ANY of the search strings is in the line (OR logic)
        should_highlight = False
        for search_string in search_strings:
            if search_string and search_string.lower() in line.lower():
                should_highlight = True
                break
        
        # If no match found, return original line
        if not should_highlight:
            return line
        
        # If match found, apply highlighting to ALL matching strings in the line
        highlighted_line = line
        for i, search_string in enumerate(search_strings):
            if search_string:
                color = colors[i % len(colors)]
                # Case-insensitive highlighting
                pattern = re.compile(re.escape(search_string), re.IGNORECASE)
                highlighted_line = pattern.sub(
                    lambda m: f"{color}{Style.BRIGHT}{m.group()}{Style.RESET_ALL}", 
                    highlighted_line
                )
        
        return highlighted_line
    
    print(f"{Fore.GREEN}📱 Starting logcat for device: {device_serial}{Style.RESET_ALL}")
    if process_filter:
        print(f"{Fore.BLUE}🔍 Filtering by process: {process_filter}{Style.RESET_ALL}")
    if highlight_strings:
        print(f"{Fore.CYAN}🎨 Highlighting strings: {highlight_strings}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}💡 Press Ctrl+C to stop{Style.RESET_ALL}")
    print("=" * 80)
    
    # Store logcat output for potential saving
    logcat_output = []
    
    try:
        # Build logcat command with optional process filter
        cmd = f'{adb_command} -s {device_serial} logcat'
        if process_filter:
            # Add process filter using grep
            cmd += f' | grep "{process_filter}"'
        
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1
        )
        
        for line in iter(process.stdout.readline, ''):
            if line:
                # Store the original line for saving
                logcat_output.append(line.rstrip())
                
                highlighted_line = highlight_line(line.rstrip())
                print(highlighted_line)
                sys.stdout.flush()
                
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️ Logcat stopped by user{Style.RESET_ALL}")
        if process:
            process.terminate()
        
        # Ask user if they want to save the output
        if logcat_output:
            save_choice = input(f"{Fore.CYAN}💾 Do you want to save the logcat output to a file? (y/n): {Style.RESET_ALL}").strip().lower()
            if save_choice in ['y', 'yes']:
                # Generate filename with timestamp
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"logcat_output_{timestamp}.txt"
                
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(f"Logcat output for device: {device_serial}\n")
                        if process_filter:
                            f.write(f"Process filter: {process_filter}\n")
                        if highlight_strings:
                            f.write(f"Highlight strings: {highlight_strings}\n")
                        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("=" * 80 + "\n")
                        
                        for line in logcat_output:
                            f.write(line + "\n")
                    
                    print(f"{Fore.GREEN}✅ Logcat output saved to: {filename}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}❌ Error saving logcat output: {e}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}📝 Logcat output not saved{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}⚠️ No logcat output to save{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}❌ Error running logcat: {e}{Style.RESET_ALL}")
    finally:
        if 'process' in locals():
            process.terminate()


def run_separate_terminal_logcat(highlight_strings, process_filter=None):
    """Run logcat in a separate terminal using the current redroid.py script."""
    # global adb_command, config.device_serial
    
    # Prepare the command to run redroid.py with logcat parameters
    current_script = os.path.abspath(__file__)
    
    # Create command arguments for the separate terminal
    args = [
        sys.executable, current_script,
        "--logcat-mode",
        "--device", config.device_serial,
        "--adb-command", adb_command
    ]
    
    if highlight_strings:
        args.extend(["--highlight", highlight_strings])
    
    if process_filter:
        args.extend(["--process-filter", process_filter])
    
    cmd = " ".join(f'"{arg}"' for arg in args)
    
    print(Fore.GREEN + "✅ Smart logcat will start in separate terminal!" + Style.RESET_ALL)
    print(Fore.CYAN + "🚀 Opening logcat in new terminal..." + Style.RESET_ALL)
    
    # Open in new terminal
    open_new_terminal(cmd)
    
    if highlight_strings:
        print(Fore.CYAN + f"🎨 Highlighting: {highlight_strings}" + Style.RESET_ALL)
    if process_filter:
        print(Fore.BLUE + f"🔍 Process filter: {process_filter}" + Style.RESET_ALL)

# ============================================================
#  Red Team / Mobile Security Functions (MobSF, nuclei, apkleaks, Frida, Drozer, etc.)
# ============================================================


