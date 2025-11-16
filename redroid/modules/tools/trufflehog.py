#!/usr/bin/env python3
"""
TruffleHog integration
"""

import os
import subprocess
import shutil
from colorama import Fore, Style

def run_trufflehog_against_apk():
    # Check if Docker is available
    if not shutil.which("docker"):
        print(Fore.RED + "❌ Docker is not installed or not in the PATH." + Style.RESET_ALL)
        return

    while True:
        apk_path_input = input("📝 Enter the path to the APK file: ").strip()
        apk_path = apk_path_input.strip("'").strip('"')
        if os.path.exists(apk_path):
            break
        else:
            print(f"❌ Error: The file {apk_path_input} does not exist.")

    script_dir = os.getcwd()
    output_dir = os.path.join(script_dir, os.path.splitext(os.path.basename(apk_path))[0])
    
    if os.path.exists(output_dir):
        print(f"\n⚠️ The directory \"{output_dir}\" already exists.")
        print("What would you like to do?")
        print("1. Scan directly using the existing Apktool output")
        print("2. Overwrite the output with a fresh decompilation")
        action_choice = input("\nEnter your choice (1 or 2): ").strip()
        if action_choice not in ['1', '2']:
            print("\n❌ Invalid choice. Operation cancelled.\n")
            return
        if action_choice == '2':
            shutil.rmtree(output_dir)

    # Decompile APK if directory doesn't exist or user chose to overwrite
    if not os.path.exists(output_dir):
        apktool_command = "apktool"
        try:
            print(Fore.CYAN + f"🔧 Decompiling APK with apktool..." + Style.RESET_ALL)
            subprocess.run(shlex.split(f'{apktool_command} d "{apk_path}" -o "{output_dir}"'), check=True)
            print(Fore.GREEN + f"✅ APK decompiled successfully to {output_dir}" + Style.RESET_ALL)
        except subprocess.CalledProcessError as e:
            print(f"\n❌ Error: Failed to decompile APK. {e}\n")
            return
        except FileNotFoundError as e:
            print(f"\n❌ Error: {e}. Ensure apktool is installed and accessible.")
            return

    # Run TruffleHog using Docker
    print(Fore.CYAN + f"🔍 Running TruffleHog on decompiled APK..." + Style.RESET_ALL)
    
    # Use proper Unix path format
    docker_cmd = f'docker run --rm -v "${{PWD}}:/pwd" trufflesecurity/trufflehog:latest filesystem /pwd/{os.path.basename(output_dir)} --results=verified,unknown'
    
    try:
        print(Fore.CYAN + f"🐷 Executing: {docker_cmd}" + Style.RESET_ALL)
        result = subprocess.run(docker_cmd, shell=True, capture_output=True, text=True, 
                              encoding='utf-8', errors='replace', check=True)
        
        # Display results
        if result.stdout.strip():
            print(Fore.GREEN + "✅ TruffleHog scan completed!" + Style.RESET_ALL)
            print(Fore.YELLOW + "\n📋 TruffleHog Results:" + Style.RESET_ALL)
            print(result.stdout)
        else:
            print(Fore.GREEN + "✅ TruffleHog scan completed - No secrets found!" + Style.RESET_ALL)
        
        # Save output to file
        save_output = input(Fore.CYAN + "Do you want to save the output to a file? (y/n): " + Style.RESET_ALL).strip().lower()
        if save_output in ['y', 'yes']:
            output_filename = f"{os.path.splitext(os.path.basename(apk_path))[0]}_trufflehog_output.txt"
            output_file = os.path.join(script_dir, output_filename)
            with open(output_file, "w", encoding='utf-8') as file:
                file.write(f"TruffleHog Scan Results for: {apk_path}\n")
                file.write(f"Decompiled directory: {output_dir}\n")
                file.write(f"Command executed: {docker_cmd}\n")
                file.write("=" * 50 + "\n")
                file.write(result.stdout if result.stdout else "No output from TruffleHog\n")
                if result.stderr:
                    file.write("\n" + "=" * 50 + "\n")
                    file.write("STDERR:\n")
                    file.write(result.stderr)
            print(Fore.GREEN + f"✅ Output saved to {output_file}" + Style.RESET_ALL)
            
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error running TruffleHog: {e}" + Style.RESET_ALL)
        try:
            if hasattr(e, 'stderr') and e.stderr:
                print(Fore.RED + f"Error details: {e.stderr}" + Style.RESET_ALL)
        except UnicodeDecodeError:
            print(Fore.RED + "Error details: [Unable to decode error message due to encoding issues]" + Style.RESET_ALL)
    except UnicodeDecodeError as e:
        print(Fore.YELLOW + f"⚠️ Unicode encoding issue detected: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "TruffleHog may have completed successfully despite the encoding warning." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"❌ An unexpected error occurred: {str(e)}" + Style.RESET_ALL)
    
    print(Fore.GREEN + "🔍 TruffleHog analysis complete." + Style.RESET_ALL)


