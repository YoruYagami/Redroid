#!/usr/bin/env python3
"""
Main menu for Redroid
"""

from colorama import Fore, Style
import redroid.config as config


def show_main_menu():
    """Display the main menu"""
    logo = r"""
    __________       ________               .__    .___
    \______   \ ____ \______ \_______  ____ |__| __| _/
     |       _// __ \ |    |  \_  __ \/  _ \|  |/ __ |
     |    |   \  ___/ |       \  | \(  <_> )  / /_/ |
     |____|_  /\___  >_______  /__|   \____/|__\____ |
            \/     \/        \/                     \/
    """

    print(Fore.CYAN + logo + Style.RESET_ALL)

    print(Fore.RED + " Version  : " + Fore.YELLOW + config.VERSION)
    print(Fore.YELLOW + " Platform : Linux Compatible")
    print()

    print("=" * 50)
    print("1. 🎯  Set Target")
    print("2. 🚀  Run Tools")
    print("3. 🎮  Emulator Options")
    print("4. 🕵️  Frida")
    print("5. 🏹  Drozer")
    print("6. 💥  Exploits")
    print("7. 🔑  API Keys Testing")
    print("8. ❌  Exit")
    print()
