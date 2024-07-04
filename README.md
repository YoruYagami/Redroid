# Redroid

Redroid is a comprehensive tool for managing and interacting with the Nox Android emulator. It provides various functionalities including installing tools, managing the Nox emulator, and running Frida scripts.

> :warning: Redroid is in an early state of release. Many more options and tools will be added later on.

## Features

- Install essential tools like Frida, Objection, reFlutter, Jadx, apktool, and nuclei.
- Manage the Nox emulator:
  - Remove ads and bloatware.
  - Install Burp Suite certificate.
  - Install and run Frida Server.
  - Open an ADB shell.
  - Check if root is enabled.
  - Manage proxy settings.
- Run Frida scripts.

## Requirements

- Python 3.x
- `adb` and Nox Player installed on your machine.

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/Redroid.git
   cd Redroid
   ```

2. Install the required Python packages:
   ```sh
   pip install -r requirements.txt
   ```

## Usage

Run the `Redroid` script using Python:
```sh
python adb_nox_menu.py
```

### Main Menu

- `1. Install Tools`
  - `1. Frida`
  - `2. Objection`
  - `3. reFlutter`
  - `4. Jadx`
  - `5. Download apktool (.bat + .jar)`
  - `6. Download nuclei`
  - `7. Back`
- `2. NOX Player Options`
  - `1. Remove Ads From Nox emulator`
  - `2. Install Burp Certificate`
  - `3. Install Frida Server`
  - `4. Run Frida Server`
  - `5. Get ADB shell`
  - `6. Check if root is enabled`
  - `7. Print proxy status`
  - `8. Set up/modify proxy`
  - `9. Remove proxy`
  - `10. Back`
- `3. Frida`
  - `1. List installed applications`
  - `2. Back`
- `4. Exit`

### Detailed Options

#### Install Tools

- **Frida**: Installs Frida tools.
- **Objection**: Installs Objection.
- **reFlutter**: Installs reFlutter.
- **Jadx**: Downloads the latest version of Jadx and places it in the `Redroid` folder on the desktop.
- **Download apktool (.bat + .jar)**: Downloads the latest version of apktool and places it in the `Redroid` folder on the desktop. You need to move these files manually to the `C:\Windows` folder.
- **Download nuclei**: Downloads the latest version of nuclei and places it in the `Redroid` folder on the desktop.

#### NOX Player Options

- **Remove Ads From Nox emulator**: Removes ads and bloatware from the Nox emulator.
- **Install Burp Certificate**: Installs the Burp Suite certificate on the Nox emulator. You need to specify the port Burp Suite is using to intercept requests.
- **Install Frida Server**: Installs the Frida server on the Nox emulator.
- **Run Frida Server**: Runs the Frida server on the Nox emulator.
- **Get ADB shell**: Opens an ADB shell.
- **Check if root is enabled**: Checks if root access is enabled on the Nox emulator.
- **Print proxy status**: Prints the current proxy status.
- **Set up/modify proxy**: Sets up or modifies the proxy.
- **Remove proxy**: Removes the proxy settings from the Nox emulator.

#### Frida

- **List installed applications**: Lists the installed applications on the Nox emulator.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any bugs, improvements, or features you would like to add.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
