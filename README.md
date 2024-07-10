# 🚀 Redroid

Welcome to **Redroid**! Enhance your mobile security testing capabilities with this powerful toolset. Easily manage and use tools like Frida, Jadx, Apktool, Nuclei, Mob-FS, and more, directly from a user-friendly command-line interface.

## 🛠️ Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/yourusername/redroid.git
    cd redroid
    ```

2. **Install dependencies**:
    Create a virtual environment and install required Python packages.
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```

3. **Run the script**:
    ```sh
    python redroid.py
    ```

## 📖 Usage

Once the script is running, you will see a main menu with various options. Here is a brief overview:

### Main Menu

1. **Install Tools**:
    - **Frida**: Install Frida tools.
    - **Objection**: Install objection.
    - **reFlutter**: Install reFlutter.
    - **Jadx**: Download the latest Jadx GUI.
    - **Apktool**: Download and set up Apktool.
    - **Nuclei**: Download and install Nuclei.
    - **Mob-FS (docker)**: Install Mob-FS using Docker.
    - **apkleaks**: Install apkleaks.

2. **Run Tools**:
    - **Run Mob-FS (docker)**: Run Mob-FS in a Docker container.
    - **Run nuclei against APK**: Decompile and Vuln Scan APK with custom nuclei templates

3. **NOX Player Options**:
    - **Remove Ads From Nox emulator**: Remove ads and bloatware from the Nox emulator.
    - **Install Burp Certificate**: Install Burp Suite's CA certificate in the Nox emulator.
    - **Install Frida Server**: Install Frida server on the Nox emulator.
    - **Get ADB shell**: Open an ADB shell in the Nox emulator.
    - **Print proxy status**: Print the current proxy settings of the Nox emulator.
    - **Set up/modify proxy**: Set or modify the proxy settings for the Nox emulator.
    - **Remove proxy**: Remove the proxy settings from the Nox emulator.

4. **Frida**:
    - **List installed applications**: List all installed applications on the device.
    - **Run Frida Server**: Start the Frida server on the Nox emulator.

5. **Exit**: Exit the application.

## 🤝 Contribution

We welcome contributions! Please fork this repository and submit a pull request for any enhancements or bug fixes.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

🎉 **Enjoy using Redroid!** If you have any questions or run into any issues, feel free to open an issue on GitHub.

