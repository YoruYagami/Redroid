# 🚀 Redroid

Welcome to **Redroid**! Enhance your mobile security testing capabilities with this powerful toolset. Easily manage and use tools like Frida, Jadx, Apktool, Nuclei, Mob-FS docker Dynamic Analaysis enabled, and more, directly from a user-friendly command-line interface.

## 🛠️ Installation

### Prerequisites
- Python 3.6 or higher
- Git

### Steps

1. **Clone the repository**:
    ```sh
    git clone https://github.com/yourusername/redroid.git
    cd redroid
    ```

2. **Install dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

3. **Run the script**:
    ```sh
    python redroid.py
    ```

## 📖 Usage

Once the script is running, you will see a main menu with various options. Here is a brief overview:

### Main Menu

1. 🛠️**Install Tools**:
    - 🧩**Frida**: Install Frida tools.
    - 🔐**Objection**: Install objection.
    - 🛠️**reFlutter**: Install reFlutter.
    - 🖥️**Jadx**: Download the latest Jadx GUI.
    - 🗃️**Apktool**: Download and set up Apktool.
    - 🔎**Nuclei**: Download and install Nuclei.
    - 📦**Mob-FS (docker)**: Install Mob-FS using Docker.
    - 🔍**apkleaks**: Install apkleaks.

2. 🚀**Run Tools**:
    - 🛡️**Run Mob-FS (docker)**: Run Mob-FS in a Docker container.
    - 🔍**Run nuclei against APK**: Decompile and run Nuclei vulnerability scan on an APK with custom templates.
    - 🔍**Run apkleaks against APK**: Decompile and run apkleaks scan on an APK.

 3. 🎮**Emulator Player Options**:
    - 🧹**Remove Ads From Emulator**: Remove ads and bloatware from the Nox Emulator.
    - 🛡️**Install Burp Certificate**: Install Burp Suite's CA certificate in the Emulator.
    - 💻**Open ADB shell**: Open an ADB shell in the Emulator.
    - 🌐**Print proxy status**: Print the current proxy settings of the Emulator.
    - ⚙️**Set up/modify proxy**: Set or modify the proxy settings for the emulator.
    - ❌**Remove proxy**: Remove the proxy settings from the Emulator.

4. 🕵️**Frida**:
    - ▶️ **Run Frida Server**: Start the Frida server in the background on the Emulator.
    - 📜**List Installed Applications**: List all installed applications on the device.
    - 🔓**Run SSL Pinning Bypass**: Execute an SSL pinning bypass script on a specific app.
    - 🛡️**Run Root Check Bypass**: Execute a root check bypass script on a specific app.
    - 🔑**Android Biometric Bypass**: Run a biometric bypass script on a specific app.
    - 📝**Run Custom Script**: Execute a custom Frida script provided by the user.

5. **Exit**: Exit the application.

## 🤝 Contribution

We welcome contributions! Please fork this repository and submit a pull request for any enhancements or bug fixes.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

🎉 **Enjoy using Redroid!** If you have any questions or run into any issues, feel free to open an issue on GitHub.
