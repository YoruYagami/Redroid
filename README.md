## Redroid - Android Application Penetration Testing Automation Toolkit

> :warning: Work in Progress
This tool is currently in active development. Features and behavior may change, and some modules may not work as expected on all environments. Feel free to PR/Issue.

Redroid is a versatile mobile security toolkit built to assist pentesters during android application security assessments. It streamlines the setup of  burp certificate, manages proxy configurations and integrates with tools like Frida, Drozer, MobSF, Nuclei, and ApkLeaks. The toolkit automates common tasks such as pulling APKs, installing agents, and generating exploit payloads like for doing tapjacking and task hijacking demos. Its interactive CLI interface makes navigation and execution intuitive, helping operators focus more on analysis and exploitation rather than setup overhead.

![image](static/redroid_menu.png)

## Installation

### Using pipx (Recommended)

The easiest way to install Redroid is using pipx, which will install it in an isolated environment:

```bash
pipx install redroid
```

After installation, you can run the tool from anywhere:

```bash
redroid
```

### Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/samsepi01/Redroid.git
cd Redroid
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the tool:
```bash
python redroid.py
```

### Development Installation

For development purposes, you can install in editable mode:

```bash
git clone https://github.com/samsepi01/Redroid.git
cd Redroid
pip install -e .
```

#### To do
- [X] Multi devices handling
- [X] Fix logic of existing functions (ex. mobsf)
- [X] Add trufflehog security check on source code
- [ ] Add firebase testing check
- [ ] Add manual checks in the drozer menu 
- [X] Add logcat stream check
- [X] Automatic apk Sign/Patching
- [ ] Make everything cross-platform (Windows <-> Kali Linux)
