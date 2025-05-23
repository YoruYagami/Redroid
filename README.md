## Redroid - Android Application Penetration Testing Automation Toolkit

> :warning: Work in Progress
This tool is currently in active development. Features and behavior may change, and some modules may not work as expected on all environments. Feel free to PR/Issue.

Redroid is a versatile mobile security toolkit built to assist pentesters during android application security assessments. It streamlines the setup of  burp certificate, manages proxy configurations and integrates with tools like Frida, Drozer, MobSF, Nuclei, and ApkLeaks. The toolkit automates common tasks such as pulling APKs, installing agents, and generating exploit payloads like for doing tapjacking and task hijacking demos. Its interactive CLI interface makes navigation and execution intuitive, helping operators focus more on analysis and exploitation rather than setup overhead.

![image](static/redroid_menu.png)

#### To do
- [ ] Multi devices handling
- [ ] Fix logic of existing functions (ex. mobsf)
- [ ] Add trufflehog security check on source code
- [ ] Add firebase testing check
- [ ] Add manual check in the drozer menu 
- [ ] Add logcat stream check
- [ ] Automatic apk Sign/Patching
- [ ] Make everything cross-platform (Windows <-> Kali Linux)