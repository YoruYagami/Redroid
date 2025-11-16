# Redroid Refactoring Guide

## 📁 Nuova Struttura

La nuova struttura modulare organizza il codice in modo logico:

```
Redroid/
├── main.py                          # Nuovo entry point modulare
├── redroid.py                       # File originale (mantenuto per compatibilità)
├── redroid/
│   ├── __init__.py
│   ├── config.py                    # ✅ Variabili globali e configurazione
│   │
│   ├── core/                        # Funzionalità core
│   │   ├── __init__.py
│   │   ├── device.py                # ✅ Device detection & management
│   │   ├── adb.py                   # ✅ ADB commands
│   │   └── utils.py                 # ⏳ Utility functions (TODO)
│   │
│   ├── menus/                       # Menu system
│   │   ├── __init__.py
│   │   ├── main_menu.py             # ✅ Main menu
│   │   ├── run_tools_menu.py        # ⏳ TODO
│   │   ├── emulator_menu.py         # ⏳ TODO
│   │   ├── frida_menu.py            # ⏳ TODO
│   │   ├── drozer_menu.py           # ⏳ TODO
│   │   ├── exploits_menu.py         # ⏳ TODO
│   │   └── api_keys_menu.py         # ⏳ TODO
│   │
│   └── modules/                     # Moduli funzionali
│       ├── target/                  # Target app management
│       │   ├── __init__.py
│       │   └── target_app.py        # ⏳ TODO
│       │
│       ├── tools/                   # Tools (MobSF, nuclei, etc.)
│       │   ├── __init__.py
│       │   ├── mobsf.py             # ⏳ TODO
│       │   ├── nuclei.py            # ⏳ TODO
│       │   ├── apkleaks.py          # ⏳ TODO
│       │   ├── trufflehog.py        # ⏳ TODO
│       │   └── android_studio.py    # ⏳ TODO
│       │
│       ├── emulator/                # Emulator functionality
│       │   ├── __init__.py
│       │   ├── proxy.py             # ⏳ TODO
│       │   ├── certificate.py       # ⏳ TODO
│       │   ├── logcat.py            # ⏳ TODO
│       │   └── shell.py             # ⏳ TODO
│       │
│       ├── frida/                   # Frida modules
│       │   ├── __init__.py
│       │   ├── server.py            # ⏳ TODO
│       │   ├── ssl_bypass.py        # ⏳ TODO
│       │   ├── root_bypass.py       # ⏳ TODO
│       │   ├── biometric_bypass.py  # ⏳ TODO
│       │   ├── custom_script.py     # ⏳ TODO
│       │   └── memory_dump.py       # ⏳ TODO
│       │
│       ├── drozer/                  # Drozer functionality
│       │   ├── __init__.py
│       │   ├── agent.py             # ⏳ TODO
│       │   ├── forward.py           # ⏳ TODO
│       │   └── vulnscan.py          # ⏳ TODO
│       │
│       ├── exploits/                # Exploits
│       │   ├── __init__.py
│       │   ├── apk_utils.py         # ⏳ TODO (sign_apk)
│       │   ├── tapjacking.py        # ⏳ TODO
│       │   └── task_hijacking.py    # ⏳ TODO
│       │
│       └── api_keys/                # API keys testing
│           ├── __init__.py
│           └── google_maps.py       # ⏳ TODO
```

## 🚀 Come Usare

### Versione Originale (sempre funzionante)
```bash
python3 redroid.py
```

### Versione Modulare (nuovo)
```bash
python3 main.py
```

## 📝 Come Completare il Refactoring

Il refactoring è stato iniziato ma non completato. Ecco come procedere:

### 1. Migrare le Funzioni Manualmente

Per ogni modulo TODO, estrai le funzioni corrispondenti da `redroid.py`:

#### Esempio: Creare `redroid/modules/target/target_app.py`

```python
#!/usr/bin/env python3
"""
Target app management
"""

import subprocess
from colorama import Fore, Style
import redroid.config as config
from redroid.core.adb import run_adb_command


def list_relevant_apps(include_system_apps=False):
    """List relevant apps running on the device"""
    # Copia il codice dalla funzione in redroid.py
    ...


def set_target_app():
    """Set the target application"""
    # Copia il codice dalla funzione in redroid.py
    ...
```

### 2. Aggiornare gli Import in main.py

Dopo aver creato un nuovo modulo, aggiorna `main.py` per usarlo:

```python
# Prima (usa vecchio redroid.py)
old_redroid.set_target_app()

# Dopo (usa nuovo modulo)
from redroid.modules.target.target_app import set_target_app
set_target_app()
```

### 3. Gestire le Variabili Globali

Tutte le variabili globali sono in `redroid/config.py`:

```python
import redroid.config as config

# Usa:
config.device_serial
config.adb_command
config.target_app
config.emulator_type
```

## 🛠️ Script Automatici

Sono stati creati due script per aiutare:

### 1. `auto_refactor.py`
Script automatico che tenta di estrarre e organizzare le funzioni.

```bash
python3 auto_refactor.py
```

### 2. `refactor_with_ast.py`
Versione più avanzata che usa AST (richiede `pip install astor`).

```bash
pip install astor
python3 refactor_with_ast.py
```

## ✅ Cosa È Già Fatto

- ✅ Struttura delle cartelle creata
- ✅ `redroid/config.py` - Variabili globali
- ✅ `redroid/core/device.py` - Device detection e switching
- ✅ `redroid/core/adb.py` - Comandi ADB
- ✅ `redroid/menus/main_menu.py` - Menu principale
- ✅ `main.py` - Entry point ibrido funzionante

## ⏳ TODO

- ⏳ Migrare tutte le funzioni ai rispettivi moduli
- ⏳ Creare i file menu per ogni sottomenu
- ⏳ Testare ogni modulo indipendentemente
- ⏳ Rimuovere le dipendenze da `old_redroid` in `main.py`
- ⏳ Eventualmente deprecare `redroid.py` originale

## 🎯 Priorità di Migrazione

1. **Alta Priorità** (funzioni usate frequentemente):
   - `modules/target/target_app.py` (set_target_app, list_relevant_apps)
   - `modules/emulator/logcat.py` (logcat functions)
   - `modules/frida/server.py` (frida server management)

2. **Media Priorità**:
   - Tutti i moduli in `modules/tools/`
   - Moduli Frida specifici

3. **Bassa Priorità**:
   - `modules/exploits/` (già implementate le funzioni principali)
   - `modules/api_keys/`

## 💡 Tips

1. **Testa Incrementalmente**: Dopo ogni migrazione, testa con `python3 main.py`
2. **Mantieni Compatibilità**: `redroid.py` deve continuare a funzionare
3. **Usa Import Relativi**: Nei moduli usa `import redroid.config as config`
4. **Documenta**: Aggiungi docstrings a tutte le funzioni migrate

## 🐛 Troubleshooting

### ImportError
Se ottieni errori di import, assicurati di avere tutti gli `__init__.py`:
```bash
find redroid -type d -exec touch {}/__init__.py \;
```

### Variabili Globali Non Sincronizzate
Usa sempre `config.variable_name` invece di variabili globali dirette.

## 📚 Risorse

- Documentazione originale: `redroid.py` contiene tutte le funzioni
- Struttura menu: Vedi funzioni `show_*_menu()` in `redroid.py`
- Logica menu: Vedi la funzione `main()` in `redroid.py`
