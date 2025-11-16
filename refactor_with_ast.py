#!/usr/bin/env python3
"""
Advanced refactoring using AST for accurate parsing
"""

import ast
import os
import astor  # pip install astor


# Function to module mapping
FUNCTION_MAP = {
    # Core - Device
    'detect_emulator': ('redroid/core/device.py', []),
    'switch_device': ('redroid/core/device.py', ['get_connected_devices']),
    'setup_ctrl_d_handler': ('redroid/core/device.py', []),
    'safe_shutdown': ('redroid/core/device.py', []),
    'check_and_handle_device_switch': ('redroid/core/device.py', ['switch_device']),
    'get_input_with_device_switch_check': ('redroid/core/device.py', ['switch_device', 'safe_shutdown']),

    # Core - ADB
    'connect_nox_adb_ports': ('redroid/core/adb.py', []),
    'get_adb_command': ('redroid/core/adb.py', []),
    'get_connected_devices': ('redroid/core/adb.py', []),
    'run_adb_command': ('redroid/core/adb.py', []),

    # ... (rest of mappings)
}


def parse_python_file(filepath):
    """Parse Python file and return AST"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return ast.parse(f.read())


def extract_functions(tree):
    """Extract all functions from AST"""
    functions = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions[node.name] = node
    return functions


def get_function_source(node):
    """Convert AST node back to source code"""
    return astor.to_source(node)


def create_module(path, functions_code, imports):
    """Create a Python module file"""
    os.makedirs(os.path.dirname(path), exist_ok=True)

    content = '''#!/usr/bin/env python3
"""
Auto-generated module
"""

'''
    content += '\n'.join(imports) + '\n\n'
    content += 'import redroid.config as config\n'
    content += 'from colorama import Fore, Style\n\n'
    content += '\n\n'.join(functions_code)

    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"✅ Created: {path}")


def main():
    print("🔧 Refactoring using AST...")

    try:
        tree = parse_python_file('redroid.py')
        functions = extract_functions(tree)

        print(f"📝 Found {len(functions)} functions")

        # Group by module
        modules = {}
        for func_name, (module_path, deps) in FUNCTION_MAP.items():
            if func_name in functions:
                if module_path not in modules:
                    modules[module_path] = []
                func_source = get_function_source(functions[func_name])
                modules[module_path].append(func_source)
                print(f"  ➕ {func_name} -> {module_path}")

        # Create module files
        base_imports = ['import os', 'import sys', 'import subprocess', 'import time']
        for module_path, func_codes in modules.items():
            create_module(module_path, func_codes, base_imports)

        print("\n✅ Refactoring complete using AST!")

    except ImportError:
        print("❌ astor library not found. Install with: pip install astor")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == '__main__':
    main()
