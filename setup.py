#!/usr/bin/env python3
"""Setup script for Redroid - Android Security Testing Tool."""

from setuptools import setup, find_packages
import os

# Read the README file for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Redroid - Android Security Testing Tool"

# Read requirements
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_path):
        with open(requirements_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name="redroid",
    version="1.0.0",
    author="YoruYagami",
    description="Android Security Testing Tool with Emulator Support",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/YoruYagami/Redroid",
    packages=find_packages(),
    py_modules=["redroid"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "redroid=redroid:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["frida-scripts/*.js", "static/*"],
    },
    zip_safe=False,
    keywords="android security testing frida emulator adb mobile pentesting",
)
