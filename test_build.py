#!/usr/bin/env python3
"""Test script to verify the package can be built and installed correctly."""

import subprocess
import sys
import os

def run_command(cmd, description):
    """Run a command and return True if successful."""
    print(f"\n🔧 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {description} - SUCCESS")
            return True
        else:
            print(f"❌ {description} - FAILED")
            print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ {description} - FAILED with exception: {e}")
        return False

def main():
    """Test the package build process."""
    print("🚀 Testing Redroid package build...")
    
    # Check if we're in the right directory
    if not os.path.exists("redroid.py"):
        print("❌ redroid.py not found. Please run this from the project root directory.")
        sys.exit(1)
    
    # Clean previous builds
    run_command("rm -rf build/ dist/ *.egg-info/", "Cleaning previous builds")
    
    # Test building the package
    success = True
    success &= run_command("python -m build", "Building package with build module")
    
    if success:
        print("\n🎉 Package build test completed successfully!")
        print("\nTo install with pipx:")
        print("1. Build the package: python -m build")
        print("2. Install locally: pipx install dist/redroid-1.0.0-py3-none-any.whl")
        print("3. Or install from PyPI (when published): pipx install redroid")
    else:
        print("\n💥 Package build test failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
