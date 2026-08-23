# Root My Galaxy

<img width="108" height="108" alt="sprout_icon_108" src="https://github.com/user-attachments/assets/2ba0e360-0876-489c-b256-f75df7589785" />


Root My Galaxy is a one-click installer for explicitly
supported Samsung model and kernel combinations. The application itself is kept separate
from device offsets, native exploit payloads, and KernelSU build artifacts.


[Latest release](https://github.com/HyperRamzey/Root-My-Galaxy/releases)

The device feed and native payloads are maintained in
[Root-My-Galaxy-Payloads](https://github.com/HyperRamzey/Root-My-Galaxy-Payloads).

## Application


<img width="200" alt="KakaoTalk_20260718_170922353" src="https://github.com/user-attachments/assets/3f562ea4-8c39-4ade-bfd3-93eea1a1cc24" />
<img width="200" alt="KakaoTalk_20260718_171127319" src="https://github.com/user-attachments/assets/8dde0443-12cf-4058-ba76-0337aefb92a0" />
<img width="200" alt="KakaoTalk_20260718_171030202" src="https://github.com/user-attachments/assets/f656e8af-60a6-4fcb-a3db-d4232bede613" />

The app selects a payload whose model list and three-part kernel version match
the phone. For example, `6.6.98-android15-8-...` matches `6.6.98`. Advanced
mode filters the catalog by both values and allows manual selection with model
and kernel-version warnings.

## Build

Requirements:

- Android Studio JBR 21
- Android SDK 37
- Android NDK 28 or newer
- CMake 3.22.1

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat :app:assembleDebug
```

Output:

```text
app/build/outputs/apk/debug/app-debug.apk
```

## Root on boot (Fold5)

Root and KernelSU are volatile — a reboot removes them. The app can re-apply
root automatically after every reboot using the device's own wireless ADB
daemon (no PC needed).

### One-time setup

1. Install the APK with all permissions granted:

   ```cmd
   adb install -g app-debug.apk
   ```

   The `-g` flag grants `WRITE_SECURE_SETTINGS`, which lets the app enable
   wireless debugging programmatically on boot.

2. Run the exploit once (via Shizuku or USB ADB). After KernelSU loads, the
   app registers its own ADB key with adbd (`/data/misc/adb/adb_keys`).
   This key persists across reboots.

3. Enable **Auto-root on boot** in Settings.

### What happens on boot

1. `BOOT_COMPLETED` fires → the app enables wireless debugging
   (`Settings.Global.adb_wifi_enabled = 1`).
2. The app connects to `127.0.0.1:5555` using its registered ADB key
   (no pairing prompt — the key was pre-authorized).
3. The exploit runs in the `u:r:shell:s0` context, loads KernelSU, mounts
   modules, and restarts zygote.
4. A notification reports success or failure.

### Module apply

After KernelSU loads, tap **Apply Modules (Restart Zygote)** to mount KSU
modules and restart zygote. This makes Zygisk-based modules (LSPosed, etc.)
take effect immediately via a ~5s soft-reboot (kernel and root persist).

Use only on devices you own or are explicitly authorized to test.
