# Root My Galaxy

<img width="108" height="108" alt="sprout_icon_108" src="https://github.com/user-attachments/assets/2ba0e360-0876-489c-b256-f75df7589785" />

Root My Galaxy is a one-click installer for explicitly supported Samsung
model + kernel combinations. It runs a kernel exploit (CVE-2026-43499) to
gain temporary root, loads KernelSU as a live module, and applies your KSU
modules — with an optional **auto-root** mode that restores all of that
after every reboot, using the phone's own wireless ADB daemon (no PC).

The application is kept separate from device offsets, native exploit
payloads, and KernelSU build artifacts: those live in
[Root-My-Galaxy-Payloads](https://github.com/HyperRamzey/Root-My-Galaxy-Payloads),
which also serves the live feed this app consumes.

[Latest release](https://github.com/HyperRamzey/Root-My-Galaxy/releases)
(current: **v0.2.28**)

Use only on devices you own or are explicitly authorized to test.

## Application

<img width="200" alt="KakaoTalk_20260718_170922353" src="https://github.com/user-attachments/assets/3f562ea4-8c39-4ade-bfd3-93eea1a1cc24" />
<img width="200" alt="KakaoTalk_20260718_171127319" src="https://github.com/user-attachments/assets/8dde0443-12cf-4058-ba76-0337aefb92a0" />
<img width="200" alt="KakaoTalk_20260718_171030202" src="https://github.com/user-attachments/assets/f656e8af-60a6-4fcb-a3db-d4232bede613" />

The app selects a payload whose model list and three-part kernel version
match the phone (e.g. `6.6.98-android15-8-...` matches `6.6.98`). Advanced
mode filters the catalog by both values and allows manual selection with
model and kernel-version warnings.

### Payload delivery

- Feed: `support/targets-v3.json` from the payloads repo's `main`
  (schema v3: per-payload `exploit` / `rootHelper` / `kernelsu` entries
  with `url` + `size`).
- Every download is validated against the feed-declared size; a size
  change invalidates the local cache and forces a re-download.
- Bundled fallbacks ship inside the APK
  (`app/src/main/jniLibs/arm64-v8a/libcve43499app.so`,
  `libcve43499root.so`) so the app can stage payloads even before the
  first feed fetch succeeds.

### KernelSU manager

The app installs and updates the **mainline KernelSU manager**
(`me.weishu.kernelsu`) directly from official
[tiann/KernelSU](https://github.com/tiann/KernelSU) releases. The payload's
`ksud` is cert-hash-patched so this official manager gets crowned — no
forked or spoofed manager builds (the old spoof machinery was removed).

## Root on boot (auto-root)

Root and KernelSU are volatile — a reboot removes them. With **Auto-root on
boot** enabled, the app re-applies root automatically after every reboot.

### One-time setup

1. Install the APK with all permissions granted:

   ```cmd
   adb install -g app-release.apk
   ```

   The `-g` flag grants `WRITE_SECURE_SETTINGS`, which lets the app enable
   wireless debugging programmatically on boot.

2. Run the exploit once (via Shizuku or USB ADB). After KernelSU loads, the
   app registers its own ADB key with adbd (`/data/misc/adb/adb_keys`).
   This key persists across reboots.

3. Enable **Auto-root on boot** in Settings.

### What happens on boot

1. `BOOT_COMPLETED` fires → `RootOnBootService` starts (foreground service,
   `rmg:RootOnBoot` wakelock) and enables wireless debugging
   (`Settings.Global.adb_wifi_enabled = 1`).
2. The app connects to its own adbd (`127.0.0.1`, discovered port) using
   the pre-registered ADB key — no pairing prompt.
3. Payloads are staged from the app cache to `/data/local/tmp` and the
   exploit runs in the `u:r:shell:s0` context with a tuned environment
   (`SLIDE_SOURCE=tracefs`, `RMG_PIN_GATE_WAIT_SEC=180`,
   `EXPLOIT_ATTEMPTS=3`, `P0_ATTEMPT_TIMEOUT_SEC=115`,
   `EXPLOIT_ATTEMPT_TIMEOUT_SEC=600`, …).
4. On success the root daemon late-loads KernelSU and the shell-context
   keeper applies modules (`post-fs-data` / `services` / `boot-completed`),
   restarts zygote only if every stage succeeded, and writes a boot-scoped
   done marker — the app waits for that marker instead of touching
   ksud/zygote itself.
5. On failure the service reboots the device and retries (up to 6 boots;
   3 exploit attempts per boot). A notification reports success or failure.

### Module apply

After KernelSU loads, tap **Apply Modules (Restart Zygote)** to mount KSU
modules and restart zygote. This makes Zygisk-based modules (LSPosed, etc.)
take effect immediately via a ~5s soft-reboot (kernel and root persist).

> Note for Fold5 (`f946b`): modules that ship system files must be
> magic-mounted, not overlay-mounted — the post-exploit kernel panics on
> overlayfs `fsmount`. See the payloads repo
> (`docs/stability-notes-f946b.md`) for the hybrid-mount rules.

## Settings

| Preference | Key | Effect |
| --- | --- | --- |
| Auto-root on boot | `auto_root_boot` | run the full pipeline after every reboot |
| Auto-apply modules | `auto_apply_modules` | keeper applies KSU modules automatically |
| Boot retry count | `boot_retry_count` | reboot-retry ladder state (max 6) |
| Advanced mode | `advanced_mode` | manual payload selection with warnings |
| Theme / accent | `theme_mode`, `accent_color` | UI appearance |
| ADB paired | `adb_paired` | wireless-debugging pairing state |

## Permissions

`INTERNET` (feed + manager releases), `REQUEST_INSTALL_PACKAGES` (manager
APK), `RECEIVE_BOOT_COMPLETED`, `SCHEDULE_EXACT_ALARM` / `USE_EXACT_ALARM`
(boot-service retries), `FOREGROUND_SERVICE` (+ `SPECIAL_USE`),
`WAKE_LOCK`, `POST_NOTIFICATIONS`, `WRITE_SECURE_SETTINGS` (granted via
`adb install -g`; enables wireless debugging on boot).

## Build

Requirements:

- Android Studio JBR 21
- Android SDK 37 (compile), target SDK 36, min SDK 33
- Android NDK r28 or newer
- CMake 3.22.1

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat :app:assembleRelease
```

Output: `app/build/outputs/apk/release/app-release.apk`.

Releases are published via the `release` workflow (`workflow_dispatch`,
optionally pinned to a specific `v*` tag).
