package dev.busung.s25uroot

import android.content.Context
import android.provider.Settings
import java.io.File

/**
 * Handles registering the app's ADB public key with adbd so that
 * LocalAdbClient can authenticate on subsequent boots without re-pairing.
 *
 * Strategy:
 * 1. Primary: After a successful exploit (root available), write the app's
 *    ADB public key to /data/misc/adb/adb_keys via the root helper.
 * 2. The key persists across reboots (it's in /data/misc/adb/).
 * 3. On boot, the app enables wireless debugging and connects to
 *    localhost:5555 using the registered key.
 *
 * This avoids implementing the full SPAKE2+TLS pairing protocol.
 * The one-time requirement is a single successful exploit run (via Shizuku
 * or USB ADB) to register the key.
 */
object AdbPairing {
    private const val ADB_KEYS_PATH = "/data/misc/adb/adb_keys"
    private const val WIRELESS_ADB_PORT = 5555
    private const val ADB_WIFI_ENABLED_SETTING = "adb_wifi_enabled"

    /**
     * Registers the app's ADB public key with adbd via root.
     * Must be called after a successful exploit (root available).
     * Returns true if the key was registered successfully.
     */
    fun registerKeyViaRoot(context: Context, rootHelperPath: String): Boolean {
        val keyDir = File(context.filesDir, "adb_keys")
        val keys = AdbKeyStore.loadOrGenerate(keyDir)
        val pubKeyEncoded = AdbKeyStore.encodePublicKey(
            keys.public as java.security.interfaces.RSAPublicKey,
        )
        val pubKeyLine = String(pubKeyEncoded).trim()

        // Append our key to /data/misc/adb/adb_keys if not already present
        val checkCmd = "grep -qF '${pubKeyLine.take(40)}' $ADB_KEYS_PATH 2>/dev/null"
        val check = executeRoot(rootHelperPath, checkCmd)
        if (check.exitCode == 0) return true // already registered

        val appendCmd = "echo '$pubKeyLine' >> $ADB_KEYS_PATH"
        val result = executeRoot(rootHelperPath, appendCmd)
        return result.exitCode == 0
    }

    /**
     * Enables wireless debugging (ADB over WiFi) programmatically.
     * Requires WRITE_SECURE_SETTINGS permission (granted via `adb install -g`).
     * Returns true if wireless debugging is enabled or was already enabled.
     */
    fun enableWirelessAdb(context: Context): Boolean {
        return try {
            Settings.Global.putInt(
                context.contentResolver,
                ADB_WIFI_ENABLED_SETTING,
                1,
            )
        } catch (e: SecurityException) {
            false
        }
    }

    /**
     * Checks if wireless debugging is currently enabled.
     */
    fun isWirelessAdbEnabled(context: Context): Boolean {
        return try {
            Settings.Global.getInt(
                context.contentResolver,
                ADB_WIFI_ENABLED_SETTING,
                0,
            ) == 1
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Checks if the app has WRITE_SECURE_SETTINGS permission.
     */
    fun hasWriteSecureSettings(context: Context): Boolean {
        return context.checkCallingOrSelfPermission(
            "android.permission.WRITE_SECURE_SETTINGS",
        ) == android.content.pm.PackageManager.PERMISSION_GRANTED
    }

    /**
     * Returns the port adbd listens on for wireless debugging.
     * Default is 5555 but can vary.
     */
    fun getAdbPort(): Int = WIRELESS_ADB_PORT

    /**
     * Tests connectivity to the local ADB daemon.
     * Returns true if we can authenticate and run a command.
     */
    fun testConnection(context: Context): Boolean {
        val keyDir = File(context.filesDir, "adb_keys")
        return try {
            val result = LocalAdbClient.shell(
                "127.0.0.1",
                getAdbPort(),
                "id",
                keyDir,
            )
            result.output.contains("uid=")
        } catch (e: Exception) {
            false
        }
    }

    private fun executeRoot(helperPath: String, command: String): LocalAdbClient.ShellResult {
        return try {
            val process = ProcessBuilder(helperPath, "-c", command)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().readText()
            val code = process.waitFor()
            LocalAdbClient.ShellResult(code, output.trim())
        } catch (e: Exception) {
            LocalAdbClient.ShellResult(-1, e.message ?: "unknown error")
        }
    }
}
