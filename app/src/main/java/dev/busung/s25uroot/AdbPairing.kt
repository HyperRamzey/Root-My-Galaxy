package dev.busung.s25uroot

import android.content.Context
import android.provider.Settings
import android.util.Log
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

private const val TAG = "AdbPairing"

/**
 * Helpers for wireless-debugging state and local ADB connectivity.
 * Pairing itself is handled by [AdbPairingService] (notification UX).
 */
object AdbPairing {
    private const val ADB_WIFI_ENABLED_SETTING = "adb_wifi_enabled"

    /**
     * Enables wireless debugging programmatically.
     * Requires WRITE_SECURE_SETTINGS (granted via `adb install -g`).
     */
    fun enableWirelessAdb(context: Context): Boolean = try {
        Settings.Global.putInt(context.contentResolver, ADB_WIFI_ENABLED_SETTING, 1)
    } catch (e: SecurityException) {
        Log.w(TAG, "WRITE_SECURE_SETTINGS not granted", e)
        false
    }

    fun isWirelessAdbEnabled(context: Context): Boolean = try {
        Settings.Global.getInt(context.contentResolver, ADB_WIFI_ENABLED_SETTING, 0) == 1
    } catch (e: Exception) {
        false
    }

    fun hasWriteSecureSettings(context: Context): Boolean =
        context.checkCallingOrSelfPermission("android.permission.WRITE_SECURE_SETTINGS") ==
            android.content.pm.PackageManager.PERMISSION_GRANTED

    /**
     * Discovers the wireless-debugging connect port via mDNS.
     * Returns the port, or -1 if not found within [timeoutMs].
     */
    fun discoverConnectPort(context: Context, timeoutMs: Long = 15_000): Int {
        val latch = CountDownLatch(1)
        var port = -1
        val mdns = AdbMdns(context, AdbMdns.TLS_CONNECT) { discovered ->
            if (discovered > 0) {
                port = discovered
                latch.countDown()
            }
        }
        mdns.start()
        try {
            latch.await(timeoutMs, TimeUnit.MILLISECONDS)
        } finally {
            mdns.stop()
        }
        return port
    }

    /**
     * Tests connectivity to the local ADB daemon over wireless debugging.
     * Returns true if we can authenticate and run a command.
     */
    fun testConnection(context: Context): Boolean {
        val port = discoverConnectPort(context)
        if (port <= 0) {
            Log.w(TAG, "No wireless-debugging connect port found")
            return false
        }
        return try {
            val keyManager = AdbKeyManager(context)
            val result = LocalAdbClient.shellOnce("127.0.0.1", port, keyManager, "id")
            result.output.contains("uid=")
        } catch (e: Exception) {
            Log.w(TAG, "Connection test failed", e)
            false
        }
    }
}
