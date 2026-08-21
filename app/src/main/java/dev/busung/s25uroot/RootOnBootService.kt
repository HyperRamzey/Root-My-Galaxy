package dev.busung.s25uroot

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Foreground service that re-applies root + KernelSU after boot using the
 * device's own wireless ADB daemon. No PC required.
 *
 * Flow:
 * 1. Enable wireless debugging (WRITE_SECURE_SETTINGS).
 * 2. Wait for adbd to listen on TCP.
 * 3. Connect to 127.0.0.1:5555 with the pre-registered ADB key.
 * 4. Stage payload + root helper + ksud into /data/local/tmp.
 * 5. Run the exploit (one attempt per boot).
 * 6. Load KernelSU, mount modules, restart zygote.
 * 7. Report the result via notification.
 */
class RootOnBootService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startInForeground()
        scope.launch {
            val result = runCatching { runRootOnBoot() }
            val message = result.fold(
                onSuccess = { getString(R.string.boot_notification_success) },
                onFailure = {
                    getString(R.string.boot_notification_failed, it.message ?: it.javaClass.simpleName)
                },
            )
            notifyResult(result.isSuccess, message)
            stopForeground(STOP_FOREGROUND_DETACH)
            stopSelf()
        }
        return START_NOT_STICKY
    }

    private fun runRootOnBoot() {
        updateNotification(getString(R.string.boot_notification_running))

        // 1. Enable wireless debugging
        if (!AdbPairing.isWirelessAdbEnabled(this)) {
            check(AdbPairing.enableWirelessAdb(this)) {
                "Could not enable wireless debugging (WRITE_SECURE_SETTINGS missing?)"
            }
        }

        // 2. Wait for adbd to listen on TCP
        val port = AdbPairing.getAdbPort()
        waitForAdbd(port)

        // 3. Verify connectivity
        val keyDir = File(filesDir, "adb_keys")
        check(AdbPairing.testConnection(this)) {
            "Could not authenticate to local adbd (ADB key not registered?)"
        }

        // 4. Resolve target and stage payloads
        val profile = PayloadRepository(this).resolveTarget(DeviceSnapshot.current())
        val payloadDir = File(filesDir, "payloads/${profile.profileId}")
        val exploit = File(payloadDir, "cve-2026-43499-app.so")
        val rootHelper = File(payloadDir, "cve-2026-43499-root")
        val ksud = File(payloadDir, "ksud-s25u-kdp")
        check(exploit.exists() && rootHelper.exists() && ksud.exists()) {
            "Cached payloads missing for ${profile.profileId} — run the exploit once from the app first"
        }

        val remoteExploit = "/data/local/tmp/f946b.so"
        val remoteHelper = "/data/local/tmp/cve-2026-43499-root"
        val remoteKsud = "/data/local/tmp/ksud-s25u-kdp"

        LocalAdbClient.push("127.0.0.1", port, exploit, remoteExploit, 0b111101101, keyDir)
        LocalAdbClient.push("127.0.0.1", port, rootHelper, remoteHelper, 0b111101101, keyDir)
        LocalAdbClient.push("127.0.0.1", port, ksud, remoteKsud, 0b111101101, keyDir)

        // 5. Run the exploit (one attempt per boot)
        val exploitCmd = buildString {
            append("SLIDE_SOURCE=tracefs ")
            append("EXPLOIT_ATTEMPTS=1 ")
            append("P0_ATTEMPT_TIMEOUT_SEC=115 ")
            append("EXPLOIT_ATTEMPT_TIMEOUT_SEC=600 ")
            append("$remoteHelper --run-payload $remoteExploit $remoteHelper /data/local/tmp/f946b.log")
        }
        val exploitResult = LocalAdbClient.shell("127.0.0.1", port, exploitCmd, keyDir)
        check(exploitResult.output.contains("exploit completed") || exploitResult.output.contains("slide-kaslr-ok")) {
            "Exploit did not succeed this boot: ${exploitResult.output.takeLast(200)}"
        }

        // 6. Load KernelSU
        val lateLoad = LocalAdbClient.shell("127.0.0.1", port, "$remoteHelper --late-load", keyDir)
        check(lateLoad.exitCode == 0) { "KernelSU late-load failed: ${lateLoad.output}" }

        // 7. Mount modules + restart zygote
        LocalAdbClient.shell("127.0.0.1", port, "/data/adb/ksu/bin/ksud module mount", keyDir)
        LocalAdbClient.shell("127.0.0.1", port, "setprop ctl.restart zygote", keyDir)
    }

    private fun waitForAdbd(port: Int, timeoutMs: Long = 60_000) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (SystemClock.elapsedRealtime() < deadline) {
            try {
                java.net.Socket().use { socket ->
                    socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 1_000)
                    return
                }
            } catch (e: Exception) {
                Thread.sleep(2_000)
            }
        }
        error("adbd did not start listening on port $port within ${timeoutMs / 1000}s")
    }

    private fun startInForeground() {
        createChannel()
        startForegroundCompat(buildNotification(getString(R.string.boot_notification_running)))
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun notifyResult(success: Boolean, message: String) {
        val manager = getSystemService(NotificationManager::class.java)
        val builder = baseNotification(message)
            .setSmallIcon(if (success) android.R.drawable.checkbox_on_background else android.R.drawable.stat_notify_error)
            .setOngoing(false)
        manager.notify(NOTIFICATION_ID, builder.build())
    }

    private fun buildNotification(text: String): Notification =
        baseNotification(text)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .build()

    private fun baseNotification(text: String): NotificationCompat.Builder {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            launchIntent,
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(contentIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
    }

    private fun createChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.boot_notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val CHANNEL_ID = "root_on_boot"
        private const val NOTIFICATION_ID = 0x524F42
    }
}
