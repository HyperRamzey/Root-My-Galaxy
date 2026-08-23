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
            RootOnBootProgress.update(RootOnBootState.Done(result.isSuccess, message))
            notifyResult(result.isSuccess, message)
            stopForeground(STOP_FOREGROUND_DETACH)
            stopSelf()
        }
        return START_NOT_STICKY
    }

    private fun runRootOnBoot() {
        if (NativeProbe.isKernelSuActive()) {
            // Already rooted this boot (manual run or earlier retry): keep
            // the alarm retries harmless and report success immediately.
            return
        }
        val started = System.currentTimeMillis()
        fun running(stage: String, lastLine: String = "", etaMs: Long = -1) {
            RootOnBootProgress.update(
                RootOnBootState.Running(
                    stage = stage,
                    lastLine = lastLine,
                    elapsedMs = System.currentTimeMillis() - started,
                    etaMs = etaMs,
                ),
            )
            updateNotification("$stage${if (lastLine.isNotBlank()) " — $lastLine" else ""}")
        }

        running(getString(R.string.boot_stage_connecting))

        // 1-3. Enable wireless debugging, discover port, connect (shared session).
        val adb = WirelessAdbSession.open(this)

        // 4. Resolve target and stage payloads
        running(getString(R.string.boot_stage_staging))
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
        val remoteKsudStage = "/data/local/tmp/.ksud-stage"

        adb.push(exploit, remoteExploit, executable = true)
        adb.push(rootHelper, remoteHelper, executable = true)
        adb.push(ksud, remoteKsud, executable = true)
        adb.push(ksud, remoteKsudStage, executable = true)

        // 5. Run the exploit (one attempt per boot) in a streaming shell that
        // stays open for the full run — adbd kills a backgrounded process the
        // moment its shell stream closes, and the helper streams the live log
        // to stdout via a foreground supervisor.
        running(getString(R.string.boot_stage_exploit), etaMs = RootOnBootProgress.EXPLOIT_ETA_MS)
        val exploitCmd = buildString {
            append("RMG_MANAGER_PACKAGE=${BuildConfig.APPLICATION_ID} ")
            append("SLIDE_SOURCE=tracefs ")
            append("EXPLOIT_ATTEMPTS=1 ")
            append("P0_ATTEMPT_TIMEOUT_SEC=115 ")
            append("EXPLOIT_ATTEMPT_TIMEOUT_SEC=600 ")
            append("$remoteHelper --run-payload $remoteExploit $remoteHelper /data/local/tmp/f946b.log")
        }
        // Stream the exploit output. Once we see "exploit completed", the
        // supervisor will auto-trigger late-load + apply-modules (which kills
        // zygote and drops the ADB connection), so we must NOT wait for the
        // stream to close — return as soon as the success marker appears.
        var exploitDone = false
        val exploitOutput = try {
            adb.runStreaming(
                exploitCmd,
                shouldStop = { exploitDone },
            ) { accumulated ->
                val lastLine = accumulated.lineSequence()
                    .filter { it.isNotBlank() }
                    .lastOrNull()
                    ?.takeLast(100)
                    ?: ""
                val elapsed = System.currentTimeMillis() - started
                val remaining = (RootOnBootProgress.EXPLOIT_ETA_MS - elapsed).coerceAtLeast(0)
                running(getString(R.string.boot_stage_exploit), lastLine, remaining)
                if (accumulated.contains("exploit completed")) {
                    exploitDone = true
                }
            }
        } catch (_: Exception) {
            // Stream may be interrupted when zygote kill drops ADB — that's OK
            // if we already saw the success marker.
            ""
        }
        if (!exploitDone) {
            // Stream ended without success marker — check the log file
            val logContent = adb.readLog("/data/local/tmp/f946b.log")
            check(logContent.contains("exploit completed")) {
                "Exploit did not succeed this boot: ${(exploitOutput + logContent).takeLast(200)}"
            }
        }

        // 6. Load KernelSU
        running(getString(R.string.boot_stage_kernelsu))
        val lateLoad = adb.shell("$remoteHelper --late-load")
        check(lateLoad.exitCode == 0) { "KernelSU late-load failed: ${lateLoad.output}" }

        // 7. Activate modules + restart zygote. Prefer `su -c` (persists under
        // Enforcing once shell has been granted root by KernelSU); fall back
        // to the daemon apply-modules path while SELinux is still permissive.
        running(getString(R.string.boot_stage_modules))
        val suCheck = adb.shell("su -c id 2>&1")
        if (suCheck.exitCode == 0 && suCheck.output.contains("uid=0")) {
            adb.shell("su -c 'setsid sh -c \"timeout 30 /data/adb/ksud post-fs-data > /data/local/tmp/ksud-pfd.log 2>&1 < /dev/null\" & echo pfd_bg'")
            Thread.sleep(12_000)
            adb.shell("su -c 'setsid sh -c \"timeout 30 /data/adb/ksud services > /data/local/tmp/ksud-svc.log 2>&1 < /dev/null\" & echo svc_bg'")
            Thread.sleep(5_000)
            adb.shell("su -c 'setsid sh -c \"timeout 30 /data/adb/ksud boot-completed > /data/local/tmp/ksud-bc.log 2>&1 < /dev/null\" & echo bc_bg'")
            Thread.sleep(3_000)
            adb.shell("su -c 'for p in \$(pidof zygote64) \$(pidof zygote); do kill -9 \$p 2>/dev/null; done; echo zygote-killed'")
        } else {
            val apply = adb.shell("$remoteHelper --apply-modules")
            if (apply.exitCode != 0) {
                adb.shellAsRoot(
                    "for p in \$(pidof zygote64) \$(pidof zygote); do kill -9 \$p 2>/dev/null; done; echo killed",
                    helperPath = remoteHelper,
                )
            }
        }
        adb.close()
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
