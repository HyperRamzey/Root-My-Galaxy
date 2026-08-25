package dev.busung.s25uroot

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.BatteryManager
import android.os.IBinder
import android.os.PowerManager
import android.provider.Settings
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
        // Foreground contract first: a duplicate start while the pipeline is
        // already running must still enter the foreground before returning,
        // otherwise the system raises ForegroundServiceDidNotStartInTime and
        // crashes the app in a loop (observed on alarm retries).
        startInForeground()
        // Single-instance guard: BOOT_COMPLETED plus the alarm retries must
        // never run two pipelines concurrently - overlapping exploits,
        // late-loads or zygote kills destabilize the device (observed
        // soft-reboot loops).
        if (!RUNNING.compareAndSet(false, true)) {
            stopSelf()
            return START_NOT_STICKY
        }
        // Fresh timeline per pipeline run (notification + app console).
        LiveLog.clear()
        scope.launch {
            val result = runCatching { runRootOnBoot() }
            val message = result.fold(
                onSuccess = { getString(R.string.boot_notification_success) },
                onFailure = {
                    getString(R.string.boot_notification_failed, it.message ?: it.javaClass.simpleName)
                },
            )
            if (!result.isSuccess && message.contains(LocalAdbClient.PAIRING_LOST_MARKER)) {
                // adbd rejected our key: pairing no longer valid. Clear the
                // flag so the boot gate stops silently skipping and surfaces
                // a re-pair prompt instead.
                AppPreferences.setAdbPaired(this@RootOnBootService, false)
                android.util.Log.w("RootOnBootService", "pairing lost; adbPaired cleared for re-pair")
            }
            try {
                RootOnBootProgress.update(RootOnBootState.Done(result.isSuccess, message))
                notifyResult(result.isSuccess, message)
            } finally {
                // Must run even if progress/notification plumbing throws:
                // a wedged RUNNING flag turns every later start into a
                // silent no-op until process death.
                RUNNING.set(false)
                stopForeground(STOP_FOREGROUND_DETACH)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    @Volatile
    private var activeSession: WirelessAdbSession? = null

    private fun runRootOnBoot() {
        // The exploit choreography is timing-sensitive: a suspended SoC
        // (screen off -> deep idle) desynchronizes it — observed as a hard
        // kernel hang on F946B — so the display must stay on for the whole
        // pipeline. Hold a full wakelock for the CPU side and, while on
        // external power, pin STAY_ON_WHILE_PLUGGED_IN for the display
        // side (FULL_WAKE_LOCK alone is ignored by recent One UI builds).
        // STAY_ON needs WRITE_SECURE_SETTINGS, which the apply script
        // self-grants after the first successful root.
        val powerManager = getSystemService(PowerManager::class.java)
        // Full wakelock with CAUSES_WAKEUP: light the display ourselves so a
        // boot-time run never starts against a suspended SoC. Partial alone
        // is not enough on Samsung idle governors (see screen-off failures).
        val wakeLock = powerManager?.newWakeLock(
            PowerManager.FULL_WAKE_LOCK or
                PowerManager.ACQUIRE_CAUSES_WAKEUP,
            "rmg:RootOnBoot",
        )
        wakeLock?.acquire(PIPELINE_WAKELOCK_MS)
        // Live handle the watchdog uses to force-unwind a wedged pipeline.
        activeSession = null
        val previousStayOn = runCatching {
            Settings.Global.getInt(
                contentResolver,
                Settings.Global.STAY_ON_WHILE_PLUGGED_IN,
            )
        }.getOrDefault(0)
        runCatching {
            // AC | USB | WIRELESS
            Settings.Global.putInt(
                contentResolver,
                Settings.Global.STAY_ON_WHILE_PLUGGED_IN,
                BatteryManager.BATTERY_PLUGGED_AC or
                    BatteryManager.BATTERY_PLUGGED_USB or
                    BatteryManager.BATTERY_PLUGGED_WIRELESS,
            )
        }
        // Failsafe watchdog: no matter how deep we are blocked inside a
        // wedged ADB transport or a hung exploit, force the pipeline to
        // unwind at the same bound as the wakelock. Closing the session
        // makes every in-flight operation throw; the finally blocks then
        // restore stay-on, release the wake lock and report failure.
        val watchdog = java.util.concurrent.Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "rmg-watchdog").apply { isDaemon = true }
        }
        try {
            watchdog.schedule({
                android.util.Log.e("RootOnBootService", "watchdog fired after ${PIPELINE_WAKELOCK_MS / 1000}s; forcing session close")
                runCatching { activeSession?.close() }
            }, PIPELINE_WAKELOCK_MS + 60_000, java.util.concurrent.TimeUnit.MILLISECONDS)
            runRootOnBootLocked()
        } finally {
            watchdog.shutdownNow()
            activeSession = null
            runCatching {
                Settings.Global.putInt(
                    contentResolver,
                    Settings.Global.STAY_ON_WHILE_PLUGGED_IN,
                    previousStayOn,
                )
            }
            runCatching { if (wakeLock?.isHeld == true) wakeLock.release() }
        }
    }

    private fun runRootOnBootLocked() {
        if (RootStatusProbe.isRootLiveThisBoot(this)) {
            // Already rooted this boot (manual run or earlier retry): keep
            // the alarm retries harmless and report success immediately.
            AppPreferences.setBootRetryCount(this, 0)
            return
        }
        val started = System.currentTimeMillis()
        fun running(stage: String, lastLine: String = "", etaMs: Long = -1) {
            // Stage transitions join the shared live log so the expanded
            // notification and the in-app console show one timeline.
            if (lastLine.isBlank()) {
                LiveLog.add("• $stage")
            } else {
                LiveLog.add("$stage — $lastLine")
            }
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
        activeSession = adb
        // Every exit path below must release the session: check() failures
        // (interactive gate, staging, module wait) previously leaked the TLS
        // socket and reader thread. The explicit close() calls further down
        // are kept as fast-paths; double-close is fully guarded.
        try {

        // Wake the display: with the screen off the SoC can enter suspend
        // between timing-critical exploit steps even under a partial
        // wakelock (vendor idle governors are stricter than AOSP). Screen
        // on + wakelock keeps the pipeline window stable.
        runCatching { adb.shell("input keyevent KEYCODE_WAKEUP") }

        // Decisive KernelSU check via the ADB session itself. The app-domain
        // probes lie in two real scenarios: (a) SELinux hides /proc/modules
        // and (b) sucompat denies our uid when manager registration was
        // skipped (manual-launcher roots) — yet shell uid 2000 is ALWAYS
        // allowed once KernelSU is loaded. If shell-su answers uid=0 the
        // device is already rooted: record the receipt and exit QUIETLY —
        // no unlock, no activity foregrounding, no focus theft.
        runCatching {
            val idOut = adb.shell("su -c id")
            if (idOut.output.contains("uid=0")) {
                RootStatusProbe.storeBootReceipt(this)
                LiveLog.add("• KernelSU already active (shell su) — skipping")
                running(getString(R.string.boot_stage_connecting), "already rooted")
                BootReceiver.cancelRetryAlarms(this)
                batteryWindDown(adb)
                return
            }
        }

        // NOTE: the unlock + MainActivity-foreground block lives further
        // down, immediately before the exploit launch. Running it here
        // stole screen focus even on boots where KernelSU was already
        // active and every later stage skipped — pure distraction.

        // Hard gate: refuse to run the choreography unless the display is
        // verifiably interactive. A suspending SoC mid-sequence has been
        // observed to corrupt kernel state and hang the device outright —
        // failing into the reboot-retry ladder is always safer.
        val pm = getSystemService(PowerManager::class.java)
        val interactiveDeadline = System.currentTimeMillis() + 20_000
        var interactive = false
        while (System.currentTimeMillis() < interactiveDeadline) {
            if (pm?.isInteractive == true) {
                interactive = true
                break
            }
            runCatching { adb.shell("input keyevent KEYCODE_WAKEUP") }
            runCatching { adb.shell("input keyevent 82") }
            Thread.sleep(2_000)
        }
        check(interactive) {
            "Display never came interactive — refusing the exploit against " +
                "a suspending SoC; reboot-retry will re-run with the screen forced on"
        }

        // 4. Resolve target and stage payloads
        running(getString(R.string.boot_stage_staging))
        val repository = PayloadRepository(this)
        // Cached fallback keeps the pipeline alive when GitHub times out
        // right after boot (observed HTTP 504 from api.github.com).
        val profile = repository.resolveTarget(DeviceSnapshot.current(), allowCached = true)
        val payloadDir = File(filesDir, "payloads/${profile.profileId}")
        val exploit = File(payloadDir, "cve-2026-43499-app.so")
        val rootHelper = File(payloadDir, "cve-2026-43499-root")
        // Cache file is named after the feed artifact since v0.2.8; fall back
        // to the legacy alias for caches written by older builds.
        fun ksudCandidates(): Sequence<File> = sequenceOf(
            profile.kernelSu.url.substringAfterLast('/'),
            LEGACY_KSUD_NAME,
        ).map { File(payloadDir, it) }

        // Refresh-on-boot: resolveTarget() already fetched the live manifest,
        // so compare the cached artifacts against its expected sizes. A
        // mismatch means a payload was updated upstream since the last run -
        // re-download before staging so every boot executes the current
        // build instead of whatever the cache happens to hold.
        fun cacheComplete(): Boolean =
            exploit.exists() && exploit.length() == profile.exploit.size &&
                rootHelper.exists() && profile.rootHelper?.let { rootHelper.length() == it.size } == true &&
                ksudCandidates().any { it.exists() && it.length() == profile.kernelSu.size }
        if (!cacheComplete()) {
            running(getString(R.string.boot_stage_staging), "refreshing payloads from feed")
            val refreshed = runCatching { repository.download(profile) {} }
            if (refreshed.isFailure && !exploit.exists()) {
                check(false) {
                    "Payload refresh failed and no cache exists for ${profile.profileId}: " +
                        refreshed.exceptionOrNull()?.message
                }
            }
        }
        val ksud = ksudCandidates().firstOrNull { it.exists() }
            ?: File(payloadDir, profile.kernelSu.url.substringAfterLast('/'))
        check(exploit.exists() && rootHelper.exists() && ksud.exists()) {
            "Cached payloads missing for ${profile.profileId} — run the exploit once from the app first"
        }

        // Work-dir staging resolution. Anti-log addons (KillLogger-class)
        // wipe /data/local/tmp every boot and whatever recreates it labels
        // system_data_file, which permanently denies adbd staging. When the
        // probe fails we bootstrap from the app's own bundled jniLibs
        // (apk_data_file is executable by shell) and defer ksud staging
        // until the exploit's heal lands — see ExploitStaging.
        val launch = ExploitStaging.resolve(this, adb, profile.profileId)
        val remoteExploit = launch.payloadPath
        val remoteHelper = launch.helperPath
        val remoteLog = launch.logPath
        val remoteKsud = "/data/local/tmp/${ksud.name}"
        val remoteKsudStage = "/data/local/tmp/.ksud-stage"

        if (launch.workDirHealthy) {
            adb.push(exploit, remoteExploit, executable = true)
            adb.push(rootHelper, remoteHelper, executable = true)
            adb.push(ksud, remoteKsud, executable = true)
            // .ksud-stage is intentionally NOT pre-pushed: the apply
            // script resolves ksud from the primary path first, and the
            // late-load fallback stages it on demand — the duplicate
            // 4.8MB push cost ~1-2s of serial ADB per boot.
        } else {
            // Bundled binaries need no staging; only the log home must
            // exist. Drop any stale SD log first — a leftover success
            // marker from an earlier boot would fake a pass below.
            ExploitStaging.prepareLogDir(adb, remoteLog)
            runCatching { adb.shell("rm -f '$remoteLog'") }
        }

        // 5. Run the exploit (one attempt per boot) in a streaming shell that
        // stays open for the full run — adbd kills a backgrounded process the
        // moment its shell stream closes, and the helper streams the live log
        // to stdout via a foreground supervisor.
        running(getString(R.string.boot_stage_exploit), etaMs = RootOnBootProgress.EXPLOIT_ETA_MS)
        val exploitCmd = buildString {
            // The app just downloaded fresh, size-verified binaries from
            // the pinned commit — the helper's own feed self-update is
            // redundant network time on the serial pre-exploit path.
            append("RMG_SELF_UPDATE=0 ")
            // Halved kernelsnitch sample count: e2e shows the x5
            // threshold holds with 64 repeats on A715 (majority-vote
            // confirmation absorbs the extra jitter).
            append("RMG_KSNITCH_REPEAT=64 ")
            append("RMG_KSNITCH_AVERAGE=4 ")
            append("RMG_MANAGER_PACKAGE=${BuildConfig.APPLICATION_ID} ")
            append("SLIDE_SOURCE=tracefs ")
            append("EXPLOIT_ATTEMPTS=1 ")
            append("P0_ATTEMPT_TIMEOUT_SEC=115 ")
            append("EXPLOIT_ATTEMPT_TIMEOUT_SEC=600 ")
            append("$remoteHelper --run-payload $remoteExploit $remoteHelper $remoteLog")
        }
        // Stream the exploit output. Once we see "exploit completed", the
        // supervisor will auto-trigger late-load + apply-modules (which kills
        // zygote and drops the ADB connection), so we must NOT wait for the
        // stream to close — return as soon as the success marker appears.
        var exploitDone = false
        // Only feed NEW streamed bytes into the live log: `accumulated`
        // grows monotonically, so remember how much we already consumed.
        var logConsumed = 0
        val exploitOutput = try {
            adb.runStreaming(
                exploitCmd,
                shouldStop = { exploitDone },
            ) { accumulated ->
                if (accumulated.length > logConsumed) {
                    LiveLog.addAll(accumulated.substring(logConsumed))
                    logConsumed = accumulated.length
                }
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
        var exploitSucceeded = exploitDone
        if (!exploitSucceeded) {
            val logContent = adb.readLog(remoteLog)
            exploitSucceeded = logContent.contains("exploit completed")
        }
        if (!exploitSucceeded) {
            // One clean attempt per boot: a burned attempt cannot be repeated
            // safely, so reboot for a fresh one - bounded by a consecutive
            // retry budget so a persistently failing state cannot loop
            // the device forever.
            val attempts = AppPreferences.bootRetryCount(this) + 1
            if (attempts <= MAX_BOOT_RETRIES) {
                AppPreferences.setBootRetryCount(this, attempts)
                running(
                    getString(R.string.boot_stage_exploit),
                    "failed - rebooting to retry ($attempts/$MAX_BOOT_RETRIES)",
                )
                runCatching { adb.shell("sync; sleep 2; reboot") }
                Thread.sleep(20_000) // let adbd drop as the device reboots
                adb.close()
                return
            }
            error(
                "Exploit did not succeed this boot and the retry budget is " +
                    "exhausted ($MAX_BOOT_RETRIES): ${exploitOutput.takeLast(200)}"
            )
        }
        AppPreferences.setBootRetryCount(this, 0)

        // 6. Load KernelSU
        running(getString(R.string.boot_stage_kernelsu))
        if (!launch.workDirHealthy) {
            // Fallback mode: ksud was never staged. The root daemon healed
            // /data/local/tmp during its permissive activation window; the
            // su-based heal below covers the lost race where SELinux
            // re-enforced first. Either way, verify staging before pushing.
            ExploitStaging.prepareLogDir(adb, remoteLog)
            val staged = ExploitStaging.pushWhenStable(adb, ksud, remoteKsud) &&
                runCatching { adb.push(ksud, remoteKsudStage, executable = true) }.isSuccess
            check(staged) {
                "Work dir still unwritable after exploit — cannot stage ksud " +
                    "for late-load (KillLogger-class module still wiping?)"
            }
        }
        val lateLoad = adb.shell("$remoteHelper --late-load")
        check(lateLoad.exitCode == 0) { "KernelSU late-load failed: ${lateLoad.output}" }

        // 7. Module activation is OWNED by the native side (root-daemon
        // watcher + shell-context stability keeper). The app must not run
        // ksud stages or kill zygote itself: duplicating the native actors
        // caused concurrent framework restarts and soft-reboot loops. Wait
        // for the boot-scoped done marker instead.
        running(getString(R.string.boot_stage_modules))
        val deadline = System.currentTimeMillis() + MODULE_WAIT_MS
        var applied = false
        while (System.currentTimeMillis() < deadline) {
            val done = adb.shell(
                "cat /data/local/tmp/.cve43499-modules-done 2>/dev/null"
            ).output.trim()
            val live = adb.shell(
                "cat /proc/sys/kernel/random/boot_id 2>/dev/null"
            ).output.trim()
            if (live.isNotEmpty() && done.startsWith(live)) {
                applied = true
                break
            }
            // Secondary signal: KernelSU live this boot means the exploit +
            // late-load succeeded even if the done-marker was lost (e.g. an
            // apply actor died before recording completion). Accept it after
            // a grace period instead of reporting a false failure.
            if (System.currentTimeMillis() - started > KSU_ACTIVE_GRACE_MS &&
                RootStatusProbe.isActive()
            ) {
                applied = true
                break
            }
            Thread.sleep(10_000)
        }
        // Modules confirmed: full battery wind-down before dropping the
        // session — cancel pending retry alarms, put the display back to
        // sleep (we woke it for the choreography) and switch wireless
        // debugging off so adbd stops holding the Wi-Fi radio awake.
        BootReceiver.cancelRetryAlarms(this)
        RootStatusProbe.storeBootReceipt(this)
        batteryWindDown(adb)
        check(applied) { "Module activation did not complete within ${MODULE_WAIT_MS / 1000}s" }
        } finally {
            runCatching { adb.close() }
        }
    }

    /**
     * Post-success power hygiene, executed while the ADB session is still
     * alive. Order matters: display sleep first (no further input needed),
     * then wireless debugging off (adbd releases the radio), then the
     * caller closes the socket.
     */
    private fun batteryWindDown(adb: WirelessAdbSession) {
        LiveLog.add("• Battery wind-down: display sleep + wireless adb off")
        // Only put the display to sleep when nobody is actively using the
        // phone (keyguard locked OR screen already off = unattended boot).
        val km = getSystemService(android.app.KeyguardManager::class.java)
        val pm = getSystemService(PowerManager::class.java)
        val userActive = pm?.isInteractive == true && km?.isKeyguardLocked == false
        if (!userActive) {
            runCatching { adb.shell("input keyevent KEYCODE_SLEEP") }
        }
        runCatching { adb.shell("settings put global adb_wifi_enabled 0") }
        runCatching { adb.shell("setprop service.adb.tls.port \"\"") }
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

    private fun buildNotification(text: String): Notification {
        val builder = baseNotification(text)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
        // Expandable style: show the most recent pipeline/exploit lines so
        // the user can see what is happening without opening the app.
        val recent = LiveLog.recent(LiveLog.NOTIFICATION_LINES)
        if (recent.isNotEmpty()) {
            val inbox = NotificationCompat.InboxStyle()
                .setBigContentTitle(getString(R.string.app_name))
                .setSummaryText(text)
            for (line in recent) {
                inbox.addLine(line)
            }
            builder.setStyle(inbox)
        }
        return builder.build()
    }

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
        private const val MODULE_WAIT_MS = 300_000L
        private const val MAX_BOOT_RETRIES = 3
        private const val LEGACY_KSUD_NAME = "ksud-s25u-kdp"
        /** Wait this long for a fresh done-marker before trusting the
         * KernelSU-active probe as a success fallback. */
        private const val KSU_ACTIVE_GRACE_MS = 120_000L
        /** Upper bound for one full pipeline (connect + staging + exploit +
         * late-load + module wait). */
        private const val PIPELINE_WAKELOCK_MS = 20 * 60_000L

        @Volatile
        private var RUNNING = java.util.concurrent.atomic.AtomicBoolean(false)
    }
}
