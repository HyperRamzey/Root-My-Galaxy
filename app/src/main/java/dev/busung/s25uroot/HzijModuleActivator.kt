package dev.busung.s25uroot

import android.content.Context
import android.util.Log
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Mounts KernelSU modules and restarts zygote on the HZIJ DirtyFrag path.
 *
 * The normal installer can drive ksud through the wireless-ADB shell. HZIJ
 * roots without ADB, but it does have a working KernelSU `su`, so the same
 * lifecycle can run directly as root:
 *
 *   post-fs-data -> services -> boot-completed -> zygote restart
 *
 * The zygote restart is the soft reboot the UI promises. It kills this app
 * too, so the restart command is detached into its own session and the boot
 * id scoped marker is written first: after the framework comes back the
 * same boot must not auto-apply a second time.
 */
object HzijModuleActivator {
    private const val TAG = "HzijModules"
    private const val LOG_PATH = "/data/local/tmp/rmg-hzij-modules.log"
    private const val PREFS = "hzij_modules"
    private const val BOOT_KEY = "applied_boot_id"

    /** True when module activation was already started on this kernel boot. */
    fun appliedThisBoot(context: Context): Boolean {
        val bootId = currentBootId() ?: return false
        return modulePrefs(context).getString(BOOT_KEY, null) == bootId
    }

    /**
     * Runs the KernelSU lifecycle as root and schedules the zygote restart.
     *
     * @param force manual button path; auto callers pass false so a soft
     *              reboot cannot repeat on the same boot.
     */
    fun apply(context: Context, report: (String) -> Unit, force: Boolean = false): Boolean {
        if (!DirtyFragRunner.isHzijDevice()) {
            report("module activation: not an HZIJ device")
            return false
        }
        if (!force && appliedThisBoot(context)) {
            report("modules already applied this boot; tap again to force")
            return false
        }
        if (!SuProbe.isActive()) {
            report("module activation: su is not live")
            return false
        }

        val command = buildString {
            append("LOG=").append(LOG_PATH).append("; ")
            append(": > \"\$LOG\" 2>/dev/null; ")
            append("/system/bin/timeout 30 /data/adb/ksud post-fs-data >> \"\$LOG\" 2>&1; ")
            append("echo PFD=\$? >> \"\$LOG\"; ")
            append("/system/bin/timeout 30 /data/adb/ksud services >> \"\$LOG\" 2>&1; ")
            append("echo SVC=\$? >> \"\$LOG\"; ")
            append("/system/bin/timeout 30 /data/adb/ksud boot-completed >> \"\$LOG\" 2>&1; ")
            append("echo BC=\$? >> \"\$LOG\"; ")
            append("tail -n 40 \"\$LOG\" 2>/dev/null")
        }
        val output = runSu(command, 110_000L)
        if (output == null) {
            report("module activation: ksud stages failed to run")
            return false
        }
        output.lineSequence()
            .filter { it.isNotBlank() }
            .toList()
            .takeLast(12)
            .forEach { report("modules: ${it.trim()}") }

        // Marker first: the detached shell kills zygote in two seconds and
        // this process dies with it. The marker is what stops another auto
        // apply after the soft-reboot BOOT_COMPLETED broadcast.
        markApplied(context)
        val killCommand = "setsid /system/bin/sh -c 'sleep 2; " +
            "pids=\"\$(pidof zygote64) \$(pidof zygote)\"; " +
            "[ -n \"\$pids\" ] && kill -9 \$pids 2>/dev/null' " +
            ">/dev/null 2>&1 < /dev/null &"
        val started = runSu(killCommand, 5_000L) != null
        if (started) {
            report("module activation: zygote restart scheduled (soft reboot)")
        } else {
            report("module activation: could not schedule zygote restart")
        }
        Log.i(TAG, "apply force=$force stagesRan=true zygoteRestart=$started")
        return started
    }

    private fun runSu(command: String, timeoutMs: Long): String? {
        var process: Process? = null
        return try {
            val proc = ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true)
                .start()
            process = proc
            val finished = proc.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
            if (!finished) {
                proc.destroyForcibly()
                runCatching { proc.inputStream.close() }
                Log.w(TAG, "su command timed out after ${timeoutMs}ms")
                null
            } else {
                proc.inputStream.bufferedReader().use { it.readText() }
            }
        } catch (t: Throwable) {
            process?.destroyForcibly()
            Log.w(TAG, "su command failed: ${t.javaClass.simpleName}: ${t.message}")
            null
        }
    }

    private fun markApplied(context: Context) {
        val bootId = currentBootId() ?: return
        modulePrefs(context).edit().putString(BOOT_KEY, bootId).commit()
    }

    private fun currentBootId(): String? = runCatching {
        File("/proc/sys/kernel/random/boot_id").readText().trim()
    }.getOrNull()

    private fun modulePrefs(context: Context) = context
        .createDeviceProtectedStorageContext()
        .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
