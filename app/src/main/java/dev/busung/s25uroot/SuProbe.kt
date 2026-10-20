package dev.busung.s25uroot

import android.util.Log
import java.util.concurrent.TimeUnit

/**
 * Fallback KernelSU activity probe.
 *
 * NativeProbe.isKernelSuActive() relies on /sys/module/kernelsu and
 * /proc/modules, which Samsung SELinux denies to app domains once the
 * module is loaded and the system locked down — producing false
 * "Not installed" states even while root is fully live.
 *
 * This app is the granted manager (RMG_MANAGER_PACKAGE), so when
 * KernelSU is active its sucompat hook answers our own `su` exec with
 * uid=0. That is the authoritative signal.
 */
object SuProbe {
    private const val TAG = "SuProbe"

    /** Why the last probe failed, for diagnostics. */
    enum class Failure { NONE, DENIED, ABSENT, ERROR }

    @Volatile
    var lastFailure: Failure = Failure.NONE
        private set

    fun isActive(): Boolean {
        lastFailure = Failure.NONE
        var process: Process? = null
        return try {
            val proc = ProcessBuilder("su", "-c", "id")
                .redirectErrorStream(true)
                .start()
            process = proc
            // Wait before draining stdout: a su that never exits (manager
            // prompt, dead socket) would otherwise block readLine() forever and
            // the 3 s timeout below would never be reached. The `id` output is
            // tiny, so it cannot fill the pipe while we wait.
            val finished = proc.waitFor(3, TimeUnit.SECONDS)
            if (!finished) {
                proc.destroyForcibly()
                runCatching { proc.waitFor(1, TimeUnit.SECONDS) }
                runCatching { proc.inputStream.close() }
                lastFailure = Failure.ERROR
                Log.d(TAG, "su probe timed out")
                return false
            }
            val output = proc.inputStream.bufferedReader().use { it.readText() }
            val exit = proc.exitValue()
            val ok = exit == 0 && output.contains("uid=0")
            Log.d(TAG, "su probe: exit=$exit ok=$ok")
            if (!ok) lastFailure = Failure.DENIED
            ok
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            process?.destroyForcibly()
            lastFailure = Failure.ERROR
            Log.d(TAG, "su probe interrupted")
            false
        } catch (t: Throwable) {
            process?.destroyForcibly()
            Log.d(TAG, "su probe unavailable: ${t.javaClass.simpleName}")
            lastFailure = Failure.ABSENT
            false
        }
    }
}
