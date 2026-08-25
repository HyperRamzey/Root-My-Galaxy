package dev.busung.s25uroot

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
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
        return try {
            val process = ProcessBuilder("su", "-c", "id")
                .redirectErrorStream(true)
                .start()
            val output = StringBuilder()
            BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    output.append(line).append('\n')
                }
            }
            val finished = process.waitFor(3, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                lastFailure = Failure.ERROR
                return false
            }
            val ok = process.exitValue() == 0 &&
                output.contains("uid=0")
            Log.d(TAG, "su probe: exit=${process.exitValue()} ok=$ok")
            if (!ok) lastFailure = Failure.DENIED
            ok
        } catch (t: Throwable) {
            // IOException at start = no su visible to this uid. KernelSU's
            // sucompat only answers callers it allows (manager/shell); a
            // non-manager app sees ENOENT/EACCES here.
            Log.d(TAG, "su probe unavailable: ${t.javaClass.simpleName}")
            lastFailure = Failure.ABSENT
            false
        }
    }
}
