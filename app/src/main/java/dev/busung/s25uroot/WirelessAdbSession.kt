package dev.busung.s25uroot

import android.content.Context
import android.os.SystemClock
import android.util.Log
import java.io.Closeable
import java.io.File

private const val TAG = "WirelessAdbSession"

/**
 * A live connection to the device's own adbd over wireless debugging.
 *
 * Encapsulates the full bring-up sequence (enable wireless debugging, discover
 * the dynamic connect port via mDNS, authenticate with the paired ADB key) and
 * exposes push/shell operations. All commands run in the `u:r:shell:s0`
 * context, which is what the tracefs exploit route requires — no PC needed.
 *
 * Use [open] to create and connect a session, then [close] when done.
 */
class WirelessAdbSession private constructor(
    private val client: LocalAdbClient,
) : Closeable {

    /** Pushes a local file to the device and marks it executable. */
    fun push(localFile: File, remotePath: String, executable: Boolean = false) {
        client.push(localFile, remotePath)
        if (executable) {
            val chmod = client.shell("chmod 755 '$remotePath'")
            check(chmod.exitCode == 0) { "chmod 755 $remotePath failed: ${chmod.output}" }
        }
        Log.d(TAG, "pushed ${localFile.name} -> $remotePath")
    }

    /** Runs a shell command and returns its combined output. */
    fun shell(command: String): LocalAdbClient.ShellResult = client.shell(command)

    /**
     * Runs [command] as root via the exploit's root daemon.
     *
     * The ADB shell runs in `u:r:shell:s0`, which SELinux denies for
     * privileged operations (`setprop ctl.*`, killing root-owned zygote,
     * mounting modules). The root helper's client mode forwards the command
     * to the persistent root daemon (`/data/local/tmp/temp_su.sock`), which
     * executes it as uid 0 / `u:r:kernel:s0`.
     *
     * The daemon execs `sh -c "<command>"`, so [command] is escaped for a
     * double-quoted root shell. Requires the daemon to be alive (same boot as
     * the exploit — root is volatile across reboots).
     */
    fun shellAsRoot(
        command: String,
        helperPath: String = DEFAULT_HELPER_PATH,
    ): LocalAdbClient.ShellResult {
        val escaped = command
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("$", "\\$")
            .replace("`", "\\`")
        return client.shell("$helperPath -c \"$escaped\"")
    }

    /**
     * Runs [command] inside a single ADB shell that stays open for the
     * command's full lifetime, streaming its stdout chunk-by-chunk via
     * [onOutput] and returning the accumulated output.
     *
     * adbd kills a backgrounded process the instant its shell stream closes,
     * so a long-running exploit (up to 15 minutes) must run in the foreground
     * of an *open* shell. The root helper's `--run-payload` mode already forks
     * the payload into its own session (so it survives) and streams the live
     * log to stdout via a foreground supervisor, so streaming the helper's
     * stdout directly yields real-time progress.
     */
    fun runStreaming(
        command: String,
        shouldStop: () -> Boolean = { false },
        onOutput: (String) -> Unit,
    ): String {
        val accumulated = StringBuilder()
        client.shellStreaming(command, shouldStop = shouldStop) { chunk ->
            accumulated.append(chunk)
            onOutput(accumulated.toString())
        }
        return accumulated.toString()
    }

    /** Removes a remote file, ignoring errors. */
    fun remove(remotePath: String) {
        client.shell("rm -f '$remotePath'")
    }

    /** Reads the current contents of a remote file (empty string if missing). */
    fun readLog(remotePath: String): String =
        client.shell("cat '$remotePath' 2>/dev/null").output

    override fun close() {
        runCatching { client.close() }
    }

    companion object {
        /** Default path of the staged root helper (client mode -> root daemon). */
        const val DEFAULT_HELPER_PATH = "/data/local/tmp/ksu-helper"

        /**
         * Enables wireless debugging (if needed and permitted), discovers the
         * connect port, and authenticates. Throws if the session cannot be
         * established — callers treat this as the "wireless ADB required" gate.
         */
        fun open(context: Context, portDiscoveryTimeoutMs: Long = 60_000): WirelessAdbSession {
            // 1. Ensure wireless debugging is on.
            if (!AdbPairing.isWirelessAdbEnabled(context)) {
                check(AdbPairing.enableWirelessAdb(context)) {
                    "Wireless debugging is off and could not be enabled " +
                        "(grant WRITE_SECURE_SETTINGS via `adb install -g`)"
                }
            }

            // 2. Discover the dynamic connect port via mDNS.
            val port = discoverPort(context, portDiscoveryTimeoutMs)
            check(port > 0) { "Wireless-debugging connect port not found via mDNS" }
            Log.d(TAG, "discovered connect port=$port")

            // 3. Connect + authenticate with the paired key.
            val keyManager = AdbKeyManager(context)
            val client = LocalAdbClient("127.0.0.1", port, keyManager)
            client.connect()
            Log.d(TAG, "connected to local adbd")
            return WirelessAdbSession(client)
        }

        private fun discoverPort(context: Context, timeoutMs: Long): Int {
            val deadline = SystemClock.elapsedRealtime() + timeoutMs
            while (SystemClock.elapsedRealtime() < deadline) {
                val port = AdbPairing.discoverConnectPort(context, timeoutMs = 10_000)
                if (port > 0) return port
                Thread.sleep(2_000)
            }
            return -1
        }
    }
}
