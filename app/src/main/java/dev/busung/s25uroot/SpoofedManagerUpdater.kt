package dev.busung.s25uroot

import android.os.Build
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

/**
 * Spoofed KSU manager ("SystemTune") install/update, driven over root shell.
 *
 * The manager is built per upstream commit in
 * HyperRamzey/Root-My-Galaxy-Manager with a spoofed application id, so it
 * cannot be discovered by name from the outside. Detection therefore runs
 * through root shell: a registry file written at install time
 * (/data/adb/.rmg/ksumgr, "<versionCode> <pkg>") is the primary record, and
 * `pm path` / `dumpsys package` probes verify or recover it. Runs after the
 * exploit lands and before module activation so the manager UI exists while
 * modules mount.
 */
object SpoofedManagerUpdater {

    private const val FEED_URL =
        "https://raw.githubusercontent.com/HyperRamzey/Root-My-Galaxy-Manager/main/feed.json"
    private const val REGISTRY = "/data/adb/.rmg/ksumgr"
    private const val REMOTE_APK = "/data/local/tmp/.rmg-mgr.apk"
    private const val MAX_FEED_BYTES = 16 * 1024
    private const val MAX_APK_BYTES = 128 * 1024 * 1024

    private data class Feed(
        val pkg: String,
        val versionCode: Int,
        val versionName: String,
        val url: String,
        val sha256: String,
    )

    /**
     * Ensures the spoofed manager matches the feed. Returns a one-line
     * report for the run log; throws only on unexpected pipeline-level
     * failures (callers wrap this in runCatching anyway).
     */
    fun ensureInstalled(adb: WirelessAdbSession): String {
        val feed = fetchFeed() ?: return "feed unavailable"
        if (feed.pkg.isEmpty() || feed.versionCode <= 0) return "feed malformed"

        // Detection via root shell: registry first, then a live pm probe.
        val registry = adb.shell("su -c 'cat $REGISTRY 2>/dev/null'").output.trim()
        var pkg = feed.pkg
        var installed = 0
        val regParts = registry.split(' ')
        if (regParts.size >= 2) {
            installed = regParts[0].toIntOrNull() ?: 0
            pkg = regParts[1]
        }
        val pmPath = adb.shell("su -c 'pm path $pkg 2>/dev/null'").output.trim()
        if (pmPath.isEmpty()) {
            installed = 0 // registry stale: package was uninstalled
        } else if (installed == 0) {
            // Present but unregistered (manual install): read its version.
            // grep runs on-device — a full dumpsys dump would blow the
            // ADB response size limit.
            val dump = adb.shell(
                "su -c 'dumpsys package $pkg 2>/dev/null | grep -m1 versionCode'"
            ).output
            installed = Regex("versionCode=(\\d+)").find(dump)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        }
        if (installed >= feed.versionCode) return "up-to-date ($installed)"

        // Spoof-id rotation: a registry package that differs from the
        // feed's current id is an older-generation build — remove it so
        // exactly one manager exists after the update.
        if (pkg != feed.pkg && pmPath.isNotEmpty()) {
            adb.shell("su -c 'pm uninstall $pkg'")
            installed = 0
        }

        // Download through the app network, verify, install via root shell.
        val apk = download(feed.url) ?: return "download failed"
        try {
            if (apk.length() > MAX_APK_BYTES) return "download too large"
            runCatching { adb.shell("su -c 'rm -f $REMOTE_APK'") }
            adb.push(apk, REMOTE_APK)
            val remoteSha = adb.shell("su -c 'sha256sum $REMOTE_APK 2>/dev/null'").output
                .trim().split(' ').firstOrNull() ?: ""
            if (!remoteSha.equals(feed.sha256, ignoreCase = true)) {
                return "sha mismatch"
            }
            val install = adb.shell("su -c 'pm install -r $REMOTE_APK'")
            if (install.exitCode != 0) {
                return "install failed: ${install.output.trim().takeLast(120)}"
            }
            adb.shell(
                "su -c 'mkdir -p /data/adb/.rmg; " +
                    "echo \"${feed.versionCode} ${feed.pkg}\" > $REGISTRY'"
            )
            return "installed ${feed.versionName}(${feed.versionCode})"
        } finally {
            apk.delete()
            runCatching { adb.shell("su -c 'rm -f $REMOTE_APK'") }
        }
    }

    private fun fetchFeed(): Feed? = runCatching {
        val text = httpGet(FEED_URL, maxBytes = MAX_FEED_BYTES)
            ?.toString(Charsets.UTF_8) ?: return null
        val json = JSONObject(text)
        Feed(
            pkg = json.optString("pkg"),
            versionCode = json.optInt("versionCode"),
            versionName = json.optString("versionName"),
            url = json.optString("url"),
            sha256 = json.optString("sha256"),
        )
    }.getOrNull()

    private fun download(url: String): File? = runCatching {
        val bytes = httpGet(url, maxBytes = MAX_APK_BYTES) ?: return null
        val out = File.createTempFile("rmg-mgr", ".apk")
        out.writeBytes(bytes)
        out
    }.getOrNull()

    /**
     * GET with manual redirect handling (release assets 302 to the download
     * CDN) — every hop is constrained to GitHub hosts so a captive-portal
     * or hijacked redirect cannot re-point the manager APK elsewhere.
     */
    private fun httpGet(rawUrl: String, maxBytes: Int): ByteArray? {
        var url = rawUrl
        repeat(5) {
            val connection = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000
                readTimeout = 120_000
                instanceFollowRedirects = false
                setRequestProperty("User-Agent", "S25URoot/${BuildConfig.VERSION_NAME}")
            }
            connection.connect()
            val code = connection.responseCode
            if (code in 300..399) {
                val location = connection.getHeaderField("Location") ?: return null
                connection.disconnect()
                val next = URL(URL(url), location).toString()
                require(
                    next.startsWith("https://github.com/") ||
                        next.startsWith("https://objects.githubusercontent.com/") ||
                        next.startsWith("https://release-assets.githubusercontent.com/") ||
                        next.startsWith("https://raw.githubusercontent.com/")
                ) { "redirect to untrusted host" }
                url = next
                return@repeat
            }
            if (code != HttpURLConnection.HTTP_OK) {
                connection.disconnect()
                return null
            }
            val bytes = connection.inputStream.use { input ->
                val buffer = ByteArray(64 * 1024)
                var total = 0
                val out = java.io.ByteArrayOutputStream()
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    total += n
                    if (total > maxBytes) return null
                    out.write(buffer, 0, n)
                }
                out.toByteArray()
            }
            connection.disconnect()
            return bytes
        }
        return null
    }
}
