package dev.busung.s25uroot

import android.content.Context
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

    // Pull the OFFICIAL KernelSU manager so the crown's
    // EXPECTED_HASH (c371...) matches — the pipeline's keystore never did.
    private const val FEED_URL =
        "https://api.github.com/repos/tiann/KernelSU/releases/latest"
    private const val REGISTRY = "/data/adb/.rmg/ksumgr"
    private const val REMOTE_APK = "/data/local/tmp/.rmg-mgr.apk"
    private const val BACKUP_PREF = "spoofed_manager"
    private const val BACKUP_KEY = "registry"
    private const val MAX_FEED_BYTES = 64 * 1024
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
    fun ensureInstalled(adb: WirelessAdbSession, context: Context? = null): String {
        val feed = fetchFeed() ?: return "feed unavailable"
        if (feed.pkg.isEmpty() || feed.versionCode <= 0) return "feed malformed"

        // Detection via root shell: registry first, then a live pm probe.
        // The registry is dual-recorded (root file + app-private prefs):
        // if the root file is lost (module wipes, /data/adb resets), the
        // backup still remembers the old spoofed id so rotation can
        // uninstall it instead of orphaning a second manager.
        val registry = adb.shell("su -c 'cat $REGISTRY 2>/dev/null'").output.trim()
            .ifEmpty {
                context?.getSharedPreferences(BACKUP_PREF, Context.MODE_PRIVATE)
                    ?.getString(BACKUP_KEY, null)
            }
            .orEmpty()
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
        // Up-to-date requires BOTH the version and the current spoof id:
        // per-run identities can reuse the upstream versionCode, and an
        // id change must rotate even when the version matches.
        if (installed >= feed.versionCode && pkg == feed.pkg) {
            return "up-to-date ($installed)"
        }

        // Spoof-id rotation: a registry package that differs from the
        // feed's current id is an older-generation build — remove it and
        // VERIFY removal before installing the new one, otherwise a failed
        // uninstall would leave two managers on the device.
        if (pkg != feed.pkg && pmPath.isNotEmpty()) {
            adb.shell("su -c 'pm uninstall $pkg'")
            val gone = adb.shell("su -c 'pm path $pkg 2>/dev/null'").output.trim().isEmpty()
            if (!gone) return "rotation blocked: old $pkg uninstall failed"
            installed = 0
        }

        // Download through the app network, verify, install via root shell.
        var feedEffective = feed
        val apk = download(feed.url) ?: return "download failed"
        try {
            if (apk.length() > MAX_APK_BYTES) return "download too large"
            // Official feed has no versionCode — resolve it from the APK itself.
            if (feedEffective.versionCode == 0 && context != null) {
                val info = runCatching {
                    context.packageManager.getPackageArchiveInfo(apk.absolutePath, 0)
                }.getOrNull()
                val vc = if (Build.VERSION.SDK_INT >= 28) {
                    info?.longVersionCode?.toInt() ?: 0
                } else {
                    @Suppress("DEPRECATION") info?.versionCode ?: 0
                }
                if (vc > 0) feedEffective = feedEffective.copy(versionCode = vc)
            }
            // Re-check up-to-date now that we know the real versionCode (official case).
            if (installed >= feedEffective.versionCode && pkg == feedEffective.pkg && feedEffective.versionCode != 0) {
                return "up-to-date ($installed)"
            }
            runCatching { adb.shell("su -c 'rm -f $REMOTE_APK'") }
            adb.push(apk, REMOTE_APK)
            if (feedEffective.sha256.isNotEmpty()) {
                val remoteSha = adb.shell("su -c 'sha256sum $REMOTE_APK 2>/dev/null'").output
                    .trim().split(' ').firstOrNull() ?: ""
                if (!remoteSha.equals(feedEffective.sha256, ignoreCase = true)) {
                    return "sha mismatch"
                }
            }
            val install = adb.shell(
                "su -c 'pm install -r $REMOTE_APK " +
                    "> /data/local/tmp/.rmg-install.log 2>&1; exit \$?'"
            )
            val installLog = adb.shell(
                "cat /data/local/tmp/.rmg-install.log 2>/dev/null"
            ).output.trim()
            if (install.exitCode != 0) {
                return "install failed (exit ${install.exitCode}): " +
                    installLog.takeLast(160).ifEmpty { install.output.trim().takeLast(120) }
            }
            adb.shell(
                "su -c 'mkdir -p /data/adb/.rmg; " +
                    "echo \"${feedEffective.versionCode} ${feedEffective.pkg}\" > $REGISTRY'"
            )
            context?.getSharedPreferences(BACKUP_PREF, Context.MODE_PRIVATE)
                ?.edit()
                ?.putString(BACKUP_KEY, "${feedEffective.versionCode} ${feedEffective.pkg}")
                ?.apply()
            return "installed ${feedEffective.versionName}(${feedEffective.versionCode})"
        } finally {
            apk.delete()
            runCatching { adb.shell("su -c 'rm -f $REMOTE_APK'") }
        }
    }

    private fun fetchFeed(): Feed? = runCatching {
        val text = httpGet(FEED_URL, maxBytes = MAX_FEED_BYTES)
            ?.toString(Charsets.UTF_8) ?: return null
        val json = JSONObject(text)
        // Official tiann/KernelSU release has {tag_name, assets:[{name,browser_download_url}]}
        // Fall back to our old feed.json shape (pkg/versionCode/url/sha256) if present.
        if (json.has("assets")) {
            val assets = json.optJSONArray("assets")
            var apkUrl: String? = null
            if (assets != null) {
                for (i in 0 until assets.length()) {
                    val a = assets.optJSONObject(i) ?: continue
                    val name = a.optString("name")
                    if (name.endsWith(".apk", ignoreCase = true)) {
                        apkUrl = a.optString("browser_download_url")
                        if (name.contains("manager", ignoreCase = true)) break
                    }
                }
            }
            if (apkUrl.isNullOrEmpty()) return null
            val tag = json.optString("tag_name", json.optString("name"))
            return Feed(
                pkg = "me.weishu.kernelsu",
                versionCode = 0, // resolved after download via PackageManager
                versionName = tag,
                url = apkUrl,
                sha256 = "",
            )
        }
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
