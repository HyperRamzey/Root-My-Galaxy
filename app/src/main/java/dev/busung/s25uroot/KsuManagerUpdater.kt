package dev.busung.s25uroot

import android.content.Context
import android.os.Build
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

/**
 * Mainline KernelSU manager install/update, driven over root shell.
 *
 * The payload's KernelSU module is built with the upstream manager-signature
 * pin (KSU_EXPECTED_HASH/SIZE = the official KernelSU release certificate),
 * so the mainline manager APK from tiann/KernelSU is exactly what the kernel
 * crowns as manager. No spoofed identity, no registry, no rotation:
 * presence and version are resolved with `pm` through the root shell (the
 * manager may be hidden from the app domain by KSU itself). Runs after the
 * exploit lands and before module activation so the manager UI exists while
 * modules mount.
 */
object KsuManagerUpdater {

    private const val MANAGER_PACKAGE = "me.weishu.kernelsu"
    private const val FEED_URL =
        "https://api.github.com/repos/tiann/KernelSU/releases/latest"
    private const val REMOTE_APK = "/data/local/tmp/.rmg-mgr.apk"
    private const val MAX_FEED_BYTES = 64 * 1024
    private const val MAX_APK_BYTES = 128 * 1024 * 1024

    /* Leftovers from the removed spoofed-manager machinery. Cleaned up
     * best-effort on every run so devices converge to the mainline-only
     * state; nothing reads or writes these anymore. */
    private const val LEGACY_REGISTRY = "/data/adb/.rmg/ksumgr"
    private const val LEGACY_PREF = "spoofed_manager"

    private data class Release(
        val versionCode: Int,
        val versionName: String,
        val url: String,
    )

    /**
     * Ensures the mainline KernelSU manager is installed and current.
     * Returns a one-line report for the run log; throws only on unexpected
     * pipeline-level failures (callers wrap this in runCatching anyway).
     */
    fun ensureInstalled(adb: WirelessAdbSession, context: Context? = null): String {
        cleanLegacyState(adb, context)

        val release = fetchRelease() ?: return "manager feed unavailable"
        val installed = installedVersionCode(adb)
        if (installed > 0 && release.versionCode > 0 &&
            installed >= release.versionCode
        ) {
            return "manager up-to-date ($MANAGER_PACKAGE versionCode=$installed)"
        }

        // Download through the app network, install via root shell.
        val apk = download(release.url) ?: return "manager download failed"
        try {
            if (apk.length() > MAX_APK_BYTES) return "manager download too large"
            var feedVersionCode = release.versionCode
            if (feedVersionCode == 0 && context != null) {
                feedVersionCode = archiveVersionCode(context, apk)
            }
            // Re-check now that the real versionCode is known: the asset
            // name may not have carried one.
            if (installed > 0 && feedVersionCode > 0 && installed >= feedVersionCode) {
                return "manager up-to-date ($MANAGER_PACKAGE versionCode=$installed)"
            }
            runCatching { adb.shell("su -c 'rm -f $REMOTE_APK'") }
            adb.push(apk, REMOTE_APK)
            val install = adb.shell(
                "su -c 'pm install -r $REMOTE_APK " +
                    "> /data/local/tmp/.rmg-install.log 2>&1; exit \$?'"
            )
            val installLog = adb.shell(
                "cat /data/local/tmp/.rmg-install.log 2>/dev/null"
            ).output.trim()
            if (install.exitCode != 0) {
                return "manager install failed (exit ${install.exitCode}): " +
                    installLog.takeLast(160).ifEmpty { install.output.trim().takeLast(120) }
            }
            val verify = installedVersionCode(adb)
            if (verify <= 0) {
                return "manager install unverified (pm path empty after install)"
            }
            return "manager installed ${release.versionName}($verify)"
        } finally {
            apk.delete()
            runCatching { adb.shell("su -c 'rm -f $REMOTE_APK'") }
        }
    }

    /** Version code of the installed mainline manager, 0 when absent. */
    fun installedVersionCode(adb: WirelessAdbSession): Int {
        val pmPath = adb.shell("su -c 'pm path $MANAGER_PACKAGE 2>/dev/null'")
            .output.trim()
        if (pmPath.isEmpty()) return 0
        // grep runs on-device — a full dumpsys dump would blow the ADB
        // response size limit.
        val dump = adb.shell(
            "su -c 'dumpsys package $MANAGER_PACKAGE 2>/dev/null | grep -m1 versionCode'"
        ).output
        return Regex("versionCode=(\\d+)").find(dump)?.groupValues?.get(1)
            ?.toIntOrNull() ?: 0
    }

    /** Best-effort removal of the removed spoofed-manager machinery. */
    private fun cleanLegacyState(adb: WirelessAdbSession, context: Context?) {
        runCatching { adb.shell("su -c 'rm -f $LEGACY_REGISTRY'") }
        if (context != null) {
            runCatching {
                context.getSharedPreferences(LEGACY_PREF, Context.MODE_PRIVATE)
                    .edit().clear().apply()
            }
        }
    }

    private fun archiveVersionCode(context: Context, apk: File): Int {
        val info = runCatching {
            context.packageManager.getPackageArchiveInfo(apk.absolutePath, 0)
        }.getOrNull() ?: return 0
        return if (Build.VERSION.SDK_INT >= 28) {
            info.longVersionCode.toInt()
        } else {
            @Suppress("DEPRECATION") info.versionCode
        }
    }

    /**
     * Latest official tiann/KernelSU release. The manager asset is named
     * KernelSU_v<version>_<versionCode>-release.apk, which carries the
     * versionCode without needing to download and parse the APK first.
     */
    private fun fetchRelease(): Release? = runCatching {
        val text = httpGet(FEED_URL, maxBytes = MAX_FEED_BYTES)
            ?.toString(Charsets.UTF_8) ?: return null
        val json = JSONObject(text)
        val assets = json.optJSONArray("assets") ?: return null
        var apkName: String? = null
        var apkUrl: String? = null
        for (i in 0 until assets.length()) {
            val a = assets.optJSONObject(i) ?: continue
            val name = a.optString("name")
            if (name.endsWith(".apk", ignoreCase = true)) {
                apkName = name
                apkUrl = a.optString("browser_download_url")
                break
            }
        }
        if (apkUrl.isNullOrEmpty()) return null
        val tag = json.optString("tag_name", json.optString("name"))
        val versionCode = Regex("_(\\d+)-release\\.apk", RegexOption.IGNORE_CASE)
            .find(apkName.orEmpty())?.groupValues?.get(1)?.toIntOrNull() ?: 0
        Release(versionCode = versionCode, versionName = tag, url = apkUrl)
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
