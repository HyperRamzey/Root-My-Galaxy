package dev.busung.s25uroot

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

data class UpdateInfo(
    val versionName: String,
    val apkUrl: String?,
    val releaseUrl: String,
    /** Declared asset size in bytes (GitHub API), -1 if unknown. */
    val size: Long = -1L,
    /** SHA-256 digest of the asset ("sha256:..." field), null if absent. */
    val sha256: String? = null,
)

const val ROOT_MY_GALAXY_URL = "https://github.com/HyperRamzey/Root-My-Galaxy"

object AppUpdater {

    private const val GITHUB_API = "https://api.github.com/repos/HyperRamzey/Root-My-Galaxy"
    private const val RELEASES_PAGE = "$ROOT_MY_GALAXY_URL/releases/latest"

    suspend fun fetchLatestRelease(): UpdateInfo? = withContext(Dispatchers.IO) {
        try {
            val connection = URL("$GITHUB_API/releases/latest").openConnection() as HttpURLConnection
            try {
                connection.requestMethod = "GET"
                connection.setRequestProperty("User-Agent", "RootMyGalaxy/${BuildConfig.VERSION_NAME}")
                connection.setRequestProperty("Accept", "application/vnd.github+json")
                connection.connectTimeout = 10_000
                connection.readTimeout = 10_000
                if (connection.responseCode != HttpURLConnection.HTTP_OK) return@withContext null
                val body = connection.inputStream.bufferedReader().use { it.readText() }

                val json = JSONObject(body)
                val tag = json.optString("tag_name").trim().removePrefix("v")
                if (tag.isBlank()) return@withContext null
                var apkUrl: String? = null
                var apkSize = -1L
                var apkSha256: String? = null
                json.optJSONArray("assets")?.let { assets ->
                    for (i in 0 until assets.length()) {
                        val asset = assets.getJSONObject(i)
                        if (asset.optString("name").endsWith(".apk")) {
                            apkUrl = asset.optString("browser_download_url").ifEmpty { null }
                            apkSize = if (asset.has("size") && !asset.isNull("size")) {
                                asset.getLong("size")
                            } else -1L
                            // GitHub returns digests like "sha256:abcdef..."
                            apkSha256 = asset.optString("digest")
                                .takeIf { it.startsWith("sha256:") }
                                ?.substringAfter("sha256:")
                            break
                        }
                    }
                }
                UpdateInfo(
                    versionName = tag,
                    apkUrl = apkUrl,
                    releaseUrl = json.optString("html_url").ifEmpty { RELEASES_PAGE },
                    size = apkSize,
                    sha256 = apkSha256,
                )
            } finally {
                connection.disconnect()
            }
        } catch (_: Exception) {
            null
        }
    }

    fun isUpdateAvailable(latestVersion: String, currentVersion: String): Boolean =
        compareVersions(latestVersion, currentVersion) > 0

    /** Numeric X.Y.Z comparison so an older remote tag (e.g. upstream at
     * 0.2.6 while this build is 0.2.9) never triggers a downgrade prompt. */
    private fun compareVersions(a: String, b: String): Int {
        fun parse(v: String): List<Int> =
            v.trim().removePrefix("v").split('.').map { part ->
                part.takeWhile { it.isDigit() }.toIntOrNull() ?: 0
            }
        val left = parse(a)
        val right = parse(b)
        val size = maxOf(left.size, right.size)
        for (i in 0 until size) {
            val l = left.getOrElse(i) { 0 }
            val r = right.getOrElse(i) { 0 }
            if (l != r) return l.compareTo(r)
        }
        return 0
    }

    suspend fun downloadApk(
        context: Context,
        url: String,
        expectedSize: Long = -1L,
        expectedSha256: String? = null,
        onProgress: (Float) -> Unit = {},
    ): File? = withContext(Dispatchers.IO) {
        val dir = File(context.cacheDir, "updates").apply { mkdirs() }
        val target = File(dir, "update.apk")
        try {
            // Never grow a stale file from a previous failed attempt.
            target.delete()
            val connection = URL(url).openConnection() as HttpURLConnection
            try {
                connection.requestMethod = "GET"
                connection.setRequestProperty("User-Agent", "RootMyGalaxy/${BuildConfig.VERSION_NAME}")
                connection.connectTimeout = 15_000
                connection.readTimeout = 30_000
                if (connection.responseCode != HttpURLConnection.HTTP_OK) return@withContext null
                val total = when {
                    expectedSize > 0 -> expectedSize.toInt()
                    else -> connection.contentLength
                }
                val digest = java.security.MessageDigest.getInstance("SHA-256")
                val buffer = ByteArray(64 * 1024)
                var downloaded = 0L
                connection.inputStream.use { input ->
                    target.outputStream().use { output ->
                        while (true) {
                            val read = input.read(buffer)
                            if (read < 0) break
                            output.write(buffer, 0, read)
                            digest.update(buffer, 0, read)
                            downloaded += read
                            if (total > 0) {
                                onProgress((downloaded.toFloat() / total).coerceIn(0f, 1f))
                            }
                        }
                    }
                }
                // Integrity gates: a truncated or corrupted transfer used
                // to reach the system installer and fail as a cryptic
                // "App not installed" (often blamed on Play Protect).
                if (target.length() == 0L) return@withContext null
                if (expectedSize > 0 && target.length() != expectedSize) {
                    android.util.Log.e("AppUpdater",
                        "size mismatch: got ${target.length()} want $expectedSize")
                    target.delete(); return@withContext null
                }
                if (!expectedSha256.isNullOrBlank()) {
                    val actual = digest.digest().joinToString("") { "%02x".format(it) }
                    if (!actual.equals(expectedSha256, ignoreCase = true)) {
                        android.util.Log.e("AppUpdater", "sha256 mismatch: got $actual")
                        target.delete(); return@withContext null
                    }
                }
                target
            } finally {
                connection.disconnect()
            }
        } catch (_: Exception) {
            target.delete()
            null
        }
    }

    fun installApk(context: Context, apk: File): Boolean {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", apk)
        return try {
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(intent)
            true
        } catch (_: ActivityNotFoundException) {
            false
        }
    }

    fun openReleasesPage(context: Context) {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(RELEASES_PAGE)))
    }
}
