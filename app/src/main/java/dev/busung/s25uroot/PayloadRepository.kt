package dev.busung.s25uroot

import android.content.Context
import android.system.Os
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
    val rootHelper: File? = null,
)

class PayloadRepository(private val context: Context) {
    fun loadTargets(): List<TargetProfile> {
        val commit = resolveMainCommit()
        val manifestBytes = downloadBytes(rawUrl(commit, "support/targets-v3.json"), MAX_MANIFEST_BYTES)
        // Persist for offline fallback (see resolveTarget(allowCached)).
        runCatching { File(context.filesDir, MANIFEST_CACHE).writeBytes(manifestBytes) }
        return SupportManifest.parse(manifestBytes).targets.map { profile -> profile.copy(
            exploit = profile.exploit.copy(url = pinArtifactUrl(profile.exploit.url, commit)),
            kernelSu = profile.kernelSu.copy(url = pinArtifactUrl(profile.kernelSu.url, commit)),
            rootHelper = profile.rootHelper?.copy(url = pinArtifactUrl(profile.rootHelper.url, commit)),
        ) }
    }

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile = resolveTarget(snapshot, allowCached = false)

    /**
     * Resolves the target profile against the live feed, falling back to the
     * last successfully downloaded manifest when the network is unavailable
     * (GitHub API intermittently returns 504 in the first minutes after
     * boot). Without this, a transient API outage would abort root-on-boot
     * even though a valid payload cache exists locally.
     */
    fun resolveTarget(snapshot: DeviceSnapshot, allowCached: Boolean): TargetProfile {
        try {
            val profile = loadTargets().firstOrNull { it.matches(snapshot) }
            if (profile != null) {
                runCatching { cacheManifest() }
                return profile
            }
        } catch (e: Exception) {
            if (!allowCached) throw e
            val cached = loadTargetsFromCache()?.firstOrNull { it.matches(snapshot) }
            if (cached != null) return cached
            throw e
        }
        error(context.getString(R.string.repo_no_profile))
    }

    private fun cacheManifest() {
        val bytes = downloadBytes(rawUrl(resolveMainCommit(), MANIFEST_PATH), MAX_MANIFEST_BYTES)
        File(context.filesDir, MANIFEST_CACHE).writeBytes(bytes)
    }

    private fun loadTargetsFromCache(): List<TargetProfile>? = runCatching {
        val file = File(context.filesDir, MANIFEST_CACHE)
        if (!file.exists()) return null
        // Offline fallback: serve the last good manifest as-is. The boot
        // path only needs sizes + file names from it; any refresh download
        // will re-pin to a live commit once the network is back.
        SupportManifest.parse(file.readBytes()).targets
    }.getOrNull()

    fun resolveTarget(profileId: String): TargetProfile = loadTargets()
        .firstOrNull { it.profileId == profileId }
        ?: error(context.getString(R.string.repo_profile_missing, profileId))

    fun download(profile: TargetProfile, onProgress: (String) -> Unit): VerifiedPayloads {
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
        val exploit = downloadArtifact(
            profile.exploit,
            File(directory, "cve-2026-43499-app.so"),
            context.getString(R.string.artifact_exploit),
            onProgress,
        )
        val kernelSu = downloadArtifact(
            profile.kernelSu,
            File(directory, remoteFileName(profile.kernelSu.url)),
            context.getString(R.string.artifact_kernelsu),
            onProgress,
        )
        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        val rootHelper = profile.rootHelper?.let { helper ->
            val file = downloadArtifact(
                helper,
                File(directory, "cve-2026-43499-root"),
                context.getString(R.string.artifact_exploit),
                onProgress,
            )
            Os.chmod(file.absolutePath, 0b100100100)
            file
        }
        return VerifiedPayloads(profile, exploit, kernelSu, rootHelper)
    }

    private fun downloadArtifact(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        onProgress(context.getString(R.string.repo_downloading, label))
        val temporary = File(destination.parentFile, "${destination.name}.part")
        val connection = open(artifact.url)
        require(connection.contentLengthLong == -1L || connection.contentLengthLong == artifact.size) {
            context.getString(R.string.repo_size_mismatch, label)
        }
        var total = 0L
        connection.inputStream.use { input ->
            FileOutputStream(temporary).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= artifact.size) {
                        context.getString(R.string.repo_size_exceeded, label)
                    }
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
            }
        }
        connection.disconnect()
        require(total == artifact.size) { context.getString(R.string.repo_incomplete, label) }
        if (destination.exists()) destination.delete()
        require(temporary.renameTo(destination)) {
            context.getString(R.string.repo_finalize_failed, label)
        }
        onProgress(context.getString(R.string.repo_verified, label))
        return destination
    }

    private fun resolveMainCommit(): String {
        val response = downloadBytes(COMMIT_API_URL, MAX_COMMIT_RESPONSE_BYTES)
        val commit = JSONObject(response.toString(Charsets.UTF_8))
            .getJSONObject("object")
            .getString("sha")
        require(commit.matches(Regex("[0-9a-f]{40}"))) { context.getString(R.string.repo_commit_invalid) }
        return commit
    }

    private fun rawUrl(commit: String, path: String) = "$RAW_REPOSITORY/$commit/$path"

    private fun remoteFileName(url: String) = url.substringAfterLast('/')

    private fun pinArtifactUrl(url: String, commit: String): String {
        require(url.startsWith(MUTABLE_RAW_PREFIX)) { context.getString(R.string.repo_url_invalid) }
        return "$RAW_REPOSITORY/$commit/${url.removePrefix(MUTABLE_RAW_PREFIX)}"
    }

    private fun downloadBytes(url: String, maximum: Int): ByteArray {
        val connection = open(url)
        val bytes = connection.inputStream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) {
                    context.getString(R.string.repo_response_too_large)
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        connection.disconnect()
        return bytes
    }

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            // Never follow redirects: a 302 (captive portal, repo transfer)
            // would silently re-point a commit-pinned URL at an arbitrary
            // host, leaving size equality as the only integrity check.
            instanceFollowRedirects = false
            setRequestProperty("User-Agent", "S25URoot/${BuildConfig.VERSION_NAME}")
            connect()
            require(responseCode == HttpURLConnection.HTTP_OK) { "HTTP $responseCode" }
        }

    companion object {
        private const val COMMIT_API_URL =
            "https://api.github.com/repos/HyperRamzey/Root-My-Galaxy-Payloads/git/ref/heads/main"
        private const val RAW_REPOSITORY =
            "https://raw.githubusercontent.com/HyperRamzey/Root-My-Galaxy-Payloads"
        private const val MUTABLE_RAW_PREFIX = "$RAW_REPOSITORY/main/"
        private const val MANIFEST_PATH = "support/targets-v3.json"
        private const val MANIFEST_CACHE = "payloads/targets-cache.json"
        private const val MAX_COMMIT_RESPONSE_BYTES = 16 * 1024
        private const val MAX_MANIFEST_BYTES = 256 * 1024
    }
}
