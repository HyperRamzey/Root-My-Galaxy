package dev.busung.s25uroot

import org.json.JSONArray
import org.json.JSONObject

data class RemoteArtifact(
    val url: String,
    val size: Long,
)

data class TargetProfile(
    val profileId: String,
    val displayName: String,
    val models: Set<String>,
    val kernelVersions: Set<String>,
    val exploit: RemoteArtifact,
    val kernelSu: RemoteArtifact,
    val rootHelper: RemoteArtifact? = null,
    val slideSource: String? = null,
    /**
     * Optional firmware pins, normalised to upper case. A single entry is a
     * HARD pin: that payload is for exactly that firmware and is rejected
     * elsewhere. Two entries mean the payload is known-good on both and is
     * merely *allowed* on the non-primary one.
     *
     * Empty (the default) means the profile expresses no firmware opinion and
     * matching stays on model+kernel, which is what every pre-firmware feed
     * entry means.
     */
    val firmwareVersions: Set<String> = emptySet(),
) {
    init {
        require(models.isNotEmpty()) { "Payload must support at least one model" }
        require(kernelVersions.isNotEmpty()) { "Payload must support at least one kernel version" }
    }

    fun matchesDevice(snapshot: DeviceSnapshot): Boolean =
        models.any { it.equals(snapshot.model, ignoreCase = true) }

    fun matchesKernelVersion(snapshot: DeviceSnapshot): Boolean =
        snapshot.kernelVersion in kernelVersions

    /**
     * Firmware pin gate. Unlike model and kernel this is deliberately
     * three-state: [firmware] is null whenever the feed has no opinion about
     * this device — a blank or non-canonical fingerprint, or a build token no
     * feed entry claims. Null passes rather than fails, so an unrecognised
     * build still resolves to something instead of showing an empty catalog.
     *
     * A *listed* firmware that this profile does not claim is a hard reject
     * (the known-bad pairing). The "no opinion" resolution happens once, in
     * [PayloadRepository.effectiveFirmware], which needs the whole feed to
     * tell "unclaimed" apart from "claimed by a different profile".
     */
    fun matchesFirmware(firmware: String?): Boolean {
        if (firmwareVersions.isEmpty()) return true
        if (firmware == null) return true
        return firmwareVersions.any { it.equals(firmware, ignoreCase = true) }
    }

    fun matchesFirmware(snapshot: DeviceSnapshot): Boolean = matchesFirmware(snapshot.firmware)

    /**
     * @param firmware the feed-resolved firmware, or null for no opinion.
     *   Defaults to the raw [DeviceSnapshot.firmware], i.e. the strict
     *   per-profile read with no feed context; every real call site resolves
     *   it through [PayloadRepository.effectiveFirmware] first.
     */
    fun matches(snapshot: DeviceSnapshot, firmware: String? = snapshot.firmware): Boolean =
        matchesDevice(snapshot) && matchesKernelVersion(snapshot) && matchesFirmware(firmware)

    /**
     * How tightly this profile is pinned to the device's firmware; higher wins
     * during auto-selection. See PayloadRepository.selectTarget().
     *
     * - 2 = exact single-firmware pin: this is the payload the device's own
     *   firmware *requires* (GZE5 device -> the GZE5 payload).
     * - 1 = allowed but not required: the device's firmware is one of several
     *   this payload supports (GZE5 device -> the GZH2 payload).
     * - 0 = no usable opinion, either because the profile is unconstrained or
     *   because the device's firmware is unknown. All 0s tie, so feed order
     *   decides exactly as it did before firmware matching existed.
     */
    fun firmwareMatchRank(firmware: String?): Int {
        if (firmwareVersions.isEmpty()) return 0
        if (firmware == null) return 0
        val listed = firmwareVersions.any { it.equals(firmware, ignoreCase = true) }
        if (!listed) return 0
        return if (firmwareVersions.size == 1) PIN_EXACT else PIN_ALLOWED
    }

    fun firmwareMatchRank(snapshot: DeviceSnapshot): Int = firmwareMatchRank(snapshot.firmware)

    val supportedModels: String
        get() = models.joinToString()

    val supportedKernelVersions: String
        get() = kernelVersions.joinToString()

    val supportedFirmwareVersions: String
        get() = firmwareVersions.joinToString()

    private companion object {
        const val PIN_EXACT = 2
        const val PIN_ALLOWED = 1
    }
}

data class SupportManifest(
    val schemaVersion: Int,
    val targets: List<TargetProfile>,
) {
    companion object {
        fun parse(bytes: ByteArray): SupportManifest {
            val root = JSONObject(bytes.toString(Charsets.UTF_8))
            val schemaVersion = root.getInt("schemaVersion")
            require(schemaVersion == 3) { "Unsupported support manifest schema" }
            val payloadsJson = root.getJSONArray("payloads")
            val payloads = buildList {
                for (index in 0 until payloadsJson.length()) {
                    val payload = payloadsJson.getJSONObject(index)
                    val exploit = payload.getJSONObject("exploit")
                    val kernelSu = payload.getJSONObject("kernelsu")
                    add(
                        TargetProfile(
                            profileId = payload.getString("payloadId"),
                            displayName = payload.getString("displayName"),
                            models = payload.getJSONArray("models").strings(),
                            kernelVersions = payload.getJSONArray("kernelVersions").strings(),
                            exploit = RemoteArtifact(
                                url = exploit.getString("url"),
                                size = exploit.getLong("size"),
                            ),
                            kernelSu = RemoteArtifact(
                                url = kernelSu.getString("url"),
                                size = kernelSu.getLong("size"),
                            ),
                            rootHelper = payload.optJSONObject("rootHelper")?.let {
                                RemoteArtifact(
                                    url = it.getString("url"),
                                    size = it.getLong("size"),
                                )
                            },
                            slideSource = payload.optString("slideSource", "").takeIf(String::isNotBlank),
                            // Optional since schema v3 shipped: absent in
                            // every pre-firmware entry and in the payload's
                            // own feed reader, which is why it must stay
                            // additive rather than bump the schema.
                            firmwareVersions = payload.optJSONArray("firmwareVersions")
                                ?.strings()
                                ?.mapTo(mutableSetOf<String>()) { it.trim().uppercase() }
                                ?: emptySet(),
                        ),
                    )
                }
            }
            return SupportManifest(schemaVersion, payloads)
        }

        private fun JSONArray.strings(): Set<String> = buildSet {
            for (index in 0 until length()) add(getString(index))
        }
    }
}
