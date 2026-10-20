package dev.busung.s25uroot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Guards the F946BXXU7HZIJ (One UI 9 / kernel 5.15.194) feed entry.
 *
 * HZIJ is the first Fold5 build on 5.15.194, so the kernel version already
 * separates it from GZE5/GZH2 (5.15.189). The firmware pin is still exercised
 * because it is what turns the build into a claimed firmware: without it a
 * hypothetical 5.15.194 device on another build would silently fall through
 * to HZIJ offsets.
 */
class HzijSelectionTest {
    private val gze5 = profile("f946b-F946BXXS7GZE5", "5.15.189", setOf("F946BXXS7GZE5"))
    private val gzh2 = profile(
        "f946b-F946BXXS7GZH2",
        "5.15.189",
        setOf("F946BXXS7GZH2", "F946BXXS7GZE5"),
    )
    private val hzij = profile("f946b-F946BXXU7HZIJ", "5.15.194", setOf("F946BXXU7HZIJ"))

    /** Real feed order: the older builds come first, HZIJ is appended last. */
    private val feed = listOf(gze5, gzh2, hzij)

    @Test
    fun hzijDeviceAutoSelectsTheHzijPayload() {
        assertEquals(
            "f946b-F946BXXU7HZIJ",
            selectedFor(kernel = "5.15.194", fingerprint = FINGERPRINT_HZIJ),
        )
    }

    @Test
    fun hzijProfileIsNotSelectableOnGzh2() {
        assertFalse(hzij.matches(snapshot("5.15.189", FINGERPRINT_GZH2), "F946BXXS7GZH2"))
    }

    @Test
    fun hzijProfileIsNotSelectableOnGze5() {
        assertFalse(hzij.matches(snapshot("5.15.189", FINGERPRINT_GZE5), "F946BXXS7GZE5"))
    }

    @Test
    fun hzijProfileRequiresTheHzijKernel() {
        // A HZIJ-firmware device reporting the old 5.15.189 kernel must not get
        // a payload built for 5.15.194 offsets.
        assertFalse(hzij.matches(snapshot("5.15.189", FINGERPRINT_HZIJ), "F946BXXU7HZIJ"))
        assertNull(
            PayloadRepository.selectTargetFor(
                listOf(hzij),
                snapshot("5.15.189", FINGERPRINT_HZIJ),
            ),
        )
    }

    @Test
    fun olderDevicesKeepTheirOwnPayloads() {
        assertEquals("f946b-F946BXXS7GZE5", selectedFor("5.15.189", FINGERPRINT_GZE5))
        assertEquals("f946b-F946BXXS7GZH2", selectedFor("5.15.189", FINGERPRINT_GZH2))
    }

    /**
     * The boot service's jniLibs fallback must resolve HZIJ's own runner and
     * payload. A name drift here silently re-introduces the generic GZE5
     * helper on a device whose offsets are 5.15.194-specific.
     */
    @Test
    fun hzijBundledFallbackUsesProfileQualifiedLibNames() {
        assertEquals(
            "libcve43499root-f946b-F946BXXU7HZIJ.so",
            ExploitStaging.bundledHelperName("f946b-F946BXXU7HZIJ"),
        )
        assertEquals(
            "libcve43499app-f946b-F946BXXU7HZIJ.so",
            ExploitStaging.bundledPayloadName("f946b-F946BXXU7HZIJ"),
        )
    }

    @Test
    fun hzijClaimMakesTheFirmwareKnownToTheFeed() {
        // The HZIJ entry is what turns F946BXXU7HZIJ into a claimed firmware;
        // without it the pin is inert and only the kernel separates profiles.
        assertEquals(
            "F946BXXU7HZIJ",
            PayloadRepository.effectiveFirmware(feed, snapshot("5.15.194", FINGERPRINT_HZIJ)),
        )
        assertNull(
            PayloadRepository.effectiveFirmware(feed, snapshot("5.15.194", FINGERPRINT_UNCLAIMED)),
        )
    }

    private fun selectedFor(kernel: String, fingerprint: String): String? =
        PayloadRepository.selectTargetFor(feed, snapshot(kernel, fingerprint))?.profileId

    private fun snapshot(kernel: String, fingerprint: String) = DeviceSnapshot(
        manufacturer = "samsung",
        model = "SM-F946B",
        device = "f946b",
        kernelRelease = "$kernel-android13-8-34343818-abF946BXXU7HZIJ",
        kernelVersionInfo = "#1 SMP PREEMPT",
        machine = "aarch64",
        buildId = "CP2A.260605.016",
        fingerprint = fingerprint,
        androidRelease = if (kernel == "5.15.194") "17" else "16",
        sdk = if (kernel == "5.15.194") 37 else 36,
        abi = "arm64-v8a",
        pageSize = 4096,
    )

    private fun profile(profileId: String, kernel: String, firmwareVersions: Set<String>) =
        TargetProfile(
            profileId = profileId,
            displayName = profileId,
            models = setOf("SM-F946B"),
            kernelVersions = setOf(kernel),
            exploit = RemoteArtifact("https://example.invalid/$profileId/exploit", 1),
            kernelSu = RemoteArtifact("https://example.invalid/$profileId/ksud", 1),
            firmwareVersions = firmwareVersions,
        )

    private companion object {
        const val FINGERPRINT_GZE5 =
            "samsung/f946b/f946b:16/BP4A.251205.006/F946BXXS7GZE5:user/release-keys"
        const val FINGERPRINT_GZH2 =
            "samsung/f946b/f946b:16/BP4A.251205.006/F946BXXS7GZH2:user/release-keys"
        const val FINGERPRINT_HZIJ =
            "samsung/q5qxxx/q5q:17/CP2A.260605.016/F946BXXU7HZIJ:user/release-keys"
        const val FINGERPRINT_UNCLAIMED =
            "samsung/q5qxxx/q5q:17/CP2A.260605.016/F946BXXU7HZW1:user/release-keys"
    }
}
