package dev.busung.s25uroot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the required/optional firmware policy as the two feed entries plus a
 * device see it. The hazard these guard: both firmwares report kernel
 * 5.15.189, so before firmware pins existed a GZH2 device auto-selected the
 * GZE5 payload.
 */
class SelectTargetForTest {
    private val gze5 = profile("f946b-F946BXXS7GZE5", setOf("F946BXXS7GZE5"))
    private val gzh2 = profile("f946b-F946BXXS7GZH2", setOf("F946BXXS7GZH2", "F946BXXS7GZE5"))

    /** Real feed order puts the GZE5 entry first. */
    private val feed = listOf(gze5, gzh2)

    @Test
    fun gze5DeviceAutoSelectsTheGze5Payload() {
        assertEquals("f946b-F946BXXS7GZE5", selectedFor(firmware = "F946BXXS7GZE5"))
    }

    /**
     * Feed order alone would pick GZE5 here, since it comes first. Firmware
     * pinning is what forces GZH2.
     */
    @Test
    fun gzh2DeviceAutoSelectsTheGzh2Payload() {
        assertEquals("f946b-F946BXXS7GZH2", selectedFor(firmware = "F946BXXS7GZH2"))
    }

    /** The GZE5 payload is rejected on GZH2 even though it is listed first. */
    @Test
    fun gze5PayloadIsNotSelectableOnGzh2() {
        assertFalse(gze5.matches(snapshot(fingerprint = FINGERPRINT_GZH2)))
    }

    /** GZH2 stays reachable by hand on a GZE5 device — allowed, not required. */
    @Test
    fun gzh2PayloadStaysAllowedOnGze5() {
        assertTrue(gzh2.matches(snapshot(fingerprint = FINGERPRINT_GZE5)))
    }

    /**
     * An unrecognised build must still resolve. With no usable firmware every
     * profile ranks 0, so feed order decides — today's model+kernel behaviour,
     * not a hard failure and not an empty catalog.
     */
    @Test
    fun unknownFirmwareFallsBackToFeedOrder() {
        assertEquals("f946b-F946BXXS7GZE5", selectedFor(fingerprint = "samsung/example"))
        assertEquals("f946b-F946BXXS7GZE5", selectedFor(fingerprint = ""))
    }

    @Test
    fun feedWithoutFirmwarePinsIsUnchanged() {
        val legacy = listOf(
            profile("a", emptySet()),
            profile("b", emptySet()),
        )
        assertEquals(
            "a",
            PayloadRepository.selectTargetFor(
                legacy,
                snapshot(fingerprint = FINGERPRINT_GZH2),
            )?.profileId,
        )
    }

    @Test
    fun returnsNullWhenNothingMatches() {
        val other = profile("f946b-other", setOf("F946BXXS7GZE5"))
        assertNull(
            PayloadRepository.selectTargetFor(
                listOf(other),
                snapshot(model = "SM-S928B"),
            ),
        )
    }

    /**
     * A firmware no feed entry claims is "unrecognised", not "known-bad". The
     * gate must not fail closed on it alone — model+kernel still resolves it,
     * so a device on a build we have never seen is not bricked.
     */
    @Test
    fun unclaimedFirmwareFallsBackInsteadOfFailingClosed() {
        assertEquals("f946b-F946BXXS7GZE5", selectedFor(firmware = "F946BXXS7GZW1"))
    }

    @Test
    fun effectiveFirmwareIsNullUnlessTheFeedClaimsIt() {
        assertEquals(
            "F946BXXS7GZH2",
            PayloadRepository.effectiveFirmware(feed, snapshot(fingerprint = FINGERPRINT_GZH2)),
        )
        assertNull(
            PayloadRepository.effectiveFirmware(feed, snapshot(fingerprint = FINGERPRINT_UNCLAIMED)),
        )
        assertNull(
            PayloadRepository.effectiveFirmware(feed, snapshot(fingerprint = "")),
        )
    }

    /**
     * Documents the feed-side dependency rather than endorsing it: the claim
     * set is what makes the rejection possible, so a feed that has never
     * heard of `F946BXXS7GZH2` cannot tell it from an unrecognised build.
     * `support/targets-v3.json` must ship the GZH2 entry for the app-side gate
     * to reject anything.
     */
    @Test
    fun gze5OnlyFeedCannotDetectAGzh2Device() {
        assertEquals(
            "f946b-F946BXXS7GZE5",
            PayloadRepository.selectTargetFor(
                listOf(gze5),
                snapshot(fingerprint = FINGERPRINT_GZH2),
            )?.profileId,
        )
    }

    @Test
    fun unmatchedKernelStillFiltersOut() {
        val otherKernel = TargetProfile(
            profileId = "f946b-kernel-other",
            displayName = "other kernel",
            models = setOf("SM-F946B"),
            kernelVersions = setOf("6.1.75"),
            exploit = RemoteArtifact("https://example.invalid/exploit", 1),
            kernelSu = RemoteArtifact("https://example.invalid/ksud", 1),
            firmwareVersions = setOf("F946BXXS7GZH2"),
        )
        assertNull(PayloadRepository.selectTargetFor(listOf(otherKernel), snapshot()))
    }

    private fun selectedFor(
        model: String = "SM-F946B",
        firmware: String? = null,
        fingerprint: String = if (firmware == null) {
            "samsung/example"
        } else {
            "samsung/f946b/f946b:16/BP4A.251205.006/$firmware:user/release-keys"
        },
    ): String? = PayloadRepository.selectTargetFor(feed, snapshot(model, fingerprint))?.profileId

    private fun snapshot(
        model: String = "SM-F946B",
        fingerprint: String = FINGERPRINT_GZE5,
    ) = DeviceSnapshot(
        manufacturer = "samsung",
        model = model,
        device = "f946b",
        kernelRelease = "5.15.189-android15-8",
        kernelVersionInfo = "#1 SMP PREEMPT",
        machine = "aarch64",
        buildId = "BP4A.251205.006.SMFB1U1",
        fingerprint = fingerprint,
        androidRelease = "16",
        sdk = 36,
        abi = "arm64-v8a",
        pageSize = 4096,
    )

    private fun profile(
        profileId: String,
        firmwareVersions: Set<String>,
    ) = TargetProfile(
        profileId = profileId,
        displayName = profileId,
        models = setOf("SM-F946B"),
        kernelVersions = setOf("5.15.189"),
        exploit = RemoteArtifact("https://example.invalid/$profileId/exploit", 1),
        kernelSu = RemoteArtifact("https://example.invalid/$profileId/ksud", 1),
        firmwareVersions = firmwareVersions,
    )

    private companion object {
        const val FINGERPRINT_GZE5 =
            "samsung/f946b/f946b:16/BP4A.251205.006/F946BXXS7GZE5:user/release-keys"
        const val FINGERPRINT_GZH2 =
            "samsung/f946b/f946b:16/BP4A.251205.006/F946BXXS7GZH2:user/release-keys"
        // A real-looking build that NO feed entry claims. The feed's claim set is what
        // distinguishes "unknown firmware, no opinion" from "known-bad pairing", so this
        // must be exercised through the fingerprint (the only source of firmware), not by
        // injecting a firmware value the snapshot type does not carry.
        const val FINGERPRINT_UNCLAIMED =
            "samsung/f946b/f946b:16/BP4A.251205.006/F946BXXS7GZW1:user/release-keys"
    }
}
