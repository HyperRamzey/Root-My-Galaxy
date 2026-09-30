package dev.busung.s25uroot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TargetProfileTest {
    private val profile = TargetProfile(
        profileId = "galaxy-s25-series-kernel-6.6.98",
        displayName = "Galaxy S25 series",
        models = setOf("SM-S931B", "SM-S938N"),
        kernelVersions = setOf("6.6.98"),
        exploit = RemoteArtifact("https://example.invalid/exploit", 1),
        kernelSu = RemoteArtifact("https://example.invalid/ksud", 1),
    )

    @Test
    fun matchesRegionalS25OnSameKernelVersion() {
        assertTrue(profile.matches(snapshot("SM-S931B", "6.6.98-android15-8-build-a")))
        assertTrue(profile.matches(snapshot("SM-S938N", "6.6.98-android15-8-build-b")))
    }

    @Test
    fun rejectsUnlistedModelOrKernelVersion() {
        assertFalse(profile.matches(snapshot("SM-S928B", "6.6.98-android15-8-build")))
        assertFalse(profile.matches(snapshot("SM-S938N", "6.6.102-android15-8-build")))
    }

    /**
     * A profile with no `firmwareVersions` expresses no firmware opinion, so
     * every pre-firmware feed entry keeps matching exactly as before. The
     * fixture fingerprint above is only two segments deep and must therefore
     * not start rejecting anything.
     */
    @Test
    fun profileWithoutFirmwarePinIgnoresFirmware() {
        assertTrue(profile.matchesFirmware(fold(firmware = "F946BXXS7GZE5")))
        assertTrue(profile.matchesFirmware(fold(firmware = "F946BXXS7GZH2")))
        assertTrue(profile.matchesFirmware(fold(firmware = null)))
        assertEquals(0, profile.firmwareMatchRank(fold(firmware = "F946BXXS7GZE5")))
    }

    @Test
    fun extractFirmwareSuffixFromFingerprint() {
        assertEquals(
            "F946BXXS7GZH2",
            fold(firmware = "F946BXXS7GZH2").firmware,
        )
        assertEquals(
            "F946BXXS7GZE5",
            fold(firmware = "F946BXXS7GZE5").firmware,
        )
    }

    /**
     * Regression guard for the obvious mis-parse: `user/release-keys` is the
     * last '/' segment of a real fingerprint, so `substringAfterLast('/')`
     * yields the literal "release-keys" rather than the firmware. Index 4
     * (the `build:user` segment) is the only correct index.
     */
    @Test
    fun doesNotMistakeReleaseKeysTagForFirmware() {
        val snapshot = fold(firmware = "F946BXXS7GZH2")
        assertTrue(snapshot.fingerprint.endsWith(":user/release-keys"))
        assertEquals("F946BXXS7GZH2", snapshot.firmware)
    }

    @Test
    fun treatsOddFingerprintAsUnknownFirmware() {
        assertNull(fold(fingerprint = "").firmware)
        assertNull(fold(fingerprint = "samsung/example").firmware)
        assertNull(fold(fingerprint = "samsung/f946b/f946b:16/BP4A.251205.006").firmware)
    }

    @Test
    fun hardPinnedProfileRejectsOtherFirmware() {
        val pinned = gzh2Only()
        assertTrue(pinned.matchesFirmware(fold(firmware = "F946BXXS7GZH2")))
        assertFalse(pinned.matchesFirmware(fold(firmware = "F946BXXS7GZE5")))
    }

    @Test
    fun unknownFirmwareNeverHardFailsThePin() {
        val pinned = gzh2Only()
        assertTrue(pinned.matchesFirmware(fold(fingerprint = "")))
        assertTrue(pinned.matchesFirmware(fold(fingerprint = "samsung/example")))
    }

    @Test
    fun multiFirmwareProfileIsAllowedOnBoth() {
        val both = gzh2AndGze5()
        assertTrue(both.matchesFirmware(fold(firmware = "F946BXXS7GZH2")))
        assertTrue(both.matchesFirmware(fold(firmware = "F946BXXS7GZE5")))
    }

    /**
     * The whole point of the feature: GZE5-on-GZH2 (the known-bad pair) must
     * fail the gate even though model and kernel both match.
     */
    @Test
    fun rejectsGze5PayloadOnGzh2Device() {
        val gzh2Device = fold(firmware = "F946BXXS7GZH2")
        assertTrue(gze5Only().matchesDevice(gzh2Device))
        assertTrue(gze5Only().matchesKernelVersion(gzh2Device))
        assertFalse(gze5Only().matches(gzh2Device))
    }

    @Test
    fun ranksExactPinAboveAllowedFirmware() {
        val gze5Device = fold(firmware = "F946BXXS7GZE5")
        assertEquals(2, gze5Only().firmwareMatchRank(gze5Device))
        assertEquals(1, gzh2AndGze5().firmwareMatchRank(gze5Device))
    }

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

    private fun gze5Only() = profile("f946b-F946BXXS7GZE5", setOf("F946BXXS7GZE5"))

    private fun gzh2Only() = profile("f946b-F946BXXS7GZH2", setOf("F946BXXS7GZH2"))

    private fun gzh2AndGze5() = profile(
        "f946b-F946BXXS7GZH2",
        setOf("F946BXXS7GZH2", "F946BXXS7GZE5"),
    )

    private fun fold(
        model: String = "SM-F946B",
        firmware: String? = null,
        fingerprint: String = if (firmware == null) {
            "samsung/example"
        } else {
            "samsung/f946b/f946b:16/BP4A.251205.006/$firmware:user/release-keys"
        },
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

    private fun snapshot(
        model: String,
        kernelRelease: String,
    ) = DeviceSnapshot(
        manufacturer = "samsung",
        model = model,
        device = "unused",
        kernelRelease = kernelRelease,
        kernelVersionInfo = "#1 SMP PREEMPT",
        machine = "aarch64",
        buildId = "BP4A.251205.006.S938BCZG1",
        fingerprint = "samsung/example",
        androidRelease = "16",
        sdk = 36,
        abi = "arm64-v8a",
        pageSize = 4096,
    )
}
