package dev.busung.s25uroot

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards the two auto-root status fixes:
 *
 * 1. The "Root is active" banner must be boot-scoped. The old ever-rooted
 *    check (receipt boolean without a boot comparison, plus any past
 *    history success) stayed true after reboot, so a normal unrooted
 *    post-reboot state (su ABSENT) rendered "Root is active" all boot.
 * 2. The manual apply path must not duplicate the payload supervisor's
 *    activation (double soft-reboot). The native done-marker carries
 *    "$bootId $uptimeSeconds".
 */
class InstallApplyLogicTest {

    // showUnregisteredBanner: DENIED is itself this-boot evidence.

    @Test
    fun deniedMeansLiveRegardlessOfReceipt() {
        assertTrue(
            InstallViewModel.showUnregisteredBanner(SuProbe.Failure.DENIED, false),
        )
        assertTrue(
            InstallViewModel.showUnregisteredBanner(SuProbe.Failure.DENIED, true),
        )
    }

    @Test
    fun absentNeedsThisBootReceipt() {
        // Post-reboot unrooted state: no su, stale/absent receipt.
        assertFalse(
            InstallViewModel.showUnregisteredBanner(SuProbe.Failure.ABSENT, false),
        )
        // Manager registration skipped but receipt written this boot.
        assertTrue(
            InstallViewModel.showUnregisteredBanner(SuProbe.Failure.ABSENT, true),
        )
    }

    @Test
    fun errorAndNoneNeverClaimRoot() {
        assertFalse(
            InstallViewModel.showUnregisteredBanner(SuProbe.Failure.ERROR, false),
        )
        assertFalse(
            InstallViewModel.showUnregisteredBanner(SuProbe.Failure.NONE, false),
        )
    }

    // isNativeApplyDoneOutput: "$bootId $uptime" prefix match.

    @Test
    fun freshMarkerMeansNativeDone() {
        val bootId = "550e8400-e29b-41d4-a716-446655440000"
        assertTrue(
            InstallViewModel.isNativeApplyDoneOutput("$bootId 287", bootId),
        )
    }

    @Test
    fun staleMarkerMeansNotDone() {
        assertFalse(
            InstallViewModel.isNativeApplyDoneOutput(
                "old-boot-id 999",
                "550e8400-e29b-41d4-a716-446655440000",
            ),
        )
    }

    @Test
    fun prefixCollisionIsNotDone() {
        // startsWith without a separator would accept "<bootId>-evil".
        val bootId = "550e8400-e29b-41d4-a716-446655440000"
        assertFalse(
            InstallViewModel.isNativeApplyDoneOutput("$bootId-evil 1", bootId),
        )
        assertFalse(
            InstallViewModel.isNativeApplyDoneOutput(bootId, "$bootId-evil"),
        )
    }

    @Test
    fun errorWithFreshReceiptStillBannered() {
        // Transient probe error must not flip a this-boot root to "Not
        // installed" on its own; the receipt carries the verdict.
        assertTrue(
            InstallViewModel.showUnregisteredBanner(SuProbe.Failure.ERROR, true),
        )
    }

    @Test
    fun missingMarkerOrBootIdMeansNotDone() {
        assertFalse(InstallViewModel.isNativeApplyDoneOutput("", "some-boot-id"))
        assertFalse(InstallViewModel.isNativeApplyDoneOutput("some-boot-id 1", ""))
        assertFalse(InstallViewModel.isNativeApplyDoneOutput("", ""))
    }
}
