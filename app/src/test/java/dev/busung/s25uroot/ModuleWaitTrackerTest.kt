package dev.busung.s25uroot

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The module wait must survive a slow-but-progressing keeper (the 300 s
 * fixed deadline fired on a keeper that completed a minute later) while
 * still giving up on a dead one.
 */
class ModuleWaitTrackerTest {

    @Test
    fun absoluteCapEndsWait() {
        val tracker = ModuleWaitTracker(
            startMs = 0L,
            absoluteTimeoutMs = 600_000L,
            stallTimeoutMs = 180_000L,
        )
        assertFalse(tracker.timedOut(599_999L, ""))
        assertTrue(tracker.timedOut(600_000L, ""))
    }

    @Test
    fun silenceBeforeKeeperStartsNeverStalls() {
        val tracker = ModuleWaitTracker(
            startMs = 0L,
            absoluteTimeoutMs = 600_000L,
            stallTimeoutMs = 180_000L,
        )
        // Keeper log not created yet: no signature, no stall verdict.
        assertFalse(tracker.timedOut(500_000L, ""))
    }

    @Test
    fun silentKeeperAfterProgressEndsWait() {
        val tracker = ModuleWaitTracker(
            startMs = 1_000L,
            absoluteTimeoutMs = 600_000L,
            stallTimeoutMs = 180_000L,
        )
        assertFalse(tracker.timedOut(1_000L, "287:425"))
        // Same signature: stall deadline is start+180s = 181_000.
        assertFalse(tracker.timedOut(180_999L, "287:425"))
        assertTrue(tracker.timedOut(181_000L, "287:425"))
    }

    @Test
    fun newSignatureExtendsWait() {
        val tracker = ModuleWaitTracker(
            startMs = 1_000L,
            absoluteTimeoutMs = 600_000L,
            stallTimeoutMs = 180_000L,
        )
        assertFalse(tracker.timedOut(1_000L, "287:425"))
        // Progress at t=150_000 pushes the stall deadline to 330_000.
        assertFalse(tracker.timedOut(150_000L, "310:598"))
        assertFalse(tracker.timedOut(329_999L, "310:598"))
        assertTrue(tracker.timedOut(330_000L, "310:598"))
    }

    @Test
    fun absoluteCapWinsOverContinuousProgress() {
        val tracker = ModuleWaitTracker(
            startMs = 0L,
            absoluteTimeoutMs = 600_000L,
            stallTimeoutMs = 180_000L,
        )
        var sig = 0
        var t = 0L
        while (t < 600_000L) {
            assertFalse(tracker.timedOut(t, "sig${sig++}"))
            t += 60_000L
        }
        assertTrue(tracker.timedOut(600_000L, "sigFinal"))
    }
}
