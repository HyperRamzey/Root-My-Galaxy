package dev.busung.s25uroot

/**
 * Stall-aware timeout bookkeeping for the module-activation wait in
 * [RootOnBootService].
 *
 * Background: the native keeper is slow under load (6+ minutes observed on
 * q5q while the old fixed 300 s [RootOnBootService.MODULE_WAIT_MS] fired),
 * so a fixed deadline reports false failures for flows that complete a
 * minute later. But waiting forever on a dead keeper is worse. The keeper
 * appends to ksu-keeper.log as it works (including periodic ticks), so a
 * changing `stat -c '%Y:%s'` signature means progress and extends the wait;
 * only a silent keeper (signature seen, then unchanged past [stallTimeoutMs])
 * or the absolute cap ends it.
 *
 * Pure wall-clock logic over an opaque signature string; unit-tested.
 */
internal class ModuleWaitTracker(
    startMs: Long,
    absoluteTimeoutMs: Long,
    private val stallTimeoutMs: Long,
) {
    private val absoluteDeadlineMs = startMs + absoluteTimeoutMs
    private var stallDeadlineMs = startMs + stallTimeoutMs
    private var lastKeeperSig = ""
    private var keeperSeen = false

    /**
     * @param nowMs current wall time, must be monotonic non-decreasing
     * @param keeperSig `mtime:size` of ksu-keeper.log, or "" when unreadable
     * @return true when the wait must end (absolute cap hit, or the keeper
     * went silent after having been seen)
     */
    fun timedOut(nowMs: Long, keeperSig: String): Boolean {
        if (nowMs >= absoluteDeadlineMs) return true
        if (keeperSig.isNotEmpty() && keeperSig != lastKeeperSig) {
            lastKeeperSig = keeperSig
            keeperSeen = true
            stallDeadlineMs = nowMs + stallTimeoutMs
        }
        return keeperSeen && nowMs >= stallDeadlineMs
    }
}
