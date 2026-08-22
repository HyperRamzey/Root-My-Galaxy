package dev.busung.s25uroot

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Live progress state for the root-on-boot reapply process.
 * Observable from both the foreground service notification and the app UI.
 */
sealed interface RootOnBootState {
    data object Idle : RootOnBootState

    data class Running(
        val stage: String,
        val lastLine: String = "",
        val elapsedMs: Long = 0,
        val etaMs: Long = -1,
    ) : RootOnBootState

    data class Done(
        val success: Boolean,
        val message: String,
    ) : RootOnBootState
}

object RootOnBootProgress {
    private val mutable = MutableStateFlow<RootOnBootState>(RootOnBootState.Idle)
    val state: StateFlow<RootOnBootState> = mutable.asStateFlow()

    fun update(state: RootOnBootState) {
        mutable.value = state
    }

    fun reset() {
        mutable.value = RootOnBootState.Idle
    }

    /** Typical exploit duration observed on SM-F946B (~180s). */
    const val EXPLOIT_ETA_MS = 180_000L
}
