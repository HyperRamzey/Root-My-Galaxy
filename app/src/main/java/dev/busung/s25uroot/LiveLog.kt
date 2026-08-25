package dev.busung.s25uroot

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Thread-safe rolling log shared by the boot pipeline, the foreground
 * notification (expanded inbox shows the most recent entries) and the
 * in-app scrollable console.
 *
 * Fed from RootOnBootService stage transitions and the streamed exploit
 * output; also from InstallViewModel's manual runs so the UI shows one
 * coherent log regardless of who drives the pipeline.
 */
object LiveLog {
    private const val MAX_ENTRIES = 100

    /** Lines shown in the expanded notification (>= 4 required). */
    const val NOTIFICATION_LINES = 5

    /** Minimum rows visible in the in-app console without scrolling. */
    const val UI_VISIBLE_ROWS = 9

    private val mutableLines = MutableStateFlow<List<String>>(emptyList())

    /** Immutable snapshot list, newest last. Collect from the UI. */
    val lines: StateFlow<List<String>> = mutableLines.asStateFlow()

    fun add(rawLine: String) {
        val line = clean(rawLine)
        if (line.isBlank()) return
        synchronized(this) {
            val next = mutableLines.value.toMutableList()
            next.add(line)
            while (next.size > MAX_ENTRIES) {
                next.removeAt(0)
            }
            mutableLines.value = next
        }
    }

    fun addAll(chunk: String) {
        chunk.lineSequence()
            .filter { it.isNotBlank() }
            .forEach { add(it) }
    }

    fun recent(count: Int): List<String> =
        mutableLines.value.takeLast(count)

    fun clear() {
        mutableLines.value = emptyList()
    }

    /** Strip ANSI colour escapes and trim runaway prefixes. */
    private fun clean(line: String): String =
        line.replace(Regex("\u001B\\[[0-9;]*m"), "").trim().takeLast(200)
}
