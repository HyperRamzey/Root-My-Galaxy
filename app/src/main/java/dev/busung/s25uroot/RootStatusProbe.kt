package dev.busung.s25uroot

/**
 * Authoritative "is KernelSU live right now" check.
 *
 * 1. Fast native probe (/sys/module/kernelsu, /proc/modules).
 * 2. Fallback: exec `su -c id` — this app is the granted manager, so an
 *    active KernelSU sucompat answers with uid=0. Covers Samsung
 *    policies where the native paths are SELinux-denied for app domains,
 *    which produced false "Not installed" states while root was live.
 */
object RootStatusProbe {
    @Volatile
    private var lastResult: Boolean? = null

    fun isActive(): Boolean {
        if (NativeProbe.isKernelSuActive()) {
            lastResult = true
            return true
        }
        // Negative native results are unreliable on Samsung; only cache
        // positives so a transient failure keeps retrying next call.
        SuProbe.isActive().let { su ->
            if (su) lastResult = true
            return su
        }
    }

    /**
     * True when root appears live (shell can su, native paths hidden) but
     * THIS app is not recognized by KernelSU — i.e. the boot's root came
     * from a path that skipped manager registration. The app then shows
     * an actionable state instead of a misleading "Not installed".
     */
    fun isManagerUnregistered(): Boolean {
        if (lastResult == true || NativeProbe.isKernelSuActive()) return false
        SuProbe.isActive()
        return SuProbe.lastFailure == SuProbe.Failure.ABSENT ||
            SuProbe.lastFailure == SuProbe.Failure.DENIED
    }

    /**
     * Composite gate for the boot pipeline: live probe OR this boot's
     * install receipt. The receipt closes the early-boot race where ksud
     * late-load has not finished yet — probes return false, the pipeline
     * would otherwise run its full visual circus (unlock + foregrounded
     * MainActivity) and only then discover KernelSU was already active.
     *
     * Receipt format mirrors InstallViewModel's INSTALL_RECEIPT prefs.
     */
    fun isRootLiveThisBoot(context: android.content.Context): Boolean {
        if (isActive()) return true
        val bootToken = runCatching {
            java.io.File("/proc/sys/kernel/random/boot_id")
                .readText(java.nio.charset.StandardCharsets.US_ASCII).trim()
        }.getOrNull() ?: return false
        val receipt = context.getSharedPreferences("install_receipt", android.content.Context.MODE_PRIVATE)
        return receipt.getString("kernel_boot_id", null) == bootToken &&
            receipt.getBoolean("verified", false)
    }

    /** Persist "root verified for THIS boot" after a successful apply so
     * later gates survive probe races. Called from the pipeline. */
    fun storeBootReceipt(context: android.content.Context) {
        val bootToken = runCatching {
            java.io.File("/proc/sys/kernel/random/boot_id")
                .readText(java.nio.charset.StandardCharsets.US_ASCII).trim()
        }.getOrNull() ?: return
        context.getSharedPreferences("install_receipt", android.content.Context.MODE_PRIVATE)
            .edit()
            .putString("kernel_boot_id", bootToken)
            .putBoolean("verified", true)
            .apply()
    }

    /** Last known-positive result, sticky across calls. */
    fun wasActive(): Boolean = lastResult == true || isActive()
}
