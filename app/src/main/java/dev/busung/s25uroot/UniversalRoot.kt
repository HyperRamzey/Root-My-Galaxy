package dev.busung.s25uroot

/**
 * The JNI bridge to the ported DFRoot chain.
 *
 * This declares the boundary and nothing else. The exploit itself is
 * `app/src/main/cpp/dfroot/`, ported from https://github.com/diabl0w/DFRoot, and the
 * reason it is here rather than in the `:dfr` helper is the whole point of that
 * project: this chain runs from an **ordinary app**, with no `sharedUserId`, no
 * `packages.xml` inject and no first temporary root - it drives the kernel through
 * an unprivileged `IpSecManager` transform. Everything the helper exists for is the
 * *other* chain.
 *
 * ## The name is the contract
 *
 * A JNI symbol is derived from the declaring class, so the class this declares on
 * has to be the same one exp.c exports, and the native symbol is
 * `Java_dev_busung_s25uroot_UniversalRoot_nativeRunAll` - the package and the
 * class, with the dots turned into underscores. Rename this class and the exploit
 * stops being findable with an `UnsatisfiedLinkError` that reads like a build
 * problem rather than a rename; `UniversalRootContractTest`
 * holds the two together.
 *
 * ## Why nothing here is `internal`
 *
 * Kotlin appends the *module name* to the JVM name of an `internal` function - this module is `app`, so an
 * `internal fun nativeRunAll` is really `nativeRunAll$app`, and JNI looks for a symbol mangled from that:
 * `Java_dev_busung_s25uroot_UniversalRoot_nativeRunAll_00024app`. Nothing in C is called that, so the
 * library loads, the first tap gets a payload, and the run dies at the last step with
 * `UnsatisfiedLinkError` naming a symbol that looks like a typo. The declarations below are therefore
 * public, and the only thing in this file that may ever be `internal` again is prose.
 *
 * ## The reporter
 *
 * The native side calls back on every step it takes, through a `report(String)`
 * method looked up on the object handed in - that is how a run's progress is
 * visible at all, because the interesting part of this chain happens in init and in
 * `vendor_modprobe`, where nothing of ours is running to log it.
 */
object UniversalRoot {

    init {
        // The library's name, not its path: `libdfroot.so` is loaded from this APK's
        // own lib directory, which is the one place the loader will take it from.
        System.loadLibrary("dfroot")
    }

    /** Where the exploit's progress goes. One call per step, in order. */
    fun interface Reporter {
        fun report(message: String)
    }

    /**
     * Runs the chain, and blocks until it has finished.
     *
     * There is no daemon path in the call any more, and that is upstream's change rather
     * than an omission: the shellcode reads one fixed path - this app's own data directory
     * plus `/ksud` - which the app stages before the call. So the daemon is a real file the
     * root side can name, nothing is handed over through a file descriptor, and this call
     * no longer needs this process to stay alive for its bytes to be readable.
     *
     * [koTarget] is the vendor library the chain writes through. The module's bytes are patched into
     * that file's page cache, and the shellcode's `insmod` is then asked to load them from the path it
     * names - which is how a chain that patches nothing but a vendor library gets a kernel module loaded.
     * It is a parameter rather than a constant in the native code because which vendor file exists and
     * is loadable differs by device: the app picks one (see [UniversalRootRun.chooseKoTarget]), and a
     * choice made here is one the log can name.
     *
     * [packageName] is the manager package the daemon is told to serve, and it is per
     * KernelSU: the daemon grants root to whatever this names. It is a parameter rather
     * than a literal in the native code because the chain is one library for every
     * flavour now - a compiled-in `me.weishu.kernelsu` meant a KernelSU-Next run handed
     * its daemon the wrong manager's name, and clap accepts it because to clap the value
     * is opaque, so nothing failed loudly. Since the privileged half moved into the
     * module, this travels *through* it: the shellcode passes `package_name=<manager>`
     * as an `insmod` parameter, and the module hands it to the daemon.
     *
     * There is no restart argument any more. The chain used to be told whether to reboot, and could not
     * act on it - a soft reboot is this app's setting, so the app performs it after a run, the same way
     * the payload flow does.
     *
     * Returns the native chain's own code: 0 success, 1 the daemon exited with an
     * error, 2 a check failed and the log names it, 3 the patches did not land.
     */
    external fun nativeRunAll(
        reporter: Reporter,
        koTarget: String,
        encapPort: Int,
        spi: Int,
        aesCbcKey: ByteArray,
        hmacKey: ByteArray,
        icvLen: Int,
        senderPort: Int,
        packageName: String,
    ): Int
}
