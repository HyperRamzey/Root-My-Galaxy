package dev.busung.s25uroot

import android.os.Build
import android.system.Os
import android.system.OsConstants

data class DeviceSnapshot(
    val manufacturer: String,
    val model: String,
    val device: String,
    val kernelRelease: String,
    val kernelVersionInfo: String,
    val machine: String,
    val buildId: String,
    val fingerprint: String,
    val androidRelease: String,
    val sdk: Int,
    val abi: String,
    val pageSize: Long,
) {
    val kernelVersion: String
        get() = kernelRelease.takeWhile { it.isDigit() || it == '.' }

    val kernelVersionFull: String
        get() = listOf(kernelRelease, kernelVersionInfo, machine)
            .filter(String::isNotBlank)
            .joinToString(" ")

    /**
     * Firmware suffix taken from the fingerprint, upper-cased, or null.
     *
     * [Build.FINGERPRINT] is `brand/product/device:release/id/build:user/tags`:
     *
     *     samsung/f946b/f946b:16/BP4A.251205.006/F946BXXS7GZH2:user/release-keys
     *                                                     ^^^^^^^^^^^^^^
     *                                                    index 4, before ':'
     *
     * Index 4 specifically, NOT the last '/' segment: the `user/release-keys`
     * tail would otherwise win and yield the literal "release-keys".
     *
     * Two firmwares (`F946BXXS7GZE5`, `F946BXXS7GZH2`) share kernel 5.15.189,
     * so model+kernel cannot separate them and the payload offsets differ.
     * This is the field that does. [Build.DISPLAY] is the wrong source — it is
     * the build id (`BP4A.251205.006`), which is shared.
     *
     * Null (rather than a guess) for any fingerprint that does not have the
     * canonical 5+ segment shape, or whose build token is not alphanumeric.
     * Callers must treat null as "no opinion" and fall back to model+kernel —
     * see [TargetProfile.matchesFirmware].
     */
    val firmware: String?
        get() = fingerprint
            .split('/')
            .getOrNull(FINGERPRINT_BUILD_INDEX)
            ?.substringBefore(':')
            ?.trim()
            ?.uppercase()
            ?.takeIf { token -> token.isNotEmpty() && token.all(Char::isLetterOrDigit) }

    companion object {
        fun current(): DeviceSnapshot {
            val uname = Os.uname()
            return DeviceSnapshot(
                manufacturer = Build.MANUFACTURER,
                model = Build.MODEL,
                device = Build.DEVICE,
                kernelRelease = uname.release,
                kernelVersionInfo = uname.version,
                machine = uname.machine,
                buildId = Build.DISPLAY,
                fingerprint = Build.FINGERPRINT,
                androidRelease = Build.VERSION.RELEASE,
                sdk = Build.VERSION.SDK_INT,
                abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty(),
                pageSize = Os.sysconf(OsConstants._SC_PAGESIZE),
            )
        }

        /** Fingerprint path segment holding `build:user`, per the AOSP format. */
        private const val FINGERPRINT_BUILD_INDEX = 4
    }
}
