package dev.busung.s25uroot


import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File

enum class InstallPhase {
    Checking,
    Ready,
    Downloading,
    Exploiting,
    LoadingKernelSu,
    Installed,
    Failed,
}

data class InstallUiState(
    val phase: InstallPhase = InstallPhase.Checking,
    val message: String = "",
    val probeOutput: String = "",
    val log: String = "",
) {
    val busy: Boolean
        get() = phase in setOf(
            InstallPhase.Checking,
            InstallPhase.Downloading,
            InstallPhase.Exploiting,
            InstallPhase.LoadingKernelSu,
        )
}

data class TargetCatalogUiState(
    val loading: Boolean = false,
    val profiles: List<TargetProfile> = emptyList(),
    val error: String? = null,
)

class InstallViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application
    private val repository = PayloadRepository(application)
    private val historyStore = InstallHistoryStore(application)
    private val mutableState = MutableStateFlow(InstallUiState())
    private val mutableHistory = MutableStateFlow(historyStore.closeInterruptedRuns())
    private val mutableTargetCatalog = MutableStateFlow(TargetCatalogUiState())
    private var discoveryJob: Job? = null
    private var installJob: Job? = null
    private var activeHistoryEntry: InstallHistoryEntry? = null
    /** True when the last exploit ran from bundled jniLibs because the
     * work dir was unwritable (anti-log addon wipe); installKernelSu then
     * heals + stages ksud instead of assuming the classic pushes. */
    private var lastLaunchWasFallback = false
    val state: StateFlow<InstallUiState> = mutableState.asStateFlow()
    val history: StateFlow<List<InstallHistoryEntry>> = mutableHistory.asStateFlow()
    val targetCatalog: StateFlow<TargetCatalogUiState> = mutableTargetCatalog.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        if (installJob?.isActive == true) return
        mutableHistory.value = historyStore.load()
        discoveryJob?.cancel()
        discoveryJob = viewModelScope.launch(Dispatchers.IO) {
            val probe = NativeProbe.run()
            if (detectInstalled()) {
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Installed,
                    message = app.getString(R.string.status_ksu_active),
                    probeOutput = probe,
                    log = probe,
                )
                return@launch
            }
            if (RootStatusProbe.isManagerUnregistered()) {
                // Root is live but this boot's exploit bypassed manager
                // registration (e.g. manual launcher). Say so instead of
                // the misleading "Not installed".
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Ready,
                    message = app.getString(R.string.status_root_no_manager),
                    probeOutput = probe,
                    log = "$probe\n[-] KernelSU active; manager uid not registered this boot",
                )
                return@launch
            }
            try {
                val profile = repository.resolveTarget(DeviceSnapshot.current())
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Ready,
                    message = app.getString(R.string.status_not_installed),
                    probeOutput = probe,
                    log = "$probe\n${app.getString(R.string.log_profile, profile.profileId)}",
                )
            } catch (error: Throwable) {
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Failed,
                    message = app.getString(R.string.status_support_failed),
                    probeOutput = probe,
                    log = "$probe\n[-] ${error.message ?: error.javaClass.simpleName}",
                )
            }
        }
    }

    fun deleteHistoryEntries(ids: Collection<String>) {
        val runningId = activeHistoryEntry?.id
        val toDelete = ids.filterNot { it == runningId }
        if (toDelete.isEmpty()) return
        toDelete.forEach(historyStore::delete)
        mutableHistory.value = mutableHistory.value.filterNot { it.id in toDelete }
    }

    fun loadTargetCatalog() {
        if (mutableTargetCatalog.value.loading) return
        viewModelScope.launch(Dispatchers.IO) {
            mutableTargetCatalog.value = TargetCatalogUiState(loading = true)
            mutableTargetCatalog.value = try {
                TargetCatalogUiState(
                    profiles = repository.loadTargets().sortedWith(
                        compareBy(
                            TargetProfile::displayName,
                            TargetProfile::profileId,
                        ),
                    ),
                )
            } catch (error: Throwable) {
                TargetCatalogUiState(error = error.message ?: error.javaClass.simpleName)
            }
        }
    }

    fun install(profileId: String? = null) {
        if (installJob?.isActive == true || mutableState.value.phase == InstallPhase.Installed) return
        discoveryJob?.cancel()
        installJob = viewModelScope.launch(Dispatchers.IO) {
            mutableState.value = InstallUiState(
                phase = InstallPhase.Checking,
                probeOutput = mutableState.value.probeOutput,
            )
            startHistory()
            try {
                // Gate: wireless ADB must be available before anything else.
                appendLog(app.getString(R.string.log_adb_connecting))
                val adb = WirelessAdbSession.open(app)
                val idResult = adb.shell("id")
                require(idResult.output.contains("uid=")) {
                    app.getString(R.string.error_adb_connection)
                }
                appendLog(app.getString(R.string.log_adb_connected, idResult.output.trim()))

                setPhase(InstallPhase.Checking, app.getString(R.string.status_checking_github))
                val profile = if (profileId == null) {
                    repository.resolveTarget(DeviceSnapshot.current())
                } else {
                    repository.resolveTarget(profileId)
                }
                appendLog(app.getString(R.string.log_profile, profile.profileId))
                updateHistoryProfile(profile.profileId)

                setPhase(InstallPhase.Downloading, app.getString(R.string.status_downloading_payload))
                val payloads = repository.download(profile) { appendLog("[*] $it") }
                appendLog(app.getString(R.string.log_download_verified))

                setPhase(InstallPhase.Exploiting, app.getString(R.string.status_exploit_running))
                executeExploit(adb, payloads)

                setPhase(InstallPhase.LoadingKernelSu, app.getString(R.string.status_ksu_loading))
                installKernelSu(adb, payloads)

                setPhase(InstallPhase.Installed, app.getString(R.string.status_ksu_active))
                appendLog(app.getString(R.string.log_install_complete))
                // First-install guidance: module activation needs shell root grant.
                appendLog(app.getString(R.string.first_install_shell_root_hint))
                finishHistory(InstallRunResult.Succeeded)
                if (AppPreferences.autoApplyModules(app)) {
                    applyModulesViaAdb(adb)
                }
                adb.close()
            } catch (error: Throwable) {
                appendLog("[-] ${error.message ?: error.javaClass.simpleName}")
                setPhase(InstallPhase.Failed, app.getString(R.string.status_install_failed))
                finishHistory(InstallRunResult.Failed)
            }
        }
    }

    private suspend fun executeExploit(adb: WirelessAdbSession, payloads: VerifiedPayloads) {
        val payload = payloads.exploit
        val profile = payloads.profile
        val bootToken = currentBootToken()
        val logPrefix = mutableState.value.log

        // Stage payload + root helper onto the device via ADB push — unless
        // the work dir is broken (anti-log addons like KillLogger wipe
        // /data/local/tmp every boot and whatever recreates it labels it
        // system_data_file, denying adbd forever). In that case bootstrap
        // from the app's bundled jniLibs instead and defer ksud staging.
        val launch = ExploitStaging.resolve(app, adb, payloads.profile.profileId)
        lastLaunchWasFallback = !launch.workDirHealthy
        val remotePayload = launch.payloadPath
        val remoteHelper = launch.helperPath
        val remoteLog = launch.logPath

        if (launch.workDirHealthy) {
            adb.remove(remoteLog)
            adb.push(payload, remotePayload, executable = true)
            val helperSource = payloads.rootHelper ?: nativeHelperFile()
            adb.push(helperSource, remoteHelper, executable = true)
        } else {
            ExploitStaging.prepareLogDir(adb, remoteLog)
            // Stale SD log would fake a success marker from an earlier boot.
            runCatching { adb.shell("rm -f '$remoteLog'") }
        }
        appendLog(app.getString(R.string.log_adb_staged))

        // Build the exploit command with environment variables.
        val envVars = buildList {
            add("EXPLOIT_ATTEMPTS=$EXPLOIT_ATTEMPTS")
            add("RMG_MANAGER_PACKAGE=${BuildConfig.APPLICATION_ID}")
            add("P0_ATTEMPT_TIMEOUT_SEC=$P0_ATTEMPT_TIMEOUT_SEC")
            add("EXPLOIT_ATTEMPT_TIMEOUT_SEC=$EXPLOIT_ATTEMPT_TIMEOUT_SEC")
            profile.slideSource?.let { add("SLIDE_SOURCE=$it") }
            cachedP0Offset(bootToken)?.let { add("$P0_OFFSET_ENV=$it") }
        }.joinToString(" ")

        val exploitCmd = "$envVars $remoteHelper --run-payload $remotePayload $remoteHelper $remoteLog"

        // Run the exploit in a streaming shell that stays open for the full
        // run. adbd kills a backgrounded process the moment its shell stream
        // closes, so the exploit must run in the foreground of an open shell.
        // The helper's --run-payload mode forks the payload into its own
        // session (so it survives) and streams the live log to stdout via a
        // foreground supervisor, so streaming the helper's stdout directly
        // yields real-time progress.
        var lastRawLog = ""
        adb.runStreaming(exploitCmd) { accumulated ->
            if (accumulated != lastRawLog) {
                lastRawLog = accumulated
                cacheP0Offset(bootToken, accumulated)
                publishExploitLog(logPrefix, accumulated)
            }
        }

        val rawLog = lastRawLog.ifBlank { adb.readLog(remoteLog) }
        cacheP0Offset(bootToken, rawLog)
        publishExploitLog(logPrefix, rawLog)
        require(rawLog.contains("exploit completed")) {
            app.getString(R.string.error_success_marker)
        }
        appendLog(app.getString(R.string.log_bootstrap_root))
    }

    private fun installKernelSu(adb: WirelessAdbSession, payloads: VerifiedPayloads) {
        if (lastLaunchWasFallback) {
            // The exploit ran from bundled libs; /data/local/tmp was healed
            // by the daemon/keeper, but cover the lost race against SELinux
            // re-enforcement before staging ksud.
            ExploitStaging.healAfterRoot(adb)
        }
        // Stage ksud onto the device under its feed artifact name; the
        // payload's loader resolves any /data/local/tmp/ksud-*-kdp candidate.
        val remoteKsud = "/data/local/tmp/${payloads.profile.kernelSu.url.substringAfterLast('/')}"
        val staged = ExploitStaging.pushWhenStable(adb, payloads.kernelSu, remoteKsud)
        check(staged) { "Work dir still unwritable after root — cannot stage ksud" }
        runCatching { adb.push(payloads.kernelSu, REMOTE_KSUD_STAGE_PATH, executable = true) }
        appendLog(app.getString(R.string.log_ksu_staged))

        // The payload supervisor already triggers --late-load + --apply-modules
        // immediately after exploit success (while SELinux is still permissive).
        // Verify KernelSU is loaded; if not, try late-load explicitly.
        val ksuCheck = adb.shell("grep -i kernelsu /proc/modules 2>/dev/null")
        if (!ksuCheck.output.contains("kernelsu")) {
            val lateLoad = adb.shell("${nativeHelperFile().absolutePath} --late-load")
            require(lateLoad.exitCode == 0) {
                app.getString(R.string.error_ksu_verify, lateLoad.exitCode, lateLoad.output)
            }
            if (lateLoad.output.isNotBlank()) appendLog(lateLoad.output)
        } else {
            appendLog("[+] KernelSU already loaded (supervisor auto-triggered)")
        }
        storeInstallReceipt()
        appendLog(app.getString(R.string.log_ksu_control_verified))

        // Ensure ADB key exists for root-on-boot pairing
        AdbKeyManager(app)
    }

    /**
     * Mounts KernelSU modules and restarts zygote so Zygisk-based modules
     * (LSPosed, etc.) inject into the fresh zygote process. Causes a ~5s
     * soft-reboot: lockscreen reappears, kernel and root persist.
     */
    fun applyModules() {
        if (installJob?.isActive == true) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val adb = WirelessAdbSession.open(app)
                applyModulesViaAdb(adb)
                adb.close()
            } catch (error: Throwable) {
                appendLog("[-] ${error.message ?: error.javaClass.simpleName}")
            }
        }
    }

    private fun applyModulesViaAdb(adb: WirelessAdbSession) {
        appendLog(app.getString(R.string.log_modules_applying))

        // Primary path: use `su -c` which works under Enforcing once shell
        // has been granted root by KernelSU (persists across reboots).
        val suCheck = adb.shell("su -c id 2>&1")
        if (suCheck.exitCode == 0 && suCheck.output.contains("uid=0")) {
            appendLog("[+] su available, activating modules via ksud lifecycle")
            // Run ksud stages in background with full fd detach — daemonized
            // children inherit the ADB pipe and keep the stream open forever.
            // setsid + & + redirect all fds ensures the shell returns instantly.
            adb.shell("su -c 'setsid sh -c \"timeout 30 /data/adb/ksud post-fs-data > /data/local/tmp/ksud-pfd.log 2>&1 < /dev/null\" & echo pfd_bg'")
            Thread.sleep(12_000) // post-fs-data takes ~5-10s
            adb.shell("su -c 'setsid sh -c \"timeout 30 /data/adb/ksud services > /data/local/tmp/ksud-svc.log 2>&1 < /dev/null\" & echo svc_bg'")
            Thread.sleep(5_000)
            adb.shell("su -c 'setsid sh -c \"timeout 30 /data/adb/ksud boot-completed > /data/local/tmp/ksud-bc.log 2>&1 < /dev/null\" & echo bc_bg'")
            Thread.sleep(3_000)
            appendLog("[*] ksud lifecycle stages done")
            // Restart zygote so Zygisk modules inject into fresh process
            val kill = adb.shell("su -c 'for p in \$(pidof zygote64) \$(pidof zygote); do kill -9 \$p 2>/dev/null; done; echo zygote-killed'")
            if (kill.output.contains("zygote-killed")) {
                appendLog(app.getString(R.string.log_modules_zygote_restarted))
            } else {
                appendLog("[!] zygote kill: ${kill.output.trim()}")
            }
            appendLog("[*] file marks: ${ExploitStaging.healFileMarks(adb)}")
            return
        }

        // Fallback: daemon apply-modules (only works while SELinux permissive)
        appendLog("[!] su not available, trying daemon apply-modules")
        val stagedHelper = runCatching {
            adb.shell("test -x /data/local/tmp/cve-2026-43499-root && echo ok").output
        }.getOrDefault("").contains("ok")
        val helperCmd =
            if (stagedHelper) "/data/local/tmp/cve-2026-43499-root" else REMOTE_HELPER_PATH
        val apply = adb.shell("$helperCmd --apply-modules")
        if (apply.exitCode == 0 && apply.output.contains("zygote")) {
            appendLog(app.getString(R.string.log_modules_zygote_restarted))
            appendLog("[*] file marks: ${ExploitStaging.healFileMarks(adb)}")
            return
        }
        appendLog("[-] ${app.getString(R.string.error_modules_restart, apply.output.trim().takeLast(120))}")
        appendLog(app.getString(R.string.log_grant_shell_root_hint))
    }

    /** Manual trigger from start screen: mount + soft-reboot via ksud (root). */
    fun softReboot() = restartZygisk()

    fun restartZygisk() {
        if (installJob?.isActive == true) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                appendLog(app.getString(R.string.log_modules_applying))
                val adb = WirelessAdbSession.open(app)
                applyModulesViaAdb(adb)
                // also log that soft-reboot was manually triggered
                appendLog("[+] soft-reboot triggered")
                adb.close()
            } catch (error: Throwable) {
                appendLog("[-] soft-reboot failed: ${error.message ?: error.javaClass.simpleName}")
            }
        }
    }

    private fun detectInstalled(): Boolean {
        if (RootStatusProbe.isActive()) return true
        val bootToken = currentBootToken() ?: return false
        val receipt = app.getSharedPreferences(INSTALL_RECEIPT, Application.MODE_PRIVATE)
        return receipt.getString(RECEIPT_BOOT_TOKEN, null) == bootToken &&
            receipt.getBoolean(RECEIPT_VERIFIED, false)
    }

    private fun storeInstallReceipt() {
        val bootToken = currentBootToken() ?: error(app.getString(R.string.error_boot_id))
        val stored = app.getSharedPreferences(INSTALL_RECEIPT, Application.MODE_PRIVATE)
            .edit()
            .putString(RECEIPT_BOOT_TOKEN, bootToken)
            .putBoolean(RECEIPT_VERIFIED, true)
            .commit()
        require(stored) { app.getString(R.string.error_receipt) }
    }

    private fun currentBootToken(): String? = runCatching {
        File("/proc/sys/kernel/random/boot_id")
            .readText(Charsets.US_ASCII)
            .trim()
            .takeIf(String::isNotBlank)
    }.getOrNull()

    private fun cachedP0Offset(bootToken: String?): String? {
        if (bootToken == null) return null
        val stored = app.getSharedPreferences(P0_CACHE, Application.MODE_PRIVATE)
        if (stored.getString(P0_CACHE_BOOT_TOKEN, null) != bootToken) return null
        return stored.getString(P0_CACHE_OFFSET, null)
    }

    private fun cacheP0Offset(bootToken: String?, log: String) {
        if (bootToken == null) return
        val match = P0_OFFSET_PATTERN.findAll(log).lastOrNull() ?: return
        val offset = match.groupValues[1].toLongOrNull(16) ?: return
        if (offset !in 0..P0_OFFSET_MAX || offset and P0_OFFSET_MASK != 0L) return
        val value = "0x${offset.toString(16)}"
        val stored = app.getSharedPreferences(P0_CACHE, Application.MODE_PRIVATE)
        if (stored.getString(P0_CACHE_BOOT_TOKEN, null) == bootToken &&
            stored.getString(P0_CACHE_OFFSET, null) == value
        ) return
        stored.edit()
            .putString(P0_CACHE_BOOT_TOKEN, bootToken)
            .putString(P0_CACHE_OFFSET, value)
            .apply()
    }

    private fun nativeHelperFile() = File(app.applicationInfo.nativeLibraryDir, "libcve43499root.so")

    private fun publishExploitLog(prefix: String, rawLog: String) {
        mutableState.value = mutableState.value.copy(
            log = listOf(prefix, stripAnsi(rawLog))
                .filter(String::isNotBlank)
                .joinToString("\n"),
        )
        updateHistoryLog()
    }

    private fun setPhase(phase: InstallPhase, message: String) {
        mutableState.value = mutableState.value.copy(phase = phase, message = message)
        appendLog("[*] $message")
    }

    private fun appendLog(line: String) {
        val cleanLine = stripAnsi(line).trim()
        if (cleanLine.isBlank()) return
        mutableState.value = mutableState.value.copy(
            log = (mutableState.value.log + "\n" + cleanLine).trim(),
        )
        updateHistoryLog()
    }

    private fun startHistory() {
        val entry = historyStore.create()
        activeHistoryEntry = entry
        publishHistory(entry)
    }

    private fun updateHistory(transform: (InstallHistoryEntry) -> InstallHistoryEntry) {
        val entry = activeHistoryEntry ?: return
        val updated = transform(entry)
        activeHistoryEntry = updated
        historyStore.save(updated)
        publishHistory(updated)
    }

    private fun updateHistoryLog() =
        updateHistory { it.copy(log = mutableState.value.log) }

    private fun updateHistoryProfile(profileId: String) =
        updateHistory { it.copy(profileId = profileId) }

    private fun finishHistory(result: InstallRunResult) {
        updateHistory { entry ->
            entry.copy(
                completedAtMillis = System.currentTimeMillis(),
                result = result,
                log = mutableState.value.log,
            )
        }
        activeHistoryEntry = null
    }

    private fun publishHistory(entry: InstallHistoryEntry) {
        mutableHistory.value = (mutableHistory.value.filterNot { it.id == entry.id } + entry)
            .sortedByDescending(InstallHistoryEntry::startedAtMillis)
    }

    companion object {
        private const val EXPLOIT_ATTEMPTS = "24"
        private const val P0_ATTEMPT_TIMEOUT_SEC = "45"
        private const val EXPLOIT_ATTEMPT_TIMEOUT_SEC = "120"
        private const val INSTALL_RECEIPT = "install_receipt"
        private const val RECEIPT_BOOT_TOKEN = "kernel_boot_id"
        private const val RECEIPT_VERIFIED = "verified"
        private const val P0_CACHE = "p0_cache"
        private const val P0_CACHE_BOOT_TOKEN = "kernel_boot_id"
        private const val P0_CACHE_OFFSET = "offset"
        private const val P0_OFFSET_ENV = "SLIDE_P0_OFFSET"
        private const val P0_OFFSET_MAX = 0x1f0000L
        private const val P0_OFFSET_MASK = 0xffffL
        private const val REMOTE_PAYLOAD_PATH = "/data/local/tmp/ksu-payload"
        private const val REMOTE_HELPER_PATH = "/data/local/tmp/ksu-helper"
        private const val REMOTE_KSUD_STAGE_PATH = "/data/local/tmp/.ksud-stage"
        private const val REMOTE_LOG_PATH = "/data/local/tmp/ksu-exploit.log"
        private val ANSI_ESCAPE = Regex("\u001B\\[[0-?]*[ -/]*[@-~]")
        private val P0_OFFSET_PATTERN = Regex(
            "slide-kaslr-ok[^\\n]*slide=([0-9a-fA-F]{16})",
        )

        private fun stripAnsi(value: String): String = ANSI_ESCAPE.replace(value, "").replace("\r", "")
    }
}
