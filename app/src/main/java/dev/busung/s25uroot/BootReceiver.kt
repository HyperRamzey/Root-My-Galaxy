package dev.busung.s25uroot

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/**
 * Receives BOOT_COMPLETED and starts the root-on-boot foreground service
 * if the user has enabled auto-root and the ADB key is registered.
 *
 * Samsung devices routinely deliver BOOT_COMPLETED before wireless
 * debugging is serviceable, and aggressive background managers can delay
 * the receiver itself. The receiver therefore also schedules a few
 * self-retries (2 / 5 / 9 minutes) via AlarmManager; each retry simply
 * starts RootOnBootService again, which is a no-op once root has been
 * detected as already active this boot.
 *
 * Ordering + permission contract (hardened after an observed boot where
 * One UI denied the direct background FGS start and the crash killed the
 * process before any retry was scheduled):
 *  1. Retries are scheduled BEFORE attempting the direct start.
 *  2. The direct start is guarded — a denial must never crash the
 *     receiver, because a crashed receiver schedules nothing.
 *  3. Retries use AlarmManager.setAlarmClock(): always exact (no
 *     SCHEDULE_EXACT_ALARM grant needed) and puts the app on the system's
 *     temporary allowlist, which is what makes the follow-up
 *     startForegroundService() legal from the receiver.
 *  4. A denied start from a retry reschedules the next index instead of
 *     silently dying, walking the ladder 2 -> 5 -> 9 minutes.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val retryIndex = intent.getIntExtra(EXTRA_RETRY, 0)
        val isBoot = intent.action == Intent.ACTION_BOOT_COMPLETED
        if (!isBoot && intent.action != ACTION_RETRY) return
        if (retryIndex == 0 && !isBoot) return
        if (!AppPreferences.autoRootOnBoot(context)) return
        if (!AppPreferences.adbPaired(context)) {
            // Silent return here made post-reinstall boots undiagnosable:
            // nothing ran, nothing was logged, the UI kept saying ready.
            // Record why so MainActivity renders it and the user knows to
            // re-pair wireless debugging.
            Log.w(TAG, "auto-root skipped: wireless debugging not paired")
            RootOnBootProgress.update(
                RootOnBootState.Done(
                    false,
                    "Auto-root skipped: wireless debugging is not paired. Open the app and pair once.",
                ),
            )
            return
        }

        if (RootStatusProbe.isRootLiveThisBoot(context)) {
            // KernelSU is already live this boot; nothing to restore.
            return
        }

        // Schedule first: a crashed/denied start below must never leave
        // this boot without retry coverage.
        if (isBoot) {
            scheduleRetry(context, 1)
            scheduleRetry(context, 2)
            scheduleRetry(context, 3)
        }

        val serviceIntent = Intent(context, RootOnBootService::class.java)
        val started = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
            true
        }.getOrElse { error ->
            Log.w(TAG, "direct FGS start denied (will rely on alarm retries)", error)
            false
        }
        if (!started && !isBoot && retryIndex < MAX_RETRIES) {
            // This retry was itself denied; fall through to the next rung
            // instead of losing the boot.
            scheduleRetry(context, retryIndex + 1)
        }
    }


    private fun scheduleRetry(context: Context, index: Int) {
        if (index > MAX_RETRIES) return
        val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val pending = retryPendingIntent(context, index)
        val delayMs = when (index) {
            1 -> 2 * 60_000L
            2 -> 5 * 60_000L
            else -> 9 * 60_000L
        }
        val triggerAt = System.currentTimeMillis() + delayMs
        // Triple fallback: exact (granted via USE_EXACT_ALARM) ->
        // setAlarmClock (always exact, allowlist-granting) ->
        // inexact allow-while-idle. A SecurityException here crashes the
        // receiver and loses the whole boot, so every branch is guarded.
        val scheduled = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                am.canScheduleExactAlarms()
            ) {
                am.setExactAndAllowWhileIdle(
                    AlarmManager.RTC_WAKEUP, triggerAt, pending,
                )
            } else {
                throw SecurityException("exact alarms not grantable; use alarm-clock path")
            }
        }.recoverCatching {
            val showIntent = PendingIntent.getActivity(
                context,
                0,
                context.packageManager.getLaunchIntentForPackage(context.packageName),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            am.setAlarmClock(AlarmManager.AlarmClockInfo(triggerAt, showIntent), pending)
        }.isSuccess
        if (!scheduled) {
            Log.e(TAG, "could not schedule retry index=$index; boot retry coverage lost")
        }
    }

    companion object {
        private const val TAG = "BootReceiver"
        const val ACTION_RETRY = "dev.busung.s25uroot.action.AUTO_ROOT_RETRY"
        const val EXTRA_RETRY = "retry_index"
    /** Exact-match PI factory shared by scheduling and cancellation so a
     * successful run can defuse every pending rung (each alarm wake is a
     * battery cost once root is already live). */
    private fun retryPendingIntent(context: Context, index: Int): PendingIntent {
        val intent = Intent(context, BootReceiver::class.java).apply {
            action = ACTION_RETRY
            putExtra(EXTRA_RETRY, index)
        }
        return PendingIntent.getBroadcast(
            context,
            RETRY_REQUEST_CODE_BASE + index,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    /** Defuse all pending retry rungs. */
    fun cancelRetryAlarms(context: Context) {
        val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        for (index in 1..MAX_RETRIES) {
            am.cancel(retryPendingIntent(context, index))
        }
    }

        const val MAX_RETRIES = 3
        const val RETRY_REQUEST_CODE_BASE = 4200
    }
}
