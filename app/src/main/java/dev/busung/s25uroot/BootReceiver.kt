package dev.busung.s25uroot

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

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
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val retryIndex = intent.getIntExtra(EXTRA_RETRY, 0)
        val isBoot = intent.action == Intent.ACTION_BOOT_COMPLETED
        if (!isBoot && intent.action != ACTION_RETRY) return
        if (retryIndex == 0 && !isBoot) return
        if (!AppPreferences.autoRootOnBoot(context)) return
        if (!AppPreferences.adbPaired(context)) return

        if (NativeProbe.isKernelSuActive()) {
            // KernelSU is already live this boot; nothing to restore.
            return
        }

        val serviceIntent = Intent(context, RootOnBootService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent)
        } else {
            context.startService(serviceIntent)
        }
        if (isBoot) {
            scheduleRetry(context, 1)
            scheduleRetry(context, 2)
            scheduleRetry(context, 3)
        }
    }

    private fun scheduleRetry(context: Context, index: Int) {
        if (index > MAX_RETRIES) return
        val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val intent = Intent(context, BootReceiver::class.java).apply {
            action = ACTION_RETRY
            putExtra(EXTRA_RETRY, index)
        }
        val pending = PendingIntent.getBroadcast(
            context,
            RETRY_REQUEST_CODE_BASE + index,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val delayMs = when (index) {
            1 -> 2 * 60_000L
            2 -> 5 * 60_000L
            else -> 9 * 60_000L
        }
        val triggerAt = System.currentTimeMillis() + delayMs
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && !am.canScheduleExactAlarms()) {
            am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerAt, pending)
        } else {
            am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerAt, pending)
        }
    }

    companion object {
        const val ACTION_RETRY = "dev.busung.s25uroot.action.AUTO_ROOT_RETRY"
        const val EXTRA_RETRY = "retry_index"
        const val MAX_RETRIES = 3
        const val RETRY_REQUEST_CODE_BASE = 4200
    }
}
