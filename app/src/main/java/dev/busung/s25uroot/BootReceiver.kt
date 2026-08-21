package dev.busung.s25uroot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

/**
 * Receives BOOT_COMPLETED and starts the root-on-boot foreground service
 * if the user has enabled auto-root and the ADB key is registered.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!AppPreferences.autoRootOnBoot(context)) return
        if (!AppPreferences.adbPaired(context)) return

        val serviceIntent = Intent(context, RootOnBootService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent)
        } else {
            context.startService(serviceIntent)
        }
    }
}
