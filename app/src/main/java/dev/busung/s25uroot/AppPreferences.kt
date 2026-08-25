package dev.busung.s25uroot

import android.app.LocaleManager
import android.content.Context
import android.os.LocaleList

enum class AccentColor(val storedValue: String) {
    Dynamic("dynamic"),
    Blue("blue"),
    Violet("violet"),
    Green("green"),
    Orange("orange");

    companion object {
        fun fromStoredValue(value: String?): AccentColor =
            entries.firstOrNull { it.storedValue == value } ?: Dynamic
    }
}

enum class AppThemeMode(val storedValue: String) {
    System("system"),
    Light("light"),
    Dark("dark"),
    Black("black");

    companion object {
        fun fromStoredValue(value: String?): AppThemeMode =
            entries.firstOrNull { it.storedValue == value } ?: Black
    }
}

object AppPreferences {
    private const val PREFERENCES = "appearance"
    private const val ACCENT_COLOR = "accent_color"
    private const val THEME_MODE = "theme_mode"
    private const val ADVANCED_MODE = "advanced_mode"
    private const val CONSUMED_INSTALL_REQUEST = "consumed_install_request"
    private const val AUTO_APPLY_MODULES = "auto_apply_modules"
    private const val AUTO_ROOT_BOOT = "auto_root_boot"
    private const val ADB_PAIRED = "adb_paired"
    private const val BOOT_RETRY_COUNT = "boot_retry_count"

    fun accentColor(context: Context): AccentColor = AccentColor.fromStoredValue(
        prefs(context).getString(ACCENT_COLOR, null),
    )

    fun setAccentColor(context: Context, color: AccentColor) {
        prefs(context).edit()
            .putString(ACCENT_COLOR, color.storedValue)
            .apply()
    }

    fun themeMode(context: Context): AppThemeMode = AppThemeMode.fromStoredValue(
        prefs(context).getString(THEME_MODE, null),
    )

    fun setThemeMode(context: Context, themeMode: AppThemeMode) {
        prefs(context).edit()
            .putString(THEME_MODE, themeMode.storedValue)
            .apply()
    }

    fun advancedMode(context: Context): Boolean =
        prefs(context).getBoolean(ADVANCED_MODE, false)

    fun setAdvancedMode(context: Context, enabled: Boolean) {
        prefs(context).edit()
            .putBoolean(ADVANCED_MODE, enabled)
            .apply()
    }

    fun autoApplyModules(context: Context): Boolean =
        prefs(context).getBoolean(AUTO_APPLY_MODULES, false)

    fun setAutoApplyModules(context: Context, enabled: Boolean) {
        prefs(context).edit()
            .putBoolean(AUTO_APPLY_MODULES, enabled)
            .apply()
    }

    fun autoRootOnBoot(context: Context): Boolean =
        prefs(context).getBoolean(AUTO_ROOT_BOOT, false)

    fun setAutoRootOnBoot(context: Context, enabled: Boolean) {
        prefs(context).edit()
            .putBoolean(AUTO_ROOT_BOOT, enabled)
            .apply()
    }

    fun adbPaired(context: Context): Boolean =
        prefs(context).getBoolean(ADB_PAIRED, false)

    fun setAdbPaired(context: Context, paired: Boolean) {
        prefs(context).edit()
            .putBoolean(ADB_PAIRED, paired)
            .apply()
    }

    /** Consecutive failed auto-root boots that ended in a retry reboot. */
    fun bootRetryCount(context: Context): Int =
        prefs(context).getInt(BOOT_RETRY_COUNT, 0)

    fun setBootRetryCount(context: Context, count: Int) {
        prefs(context).edit().putInt(BOOT_RETRY_COUNT, count).apply()
    }

    @Synchronized
    fun consumeInstallRequest(context: Context, requestId: String?): Boolean {
        if (requestId.isNullOrBlank()) return false
        val preferences = prefs(context)
        if (preferences.getString(CONSUMED_INSTALL_REQUEST, null) == requestId) return false
        return preferences.edit()
            .putString(CONSUMED_INSTALL_REQUEST, requestId)
            .commit()
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun languageTag(context: Context): String {
        val locales = context.getSystemService(LocaleManager::class.java).applicationLocales
        return if (locales.isEmpty) "" else locales[0].toLanguageTag()
    }

    fun setLanguage(context: Context, languageTag: String) {
        context.getSystemService(LocaleManager::class.java).applicationLocales =
            LocaleList.forLanguageTags(languageTag)
    }
}
