package com.vs.vpn

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

class SettingsManager(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("vs_vpn_prefs", Context.MODE_PRIVATE)

    var server: String
        get() = prefs.getString(KEY_SERVER, "") ?: ""
        set(value) = prefs.edit { putString(KEY_SERVER, value) }

    var secret: String
        get() = prefs.getString(KEY_SECRET, "") ?: ""
        set(value) = prefs.edit { putString(KEY_SECRET, value) }

    var listen: String
        get() = prefs.getString(KEY_LISTEN, "127.0.0.1:1080") ?: "127.0.0.1:1080"
        set(value) = prefs.edit { putString(KEY_LISTEN, value) }

    companion object {
        private const val KEY_SERVER = "server"
        private const val KEY_SECRET = "secret"
        private const val KEY_LISTEN = "listen"
    }
}
