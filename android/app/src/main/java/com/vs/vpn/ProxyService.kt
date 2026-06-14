package com.vs.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

class ProxyService : Service() {

    companion object {
        const val CHANNEL_ID = "vs_vpn_proxy"
        const val NOTIFICATION_ID = 1
        const val ACTION_START = "com.vs.vpn.START"
        const val ACTION_STOP = "com.vs.vpn.STOP"
        const val EXTRA_SERVER = "server"
        const val EXTRA_SECRET = "secret"
        const val EXTRA_LISTEN = "listen"
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val server = intent.getStringExtra(EXTRA_SERVER) ?: return START_NOT_STICKY
                val secret = intent.getStringExtra(EXTRA_SECRET)
                val listen = intent.getStringExtra(EXTRA_LISTEN) ?: "127.0.0.1:1080"

                startForeground(NOTIFICATION_ID, buildNotification("vs-vpn proxy starting..."))
                ProxyManager.start(server, secret, listen)
                updateNotification()
            }
            ACTION_STOP -> {
                ProxyManager.stop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        ProxyManager.stop()
        super.onDestroy()
    }

    private fun updateNotification() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        val text = if (ProxyManager.isRunning) "SOCKS5 proxy running on port ${ProxyManager.status.value.port}"
                   else "Proxy stopped"
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("vs-vpn")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN Proxy",
                NotificationManager.IMPORTANCE_LOW
            )
            val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }
}
