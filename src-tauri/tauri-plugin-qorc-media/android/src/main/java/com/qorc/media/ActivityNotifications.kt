package com.qorc.media

import android.app.NotificationChannel
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

object ActivityNotifications {
    private const val CHANNEL = "qorc-activity"
    internal const val ID = 4219
    private var foreground = false

    @Synchronized
    fun setForeground(context: Context, visible: Boolean) {
        foreground = visible
        if (visible) clear(context)
    }

    @Synchronized
    fun clear(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.cancel(ID)
        manager.activeNotifications
            .filter { it.notification.flags and Notification.FLAG_ONGOING_EVENT == 0 }
            .forEach { manager.cancel(it.tag, it.id) }
    }

    @Synchronized
    fun show(context: Context): Boolean {
        if (foreground || !NotificationManagerCompat.from(context).areNotificationsEnabled()) return false
        val manager = context.getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, "Messages and activity", NotificationManager.IMPORTANCE_DEFAULT)
            )
            if (manager.getNotificationChannel(CHANNEL)?.importance == NotificationManager.IMPORTANCE_NONE) return false
        }
       
        val previous = manager.activeNotifications.firstOrNull { it.id == ID && it.tag == null }
        val count = ((previous?.notification?.number ?: 0).toLong() + 1).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        val launch = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return false
        launch.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val open = PendingIntent.getActivity(context, ID, launch,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val title = if (count == 1) "New Qorc activity" else "$count new Qorc activities"
        val notification = NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(android.R.drawable.sym_action_chat)
            .setContentTitle(title)
            .setContentText("Open Qorc to view it")
            .setNumber(count)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setOnlyAlertOnce(true)
            .setAutoCancel(true)
            .setContentIntent(open)
            .build()
        manager.notify(ID, notification)
        return true
    }
}
