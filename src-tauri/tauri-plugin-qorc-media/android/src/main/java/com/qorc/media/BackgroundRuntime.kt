package com.qorc.media

import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import java.lang.ref.WeakReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

object BackgroundRuntime {
    interface EngineOwner { fun shutdownEngine() }
    private const val PREFS = "qorc-background-runtime"
    private const val ENABLED = "enabled"
    @Volatile private var runtime = WeakReference<Activity>(null)
    @Volatile private var launcher = WeakReference<Activity>(null)
    @Volatile private var quitting = false
    @Volatile private var engineAlive = false

    fun enabled(ctx: Context): Boolean = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(ENABLED, true)
    fun hasRuntime(): Boolean = engineAlive && runtime.get() != null && !quitting
    fun isQuitting(): Boolean = quitting
    fun attachRuntime(activity: Activity) { runtime = WeakReference(activity); engineAlive = true; quitting = false }
    fun attachLauncher(activity: Activity) { launcher = WeakReference(activity) }

    fun detachLauncher(activity: Activity, removed: Boolean) {
        if (launcher.get() !== activity) return
        launcher.clear()
        if (removed && !enabled(activity.applicationContext)) quit(activity.applicationContext)
    }

    fun detachRuntime(activity: Activity) {
        if (runtime.get() !== activity) return
        runtime.clear()
        engineAlive = false
        BackgroundWork.clear()
        BackgroundService.stop(activity)
    }

    fun resume(activity: Activity) {
        if (!quitting && (enabled(activity) || BackgroundWork.hasActive())) {
            try { BackgroundService.start(activity.applicationContext) }
            catch (_: Exception) { /* backgroundSet reports foreground-start failures. */ }
        }
    }

    fun setEnabled(ctx: Context, value: Boolean): Boolean {
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val previous = enabled(ctx)
        try {
            synchronized(BackgroundWork) {
                check(prefs.edit().putBoolean(ENABLED, value).commit()) { "Unable to save background setting" }
                if (value) BackgroundService.start(ctx)
                else BackgroundService.stopIfIdle(ctx)
            }
            if (value) BackgroundService.ensure(ctx)
            return true
        } catch (error: Exception) {
            synchronized(BackgroundWork) {
                prefs.edit().putBoolean(ENABLED, previous).commit()
                if (!previous) BackgroundService.stopIfIdle(ctx)
            }
            throw error
        }
    }

    fun quit(ctx: Context) {
        if (quitting) return
        quitting = true
        BackgroundWork.clear()
        BackgroundService.stop(ctx)
        val engine = runtime.get()
        engine?.runOnUiThread {
            launcher.get()?.finishAndRemoveTask()
            if (!engine.isDestroyed && !engine.isFinishing) engine.finishAndRemoveTask()
            (engine as? EngineOwner)?.shutdownEngine()
        }
    }
}

class BackgroundService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "QUIT") {
            BackgroundRuntime.quit(applicationContext)
            stopSelf()
            return START_NOT_STICKY
        }
        if ((!BackgroundRuntime.enabled(this) && !BackgroundWork.hasActive()) || !BackgroundRuntime.hasRuntime()) {
            starting = false
            ready.countDown()
            stopSelf()
            return START_NOT_STICKY
        }
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                getSystemService(NotificationManager::class.java).createNotificationChannel(
                    NotificationChannel("qorc-background", "Background connection", NotificationManager.IMPORTANCE_LOW).apply {
                        description = "Connection status only. Message and call alerts use separate channels."
                        setShowBadge(false)
                    }
                )
            }
            val open = PendingIntent.getActivity(this, 31,
                packageManager.getLaunchIntentForPackage(packageName)!!,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            val quit = PendingIntent.getService(this, 32,
                Intent(this, BackgroundService::class.java).setAction("QUIT"),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            val notification = NotificationCompat.Builder(this, "qorc-background")
                .setSmallIcon(applicationInfo.icon)
                .setContentTitle("Qorc")
                .setContentText("Background connection")
                .setContentIntent(open)
                .setCategory(NotificationCompat.CATEGORY_SERVICE)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setOngoing(false)
                .setShowWhen(false)
                .setLocalOnly(true)
                .setSilent(true)
                .setOnlyAlertOnce(true)
                .setVisibility(NotificationCompat.VISIBILITY_SECRET)
           
            if (Build.VERSION.SDK_INT < 33) notification.addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", quit)
            val built = notification.build()
            if (Build.VERSION.SDK_INT >= 34) startForeground(4218, built, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            else startForeground(4218, built)
            running = true
            failure = null
        } catch (error: Exception) {
            failure = error
            stopSelf()
        } finally { starting = false; ready.countDown() }
       
        return START_NOT_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        if (!BackgroundRuntime.enabled(this)) BackgroundRuntime.quit(applicationContext)
        else if (!BackgroundRuntime.hasRuntime()) stopSelf()
    }

    override fun onDestroy() {
        running = false
        if (!BackgroundRuntime.hasRuntime()) BackgroundWork.clear()
        super.onDestroy()
    }

    companion object {
        @Volatile private var running = false
        @Volatile private var starting = false
        @Volatile private var ready = CountDownLatch(1)
        @Volatile private var failure: Exception? = null
        private val startLock = Any()

        fun start(ctx: Context): CountDownLatch = synchronized(startLock) {
            if (!running && !starting) {
                ready = CountDownLatch(1)
                starting = true
                failure = null
                try { ContextCompat.startForegroundService(ctx, Intent(ctx, BackgroundService::class.java)) }
                catch (error: Exception) {
                    starting = false
                    failure = error
                    ready.countDown()
                    throw error
                }
            }
            ready
        }

        fun stopIfIdle(ctx: Context) = synchronized(BackgroundWork) {
            if (!BackgroundRuntime.enabled(ctx) && !BackgroundWork.hasActive()) stop(ctx)
        }

        fun stop(ctx: Context) {
            running = false
            ctx.stopService(Intent(ctx, BackgroundService::class.java))
        }

        fun ensure(ctx: Context) {
            val pending = start(ctx)
            check(pending.await(5, TimeUnit.SECONDS)) { "Android background service timed out" }
            failure?.let { throw it }
            check(running) { "Android background service did not start" }
        }
    }
}
