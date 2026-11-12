package com.qorc.media

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.*
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class CallService : Service() {
    @Volatile private var expectedStop = false
    private var wake: PowerManager.WakeLock? = null
    private val handler = Handler(Looper.getMainLooper())
    private val renew =
        object : Runnable {
            override fun run() {
                wake?.acquire(10 * 60 * 1000L)
                handler.postDelayed(this, 5 * 60 * 1000L)
            }
        }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        current = this
        wake =
            (getSystemService(Context.POWER_SERVICE) as PowerManager)
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Qorc:active-call")
                .apply { setReferenceCounted(false) }
        handler.post(renew)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            expectedStop = true
            Thread { MediaRuntime.shutdown(applicationContext) }.start()
            stopSelf()
            return START_NOT_STICKY
        }
        expectedStop = false
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                    .createNotificationChannel(
                        NotificationChannel(
                            "qorc-calls",
                            "Active Qorc calls",
                            NotificationManager.IMPORTANCE_LOW,
                        )
                    )
            }
            val launch = packageManager.getLaunchIntentForPackage(packageName)
            val open =
                launch?.let {
                    PendingIntent.getActivity(
                        this,
                        0,
                        it,
                        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                    )
                }
            val stop =
                PendingIntent.getService(
                    this,
                    1,
                    Intent(this, CallService::class.java).setAction("STOP"),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                )
            val notification =
                NotificationCompat.Builder(this, "qorc-calls")
                    .setSmallIcon(android.R.drawable.sym_call_incoming)
                    .setContentTitle("Qorc call in progress")
                    .setContentText("Tap to return to Qorc")
                    .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                    .setOngoing(true)
                    .setContentIntent(open)
                    .addAction(android.R.drawable.ic_menu_close_clear_cancel, "End media", stop)
                    .build()
            if (Build.VERSION.SDK_INT >= 29) {
                val requested = intent?.getIntExtra("types", 0) ?: 0
                val supported =
                    if (Build.VERSION.SDK_INT >= 30) requested
                    else
                        requested and
                            (android.content.pm.ServiceInfo
                                .FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK or
                                android.content.pm.ServiceInfo
                                    .FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION)
                startForeground(4217, notification, supported)
            } else startForeground(4217, notification)
            failure = null
        } catch (e: Exception) {
            failure = e
            stopSelf()
        } finally {
            ready.countDown()
        }
        return START_NOT_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        if (BackgroundRuntime.enabled(applicationContext) && BackgroundRuntime.hasRuntime()) return
        expectedStop = true
        Thread { MediaRuntime.shutdown(applicationContext) }.start()
        stopSelf()
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        wake?.let { if (it.isHeld) it.release() }
        wake = null
        if (current === this) current = null
        if (!expectedStop) Thread { MediaRuntime.shutdown(applicationContext) }.start()
        super.onDestroy()
    }

    companion object {
        @Volatile private var current: CallService? = null

        fun stop(ctx: Context) {
            current?.expectedStop = true
            ctx.stopService(Intent(ctx, CallService::class.java))
        }

        @Volatile private var ready = CountDownLatch(1)
        @Volatile private var failure: Exception? = null

        fun ensure(ctx: Context, types: Int) {
            ready = CountDownLatch(1)
            failure = null
            ContextCompat.startForegroundService(
                ctx,
                Intent(ctx, CallService::class.java).putExtra("types", types),
            )
            check(ready.await(5, TimeUnit.SECONDS)) { "Call foreground service timed out" }
            failure?.let { throw it }
        }
    }
}
