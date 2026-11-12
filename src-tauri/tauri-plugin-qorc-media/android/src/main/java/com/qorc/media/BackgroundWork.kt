package com.qorc.media

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import java.util.UUID

object BackgroundWork {
    private const val TIMEOUT_MS = 10 * 60 * 1000L
    private val handler = Handler(Looper.getMainLooper())
    private data class Lease(val lock: PowerManager.WakeLock, val expires: Long, val expiry: Runnable)
    private val leases = mutableMapOf<String, Lease>()

    fun begin(ctx: Context): String {
        val app = ctx.applicationContext
        val id = UUID.randomUUID().toString()
        synchronized(this) {
            check(BackgroundRuntime.hasRuntime() && !BackgroundRuntime.isQuitting()) { "Android runtime is stopping" }
            val now = SystemClock.elapsedRealtime()
            leases.entries.removeAll { (_, lease) ->
                if (lease.expires > now) false else {
                    handler.removeCallbacks(lease.expiry)
                    if (lease.lock.isHeld) lease.lock.release()
                    true
                }
            }
            check(leases.size < 8) { "Too many background operations" }
            val lock = (app.getSystemService(Context.POWER_SERVICE) as PowerManager)
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Qorc:authentication")
            lock.setReferenceCounted(false)
            val expiry = Runnable { end(app, id) }
            lock.acquire(TIMEOUT_MS)
            leases[id] = Lease(lock, now + TIMEOUT_MS, expiry)
            handler.postDelayed(expiry, TIMEOUT_MS)
            try {
                BackgroundService.start(app)
            } catch (error: Exception) {
                release(id)
                throw error
            }
        }
        try {
            BackgroundService.ensure(app)
        } catch (error: Exception) {
            end(app, id)
            throw error
        }
        return id
    }

    @Synchronized fun hasActive(): Boolean = leases.isNotEmpty()

    private fun release(id: String) {
        leases.remove(id)?.let {
            handler.removeCallbacks(it.expiry)
            if (it.lock.isHeld) it.lock.release()
        }
    }

    @Synchronized fun end(ctx: Context, id: String) {
        release(id)
        BackgroundService.stopIfIdle(ctx)
    }

    @Synchronized fun clear() {
        leases.keys.toList().forEach { release(it) }
    }
}
