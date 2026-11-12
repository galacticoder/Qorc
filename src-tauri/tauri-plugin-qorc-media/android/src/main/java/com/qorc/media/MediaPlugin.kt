package com.qorc.media

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.media.projection.MediaProjectionManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.result.ActivityResult
import app.tauri.PermissionState
import app.tauri.annotation.*
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin
import java.util.concurrent.Executors

@TauriPlugin(
    permissions =
        [
            Permission(strings = [Manifest.permission.RECORD_AUDIO], alias = "microphone"),
            Permission(strings = [Manifest.permission.CAMERA], alias = "camera"),
            Permission(strings = [Manifest.permission.BLUETOOTH_CONNECT], alias = "bluetooth"),
        ]
)
class MediaPlugin(private val activity: Activity) : Plugin(activity) {
    private val executor = Executors.newFixedThreadPool(3)
    private val runtime
        get() = MediaRuntime

    private var projectionPending = false
    private var backgroundSettingsPending = false
    private var projectionInvoke: Invoke? = null
    private var settingsInvoke: Invoke? = null
    private var permissionInvoke: Invoke? = null

    @Command
    fun execute(invoke: Invoke) {
        val op = invoke.getArgs().optString("op")
        when (op) {
            "activityNotification" -> {
                try { invoke.resolveObject(ActivityNotifications.show(activity.applicationContext)) }
                catch (_: Exception) { invoke.reject("Android activity notification failed") }
            }
            "workBegin", "workEnd" -> executor.execute {
                try {
                    if (op == "workBegin") invoke.resolveObject(BackgroundWork.begin(activity.applicationContext))
                    else { BackgroundWork.end(activity.applicationContext, invoke.getArgs().getString("id")); invoke.resolveObject(true) }
                } catch (_: Exception) { invoke.reject("Android background work failed") }
            }
            "backgroundGet" -> executor.execute {
                try {
                    val enabled = BackgroundRuntime.enabled(activity.applicationContext)
                    if (enabled) BackgroundService.ensure(activity.applicationContext)
                    invoke.resolveObject(enabled)
                } catch (_: Exception) { invoke.reject("Android could not start background mode") }
            }
            "backgroundSet" -> executor.execute {
                try { invoke.resolveObject(BackgroundRuntime.setEnabled(activity.applicationContext, invoke.getArgs().getBoolean("enabled"))) }
                catch (_: Exception) { invoke.reject("Android could not update background mode") }
            }
            "backgroundNoticeSettings" -> {
                if (backgroundSettingsPending) {
                    invoke.reject("Android notification settings already open")
                    return
                }
                val intent = if (Build.VERSION.SDK_INT >= 26) {
                    Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                        .putExtra(Settings.EXTRA_APP_PACKAGE, activity.packageName)
                        .putExtra(Settings.EXTRA_CHANNEL_ID, "qorc-background")
                } else Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.parse("package:${activity.packageName}"))
                backgroundSettingsPending = true
                settingsInvoke = invoke
                try { startActivityForResult(invoke, intent, "backgroundNoticeSettingsResult") }
                catch (_: Exception) {
                    backgroundSettingsPending = false
                    settingsInvoke = null
                    invoke.reject("Android notification settings could not be opened")
                }
            }
            "permission" -> requestAccess(invoke)
            "screenStart" -> {
                if (projectionPending) {
                    invoke.reject("Screen permission request already pending")
                    return
                }
                projectionPending = true
                projectionInvoke = invoke
                val manager =
                    activity.getSystemService(Context.MEDIA_PROJECTION_SERVICE)
                        as MediaProjectionManager
                startActivityForResult(
                    invoke,
                    manager.createScreenCaptureIntent(),
                    "projectionResult",
                )
            }
            else ->
                executor.execute {
                    try {
                        invoke.resolveObject(
                            runtime.execute(activity.applicationContext, invoke.getArgs())
                        )
                    } catch (_: Exception) {
                        invoke.reject("Android media operation failed: $op")
                    }
                }
        }
    }

    @ActivityCallback
    fun backgroundNoticeSettingsResult(invoke: Invoke, result: ActivityResult) {
        if (settingsInvoke !== invoke) return
        settingsInvoke = null
        backgroundSettingsPending = false
        invoke.resolveObject(true)
    }

    private fun aliases(invoke: Invoke): Array<String> {
        return when (invoke.getArgs().optString("kind")) {
            "audio",
            "microphone" -> arrayOf("microphone")
            "video",
            "camera" -> arrayOf("camera")
            "audio-video",
            "microphone-camera" -> arrayOf("microphone", "camera")
            "bluetooth" -> if (Build.VERSION.SDK_INT >= 31) arrayOf("bluetooth") else emptyArray()
            "enumerate" -> emptyArray()
            else -> throw IllegalArgumentException("Invalid media permission kind")
        }
    }

    private fun requestAccess(invoke: Invoke) {
        try {
            val requested = aliases(invoke)
            if (requested.all { getPermissionState(it) == PermissionState.GRANTED }) {
                invoke.resolveObject(true)
            } else {
                if (permissionInvoke != null) { invoke.reject("Android permission request already pending"); return }
                permissionInvoke = invoke
                requestPermissionForAliases(requested, invoke, "permissionResult")
            }
        } catch (_: Exception) {
            if (permissionInvoke === invoke) permissionInvoke = null
            invoke.reject("Invalid media permission request")
        }
    }

    @PermissionCallback
    fun permissionResult(invoke: Invoke) {
        if (permissionInvoke !== invoke) return
        permissionInvoke = null
        invoke.resolveObject(
            aliases(invoke).all { getPermissionState(it) == PermissionState.GRANTED }
        )
    }

    @ActivityCallback
    fun projectionResult(invoke: Invoke, result: ActivityResult) {
        if (projectionInvoke !== invoke) return
        projectionInvoke = null
        val data = result.data
        if (result.resultCode != Activity.RESULT_OK || data == null) {
            projectionPending = false
            invoke.reject("Screen sharing permission was not granted")
            return
        }
        executor.execute {
            try {
                runtime.startScreen(
                    activity.applicationContext,
                    invoke.getArgs(),
                    result.resultCode,
                    data,
                )
                invoke.resolveObject(true)
            } catch (_: Exception) {
                invoke.reject("Screen sharing failed to start")
            } finally {
                activity.runOnUiThread { projectionPending = false }
            }
        }
    }

    override fun onDestroy() {
        detachUiRequests()
        Thread { runtime.shutdown(activity.applicationContext) }.start()
        executor.shutdownNow()
        super.onDestroy()
    }

    /** Close UI requests without terminating an active background call. */
    fun detachUiRequests() {
        permissionInvoke?.reject("Android permission window was closed")
        projectionInvoke?.reject("Android screen sharing consent was closed")
        settingsInvoke?.reject("Android notification settings were closed")
        permissionInvoke = null; projectionInvoke = null; settingsInvoke = null
        projectionPending = false; backgroundSettingsPending = false
    }

    /** A new visible Activity owns subsequent commands; old commands may finish. */
    fun retireUiBinding() {
        detachUiRequests()
        executor.shutdown()
    }
}
