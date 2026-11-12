package com.qorc.media

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.hardware.camera2.CameraManager
import android.media.*
import android.os.Build
import android.util.Base64
import app.tauri.plugin.JSObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

internal class FrameSlot {
    @Volatile var enabled = true
    @Volatile var failure: String? = null
    private var bytes: ByteArray? = null
    private var metadata: Map<String, Any> = emptyMap()
    private val sequence = AtomicLong()

    @Synchronized
    fun offer(data: ByteArray, width: Int = 0, height: Int = 0, fps: Int = 0) {
        if (data.size > 4 * 1024 * 1024) {
            data.fill(0)
            throw IllegalArgumentException("Media frame too large")
        }
        if (failure != null) {
            data.fill(0)
            return
        }
        bytes?.fill(0)
        if (!enabled && width > 0) {
            data.fill(0)
            bytes = null
            return
        }
        if (!enabled) data.fill(0)
        bytes = data
        metadata =
            mapOf(
                "sequence" to sequence.updateAndGet { if (it >= 0xffffffffL) 1 else it + 1 },
                "capturedAt" to System.currentTimeMillis(),
                "enabled" to enabled,
                "width" to width,
                "height" to height,
                "frameRate" to fps,
            )
    }

    @Synchronized
    fun take(): Map<String, Any>? {
        failure?.let {
            clear()
            throw IllegalStateException(it)
        }
        val data = bytes ?: return null
        bytes = null
        val result = metadata + ("bytes" to Base64.encodeToString(data, Base64.NO_WRAP))
        data.fill(0)
        return result
    }

    @Synchronized
    fun clear() {
        bytes?.fill(0)
        bytes = null
    }
}

internal object MediaRuntime {
    private val playbackType
        get() =
            if (Build.VERSION.SDK_INT >= 29) ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
            else 0

    private val microphoneType
        get() =
            if (Build.VERSION.SDK_INT >= 30) ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else 0

    private val cameraType
        get() = if (Build.VERSION.SDK_INT >= 30) ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA else 0

    private val screenType
        get() =
            if (Build.VERSION.SDK_INT >= 29) ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION
            else 0

    val microphones = ConcurrentHashMap<String, Microphone>()
    val outputs = ConcurrentHashMap<String, Playback>()
    val cameras = ConcurrentHashMap<String, CameraCapture>()
    val screens = ConcurrentHashMap<String, ScreenCapture>()
    private val tags = mutableMapOf<String, Int>()
    private val epoch = AtomicLong()
    private val shuttingDown = java.util.concurrent.atomic.AtomicBoolean(false)
    private val serviceLock = Any()
    private val cancelled = ConcurrentHashMap.newKeySet<String>()

    private fun cancel(id: String) {
        if (cancelled.size > 128) cancelled.clear()
        cancelled.add(id)
    }

    private fun id(a: JSObject): String =
        a.optString("id").also { require(it.matches(Regex("[A-Za-z0-9_-]{1,128}"))) }

    fun permission(ctx: Context, permission: String) =
        ctx.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED

    private fun bt(device: AudioDeviceInfo) =
        device.type in
            listOf(AudioDeviceInfo.TYPE_BLUETOOTH_SCO, AudioDeviceInfo.TYPE_BLUETOOTH_A2DP, 26, 27)

    private fun audioDeviceLabel(device: AudioDeviceInfo, input: Boolean): String {
        val endpoint = if (input) "microphone" else "speaker"
        val route = when (device.type) {
            AudioDeviceInfo.TYPE_BUILTIN_MIC -> "Built-in microphone"
            AudioDeviceInfo.TYPE_BUILTIN_EARPIECE -> "Phone earpiece"
            AudioDeviceInfo.TYPE_BUILTIN_SPEAKER -> "Phone speaker"
            AudioDeviceInfo.TYPE_BUILTIN_SPEAKER_SAFE -> "Phone speaker (safe)"
            AudioDeviceInfo.TYPE_WIRED_HEADSET -> if (input) "Wired headset microphone" else "Wired headset"
            AudioDeviceInfo.TYPE_WIRED_HEADPHONES -> "Wired headphones"
            AudioDeviceInfo.TYPE_BLUETOOTH_SCO -> "Bluetooth headset $endpoint"
            AudioDeviceInfo.TYPE_BLUETOOTH_A2DP -> "Bluetooth headphones"
            AudioDeviceInfo.TYPE_BLE_HEADSET -> "Bluetooth LE headset $endpoint"
            AudioDeviceInfo.TYPE_BLE_SPEAKER -> "Bluetooth LE speaker"
            AudioDeviceInfo.TYPE_HEARING_AID -> "Hearing aid"
            AudioDeviceInfo.TYPE_USB_DEVICE, AudioDeviceInfo.TYPE_USB_ACCESSORY,
            AudioDeviceInfo.TYPE_USB_HEADSET -> "USB $endpoint"
            AudioDeviceInfo.TYPE_HDMI -> "HDMI"
            AudioDeviceInfo.TYPE_HDMI_ARC -> "HDMI ARC"
            AudioDeviceInfo.TYPE_HDMI_EARC -> "HDMI eARC"
            AudioDeviceInfo.TYPE_TELEPHONY -> "Telephony $endpoint"
            AudioDeviceInfo.TYPE_BUS -> "Audio bus $endpoint"
            AudioDeviceInfo.TYPE_REMOTE_SUBMIX -> "System mix $endpoint"
            AudioDeviceInfo.TYPE_LINE_ANALOG -> "Analog line $endpoint"
            AudioDeviceInfo.TYPE_LINE_DIGITAL -> "Digital line $endpoint"
            AudioDeviceInfo.TYPE_DOCK -> "Dock $endpoint"
            AudioDeviceInfo.TYPE_FM, AudioDeviceInfo.TYPE_FM_TUNER -> "FM audio"
            AudioDeviceInfo.TYPE_TV_TUNER -> "TV audio"
            else -> if (input) "Microphone" else "Speaker"
        }
        if (device.type in listOf(AudioDeviceInfo.TYPE_BUILTIN_MIC, AudioDeviceInfo.TYPE_BUILTIN_EARPIECE,
                AudioDeviceInfo.TYPE_BUILTIN_SPEAKER, AudioDeviceInfo.TYPE_BUILTIN_SPEAKER_SAFE,
                AudioDeviceInfo.TYPE_TELEPHONY, AudioDeviceInfo.TYPE_BUS, AudioDeviceInfo.TYPE_REMOTE_SUBMIX)) return route
        val product = device.productName.toString().filter { !it.isISOControl() }.trim().take(100)
        return if (product.isEmpty() || product.equals(route, ignoreCase = true)) route else "$product · $route"
    }

    fun audioDevices(ctx: Context, input: Boolean): List<Map<String, String>> {
        val manager = ctx.getSystemService(Context.AUDIO_SERVICE) as AudioManager
        return manager
            .getDevices(
                if (input) AudioManager.GET_DEVICES_INPUTS else AudioManager.GET_DEVICES_OUTPUTS
            )
            .filter {
                !bt(it) ||
                    Build.VERSION.SDK_INT < 31 ||
                    permission(ctx, Manifest.permission.BLUETOOTH_CONNECT)
            }
            .distinctBy { it.id }
            .take(32)
            .map {
                val direction = if (input) "input" else "output"
                mapOf(
                    "device_id" to "android-$direction${if(bt(it)) "-bt" else ""}:${it.id}",
                    "label" to audioDeviceLabel(it, input),
                )
            }
    }

    fun audioDevice(ctx: Context, id: String?, input: Boolean): AudioDeviceInfo? {
        if (id.isNullOrEmpty()) return null
        val manager = ctx.getSystemService(Context.AUDIO_SERVICE) as AudioManager
        return manager
            .getDevices(
                if (input) AudioManager.GET_DEVICES_INPUTS else AudioManager.GET_DEVICES_OUTPUTS
            )
            .firstOrNull { it.id == id.substringAfterLast(':').toIntOrNull() }
            ?: throw IllegalArgumentException("Selected audio device disconnected")
    }

    fun cameraDevices(ctx: Context): List<Map<String, String>> {
        val manager = ctx.getSystemService(Context.CAMERA_SERVICE) as CameraManager
        return manager.cameraIdList.take(32).map { id ->
            val facing =
                manager
                    .getCameraCharacteristics(id)
                    .get(android.hardware.camera2.CameraCharacteristics.LENS_FACING)
            mapOf(
                "device_id" to "android-camera:$id",
                "label" to
                    when (facing) {
                        0 -> "Front camera"
                        1 -> "Rear camera"
                        else -> "Camera $id"
                    },
            )
        }
    }

    fun activate(ctx: Context, tag: String, type: Int) =
        synchronized(serviceLock) {
            check(!shuttingDown.get()) { "Call media is shutting down" }
            tags[tag] = type
            try {
                CallService.ensure(ctx, tags.values.fold(0) { a, b -> a or b })
            } catch (e: Exception) {
                tags.remove(tag)
                throw e
            }
        }

    fun deactivate(ctx: Context, tag: String) =
        synchronized(serviceLock) {
            tags.remove(tag)
            if (tags.isEmpty()) CallService.stop(ctx)
            else CallService.ensure(ctx, tags.values.fold(0) { a, b -> a or b })
        }

    fun execute(ctx: Context, a: JSObject): Any {
        val op = a.optString("op")
        if (op == "microphoneDevices") return mapOf("devices" to audioDevices(ctx, true))
        if (op == "outputDevices") return mapOf("devices" to audioDevices(ctx, false))
        if (op == "cameraDevices") return mapOf("devices" to cameraDevices(ctx))
        if (op == "callAcquire") {
            activate(ctx, "call", playbackType)
            return true
        }
        if (op == "callRelease") {
            deactivate(ctx, "call")
            return true
        }
        val id = id(a)
        val startedEpoch = epoch.get()
        when (op) {
            "microphoneStart" -> {
                check(permission(ctx, Manifest.permission.RECORD_AUDIO))
                require(microphones.size < 2 && !microphones.containsKey(id))
                activate(ctx, "mic:$id", microphoneType)
                try {
                    val microphone =
                        Microphone(ctx, a.optString("deviceId").takeIf { it.isNotEmpty() })
                    microphones[id] = microphone
                    if (epoch.get() != startedEpoch) {
                        microphones.remove(id)?.close()
                        error("Call cancelled")
                    }
                } catch (e: Exception) {
                    deactivate(ctx, "mic:$id")
                    throw e
                }
            }
            "microphonePoll" ->
                return mapOf(
                    "frame" to (microphones[id] ?: error("Microphone stopped")).slot.take()
                )
            "microphoneEnabled" ->
                (microphones[id] ?: error("Microphone stopped")).slot.apply {
                    enabled = a.optBoolean("enabled")
                    clear()
                }
            "microphoneStop" -> {
                microphones.remove(id)?.close()
                deactivate(ctx, "mic:$id")
            }
            "playbackStart" -> {
                require(outputs.size < 2 && !outputs.containsKey(id))
                activate(ctx, "audio:$id", playbackType)
                try {
                    val playback = Playback(ctx, a.optString("deviceId").takeIf { it.isNotEmpty() })
                    outputs[id] = playback
                    if (epoch.get() != startedEpoch) {
                        outputs.remove(id)?.close()
                        error("Call cancelled")
                    }
                } catch (e: Exception) {
                    deactivate(ctx, "audio:$id")
                    throw e
                }
            }
            "playbackWrite" -> {
                val encoded = a.optString("bytes")
                require(encoded.length <= 5120)
                val data = Base64.decode(encoded, Base64.NO_WRAP)
                require(data.size == 960 * 4)
                (outputs[id] ?: error("Audio output stopped")).push(data)
            }
            "playbackStop" -> {
                outputs.remove(id)?.close()
                deactivate(ctx, "audio:$id")
            }
            "cameraStart" -> {
                check(!cancelled.remove(id))
                check(permission(ctx, Manifest.permission.CAMERA))
                require(cameras.size < 2 && !cameras.containsKey(id))
                activate(ctx, "camera:$id", cameraType)
                try {
                    val capture = CameraCapture(ctx, a)
                    cameras[id] = capture
                    if (cancelled.remove(id) || epoch.get() != startedEpoch) {
                        cameras.remove(id)?.close()
                        error("Camera cancelled")
                    }
                    capture.awaitReady()
                } catch (e: Exception) {
                    cameras.remove(id)?.close()
                    deactivate(ctx, "camera:$id")
                    throw e
                }
            }
            "cameraPoll" ->
                return mapOf("frame" to (cameras[id] ?: error("Camera stopped")).slot.take())
            "cameraEnabled" ->
                (cameras[id] ?: error("Camera stopped")).slot.apply {
                    enabled = a.optBoolean("enabled")
                    clear()
                }
            "cameraStop" -> {
                val capture = cameras.remove(id)
                if (capture == null) cancel(id) else capture.close()
                deactivate(ctx, "camera:$id")
            }
            "screenPoll" ->
                return mapOf(
                    "frame" to (screens[id] ?: error("Screen sharing stopped")).slot.take()
                )
            "screenStop" -> {
                val capture = screens.remove(id)
                if (capture == null) cancel(id) else capture.close()
                deactivate(ctx, "screen:$id")
            }
            else -> error("Invalid media operation")
        }
        return true
    }

    fun startScreen(ctx: Context, args: JSObject, result: Int, data: Intent) {
        val id = id(args)
        val startedEpoch = epoch.get()
        check(!cancelled.remove(id))
        require(screens.isEmpty())
        activate(ctx, "screen:$id", screenType)
        try {
            val capture = ScreenCapture(ctx, result, data)
            screens[id] = capture
            if (cancelled.remove(id) || epoch.get() != startedEpoch) {
                screens.remove(id)?.close()
                error("Screen sharing cancelled")
            }
            capture.awaitReady()
        } catch (e: Exception) {
            screens.remove(id)?.close()
            deactivate(ctx, "screen:$id")
            throw e
        }
    }

    fun shutdown(ctx: Context) {
        if (!shuttingDown.compareAndSet(false, true)) return
        epoch.incrementAndGet()
        try {
            microphones.values.forEach { runCatching { it.close() } }
            microphones.clear()
            outputs.values.forEach { runCatching { it.close() } }
            outputs.clear()
            cameras.values.forEach { runCatching { it.close() } }
            cameras.clear()
            screens.values.forEach { runCatching { it.close() } }
            screens.clear()
            synchronized(serviceLock) { tags.clear() }
            CallService.stop(ctx)
        } finally {
            shuttingDown.set(false)
        }
    }
}
