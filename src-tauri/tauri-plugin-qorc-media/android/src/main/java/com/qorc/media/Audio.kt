package com.qorc.media

import android.content.Context
import android.media.*
import android.media.audiofx.AcousticEchoCanceler
import android.media.audiofx.NoiseSuppressor
import android.os.Build
import android.os.Process
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

internal class Microphone(ctx: Context, deviceId: String?) : AutoCloseable {
    val slot = FrameSlot()
    private val running = AtomicBoolean(true)
    private val record = run {
        if (
            ctx.checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) !=
                android.content.pm.PackageManager.PERMISSION_GRANTED
        )
            throw SecurityException("Microphone permission was not granted")
        try {
            AudioRecord.Builder()
                .setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
                .setAudioFormat(
                    AudioFormat.Builder()
                        .setSampleRate(48000)
                        .setChannelMask(AudioFormat.CHANNEL_IN_MONO)
                        .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                        .build()
                )
                .setBufferSizeInBytes(
                    maxOf(
                        AudioRecord.getMinBufferSize(
                            48000,
                            AudioFormat.CHANNEL_IN_MONO,
                            AudioFormat.ENCODING_PCM_16BIT,
                        ),
                        960 * 2 * 4,
                    )
                )
                .build()
        } catch (_: SecurityException) {
            throw IllegalStateException("Microphone permission was revoked")
        }
    }
    private val echo =
        runCatching {
                if (AcousticEchoCanceler.isAvailable())
                    AcousticEchoCanceler.create(record.audioSessionId)?.apply { enabled = true }
                else null
            }
            .getOrNull()
    private val noise =
        runCatching {
                if (NoiseSuppressor.isAvailable())
                    NoiseSuppressor.create(record.audioSessionId)?.apply { enabled = true }
                else null
            }
            .getOrNull()
    private val thread: Thread

    init {
        try {
            check(record.state == AudioRecord.STATE_INITIALIZED)
            MediaRuntime.audioDevice(ctx, deviceId, true)?.let {
                check(record.setPreferredDevice(it))
            }
            record.startRecording()
            check(record.recordingState == AudioRecord.RECORDSTATE_RECORDING)
        } catch (e: Exception) {
            echo?.release()
            noise?.release()
            record.release()
            throw e
        }
        thread =
            Thread(
                    {
                        Process.setThreadPriority(Process.THREAD_PRIORITY_AUDIO)
                        val samples = ShortArray(960)
                        try {
                            while (running.get()) {
                                var offset = 0
                                while (offset < 960 && running.get()) {
                                    val n =
                                        record.read(
                                            samples,
                                            offset,
                                            960 - offset,
                                            AudioRecord.READ_BLOCKING,
                                        )
                                    check(n > 0) { "Microphone disconnected" }
                                    offset += n
                                }
                                if (!running.get()) break
                                val buffer =
                                    ByteBuffer.allocate(960 * 4).order(ByteOrder.LITTLE_ENDIAN)
                                for (s in samples) buffer.putFloat(
                                    if (slot.enabled) s.toFloat() / 32768f else 0f
                                )
                                samples.fill(0)
                                slot.offer(buffer.array())
                            }
                        } catch (_: Exception) {
                            if (running.get()) slot.failure = "Microphone recording interrupted"
                        } finally {
                            samples.fill(0)
                            try {
                                record.stop()
                            } catch (_: Exception) {}
                            echo?.release()
                            noise?.release()
                            record.release()
                            slot.clear()
                        }
                    },
                    "qorc-android-microphone",
                )
                .apply { start() }
    }

    override fun close() {
        if (!running.getAndSet(false)) return
        try {
            record.stop()
        } catch (_: Exception) {}
        thread.join(1500)
        slot.clear()
    }
}

internal class Playback(private val ctx: Context, deviceId: String?) : AutoCloseable {
    private val running = AtomicBoolean(true)
    private val queue = ArrayBlockingQueue<ByteArray>(10)
    private val manager = ctx.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    private var routingAcquired = false
    private val attributes =
        AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
            .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
            .build()
    private val track =
        AudioTrack.Builder()
            .setAudioAttributes(attributes)
            .setAudioFormat(
                AudioFormat.Builder()
                    .setSampleRate(48000)
                    .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                    .setEncoding(AudioFormat.ENCODING_PCM_FLOAT)
                    .build()
            )
            .setTransferMode(AudioTrack.MODE_STREAM)
            .setBufferSizeInBytes(
                maxOf(
                    AudioTrack.getMinBufferSize(
                        48000,
                        AudioFormat.CHANNEL_OUT_MONO,
                        AudioFormat.ENCODING_PCM_FLOAT,
                    ),
                    960 * 4 * 4,
                )
            )
            .build()
    private val thread: Thread

    init {
        try {
            check(track.state == AudioTrack.STATE_INITIALIZED)
            AudioRouting.acquire(ctx, attributes)
            routingAcquired = true
            MediaRuntime.audioDevice(ctx, deviceId, false)?.let {
                check(track.setPreferredDevice(it))
                if (
                    Build.VERSION.SDK_INT >= 31 &&
                        manager.availableCommunicationDevices.any { d -> d.id == it.id }
                )
                    check(manager.setCommunicationDevice(it))
                else if (Build.VERSION.SDK_INT < 31) {
                    @Suppress("DEPRECATION")
                    manager.isSpeakerphoneOn = it.type == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER
                    if (it.type == AudioDeviceInfo.TYPE_BLUETOOTH_SCO) {
                        @Suppress("DEPRECATION") manager.startBluetoothSco()
                        @Suppress("DEPRECATION")
                        manager.isBluetoothScoOn = true
                    }
                }
            }
            track.play()
        } catch (e: Exception) {
            track.release()
            restore()
            throw e
        }
        thread =
            Thread(
                    {
                        Process.setThreadPriority(Process.THREAD_PRIORITY_AUDIO)
                        val samples = FloatArray(960)
                        try {
                            while (running.get()) {
                                val bytes = queue.poll(100, TimeUnit.MILLISECONDS) ?: continue
                                ByteBuffer.wrap(bytes)
                                    .order(ByteOrder.LITTLE_ENDIAN)
                                    .asFloatBuffer()
                                    .get(samples)
                                bytes.fill(0)
                                for (i in samples.indices) samples[i] =
                                    if (samples[i].isFinite()) samples[i].coerceIn(-1f, 1f) else 0f
                                var offset = 0
                                while (offset < samples.size && running.get()) {
                                    val n =
                                        track.write(
                                            samples,
                                            offset,
                                            samples.size - offset,
                                            AudioTrack.WRITE_BLOCKING,
                                        )
                                    check(n > 0)
                                    offset += n
                                }
                                samples.fill(0f)
                            }
                        } catch (_: Exception) {
                            running.set(false)
                        } finally {
                            samples.fill(0f)
                            try {
                                track.stop()
                            } catch (_: Exception) {}
                            track.release()
                            restore()
                            clear()
                        }
                    },
                    "qorc-android-playback",
                )
                .apply { start() }
    }

    private fun restore() {
        if (routingAcquired) {
            routingAcquired = false
            AudioRouting.release()
        }
    }

    private fun clear() {
        while (true) (queue.poll() ?: break).fill(0)
    }

    fun push(bytes: ByteArray) {
        check(running.get()) { "Audio output interrupted" }
        if (!queue.offer(bytes)) {
            queue.poll()?.fill(0)
            if (!queue.offer(bytes)) bytes.fill(0)
        }
    }

    override fun close() {
        running.set(false)
        try {
            track.stop()
        } catch (_: Exception) {}
        thread.join(1500)
        clear()
    }
}

internal object AudioRouting {
    @Volatile private var token: Any? = null
    private var count = 0
    private var manager: AudioManager? = null
    private var previousMode = AudioManager.MODE_NORMAL
    private var previousSpeaker = false
    private var previousSco = false
    private var focus: AudioFocusRequest? = null
    private var listener: AudioManager.OnAudioFocusChangeListener? = null

    @Synchronized
    fun acquire(ctx: Context, attributes: AudioAttributes) {
        if (count > 0) {
            count++
            return
        }
        val audio = ctx.getSystemService(Context.AUDIO_SERVICE) as AudioManager
        manager = audio
        previousMode = audio.mode
        @Suppress("DEPRECATION")
        previousSpeaker = audio.isSpeakerphoneOn
        @Suppress("DEPRECATION")
        previousSco = audio.isBluetoothScoOn
        val currentToken = Any()
        token = currentToken
        val callback =
            AudioManager.OnAudioFocusChangeListener { change ->
                if (
                    change == AudioManager.AUDIOFOCUS_LOSS ||
                        change == AudioManager.AUDIOFOCUS_LOSS_TRANSIENT
                ) {
                    Thread {
                            if (token === currentToken)
                                MediaRuntime.shutdown(ctx.applicationContext)
                        }
                        .start()
                }
            }
        listener = callback
        try {
            audio.mode = AudioManager.MODE_IN_COMMUNICATION
            if (Build.VERSION.SDK_INT >= 26) {
                focus =
                    AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN_TRANSIENT)
                        .setAudioAttributes(attributes)
                        .setOnAudioFocusChangeListener(
                            callback,
                            android.os.Handler(android.os.Looper.getMainLooper()),
                        )
                        .build()
                check(audio.requestAudioFocus(focus!!) == AudioManager.AUDIOFOCUS_REQUEST_GRANTED)
            } else {
                @Suppress("DEPRECATION")
                check(
                    audio.requestAudioFocus(
                        callback,
                        AudioManager.STREAM_VOICE_CALL,
                        AudioManager.AUDIOFOCUS_GAIN_TRANSIENT,
                    ) == AudioManager.AUDIOFOCUS_REQUEST_GRANTED
                )
            }
            count = 1
        } catch (e: Exception) {
            restore(audio)
            throw e
        }
    }

    @Synchronized
    fun release() {
        if (count <= 0) return
        count--
        if (count == 0) manager?.let { restore(it) }
    }

    private fun restore(audio: AudioManager) {
        token = null
        runCatching {
            if (Build.VERSION.SDK_INT >= 31) audio.clearCommunicationDevice()
            else {
                @Suppress("DEPRECATION") audio.stopBluetoothSco()
                @Suppress("DEPRECATION")
                audio.isBluetoothScoOn = previousSco
                @Suppress("DEPRECATION")
                audio.isSpeakerphoneOn = previousSpeaker
            }
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= 26) focus?.let { audio.abandonAudioFocusRequest(it) }
            else {
                @Suppress("DEPRECATION") audio.abandonAudioFocus(listener)
            }
        }
        runCatching { audio.mode = previousMode }
        focus = null
        listener = null
        manager = null
    }
}
