package com.qorc.media

import android.content.Context
import android.content.Intent
import android.graphics.*
import android.hardware.camera2.*
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.Image
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.view.Surface
import android.view.WindowManager
import app.tauri.plugin.JSObject
import java.io.ByteArrayOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

internal fun jpeg(bitmap: Bitmap, rotation: Int = 0): Triple<ByteArray, Int, Int> {
    var picture = bitmap
    if (rotation != 0)
        picture =
            Bitmap.createBitmap(
                bitmap,
                0,
                0,
                bitmap.width,
                bitmap.height,
                Matrix().apply { postRotate(rotation.toFloat()) },
                true,
            )
    val scale = min(1.0, min(1280.0 / picture.width, 720.0 / picture.height))
    val resized =
        if (scale < 1.0)
            Bitmap.createScaledBitmap(
                picture,
                maxOf(2, (picture.width * scale).toInt()),
                maxOf(2, (picture.height * scale).toInt()),
                true,
            )
        else picture
    try {
        val out = ByteArrayOutputStream()
        check(resized.compress(Bitmap.CompressFormat.JPEG, 80, out))
        val bytes = out.toByteArray()
        require(bytes.size <= 4 * 1024 * 1024)
        return Triple(bytes, resized.width, resized.height)
    } finally {
        if (resized !== picture) resized.recycle()
        if (picture !== bitmap) picture.recycle()
    }
}

internal class CameraCapture(ctx: Context, args: JSObject) : AutoCloseable {
    val slot = FrameSlot()
    private val thread = HandlerThread("qorc-camera").apply { start() }
    private val handler = Handler(thread.looper)
    private val ready = CountDownLatch(1)
    private val closed = AtomicBoolean(false)
    @Volatile private var opening = false
    private val released = CountDownLatch(1)
    @Volatile private var camera: CameraDevice? = null
    private var capture: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    private var lastFrame = 0L
    private val fps = args.optInt("frameRate", 30).coerceIn(1, 30)

    init {
        try {
            val manager = ctx.getSystemService(Context.CAMERA_SERVICE) as CameraManager
            val selected =
                args
                    .optString("deviceId")
                    .takeIf { it.isNotEmpty() }
                    ?.removePrefix("android-camera:")
            val id =
                selected
                    ?: manager.cameraIdList.firstOrNull {
                        manager
                            .getCameraCharacteristics(it)
                            .get(CameraCharacteristics.LENS_FACING) ==
                            CameraCharacteristics.LENS_FACING_FRONT
                    }
                    ?: manager.cameraIdList.firstOrNull()
                    ?: error("No camera")
            val characteristics = manager.getCameraCharacteristics(id)
            val sizes =
                characteristics
                    .get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)!!
                    .getOutputSizes(ImageFormat.YUV_420_888)
            val requestedW = args.optInt("width", 1280)
            val requestedH = args.optInt("height", 720)
            require(requestedW in 2..1280 && requestedH in 2..720)
            val size =
                sizes
                    .filter { it.width <= 1280 && it.height <= 720 }
                    .minByOrNull {
                        kotlin.math.abs(it.width - requestedW) +
                            kotlin.math.abs(it.height - requestedH)
                    } ?: error("Camera has no supported capture resolution")
            val sensor = characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 0
            val front =
                characteristics.get(CameraCharacteristics.LENS_FACING) ==
                    CameraCharacteristics.LENS_FACING_FRONT
            reader =
                ImageReader.newInstance(size.width, size.height, ImageFormat.YUV_420_888, 2).apply {
                    setOnImageAvailableListener(
                        { source ->
                            val image =
                                try {
                                    source.acquireLatestImage()
                                } catch (_: Exception) {
                                    null
                                } ?: return@setOnImageAvailableListener
                            try {
                                val now = SystemClock.elapsedRealtime()
                                if (
                                    !closed.get() && slot.enabled && now - lastFrame >= 1000 / fps
                                ) {
                                    lastFrame = now
                                    val yuv = nv21(image)
                                    val output = ByteArrayOutputStream()
                                    check(
                                        YuvImage(
                                                yuv,
                                                ImageFormat.NV21,
                                                image.width,
                                                image.height,
                                                null,
                                            )
                                            .compressToJpeg(
                                                Rect(0, 0, image.width, image.height),
                                                85,
                                                output,
                                            )
                                    )
                                    yuv.fill(0)
                                    val encoded = output.toByteArray()
                                    val bitmap =
                                        BitmapFactory.decodeByteArray(encoded, 0, encoded.size)
                                            ?: error("Camera image decode failed")
                                    encoded.fill(0)
                                    @Suppress("DEPRECATION")
                                    val currentDisplay =
                                        (ctx.getSystemService(Context.WINDOW_SERVICE)
                                                as WindowManager)
                                            .defaultDisplay
                                            .rotation
                                    val currentDegrees =
                                        when (currentDisplay) {
                                            Surface.ROTATION_90 -> 90
                                            Surface.ROTATION_180 -> 180
                                            Surface.ROTATION_270 -> 270
                                            else -> 0
                                        }
                                    val currentRotation =
                                        if (front) (sensor + currentDegrees) % 360
                                        else (sensor - currentDegrees + 360) % 360
                                    try {
                                        val frame = jpeg(bitmap, currentRotation)
                                        slot.offer(frame.first, frame.second, frame.third, fps)
                                        ready.countDown()
                                    } finally {
                                        bitmap.recycle()
                                    }
                                }
                            } catch (_: Exception) {
                                fail("Camera frame processing failed")
                            } finally {
                                image.close()
                            }
                        },
                        handler,
                    )
                }
            if (
                ctx.checkSelfPermission(android.Manifest.permission.CAMERA) !=
                    android.content.pm.PackageManager.PERMISSION_GRANTED
            )
                throw SecurityException("Camera permission was not granted")
            opening = true
            manager.openCamera(
                id,
                object : CameraDevice.StateCallback() {
                    override fun onOpened(device: CameraDevice) {
                        opening = false
                        camera = device
                        if (closed.get()) {
                            device.close()
                            return
                        }
                        try {
                            @Suppress("DEPRECATION")
                            device.createCaptureSession(
                                listOf(reader!!.surface),
                                object : CameraCaptureSession.StateCallback() {
                                    override fun onConfigured(session: CameraCaptureSession) {
                                        if (closed.get()) {
                                            session.close()
                                            return
                                        }
                                        capture = session
                                        try {
                                            val request =
                                                device
                                                    .createCaptureRequest(
                                                        CameraDevice.TEMPLATE_RECORD
                                                    )
                                                    .apply {
                                                        addTarget(reader!!.surface)
                                                        val autofocus =
                                                            characteristics.get(
                                                                CameraCharacteristics
                                                                    .CONTROL_AF_AVAILABLE_MODES
                                                            )
                                                        if (
                                                            autofocus?.contains(
                                                                CaptureRequest
                                                                    .CONTROL_AF_MODE_CONTINUOUS_VIDEO
                                                            ) == true
                                                        ) {
                                                            set(
                                                                CaptureRequest.CONTROL_AF_MODE,
                                                                CaptureRequest
                                                                    .CONTROL_AF_MODE_CONTINUOUS_VIDEO,
                                                            )
                                                        }
                                                        val ranges =
                                                            characteristics.get(
                                                                CameraCharacteristics
                                                                    .CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES
                                                            )
                                                        val rate =
                                                            ranges
                                                                ?.filter { it.upper >= fps }
                                                                ?.minByOrNull {
                                                                    it.upper - it.lower +
                                                                        kotlin.math.abs(
                                                                            it.upper - fps
                                                                        )
                                                                }
                                                        rate?.let {
                                                            set(
                                                                CaptureRequest
                                                                    .CONTROL_AE_TARGET_FPS_RANGE,
                                                                it,
                                                            )
                                                        }
                                                    }
                                                    .build()
                                            session.setRepeatingRequest(request, null, handler)
                                        } catch (_: Exception) {
                                            fail("Camera stream failed")
                                        }
                                    }

                                    override fun onConfigureFailed(session: CameraCaptureSession) {
                                        fail("Camera profile unavailable")
                                    }
                                },
                                handler,
                            )
                        } catch (_: Exception) {
                            fail("Camera session failed")
                        }
                    }

                    override fun onClosed(device: CameraDevice) {
                        opening = false
                        released.countDown()
                        if (closed.get()) thread.quitSafely()
                    }

                    override fun onDisconnected(device: CameraDevice) {
                        device.close()
                        fail("Camera disconnected")
                    }

                    override fun onError(device: CameraDevice, error: Int) {
                        device.close()
                        fail("Camera was interrupted")
                    }
                },
                handler,
            )
        } catch (e: Exception) {
            opening = false
            close()
            throw e
        }
    }

    private fun fail(reason: String) {
        slot.failure = reason
        ready.countDown()
    }

    fun awaitReady() {
        if (!ready.await(8, TimeUnit.SECONDS) || slot.failure != null || closed.get()) {
            close()
            error("Camera did not deliver a frame")
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        slot.failure = "Camera stopped"
        ready.countDown()
        try {
            capture?.close()
        } catch (_: Exception) {}
        camera?.close()
        reader?.close()
        slot.clear()
        if (camera != null || opening) {
            if (Thread.currentThread() !== thread) released.await(2, TimeUnit.SECONDS)
        } else thread.quitSafely()
    }

    private fun nv21(image: Image): ByteArray {
        val w = image.width
        val h = image.height
        val data = ByteArray(w * h * 3 / 2)
        val planes = image.planes
        for (y in 0 until h) for (x in 0 until w) data[y * w + x] =
            planes[0].buffer.get(y * planes[0].rowStride + x * planes[0].pixelStride)
        var index = w * h
        for (y in 0 until h / 2) for (x in 0 until w / 2) {
            data[index++] =
                planes[2].buffer.get(y * planes[2].rowStride + x * planes[2].pixelStride)
            data[index++] =
                planes[1].buffer.get(y * planes[1].rowStride + x * planes[1].pixelStride)
        }
        return data
    }
}

internal class ScreenCapture(ctx: Context, resultCode: Int, data: Intent) : AutoCloseable {
    val slot = FrameSlot()
    private val thread = HandlerThread("qorc-screen").apply { start() }
    private val handler = Handler(thread.looper)
    private val ready = CountDownLatch(1)
    private val closed = AtomicBoolean(false)
    private var projection: MediaProjection? = null
    private var reader: ImageReader? = null
    private var display: VirtualDisplay? = null
    private var lastFrame = 0L
    private val density = ctx.resources.displayMetrics.densityDpi

    private val projectionCallback =
        object : MediaProjection.Callback() {
            override fun onStop() {
                slot.failure = "Screen sharing was stopped by Android"
                close()
            }

            override fun onCapturedContentResize(width: Int, height: Int) {
                if (!closed.get() && display != null && width > 0 && height > 0)
                    configure(width, height)
            }
        }

    init {
        try {
            projection =
                (ctx.getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager)
                    .getMediaProjection(resultCode, data)
                    ?: error("Screen projection permission expired")
            projection!!.registerCallback(projectionCallback, handler)
            @Suppress("DEPRECATION")
            val metrics =
                android.util.DisplayMetrics().also {
                    (ctx.getSystemService(Context.WINDOW_SERVICE) as WindowManager)
                        .defaultDisplay
                        .getRealMetrics(it)
                }
            configure(metrics.widthPixels, metrics.heightPixels)
            display =
                projection!!.createVirtualDisplay(
                    "Qorc screen sharing",
                    reader!!.width,
                    reader!!.height,
                    density,
                    DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                    reader!!.surface,
                    null,
                    handler,
                )
        } catch (e: Exception) {
            close()
            throw e
        }
    }

    @Synchronized
    private fun configure(width: Int, height: Int) {
        if (closed.get()) return
        val scale = min(1.0, min(1280.0 / width, 720.0 / height))
        val w = maxOf(2, (width * scale).toInt())
        val h = maxOf(2, (height * scale).toInt())
        if (reader?.width == w && reader?.height == h) return
        val previous = reader
        reader =
            ImageReader.newInstance(w, h, PixelFormat.RGBA_8888, 2).apply {
                setOnImageAvailableListener(
                    { source ->
                        val image =
                            try {
                                source.acquireLatestImage()
                            } catch (_: Exception) {
                                null
                            } ?: return@setOnImageAvailableListener
                        try {
                            val now = SystemClock.elapsedRealtime()
                            if (!closed.get() && now - lastFrame >= 1000 / 30) {
                                lastFrame = now
                                val plane = image.planes[0]
                                val packed =
                                    java.nio.ByteBuffer.allocate(image.width * image.height * 4)
                                val row = ByteArray(image.width * 4)
                                for (y in 0 until image.height) {
                                    plane.buffer.position(y * plane.rowStride)
                                    plane.buffer.get(row)
                                    packed.put(row)
                                }
                                row.fill(0)
                                packed.rewind()
                                val bitmap =
                                    Bitmap.createBitmap(
                                        image.width,
                                        image.height,
                                        Bitmap.Config.ARGB_8888,
                                    )
                                try {
                                    bitmap.copyPixelsFromBuffer(packed)
                                    val frame = jpeg(bitmap)
                                    slot.offer(frame.first, frame.second, frame.third, 30)
                                    ready.countDown()
                                } finally {
                                    packed.array().fill(0)
                                    bitmap.recycle()
                                }
                            }
                        } catch (_: Exception) {
                            slot.failure = "Screen capture interrupted"
                            ready.countDown()
                        } finally {
                            image.close()
                        }
                    },
                    handler,
                )
            }
        display?.let {
            it.resize(w, h, density)
            it.surface = reader!!.surface
        }
        previous?.close()
    }

    fun awaitReady() {
        if (!ready.await(8, TimeUnit.SECONDS) || slot.failure != null || closed.get()) {
            close()
            error("Screen capture did not deliver a frame")
        }
    }

    @Synchronized
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        slot.failure = slot.failure ?: "Screen sharing stopped"
        ready.countDown()
        display?.release()
        reader?.close()
        projection?.unregisterCallback(projectionCallback)
        projection?.stop()
        slot.clear()
        thread.quitSafely()
    }
}
