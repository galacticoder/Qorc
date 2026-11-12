package com.qorc.app

import android.content.Intent
import android.content.res.Configuration
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.webkit.WebView
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import app.tauri.plugin.PluginManager
import com.qorc.media.BackgroundRuntime
import com.qorc.media.ActivityNotifications

/** The app's only visible Activity/task. Its WebView belongs to EngineHost. */
class MainActivity : AppCompatActivity() {
  val pluginManager = PluginManager(this)
  private lateinit var chrome: QorcWebChromeClient
  private var backPending = false

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    chrome = QorcWebChromeClient(this)
    EngineHost.ui = this
    BackgroundRuntime.attachLauncher(this)
    // Keep chat contents out of Recents without blocking normal screenshots or
    // user-authorized screen sharing on supported Android versions.
    if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false)
    setContentView(TextView(this).apply {
      text = getString(R.string.app_name); textSize = 28f; gravity = Gravity.CENTER
    })
    fitQorcWindow(this)
    onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
      override fun handleOnBackPressed() {
        val ime = WindowInsetsCompat.Type.ime()
        if (ViewCompat.getRootWindowInsets(window.decorView)?.isVisible(ime) == true) {
          WindowInsetsControllerCompat(window, window.decorView).hide(ime)
          return
        }
        if (backPending) return
        backPending = true
        EngineHost.navigateBack(this@MainActivity) { handled ->
          backPending = false
          if (handled || isFinishing || isDestroyed) return@navigateBack
          if (BackgroundRuntime.enabled(applicationContext)) moveTaskToBack(true)
          else BackgroundRuntime.quit(applicationContext)
        }
      }
    })
    if (EngineHost.runtime == null) {
      startActivity(Intent(this, RuntimeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    } else EngineHost.attach(this)
  }

  fun show(view: WebView) {
    if (view.parent === findViewById<android.view.ViewGroup>(android.R.id.content)) return
    (view.parent as? android.view.ViewGroup)?.removeView(view)
    (view as? RustWebView)?.bindUiContext(this)
    view.webChromeClient = chrome
    setContentView(view)
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    ActivityNotifications.clear(applicationContext)
    if (intent.action != EngineHost.SHOW_UI) {
      setIntent(intent)
      pluginManager.onNewIntent(intent)
    }
    EngineHost.attach(this)
  }

  override fun onResume() {
    super.onResume()
    ActivityNotifications.setForeground(applicationContext, true)
    pluginManager.onResume()
    if (EngineHost.runtime != null) BackgroundRuntime.resume(this)
  }
  override fun onPause() {
    ActivityNotifications.setForeground(applicationContext, false)
    pluginManager.onPause()
    super.onPause()
  }
  override fun onStop() { pluginManager.onStop(); super.onStop() }
  override fun onRestart() { super.onRestart(); pluginManager.onRestart() }
  override fun onConfigurationChanged(newConfig: Configuration) {
    super.onConfigurationChanged(newConfig)
    enableEdgeToEdge()
    pluginManager.onConfigurationChanged(newConfig)
  }

  override fun onDestroy() {
    // Detach the same live view before Android removes this window. Its engine
    // and main-looper IPC remain owned by the background service.
    chrome.detachUiRequests()
    EngineHost.detach(this)
    BackgroundRuntime.detachLauncher(this, isFinishing)
    super.onDestroy()
  }
}
