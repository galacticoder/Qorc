package com.qorc.app

import android.app.Activity
import android.os.Build
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.ConsoleMessage
import android.webkit.JsResult
import android.webkit.JsPromptResult
import android.webkit.PermissionRequest
import android.webkit.ValueCallback
import android.net.Uri
import app.tauri.plugin.Plugin
import app.tauri.plugin.PluginHandle
import app.tauri.plugin.PluginManager
import com.qorc.media.MediaPlugin
import java.lang.ref.WeakReference

/** One engine/view, with replaceable UI and permission owners. No key copying. */
internal object EngineHost {
  const val SHOW_UI = "com.qorc.app.SHOW_UI"
  private var uiRef = WeakReference<MainActivity>(null)
  var ui: MainActivity?
    get() = uiRef.get()?.takeUnless { it.isFinishing || it.isDestroyed }
    set(value) { uiRef = WeakReference(value) }
  var runtime: RuntimeActivity? = null
  private var view: WebView? = null
  var nativeChrome: WebChromeClient? = null
    private set
  private var boundUi = WeakReference<MainActivity>(null)
  private val backgroundChrome = object : WebChromeClient() {
    override fun onPermissionRequest(request: PermissionRequest) { request.deny() }
    override fun onJsAlert(view: WebView, url: String, message: String, result: JsResult): Boolean { result.cancel(); return true }
    override fun onJsConfirm(view: WebView, url: String, message: String, result: JsResult): Boolean { result.cancel(); return true }
    override fun onJsPrompt(view: WebView, url: String, message: String, defaultValue: String, result: JsPromptResult): Boolean { result.cancel(); return true }
    override fun onShowFileChooser(view: WebView, callback: ValueCallback<Array<Uri>>, params: FileChooserParams): Boolean { callback.onReceiveValue(null); return true }
    override fun onReceivedTitle(view: WebView, title: String) { nativeChrome?.onReceivedTitle(view, title) }
    override fun onConsoleMessage(message: ConsoleMessage): Boolean = nativeChrome?.onConsoleMessage(message) ?: false
  }

  // Adapter for the pinned Tauri 2.10.2 Android plugin registry. Keep these
  // fields in R8 and fail explicitly if its registry contract changes.
  private val pluginsField = PluginManager::class.java.getDeclaredField("plugins").apply { isAccessible = true }
  private val listenersField = Plugin::class.java.getDeclaredField("listeners").apply { isAccessible = true }

  fun capture(engine: RuntimeActivity, webview: WebView) {
    check(runtime === engine && view == null) { "Android engine view was created twice" }
    view = webview
    if (Build.VERSION.SDK_INT >= 26) nativeChrome = webview.webChromeClient
    val owner = ui
    if (owner != null) attach(owner)
  }

  @Suppress("UNCHECKED_CAST")
  fun attach(owner: MainActivity) {
    val engine = runtime ?: return
    val webview = view ?: return
    if (boundUi.get() !== owner) {
      val old = engine.pluginManager
      val handles = (pluginsField.get(old) as Map<String, PluginHandle>).values.toList()
      for (handle in handles) {
        val type = if (handle.instance is app.tauri.dialog.DialogPlugin) QorcDialogPlugin::class.java else handle.instance.javaClass
        val replacement = type.getConstructor(Activity::class.java).newInstance(owner) as Plugin
        (listenersField.get(replacement) as MutableMap<Any?, Any?>)
          .putAll(listenersField.get(handle.instance) as Map<Any?, Any?>)
        owner.pluginManager.load(webview, handle.name, replacement, handle.config)
        // Retire the old bridge's workers, preserving the global active media.
        (handle.instance as? MediaPlugin)?.retireUiBinding()
        (handle.instance as? QorcDialogPlugin)?.detachUiRequests()
      }
      engine.pluginManager = owner.pluginManager
      boundUi = WeakReference(owner)
    }
    owner.show(webview)
  }

  fun detach(owner: MainActivity) {
    if (uiRef.get() !== owner) return
    uiRef.clear()
    val webview = view ?: return
    (webview as? RustWebView)?.bindUiContext(null)
    webview.webChromeClient = backgroundChrome
    (runtime?.pluginManager?.let { pluginsField.get(it) } as? Map<*, *>)?.values
      ?.filterIsInstance<PluginHandle>()?.forEach {
        (it.instance as? MediaPlugin)?.detachUiRequests()
        (it.instance as? QorcDialogPlugin)?.detachUiRequests()
      }
    (webview.parent as? android.view.ViewGroup)?.removeView(webview)
  }

  fun navigateBack(owner: MainActivity, result: (Boolean) -> Unit) {
    val webview = view
    if (webview == null || ui !== owner || webview.parent == null) {
      result(false)
      return
    }
    webview.evaluateJavascript(
      "!window.dispatchEvent(new Event('qorc:android-back', {cancelable:true}))"
    ) { handled -> result(handled == "true") }
  }

  fun runtimeDestroyed(engine: RuntimeActivity) {
    if (runtime !== engine) return
    runtime = null
    view = null
    nativeChrome = null
    boundUi.clear()
  }
}
