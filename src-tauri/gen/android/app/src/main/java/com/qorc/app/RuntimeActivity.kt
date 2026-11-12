package com.qorc.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.webkit.WebView
import com.qorc.media.BackgroundRuntime

/** Bootstraps one native engine. Its window may be destroyed independently. */
class RuntimeActivity : TauriActivity(), BackgroundRuntime.EngineOwner {
  override fun onCreate(savedInstanceState: Bundle?) {
    EngineHost.runtime = this
    EngineHost.ui?.let { pluginManager = it.pluginManager }
    super.onCreate(savedInstanceState)
    BackgroundRuntime.attachRuntime(this)
    EngineHost.ui?.let { BackgroundRuntime.resume(it) }
    startActivity(Intent(this, MainActivity::class.java).apply {
      action = EngineHost.SHOW_UI
      addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_REORDER_TO_FRONT)
    })
  }

  override fun setContentView(view: View?) {
    if (view is WebView) EngineHost.capture(this, view)
    else super.setContentView(view)
  }

  override fun retainRuntimeAfterWindowDestroyed(): Boolean = !BackgroundRuntime.isQuitting()

  override fun shutdownEngine() {
    BackgroundRuntime.detachRuntime(this)
    EngineHost.runtimeDestroyed(this)
    shutdownTauriRuntime()
  }
}
