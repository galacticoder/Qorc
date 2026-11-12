// Copyright 2019-2024 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

// Pinned Tauri 2.10.2 activity adapter; SDK native shutdown follows engine ownership.

package com.qorc.app

import android.content.Intent
import android.content.res.Configuration
import app.tauri.plugin.PluginManager

abstract class TauriActivity : WryActivity() {
  var pluginManager: PluginManager = PluginManager(this)
  private var pluginsDestroyed = false
  override val handleBackNavigation: Boolean = false

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    pluginManager.onNewIntent(intent)
  }

  override fun onResume() {
    super.onResume()
    pluginManager.onResume()
  }

  override fun onPause() {
    super.onPause()
    pluginManager.onPause()
  }

  override fun onRestart() {
    super.onRestart()
    pluginManager.onRestart()
  }

  override fun onStop() {
    super.onStop()
    pluginManager.onStop()
  }

  override fun onDestroy() {
    if (!retainRuntimeAfterWindowDestroyed()) shutdownPlugins()
    super.onDestroy()
  }

  private fun shutdownPlugins() {
    if (pluginsDestroyed) return
    pluginsDestroyed = true
    pluginManager.onDestroy()
  }

  fun shutdownTauriRuntime() {
    shutdownPlugins()
    shutdownWryRuntime()
  }

  override fun onConfigurationChanged(newConfig: Configuration) {
    super.onConfigurationChanged(newConfig)
    pluginManager.onConfigurationChanged(newConfig)
  }
}
