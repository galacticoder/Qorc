package com.qorc.app

import android.os.Build
import android.util.TypedValue
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.graphics.Insets
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.doOnAttach

internal fun fitQorcWindow(activity: AppCompatActivity) = with(activity) {
    // Fit the entire WebView, including fixed-position pages and portals,
    // inside Android's bars and cutouts. CSS safe areas alone do not protect
    // all screens or older WebView versions.
    val content = findViewById<View>(android.R.id.content)
    val safeTypes = WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
    val handledTypes = safeTypes or if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      WindowInsetsCompat.Type.ime()
    } else 0
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, windowInsets ->
      val safe = windowInsets.getInsets(handledTypes)
      // Older Android versions already resize the window for the keyboard.
      // Do not reserve another navigation/keyboard gap above that resized edge.
      val legacyKeyboard = Build.VERSION.SDK_INT < Build.VERSION_CODES.R &&
        windowInsets.isVisible(WindowInsetsCompat.Type.ime())
      view.setPadding(safe.left, safe.top, safe.right, if (legacyKeyboard) 0 else safe.bottom)

      // The reserved system-bar area follows Android's theme, like its icons.
      val background = TypedValue()
      if (theme.resolveAttribute(android.R.attr.colorBackground, background, true)) {
        view.setBackgroundColor(if (background.resourceId != 0) getColor(background.resourceId) else background.data)
      }

      // Send zeroed updates instead of CONSUMED, so WebView clears old safe
      // areas on rotation/keyboard dismissal without applying padding twice.
      WindowInsetsCompat.Builder(windowInsets).setInsets(handledTypes, Insets.NONE).build()
    }
    content.doOnAttach { ViewCompat.requestApplyInsets(it) }
}
