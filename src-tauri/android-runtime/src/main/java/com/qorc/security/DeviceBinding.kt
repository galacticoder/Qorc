package com.qorc.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.Keep
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

@Keep
object DeviceBinding {
    private const val ALIAS = "qorc.local-storage.binding.v1"
    private const val PROVIDER = "AndroidKeyStore"

    @JvmStatic
    @Synchronized
    fun derive(allowCreate: Boolean): ByteArray {
        val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
        if (!store.containsAlias(ALIAS)) {
            check(allowCreate) { "Device binding key is missing" }
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER)
            generator.init(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setKeySize(256)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .build()
            )
            generator.generateKey()
        }
        val key = store.getKey(ALIAS, null) as? SecretKey ?: error("Device binding key is unavailable")
        check(key.encoded == null) { "Device binding key must remain non-exportable" }
        return Mac.getInstance("HmacSHA256").run {
            init(key)
            doFinal("qorc-device-binding/android/v1\u0000".toByteArray(Charsets.UTF_8))
        }
    }
}
