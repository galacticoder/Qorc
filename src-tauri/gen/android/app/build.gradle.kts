import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

android {
    compileSdk = 36
    namespace = "com.qorc.app"
    sourceSets.getByName("main").java.srcDir("../../../android-runtime/src/main/java")
    sourceSets.getByName("main").jniLibs.srcDir("../../../vendor/tor/android/jniLibs")
    sourceSets.getByName("main").jniLibs.srcDir("../../../vendor/pir/android/jniLibs")
    sourceSets.getByName("main").assets.srcDir("../../../vendor/tor/android/licenses")
    sourceSets.getByName("main").assets.srcDir("../../../vendor/pir/android/licenses")
    packaging {
        jniLibs {
            // Native sidecars are PIE executables, launched from Android's
            // APK-owned nativeLibraryDir. Do not strip/rewrite pinned bytes.
            useLegacyPackaging = true
            keepDebugSymbols += setOf("**/libqorc_tor.so", "**/libqorc_lyrebird.so", "**/libqorc_pir_client.so")
        }
    }
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "com.qorc.app"
        minSdk = 24
        targetSdk = 36
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
    }
    if (System.getenv("QORC_ANDROID_KEYSTORE") != null) {
        signingConfigs.create("qorc") {
            storeFile = file(System.getenv("QORC_ANDROID_KEYSTORE"))
            storePassword = System.getenv("QORC_ANDROID_KEYSTORE_PASSWORD")
            keyAlias = System.getenv("QORC_ANDROID_KEY_ALIAS")
            keyPassword = System.getenv("QORC_ANDROID_KEY_PASSWORD")
        }
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            signingConfig = signingConfigs.findByName("qorc")
            isMinifyEnabled = true
            proguardFiles(
                *fileTree(".") { include("**/*.pro") }
                    .plus(getDefaultProguardFile("proguard-android-optimize.txt"))
                    .toList().toTypedArray()
            )
        }
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        buildConfig = true
    }
}

rust {
    rootDirRel = "../../../"
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    // Pinned SDK adapters retain JNI/IPC, and delegate their lifetime to the
    // background engine instead of destroying it with an Android window.
    exclude("**/generated/RustWebView.kt", "**/generated/WryActivity.kt", "**/generated/TauriActivity.kt")
    doFirst {
        val verification = providers.exec {
            workingDir(project.file("../../../.."))
            commandLine("node", "scripts/verify-android-runtime.cjs")
            isIgnoreExitValue = true
        }
        check(verification.result.get().exitValue == 0) { verification.standardError.asText.get() }
        logger.lifecycle(verification.standardOutput.asText.get().trim())
    }
}

dependencies {
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
}

apply(from = "tauri.build.gradle.kts")

val verifyAndroidTor by tasks.registering(Exec::class) {
    workingDir("../../../..")
    commandLine("node", "scripts/verify-android-tor.cjs")
}
tasks.named("preBuild").configure { dependsOn(verifyAndroidTor) }
val verifyAndroidPir by tasks.registering(Exec::class) {
    workingDir("../../../..")
    commandLine("node", "scripts/verify-android-pir.cjs")
}
tasks.named("preBuild").configure { dependsOn(verifyAndroidPir) }
