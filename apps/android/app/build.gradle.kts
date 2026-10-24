// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The Android app: Compose screens over the protocol core in ../kit.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "io.github.hunterewok.clipboardbridge"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.hunterewok.clipboardbridge"
        minSdk = 29
        targetSdk = 37
        // The release workflow passes the tag's version: -PversionName=1.2.3 -PversionCode=10203.
        versionCode = (findProperty("versionCode") as String?)?.toInt() ?: 1
        versionName = findProperty("versionName") as String? ?: "0.3.0-dev"
    }

    // The release key, when the release workflow has it (CBB_ANDROID_KEYSTORE is the
    // keystore file); without it the release APK is unsigned.
    val keystore = System.getenv("CBB_ANDROID_KEYSTORE")
    signingConfigs {
        if (keystore != null) {
            create("release") {
                storeFile = file(keystore)
                storePassword = System.getenv("CBB_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("CBB_ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("CBB_ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }
}

// The tunnel for sync away from home: mobile/cbbtun, bound by gomobile into an AAR. It
// needs Go and the Android NDK: ANDROID_NDK_HOME, else the runner's ANDROID_NDK_LATEST_HOME,
// else the NDK of the SDK that AGP picks.
val tunnelAar = layout.buildDirectory.file("cbbtun/cbbtun.aar")
val bindTunnel by tasks.registering(Exec::class) {
    val repo = rootDir.resolve("../..")
    inputs.files(repo.resolve("go.mod"), repo.resolve("go.sum"))
    inputs.dir(repo.resolve("mobile"))
    inputs.dir(repo.resolve("internal/tunnel"))
    outputs.file(tunnelAar)
    workingDir = repo
    commandLine("sh", "mobile/cbbtun/bind.sh", "android", tunnelAar.get().asFile.path)
    val ndk = androidComponents.sdkComponents.ndkDirectory
    val sdk = androidComponents.sdkComponents.sdkDirectory
    doFirst {
        environment("ANDROID_HOME", sdk.get().asFile.path)
        val home = System.getenv("ANDROID_NDK_HOME") ?: System.getenv("ANDROID_NDK_LATEST_HOME") ?: ndk.get().asFile.path
        environment("ANDROID_NDK_HOME", home)
    }
}

dependencies {
    implementation(files(tunnelAar).builtBy(bindTunnel))
    implementation("io.github.hunterewok.clipboardbridge:kit:0")
    // The kit's TLS: Conscrypt bundled, for TLS 1.3 with the exporter on every Android version.
    implementation("org.conscrypt:conscrypt-android:2.8.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    // The QR scanner: CameraX for the frames, ZXing to read them, without Google Play services.
    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")
    implementation("com.google.zxing:core:3.5.4")

    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")

    testImplementation("junit:junit:4.13.2")
}
