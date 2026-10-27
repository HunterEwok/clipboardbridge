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
// else the newest NDK in the SDK's ndk directory.
val tunnelAar = layout.buildDirectory.file("cbbtun/cbbtun.aar")
val ndkHome = providers.environmentVariable("ANDROID_NDK_HOME").orElse(providers.environmentVariable("ANDROID_NDK_LATEST_HOME"))
val bindTunnel = tasks.register<Exec>("bindTunnel") {
    val repo = rootDir.resolve("../..")
    inputs.files(repo.resolve("go.mod"), repo.resolve("go.sum"))
    inputs.dir(repo.resolve("mobile"))
    inputs.dir(repo.resolve("internal/tunnel"))
    outputs.file(tunnelAar)
    workingDir = repo
    commandLine("sh", "mobile/cbbtun/bind.sh", "android", tunnelAar.get().asFile.path)
    val sdk = androidComponents.sdkComponents.sdkDirectory
    val ndk = ndkHome
    doFirst {
        val sdkDir = sdk.get().asFile
        environment("ANDROID_HOME", sdkDir.path)
        val home = ndk.orNull ?: sdkDir.resolve("ndk").listFiles()?.filter { it.isDirectory }?.maxByOrNull { it.name }?.path
            ?: throw GradleException("no Android NDK: install one with the SDK manager or set ANDROID_NDK_HOME")
        environment("ANDROID_NDK_HOME", home)
    }
}

dependencies {
    implementation(files(tunnelAar).builtBy(bindTunnel))
    implementation("io.github.hunterewok.clipboardbridge:kit:0")
    implementation(project(":shared"))
    // The kit's TLS: Conscrypt bundled, for TLS 1.3 with the exporter on every Android version.
    implementation("org.conscrypt:conscrypt-android:2.8.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
    // The Wear OS watch (../wear) through the Wearable Data Layer of Google Play services, the
    // only way to a watch; without Play services there is no watch and the rest works as before.
    implementation("com.google.android.gms:play-services-wearable:20.0.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.11.0")
    // The QR scanner: CameraX for the frames, ZXing to read them, without Google Play services.
    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")
    implementation("com.google.zxing:core:3.5.4")
    constraints {
        // Guava comes in through the libraries above at 33.3.1, which GHSA-xxph-c9ww-hj94
        // affects; 33.7.2 fixes it.
        implementation("com.google.guava:guava:33.7.2-android")
    }

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
