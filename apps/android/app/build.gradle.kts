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
        versionCode = 1
        versionName = "0.3.0-dev"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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

dependencies {
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
