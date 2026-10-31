// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone's protocol core in Kotlin, the Android twin of
// apps/ios/ClipboardBridgeKit: pairing, certificates, records and the
// member protocol. It has no Android dependencies; its tests run against
// the Go implementation's vectors in testdata/interop.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.21"
    // Test coverage for CI's summary (docs/testing.md, "Coverage").
    jacoco
}

group = "io.github.hunterewok.clipboardbridge"
version = "0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
    // TLS 1.3 with the exporter and ALPN: the app bundles conscrypt-android,
    // the tests use the JVM build, which has the same API.
    compileOnly("org.conscrypt:conscrypt-openjdk-uber:2.8.0")
    testImplementation("org.conscrypt:conscrypt-openjdk-uber:2.8.0")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
    // The interop vectors live at the repository's root.
    systemProperty("interop.dir", rootDir.resolve("../../../testdata/interop").canonicalPath)
    testLogging { events("failed"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}

// build/reports/jacoco/test/jacocoTestReport.xml, which tools/coverage reads.
tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports { xml.required.set(true); html.required.set(false) }
}

// A script that runs InteropMain, the Kotlin twin of clipboardbridge-interop,
// for Go's interop tests: CBB_SWIFT_INTEROP and CBB_SWIFT_INTEROP_TLS name it.
val interopScript by tasks.registering {
    val classpath = sourceSets.test.get().runtimeClasspath
    val script = layout.buildDirectory.file("interop/clipboardbridge-interop")
    dependsOn(tasks.testClasses)
    inputs.files(classpath)
    outputs.file(script)
    doLast {
        val f = script.get().asFile
        val java = File(System.getProperty("java.home"), "bin/java").path
        f.writeText("#!/bin/sh\nexec '$java' -cp '${classpath.asPath}' io.github.hunterewok.clipboardbridge.kit.InteropMainKt \"\$@\"\n")
        f.setExecutable(true)
    }
}
