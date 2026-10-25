// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// CI's advisory scan: lock every configuration, so that `--write-locks` writes
// each project's gradle.lockfile with the versions Gradle resolves, which
// OSV-Scanner then checks. The lock files are not kept in the repository.
gradle.allprojects {
    dependencyLocking { lockAllConfigurations() }
}
