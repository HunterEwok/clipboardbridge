# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs or updates clipboardbridge on Windows from a release, in a
# PowerShell opened with "Run as administrator":
#
#   irm https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.ps1 | iex
#
# Options, which a piped script cannot take, come from the environment:
# CBB_PORT=N moves the member port from 8764 to N, CBB_HOME_CGNAT=1 counts
# 100.64.0.0/10 as the home network too (0 goes back), CBB_FIREWALL=express
# adds the firewall rules clipboardbridge needs without asking and says what
# it added, CBB_FIREWALL=no adds none and prints the commands that would
# (without either, install.ps1 lists the rules and asks), CBB_VERSION=v1.2.3
# picks a release instead of the latest, CBB_ATTESTATION=require refuses to
# install unless GitHub's build provenance attestation of the archive checks
# out (it needs gh, signed in), CBB_ATTESTATION=skip does not check it,
# CBB_ERROR_DETAILS=1 shows the full
# error of a failure, and
# CBB_RELEASE_DIR, for tests, takes the files from a directory instead of
# downloading them.
#
# It downloads the archive for this machine's architecture and SHA256SUMS
# from the release, checks the archive against it and, when gh is there and
# signed in, against the release workflow's attestation, and runs
# install.ps1 from the archive.

& {
	Set-StrictMode -Version 3
	$ErrorActionPreference = 'Stop'
	$ProgressPreference = 'SilentlyContinue'
	$repo = 'https://github.com/HunterEwok/clipboardbridge'
	$step = 'starting'
	$details = $env:CBB_ERROR_DETAILS -eq '1'

	try {
		$step = 'checking for administrator rights'
		$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
		if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
			throw 'run it in a PowerShell opened with "Run as administrator"'
		}

		$step = 'finding the architecture'
		# A 32-bit PowerShell on 64-bit Windows sees its own architecture; the
		# machine's is in PROCESSOR_ARCHITEW6432.
		$machine = $env:PROCESSOR_ARCHITEW6432
		if (-not $machine) {
			$machine = $env:PROCESSOR_ARCHITECTURE
		}
		switch ($machine) {
			'AMD64' { $arch = 'amd64' }
			'ARM64' { $arch = 'arm64' }
			default { throw "no release for the architecture $machine" }
		}

		$version = $env:CBB_VERSION
		if (-not $version) {
			$version = 'latest'
		}
		if ($version -eq 'latest') {
			$base = "$repo/releases/latest/download"
		} elseif ($version -match '^v\d') {
			$base = "$repo/releases/download/$version"
		} else {
			throw 'CBB_VERSION must look like v1.2.3'
		}
		$archive = "clipboardbridge-windows-$arch.zip"
		$tmp = Join-Path ([IO.Path]::GetTempPath()) ("clipboardbridge-" + [Guid]::NewGuid())
		New-Item -ItemType Directory -Path $tmp | Out-Null
		try {
			$step = "downloading $archive ($version)"
			Write-Host "Downloading $archive ($version)..."
			foreach ($f in @($archive, 'SHA256SUMS')) {
				if ($env:CBB_RELEASE_DIR) {
					Copy-Item (Join-Path $env:CBB_RELEASE_DIR $f) (Join-Path $tmp $f)
				} else {
					[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
					Invoke-WebRequest -UseBasicParsing -Uri "$base/$f" -OutFile (Join-Path $tmp $f)
				}
			}

			$step = "checking $archive against SHA256SUMS"
			$want = $null
			foreach ($line in Get-Content (Join-Path $tmp 'SHA256SUMS')) {
				$fields = $line -split '\s+'
				if ($fields.Count -ge 2 -and ($fields[1] -eq $archive -or $fields[1] -eq "*$archive")) {
					$want = $fields[0].ToLowerInvariant()
				}
			}
			if (-not $want) {
				throw "SHA256SUMS does not list $archive"
			}
			$got = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $archive)).Hash.ToLowerInvariant()
			if ($got -ne $want) {
				throw "$archive does not match SHA256SUMS; not installing it"
			}

			# SHA256SUMS comes from the same release, so it shows only that
			# the download is whole. The attestation shows that this
			# repository's release workflow built the archive.
			$step = "checking the build attestation of $archive"
			$attestation = if ($env:CBB_ATTESTATION) { $env:CBB_ATTESTATION } else { 'check' }
			$gh = Get-Command gh -ErrorAction SilentlyContinue
			$signedIn = $false
			if ($gh) {
				& $gh.Source auth status *> $null
				$signedIn = $LASTEXITCODE -eq 0
			}
			if ($env:CBB_RELEASE_DIR -or $attestation -eq 'skip') {
			} elseif ($signedIn) {
				& $gh.Source attestation verify (Join-Path $tmp $archive) --repo HunterEwok/clipboardbridge *> $null
				if ($LASTEXITCODE -ne 0) {
					throw "$archive does not have this repository's build attestation; not installing it"
				}
				Write-Host "The archive's build attestation checks out."
			} elseif ($attestation -eq 'require') {
				throw 'CBB_ATTESTATION=require needs gh, signed in (gh auth login), to check the build attestation'
			} else {
				Write-Host 'Not checked: the build attestation of the archive (it needs gh, signed in). SHA256SUMS matched.'
			}

			$step = "unpacking $archive"
			Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $tmp

			$step = 'running install.ps1'
			$arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $tmp 'clipboardbridge\packaging\windows\install.ps1'))
			if ($env:CBB_PORT) {
				$arguments += @('-Port', $env:CBB_PORT)
			}
			& powershell.exe @arguments
			if ($LASTEXITCODE -ne 0) {
				throw "install.ps1 exited with $LASTEXITCODE"
			}
		} finally {
			Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
		}
	} catch {
		Write-Host "get.ps1: $step failed: $($_.Exception.Message)" -ForegroundColor Red
		if ($details) {
			$_ | Format-List * -Force | Out-String | Write-Host
			Write-Host $_.ScriptStackTrace
		} else {
			Write-Host 'For the full error: $env:CBB_ERROR_DETAILS = "1", and run it again.'
		}
	}
}
