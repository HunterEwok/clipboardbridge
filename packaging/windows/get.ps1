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
# CBB_VERIFY=skip installs a release whose signed release files
# (docs/protocol.md, section 16) do not check out,
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

	# The project's release root keys (docs/protocol.md, section 16), base64
	# SubjectPublicKeyInfos, which sign keys.json. None yet: until they are
	# made, releases carry no signed files and nothing is checked.
	$releaseRoots = @()

	# Invoke-Quietly runs a program without its output and returns its exit
	# code. Windows PowerShell 5.1 turns a program's redirected stderr into
	# errors, which Stop would throw, so the preference is relaxed here only.
	function Invoke-Quietly {
		$ErrorActionPreference = 'Continue'
		& $args[0] @($args | Select-Object -Skip 1) *> $null
		return $LASTEXITCODE
	}

	# Get-ReleaseFile downloads a release file, or copies it from CBB_RELEASE_DIR.
	function Get-ReleaseFile($url, $path) {
		if ($env:CBB_RELEASE_DIR) {
			Copy-Item (Join-Path $env:CBB_RELEASE_DIR (Split-Path $url -Leaf)) $path
		} else {
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
			Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $path
		}
	}

	# A P-256 key from its SubjectPublicKeyInfo, for .NET Framework too.
	function Get-P256Key([byte[]]$spki) {
		$prefix = [Convert]::FromBase64String('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE')
		if ($spki.Length -ne 91 -or -not (Test-ByteEqual $spki[0..26] $prefix)) {
			throw 'a key is not P-256'
		}
		$p = New-Object Security.Cryptography.ECParameters
		$p.Curve = [Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
		$q = New-Object Security.Cryptography.ECPoint
		$q.X = [byte[]]$spki[27..58]
		$q.Y = [byte[]]$spki[59..90]
		$p.Q = $q
		[Security.Cryptography.ECDsa]::Create($p)
	}

	function Test-ByteEqual([byte[]]$a, [byte[]]$b) {
		if ($a.Length -ne $b.Length) { return $false }
		for ($i = 0; $i -lt $a.Length; $i++) {
			if ($a[$i] -ne $b[$i]) { return $false }
		}
		$true
	}

	# A DER ECDSA signature as the 64 bytes r || s that .NET takes.
	function ConvertFrom-DerSignature([byte[]]$der) {
		$out = New-Object byte[] 64
		if ($der.Length -lt 8 -or $der[0] -ne 0x30 -or $der[1] -ne $der.Length - 2) { return $null }
		$i = 2
		foreach ($half in 0, 1) {
			if ($der[$i] -ne 0x02) { return $null }
			$n = $der[$i + 1]
			$v = [byte[]]$der[($i + 2)..($i + 1 + $n)]
			$i += 2 + $n
			while ($v.Length -gt 32 -and $v[0] -eq 0) { $v = [byte[]]$v[1..($v.Length - 1)] }
			if ($v.Length -gt 32) { return $null }
			[Array]::Copy($v, 0, $out, $half * 32 + 32 - $v.Length, $v.Length)
		}
		if ($i -ne $der.Length) { return $null }
		$out
	}

	# Open-ReleaseFile checks the envelope at path with any of the keys and
	# returns its body, decoded, or throws.
	function Open-ReleaseFile($path, $type, $keys) {
		$f = Get-Content -Raw $path | ConvertFrom-Json
		$body = [Convert]::FromBase64String($f.body)
		$sig = ConvertFrom-DerSignature ([Convert]::FromBase64String($f.sig))
		foreach ($k in $keys) {
			if ($sig -and (Get-P256Key $k).VerifyData($body, $sig, [Security.Cryptography.HashAlgorithmName]::SHA256)) {
				$b = [Text.Encoding]::UTF8.GetString($body) | ConvertFrom-Json
				if ($b.type -ne $type -or $b.v -ne 1) { break }
				return @{ Bytes = $body; Value = $b }
			}
		}
		throw "$(Split-Path $path -Leaf) is not signed by the project's key; not installing"
	}

	# Test-Release checks keys.json against the root keys, release.json and,
	# for the latest release, stable.json against its release keys, and the
	# archive against release.json. CBB_VERIFY=skip skips it.
	function Test-Release($base, $version, $archive, $got, $tmp) {
		$roots = $releaseRoots
		if ($env:CBB_RELEASE_DIR -and $env:CBB_RELEASE_ROOTS) {
			$roots = @(((Get-Content -Raw $env:CBB_RELEASE_ROOTS) -split '-----END PUBLIC KEY-----') |
				ForEach-Object { ($_ -replace '-----BEGIN PUBLIC KEY-----', '' -replace '\s', '') } | Where-Object { $_ })
		}
		if ($env:CBB_VERIFY -eq 'skip') {
			Write-Host "Not checked: the release's signature (CBB_VERIFY=skip)."
			return
		}
		if ($roots.Count -eq 0) { return }
		$latest = "$repo/releases/latest/download"
		if ($env:CBB_RELEASE_DIR) { $latest = $base }
		try {
			Get-ReleaseFile "$latest/keys.json" (Join-Path $tmp 'keys.json')
			Get-ReleaseFile "$base/release.json" (Join-Path $tmp 'release.json')
		} catch {
			throw "$version has no signed release files; not installing it (CBB_VERIFY=skip installs it unchecked)"
		}
		$nowMS = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
		$keys = Open-ReleaseFile -path (Join-Path $tmp 'keys.json') -type 'keys' -keys @($roots | ForEach-Object { , [Convert]::FromBase64String($_) })
		if ([long]$keys.Value.expires_ms -le $nowMS) { throw 'keys.json has expired; check the clock, or try again later' }
		$releaseKeys = @($keys.Value.keys | ForEach-Object { , [Convert]::FromBase64String($_.key) })
		$rel = Open-ReleaseFile -path (Join-Path $tmp 'release.json') -type 'release' -keys $releaseKeys
		if ($version -eq 'latest') {
			Get-ReleaseFile "$base/stable.json" (Join-Path $tmp 'stable.json')
			$ch = Open-ReleaseFile -path (Join-Path $tmp 'stable.json') -type 'channel' -keys $releaseKeys
			if ($ch.Value.channel -ne 'stable') { throw "stable.json is not the stable channel's" }
			if ([long]$ch.Value.expires_ms -le $nowMS) { throw 'stable.json has expired; check the clock, or try again later' }
			$sum = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($rel.Bytes) | ForEach-Object { $_.ToString('x2') })
			if ($ch.Value.release_sha256 -ne $sum -or $ch.Value.release -ne $rel.Value.version) {
				throw 'release.json is not the release stable.json names; not installing'
			}
		} elseif ("v$($rel.Value.version)" -ne $version) {
			throw "release.json is for $($rel.Value.version), not $version"
		}
		$entry = $rel.Value.files | Where-Object { $_.name -eq $archive } | Select-Object -First 1
		if (-not $entry) { throw "release.json does not list $archive" }
		if ($entry.sha256 -ne $got -or [long]$entry.size -ne (Get-Item (Join-Path $tmp $archive)).Length) {
			throw "$archive does not match the signed release.json; not installing it"
		}
		Write-Host "The release's signature checks out ($($rel.Value.version))."
	}

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
			# the download is whole. The signed release files show that the
			# project signed this release (docs/protocol.md, section 16).
			$step = "checking the release's signature"
			Test-Release -base $base -version $version -archive $archive -got $got -tmp $tmp

			# The attestation shows that this repository's release workflow
			# built the archive.
			$step = "checking the build attestation of $archive"
			$attestation = if ($env:CBB_ATTESTATION) { $env:CBB_ATTESTATION } else { 'check' }
			$gh = Get-Command gh -ErrorAction SilentlyContinue
			$signedIn = $false
			if ($gh) {
				$signedIn = (Invoke-Quietly $gh.Source auth status) -eq 0
			}
			if ($env:CBB_RELEASE_DIR -or $attestation -eq 'skip') {
			} elseif ($signedIn) {
				if ((Invoke-Quietly $gh.Source attestation verify (Join-Path $tmp $archive) --repo HunterEwok/clipboardbridge) -ne 0) {
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
