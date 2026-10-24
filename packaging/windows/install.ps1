# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Installs or updates clipboardbridge on Windows 10 (1809 or later) or 11, in
# an administrator PowerShell, from the unpacked release archive:
#
#   powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1 [-Port N] [-NoFirewall]
#
# It installs cbb.exe and the windowless cbbw.exe to Program Files and adds
# them to PATH, makes the clipboardbridge local group and adds the signed-in
# user to it, creates the clipboardbridge service, which runs as the virtual
# account NT SERVICE\clipboardbridge with only the privilege it needs,
# keeps its data in ProgramData\clipboardbridge where only the service and
# administrators may reach it, starts the agent with every sign-in and now,
# and registers the uninstaller under Settings, Apps. -Port moves the member
# port from 8764 to N, kept until the next -Port; -Port 8764 goes back. It
# allows mDNS and the member port from the local network in Windows
# Firewall, on every run, after removing the rules it added before, so an
# old port stays closed; -NoFirewall (or CBB_FIREWALL=no) leaves the
# firewall alone. An outbound rule keeps the service on the home network
# until cbb away on lifts it, as the unit does on Linux; -NoFirewall keeps
# that rule. uninstall.ps1 removes it all again.
#
# A failure prints what failed and the system's message; -Details (or
# CBB_ERROR_DETAILS=1) adds the full error record and where in the script
# it happened.
[CmdletBinding()]
param(
	[int]$Port = 0,
	[switch]$NoFirewall,
	[switch]$Details,
	[string]$Bin = ''
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$name = 'clipboardbridge'
$programDir = Join-Path $env:ProgramFiles $name
$dataDir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) $name
$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$name"
$details = $Details -or $env:CBB_ERROR_DETAILS -eq '1'
$step = 'starting'

trap {
	Write-Host "install.ps1: $step failed: $($_.Exception.Message)" -ForegroundColor Red
	if ($details) {
		$_ | Format-List * -Force | Out-String | Write-Host
		Write-Host $_.ScriptStackTrace
	} else {
		Write-Host 'Run it again with -Details for the full error.'
	}
	exit 1
}

# run runs a program and returns its exit code and output. Windows
# PowerShell 5.1 turns a program's error output into an error, which stops
# the script, so the error output is collected with errors allowed.
function run {
	param([string]$file, [string[]]$arguments)
	$ErrorActionPreference = 'Continue'
	$out = & $file @arguments 2>&1 | Out-String
	return [pscustomobject]@{ Code = $LASTEXITCODE; Out = $out.Trim() }
}

# exe runs a program and fails with its output when it fails.
function exe {
	param([string]$file, [string[]]$arguments)
	$r = run $file $arguments
	if ($r.Code -ne 0) {
		throw "$file $($arguments -join ' ') exited with $($r.Code)`: $($r.Out)"
	}
	return $r.Out
}

$step = 'checking for administrator rights'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-Host 'install.ps1: run it in a PowerShell opened with "Run as administrator".' -ForegroundColor Red
	exit 1
}
if ($Port -ne 0 -and ($Port -lt 1024 -or $Port -gt 65535)) {
	Write-Host 'install.ps1: -Port takes a port from 1024 to 65535.' -ForegroundColor Red
	exit 2
}
if ($env:CBB_FIREWALL -eq 'no') {
	$NoFirewall = $true
}

$step = 'checking the binaries'
if ($Bin -eq '') {
	$Bin = Join-Path $PSScriptRoot '..\..\cbb.exe'
}
$Bin = (Resolve-Path $Bin).Path
$binW = Join-Path (Split-Path $Bin) 'cbbw.exe'
if (-not (Test-Path $binW)) {
	throw "cbbw.exe is missing beside $Bin"
}
$version = (exe $Bin @('version')).Trim()
if ($version -notmatch 'windows/') {
	throw "$Bin is not built for Windows: $version"
}

# The user signed in at the console, who gets the clipboard: the one who
# opened this window as administrator, or the one an administrator helped.
$step = 'finding the signed-in user'
$user = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $user) {
	$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
}

$step = 'stopping clipboardbridge'
$service = Get-Service -Name $name -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped') {
	Stop-Service -Name $name -Force
}
# The agents of every session and any cbb still running keep the files open.
# Stopping a process takes a moment, and an agent the last install started
# may still be starting, so each try stops what runs, waits for it to exit,
# and copies; a file still in use means another try.
$stopRunning = {
	$running = @(Get-Process -Name cbbw, cbb -ErrorAction SilentlyContinue | Where-Object {
		$_.Path -and $_.Path.StartsWith($programDir, [StringComparison]::OrdinalIgnoreCase)
	})
	$running | Stop-Process -Force -ErrorAction SilentlyContinue
	$running | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
}

$step = "copying the files to $programDir"
New-Item -ItemType Directory -Force -Path $programDir | Out-Null
for ($try = 1; ; $try++) {
	& $stopRunning
	try {
		Copy-Item -Force $Bin (Join-Path $programDir 'cbb.exe')
		Copy-Item -Force $binW (Join-Path $programDir 'cbbw.exe')
		break
	} catch {
		if ($try -ge 10 -or $_.Exception -isnot [System.IO.IOException]) {
			throw
		}
		Start-Sleep -Milliseconds 500
	}
}
Copy-Item -Force (Join-Path $PSScriptRoot 'uninstall.ps1') (Join-Path $programDir 'uninstall.ps1')
$cbb = Join-Path $programDir 'cbb.exe'
$cbbw = Join-Path $programDir 'cbbw.exe'

$step = 'adding clipboardbridge to PATH'
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (($path -split ';') -notcontains $programDir) {
	[Environment]::SetEnvironmentVariable('Path', ($path.TrimEnd(';') + ';' + $programDir), 'Machine')
}

$step = "making the $name group"
$computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
$exists = $false
foreach ($child in $computer.Children) {
	if ($child.SchemaClassName -eq 'Group' -and $child.Name -eq $name) {
		$exists = $true
	}
}
if (-not $exists) {
	$group = $computer.Create('group', $name)
	$group.Put('Description', 'May use the clipboardbridge service: cbb and the clipboard agent.')
	$group.SetInfo()
}
$step = "adding $user to the $name group"
$r = run net.exe @('localgroup', $name, $user, '/add')
# 1378: already a member.
if ($r.Code -ne 0 -and $r.Out -notmatch '1378') {
	throw "net localgroup $name $user /add exited with $($r.Code)`: $($r.Out)"
}

$step = 'creating the service'
$binPath = "`"$cbb`" service"
if (-not $service) {
	New-Service -Name $name -BinaryPathName $binPath -DisplayName 'clipboardbridge' -StartupType Automatic `
		-Description 'Shares the clipboard with the other devices at home.' | Out-Null
}
# The path through CIM, as Windows PowerShell 5.1 drops the quotes inside
# an argument that it passes to sc.exe.
$change = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'" |
	Invoke-CimMethod -MethodName Change -Arguments @{ PathName = $binPath }
if ($change.ReturnValue -ne 0) {
	throw "setting the service's path failed with $($change.ReturnValue)"
}
# A virtual account: an account of the service's own, with no password and
# no rights beyond what is granted to it here.
exe sc.exe @('config', $name, 'start=', 'auto', 'obj=', "NT SERVICE\$name") | Out-Null
exe sc.exe @('sidtype', $name, 'unrestricted') | Out-Null
exe sc.exe @('privs', $name, 'SeChangeNotifyPrivilege') | Out-Null
exe sc.exe @('failure', $name, 'reset=', '86400', 'actions=', 'restart/5000/restart/5000/restart/60000') | Out-Null
exe sc.exe @('failureflag', $name, '1') | Out-Null

# The port: the one given, else the one kept from before, else 8764. The
# service reads CBB_PORT from its environment, kept in its registry key.
$step = 'setting the port'
$kept = (Get-ItemProperty -Path $serviceKey -Name Environment -ErrorAction SilentlyContinue)
if ($Port -eq 0) {
	$Port = 8764
	if ($kept) {
		foreach ($line in $kept.Environment) {
			if ($line -match '^CBB_PORT=(\d+)$') {
				$Port = [int]$Matches[1]
			}
		}
	}
}
if ($Port -eq 8764) {
	Remove-ItemProperty -Path $serviceKey -Name Environment -ErrorAction SilentlyContinue
} else {
	New-ItemProperty -Path $serviceKey -Name Environment -PropertyType MultiString -Value @("CBB_PORT=$Port") -Force | Out-Null
}

# ProgramData lets every user create folders, so a folder that was there
# before could belong to anyone: it gets administrators as owner and a
# fresh, protected access list. The service makes run\ itself, with the
# list that lets the group reach the control socket.
$step = "narrowing $dataDir"
New-Item -ItemType Directory -Force -Path $dataDir, (Join-Path $dataDir 'state'), (Join-Path $dataDir 'logs') | Out-Null
Remove-Item -Recurse -Force (Join-Path $dataDir 'run') -ErrorAction SilentlyContinue
exe icacls.exe @($dataDir, '/setowner', '*S-1-5-32-544', '/T', '/C', '/Q') | Out-Null
exe icacls.exe @($dataDir, '/reset', '/T', '/C', '/Q') | Out-Null
exe icacls.exe @($dataDir, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "NT SERVICE\$name`:(OI)(CI)F", '/Q') | Out-Null

$step = 'allowing clipboardbridge in Windows Firewall'
# Every rule carries the group clipboardbridge, so these lines and
# uninstall.ps1 remove exactly the rules added here.
# cbb away on turns the outbound rule off; a reinstall keeps that.
$homeOnly = Get-NetFirewallRule -Name "$name-home-only" -ErrorAction SilentlyContinue
$awayOn = $homeOnly -and [string]$homeOnly.Enabled -eq 'False'
Get-NetFirewallRule -Group $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if (-not $NoFirewall) {
	New-NetFirewallRule -Group $name -DisplayName "clipboardbridge (TCP $Port)" -Direction Inbound -Action Allow `
		-Protocol TCP -LocalPort $Port -Program $cbb -RemoteAddress LocalSubnet -Profile Any `
		-Description 'clipboardbridge members and phones at home connect here.' | Out-Null
	New-NetFirewallRule -Group $name -DisplayName 'clipboardbridge mDNS (UDP 5353)' -Direction Inbound -Action Allow `
		-Protocol UDP -LocalPort 5353 -Program $cbb -RemoteAddress LocalSubnet -Profile Any `
		-Description 'clipboardbridge finds the other devices at home with mDNS.' | Out-Null
}

$step = 'keeping the service on the home network'
# The service may reach only the home network, as its systemd unit allows
# on Linux: a block rule beats every allow rule, so it holds whatever else
# the firewall allows. It is a limit, not an opening, so -NoFirewall keeps
# it. Allowed are loopback, private IPv4, link-local, multicast and
# broadcast, and unique-local, link-local and multicast IPv6; the rule
# lists the rest. cbb away on turns it off for sync away from home, and cbb
# away off on again.
$outside = @(
	'0.0.0.0-9.255.255.255', '11.0.0.0-126.255.255.255', '128.0.0.0-169.253.255.255',
	'169.255.0.0-172.15.255.255', '172.32.0.0-192.167.255.255', '192.169.0.0-223.255.255.255',
	'::2-fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'fe00::-fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
	'fec0::-feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
$enabled = if ($awayOn) { 'False' } else { 'True' }
New-NetFirewallRule -Name "$name-home-only" -Group $name -DisplayName 'clipboardbridge: only the home network' `
	-Direction Outbound -Action Block -Program $cbb -Service $name -RemoteAddress $outside -Profile Any -Enabled $enabled `
	-Description 'The clipboardbridge service reaches only the home network until cbb away on turns this rule off.' | Out-Null

$step = 'starting the service'
Start-Service -Name $name

$step = 'starting the agent with every sign-in'
New-ItemProperty -Path $runKey -Name $name -PropertyType String -Value "`"$cbbw`" agent" -Force | Out-Null

# The agent must run as the user, not as administrator: a task that runs
# once in the user's session starts it now.
# Without a signed-in user, or if the task fails, the next sign-in starts it.
$step = "starting the agent for $user"
$task = 'clipboardbridge agent start'
try {
	$action = New-ScheduledTaskAction -Execute $cbbw -Argument 'agent'
	$taskPrincipal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
	$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
	Register-ScheduledTask -TaskName $task -Action $action -Principal $taskPrincipal -Settings $settings -Force | Out-Null
	Start-ScheduledTask -TaskName $task
	Start-Sleep -Seconds 1
} catch {
	Write-Host "The agent did not start now ($($_.Exception.Message)); it starts when $user signs in again."
	if ($details) {
		$_ | Format-List * -Force | Out-String | Write-Host
	}
} finally {
	Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
}

$step = 'registering the uninstaller'
New-Item -Force -Path $uninstallKey | Out-Null
$uninstall = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $programDir 'uninstall.ps1')`""
$v = ($version -split ' ')[1]
foreach ($p in @(
		@('DisplayName', 'clipboardbridge', 'String'),
		@('DisplayVersion', $v, 'String'),
		@('Publisher', 'HunterEwok', 'String'),
		@('InstallLocation', $programDir, 'String'),
		@('DisplayIcon', $cbb, 'String'),
		@('UninstallString', $uninstall, 'String'),
		@('URLInfoAbout', 'https://github.com/HunterEwok/clipboardbridge', 'String'),
		@('NoModify', 1, 'DWord'),
		@('NoRepair', 1, 'DWord'))) {
	New-ItemProperty -Path $uninstallKey -Name $p[0] -Value $p[1] -PropertyType $p[2] -Force | Out-Null
}

$step = 'waiting for the service'
$ok = $false
for ($i = 0; $i -lt 20; $i++) {
	& $cbb status *> $null
	if ($LASTEXITCODE -eq 0) {
		$ok = $true
		break
	}
	Start-Sleep -Milliseconds 500
}
if (-not $ok) {
	throw "the service does not answer; its log is $(Join-Path $dataDir 'logs\service.log')"
}

Write-Host "clipboardbridge $v is running on TCP port $Port; $user may use it."
if ($Port -ne 8764) {
	Write-Host 'The iPhone shortcut works only with port 8764; the clipboardbridge app takes any port.'
}
if ($NoFirewall) {
	Write-Host "Windows Firewall was left alone: allow TCP $Port and UDP 5353 from the home network for $cbb."
}
Write-Host 'Next, in a new terminal: cbb pair, and scan its QR code with the phone or type the code from cbb pair on the group''s root or an admin; or start a group: cbb new.'
Write-Host 'To remove it: Settings, Apps, clipboardbridge, Uninstall.'
