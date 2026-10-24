# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Prepares a Windows device for the test bench (docs/testbench.md). Run it
# once, in an elevated PowerShell, while signed in as the user the bench
# connects as:
#
#   powershell -ExecutionPolicy Bypass -File setup-windows.ps1
#
# It turns on the OpenSSH server and registers two scheduled tasks that run in
# this user's desktop session, where the clipboard is: cbbbench-copy puts
# C:\ProgramData\cbbbench\in.txt on the clipboard, cbbbench-paste writes the
# clipboard to out.txt. An SSH session cannot reach the desktop clipboard
# itself. The controller's public key goes into
# C:\ProgramData\ssh\administrators_authorized_keys (for an administrator) or
# ~\.ssh\authorized_keys by hand.
#
# Run it again to update; -Remove takes the tasks and the folder away.
param([switch]$Remove)
$ErrorActionPreference = 'Stop'

$dir = 'C:\ProgramData\cbbbench'
$tasks = 'cbbbench-copy', 'cbbbench-paste'

if ($Remove) {
	foreach ($t in $tasks) { Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue }
	Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
	Write-Output 'The bench tasks are removed. The OpenSSH server stays.'
	exit 0
}

if ((Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0').State -ne 'Installed') {
	Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
}
Set-Service sshd -StartupType Automatic
Start-Service sshd

New-Item -ItemType Directory -Force $dir | Out-Null
Set-Content -Encoding UTF8 "$dir\copy.ps1" @'
$f = 'C:\ProgramData\cbbbench\in.txt'
if (Test-Path $f) {
	Set-Clipboard -Value ([IO.File]::ReadAllText($f, [Text.Encoding]::UTF8))
	Remove-Item $f
}
'@
Set-Content -Encoding UTF8 "$dir\paste.ps1" @'
$t = Get-Clipboard -Raw
if ($null -eq $t) { $t = '' }
$tmp = 'C:\ProgramData\cbbbench\out.tmp'
[IO.File]::WriteAllText($tmp, $t, (New-Object Text.UTF8Encoding $false))
Move-Item -Force $tmp 'C:\ProgramData\cbbbench\out.txt'
'@

$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive
foreach ($name in 'copy', 'paste') {
	$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $dir\$name.ps1"
	Register-ScheduledTask -TaskName "cbbbench-$name" -Action $action -Principal $principal -Force | Out-Null
}
Write-Output "Ready: OpenSSH server on, tasks for $user. Stay signed in: the tasks run in this session."
