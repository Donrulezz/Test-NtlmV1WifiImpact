<#
.SYNOPSIS
    Read-only check: will this Windows PC lose 802.1X Wi-Fi, wired or VPN sign-in because of the October 2026 NTLMv1 SSO change
    (KB5127648 on Windows 11, KB5126646 on Windows Server 2025)?

.DESCRIPTION
    From the October 2026 update, if HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\BlockNtlmv1SSO is not set, Windows uses
    Enforce mode (1) instead of Audit mode (0) and blocks NTLMv1-derived single sign-on credentials (Microsoft 365 message center
    MC1508562). PEAP / EAP-MSCHAPv2 profiles that sign in with the Windows logon credentials then fail. Devices with Credential
    Guard running, certificate-based profiles (EAP-TLS / PEAP-TLS), PSK networks and manually typed credentials are not affected.

    The script reads, and changes nothing:
      - whether KB5127648 / KB5126646 is installed
      - the BlockNtlmv1SSO value (missing = Enforce after the update)
      - whether Credential Guard is running
      - every Wi-Fi and wired 802.1X profile: EAP method and whether it uses the Windows logon credentials
      - NTLM/Operational event 4025 in the last 14 days (blocked NTLMv1 SSO)
    and prints a verdict per profile. -Csv writes the same to a file, for running across many PCs.

.EXAMPLE
    .\Test-NtlmV1WifiImpact.ps1
.EXAMPLE
    .\Test-NtlmV1WifiImpact.ps1 -Csv C:\Temp\ntlmv1-$env:COMPUTERNAME.csv

.NOTES
    Run in Windows PowerShell 5.1 or PowerShell 7. Admin rights give the most complete result (event log, Device Guard).
    MIT licensed. Not affiliated with Microsoft.
#>
[CmdletBinding()]
param([string]$Csv)

$ErrorActionPreference = 'Continue'
$EapNames = @{ 13 = 'EAP-TLS'; 25 = 'PEAP'; 26 = 'EAP-MSCHAPv2'; 21 = 'EAP-TTLS'; 55 = 'TEAP' }

function Get-RegValue {
    try { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name BlockNtlmv1SSO -ErrorAction Stop).BlockNtlmv1SSO }
    catch { $null }
}

function Get-CredentialGuardRunning {
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
        return [bool]($dg.SecurityServicesRunning -contains 1)
    } catch { return $null }
}

function Read-Profiles([string]$Kind) {
    # Kind: wlan or lan. Exports profiles to a temp folder and parses the EAP configuration.
    $dir = Join-Path ([IO.Path]::GetTempPath()) ("ntlmv1check-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $dir | Out-Null
    try {
        if ($Kind -eq 'lan' -and (Get-Service dot3svc -ErrorAction SilentlyContinue).Status -ne 'Running') { return @() }
        & netsh $Kind export profile folder="$dir" 2>$null | Out-Null
        foreach ($f in Get-ChildItem $dir -Filter *.xml) {
            [xml]$x = Get-Content $f.FullName -Raw
            $name = if ($x.WLANProfile) { $x.WLANProfile.name } else { $f.BaseName }
            $types = @($x.SelectNodes("//*[local-name()='Type']") | ForEach-Object { [int]$_.InnerText } | Select-Object -Unique)
            if (-not $types) { continue }  # PSK / open network: not 802.1X
            $logon = @($x.SelectNodes("//*[local-name()='UseWinLogonCredentials']") | ForEach-Object { $_.InnerText }) -contains 'true'
            $method = ($types | ForEach-Object { if ($EapNames[$_]) { $EapNames[$_] } else { "EAP type $_" } }) -join ' + '
            [pscustomobject]@{
                Kind = if ($Kind -eq 'wlan') { 'Wi-Fi' } else { 'Wired' }
                Profile = $name
                Method = $method
                MsChapV2 = $types -contains 26
                Certificate = $types -contains 13
                UsesWindowsLogon = $logon
            }
        }
    } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
}

$kb = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.HotFixID -in 'KB5127648', 'KB5126646' } | ForEach-Object HotFixID)
$reg = Get-RegValue
$cg = Get-CredentialGuardRunning
$events = $null
try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-NTLM/Operational'; Id = 4025; StartTime = (Get-Date).AddDays(-14) } -ErrorAction Stop).Count
} catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = 0 } }

$mode = switch ($reg) { 0 { 'Audit (0): SSO allowed' } 1 { 'Enforce (1): SSO blocked' } $null { if ($kb) { 'not set: Enforce after the October update' } else { 'not set (update not installed yet)' } } default { "value $reg" } }

Write-Host "`nNTLMv1 SSO check on $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host ("  October update installed : {0}" -f $(if ($kb) { $kb -join ', ' } else { 'no' }))
Write-Host ("  BlockNtlmv1SSO           : {0}" -f $mode)
Write-Host ("  Credential Guard running : {0}" -f $(if ($null -eq $cg) { 'unknown (run as admin)' } else { $cg }))
Write-Host ("  Event 4025, last 14 days : {0}" -f $(if ($null -eq $events) { 'unknown (run as admin)' } else { $events }))

$enforced = ($reg -eq 1) -or ($null -eq $reg -and $kb)
$profiles = @(Read-Profiles 'wlan') + @(Read-Profiles 'lan')
$rows = foreach ($p in $profiles) {
    $verdict =
        if ($p.Certificate -and -not $p.MsChapV2) { 'OK: certificate-based, not affected' }
        elseif (-not $p.MsChapV2) { 'OK: not MSCHAPv2' }
        elseif ($cg) { 'OK: Credential Guard is running' }
        elseif (-not $p.UsesWindowsLogon) { 'OK: user types credentials (no SSO)' }
        elseif ($enforced) { 'AFFECTED: PEAP-MSCHAPv2 with Windows logon credentials, Enforce mode' }
        else { 'AT RISK: affected once the October update is installed' }
    $p | Add-Member -NotePropertyName Verdict -NotePropertyValue $verdict -PassThru |
        Add-Member -NotePropertyName Computer -NotePropertyValue $env:COMPUTERNAME -PassThru |
        Add-Member -NotePropertyName BlockNtlmv1SSO -NotePropertyValue $(if ($null -eq $reg) { 'not set' } else { $reg }) -PassThru |
        Add-Member -NotePropertyName CredentialGuard -NotePropertyValue $cg -PassThru |
        Add-Member -NotePropertyName Event4025Last14d -NotePropertyValue $events -PassThru
}

if (-not $rows) {
    Write-Host "`n  No 802.1X Wi-Fi or wired profiles on this PC: nothing here depends on NTLMv1 SSO." -ForegroundColor Green
} else {
    $rows | Format-Table Kind, Profile, Method, UsesWindowsLogon, Verdict -AutoSize
    if ($rows.Verdict -match '^(AFFECTED|AT RISK)') {
        Write-Host "What to do:" -ForegroundColor Yellow
        Write-Host "  Quick, temporary: set BlockNtlmv1SSO = 0 (DWORD) under HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        Write-Host "  by Group Policy Preferences or Intune. This re-enables the weaker NTLMv1-derived SSO."
        Write-Host "  Lasting: move these profiles to certificate-based sign-in (EAP-TLS or PEAP-TLS), or turn on Credential Guard."
    }
}

if ($Csv) {
    $out = if ($rows) { $rows } else { [pscustomobject]@{ Computer = $env:COMPUTERNAME; Kind = ''; Profile = ''; Method = ''; MsChapV2 = ''; Certificate = ''; UsesWindowsLogon = ''; Verdict = 'No 802.1X profiles'; BlockNtlmv1SSO = $(if ($null -eq $reg) { 'not set' } else { $reg }); CredentialGuard = $cg; Event4025Last14d = $events } }
    # Spreadsheet apps run cells that start with = + - @ as formulas: prefix those with an apostrophe.
    $out | ForEach-Object {
        foreach ($prop in $_.PSObject.Properties) { if ($prop.Value -is [string] -and $prop.Value -match '^[=+\-@]') { $prop.Value = "'" + $prop.Value } }
        $_
    } | Select-Object Computer, Kind, Profile, Method, MsChapV2, Certificate, UsesWindowsLogon, Verdict, BlockNtlmv1SSO, CredentialGuard, Event4025Last14d |
        Export-Csv -Path $Csv -NoTypeInformation -Encoding UTF8
    Write-Host "Saved $Csv"
}
