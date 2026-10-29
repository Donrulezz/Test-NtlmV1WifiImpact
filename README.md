# Test-NtlmV1WifiImpact

**Find out in seconds whether a Windows PC loses 802.1X Wi-Fi, wired or VPN sign-in after the October 2026 update
(KB5127648 on Windows 11, KB5126646 on Windows Server 2025), and why.**

From the October 2026 update, if `BlockNtlmv1SSO` is not set, Windows switches from Audit to **Enforce** and blocks
NTLMv1-derived single sign-on credentials (Microsoft 365 message center MC1508562). PEAP / EAP-MSCHAPv2 profiles that sign in
with the user's Windows credentials then fail, while typing the password by hand still works. Devices with Credential Guard
running, certificate-based profiles (EAP-TLS / PEAP-TLS), PSK networks and manually typed credentials are not affected.

The script is read-only. It changes nothing.

```powershell
.\Test-NtlmV1WifiImpact.ps1
.\Test-NtlmV1WifiImpact.ps1 -Csv \\server\share\ntlmv1-$env:COMPUTERNAME.csv   # one CSV per PC, e.g. from a startup script
```

```
NTLMv1 SSO check on PC-0142
  October update installed : KB5127648
  BlockNtlmv1SSO           : not set: Enforce after the October update
  Credential Guard running : False
  Event 4025, last 14 days : 37

Kind  Profile   Method              UsesWindowsLogon Verdict
----  -------   ------              ---------------- -------
Wi-Fi CorpWiFi  PEAP + EAP-MSCHAPv2             True AFFECTED: PEAP-MSCHAPv2 with Windows logon credentials, Enforce mode
```

## What it reads

| Check | Source |
|---|---|
| October update installed | `Get-HotFix` (KB5127648, KB5126646) |
| Enforce or Audit | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\BlockNtlmv1SSO` (missing = Enforce after the update) |
| Credential Guard | `Win32_DeviceGuard.SecurityServicesRunning` contains 1 |
| 802.1X profiles | `netsh wlan / lan export profile`: EAP types (13 EAP-TLS, 25 PEAP, 26 EAP-MSCHAPv2) and `UseWinLogonCredentials` |
| Blocked sign-ins | `Microsoft-Windows-NTLM/Operational`, event 4025, last 14 days |

## What to do when it says AFFECTED

- **Quick and temporary:** set the DWORD `BlockNtlmv1SSO = 0` under the key above, with Group Policy Preferences or Intune.
  This turns the weaker NTLMv1-derived SSO back on, so treat it as a bridge.
- **Lasting:** move the Wi-Fi, wired and VPN profiles to certificate-based sign-in (EAP-TLS or PEAP-TLS), or turn on
  Credential Guard where the hardware supports it.

Run it as administrator for the event log and Device Guard results. Windows PowerShell 5.1 or PowerShell 7.

MIT licensed. Not affiliated with Microsoft. Check Microsoft's KB5127648 article and MC1508562 before changing production
settings.

## Need it done?
Many PCs, or no time to move Wi-Fi to certificates? I check every PC, deploy the stop-gap by Group Policy or Intune the same
day, and can move your Wi-Fi, wired or VPN to EAP-TLS: [fix office Wi-Fi, LAN or VPN login after KB5127648 (Fiverr, from $35)](https://www.fiverr.com/donrulezz/fix-spf-dkim-and-dmarc-so-your-emails-stop-going-to-spam).
The script stays free.
