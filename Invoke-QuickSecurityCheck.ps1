<#
.SYNOPSIS
    Free, read-only quick security check for a Windows PC (6 checks).

.DESCRIPTION
    Checks the basics most cyber insurers and IT auditors ask about:
      1. Microsoft Defender real-time protection and signature age
      2. Windows Firewall profiles
      3. BitLocker on the system drive
      4. Days since the last installed update
      5. Remote Desktop (RDP) and Network Level Authentication
      6. SMBv1

    The script makes NO changes. It only reads settings and prints PASS / WARN / FAIL.
    Run it in an elevated (Run as administrator) PowerShell window for complete results.
    Use -Html to also save a simple HTML report next to the script.

    Full version (15 checks, color-coded HTML report, local admins, ports, UAC,
    screen lock, PowerShell v2, plus 4 bonus scripts):
    https://toddler644.gumroad.com/l/ebylvl

.EXAMPLE
    .\Invoke-QuickSecurityCheck.ps1
.EXAMPLE
    .\Invoke-QuickSecurityCheck.ps1 -Html

.NOTES
    Author: William Todd. MIT License. Provided as-is; test before use.
#>
[CmdletBinding()]
param([switch]$Html)

$results = New-Object System.Collections.Generic.List[object]
function Add-Result($Check, $Status, $Detail, $Fix) {
    $results.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail; Fix = $Fix })
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# 1. Defender
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $age = $mp.AntivirusSignatureAge
    if (-not $mp.RealTimeProtectionEnabled) {
        Add-Result 'Defender real-time protection' 'FAIL' 'Real-time protection is OFF' 'Turn on real-time protection, or confirm another antivirus/EDR is active.'
    } elseif ($age -gt 3) {
        Add-Result 'Defender real-time protection' 'WARN' "On, but signatures are $age days old" 'Run Windows Update or update Defender signatures.'
    } else {
        Add-Result 'Defender real-time protection' 'PASS' "On, signatures $age day(s) old" ''
    }
} catch {
    Add-Result 'Defender real-time protection' 'WARN' 'Could not read Defender status (another antivirus may be installed)' 'Confirm your antivirus/EDR is installed, running and updating.'
}

# 2. Firewall
try {
    $off = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled } | ForEach-Object Name)
    if ($off.Count) { Add-Result 'Windows Firewall' 'FAIL' ("Disabled for: " + ($off -join ', ')) 'Turn the firewall on for all profiles (Domain, Private, Public).' }
    else { Add-Result 'Windows Firewall' 'PASS' 'Enabled for all profiles' '' }
} catch { Add-Result 'Windows Firewall' 'WARN' 'Could not read firewall profiles' 'Check Windows Security > Firewall & network protection.' }

# 3. BitLocker (system drive)
try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($bl.ProtectionStatus -eq 'On') { Add-Result 'BitLocker (system drive)' 'PASS' "Protection on ($($bl.EncryptionPercentage)% encrypted)" '' }
    else { Add-Result 'BitLocker (system drive)' 'FAIL' 'System drive is not protected' 'Turn on BitLocker (or Device Encryption) so a lost laptop is not a data breach.' }
} catch {
    $msg = if ($isAdmin) { 'BitLocker not available or not readable' } else { 'Needs Run as administrator to read' }
    Add-Result 'BitLocker (system drive)' 'WARN' $msg 'Run elevated, or check Settings > Privacy & security > Device encryption.'
}

# 4. Last update
try {
    $last = Get-HotFix -ErrorAction Stop | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($last) {
        $days = [int]((Get-Date) - $last.InstalledOn).TotalDays
        if ($days -gt 60) { Add-Result 'Windows updates' 'FAIL' "Last update installed $days days ago ($($last.HotFixID))" 'Install updates now and confirm automatic updates are working.' }
        elseif ($days -gt 35) { Add-Result 'Windows updates' 'WARN' "Last update installed $days days ago ($($last.HotFixID))" 'Check Windows Update. Monthly updates are normal.' }
        else { Add-Result 'Windows updates' 'PASS' "Last update installed $days day(s) ago ($($last.HotFixID))" '' }
    } else { Add-Result 'Windows updates' 'WARN' 'No dated updates found' 'Check Windows Update history.' }
} catch { Add-Result 'Windows updates' 'WARN' 'Could not read update history' 'Check Windows Update history.' }

# 5. RDP + NLA
try {
    $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections
    if ($deny -eq 1) { Add-Result 'Remote Desktop (RDP)' 'PASS' 'RDP is disabled' '' }
    else {
        $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction Stop).UserAuthentication
        if ($nla -eq 1) { Add-Result 'Remote Desktop (RDP)' 'WARN' 'RDP is enabled, with Network Level Authentication' 'Disable RDP if unused. Never expose it directly to the internet; put it behind a VPN with MFA.' }
        else { Add-Result 'Remote Desktop (RDP)' 'FAIL' 'RDP is enabled WITHOUT Network Level Authentication' 'Disable RDP, or at minimum require Network Level Authentication.' }
    }
} catch { Add-Result 'Remote Desktop (RDP)' 'WARN' 'Could not read RDP settings' 'Check Settings > System > Remote Desktop.' }

# 6. SMBv1
try {
    $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
    if ($smb1) { Add-Result 'SMBv1' 'FAIL' 'SMBv1 server protocol is enabled' 'Disable SMBv1. It is obsolete and was used by WannaCry.' }
    else { Add-Result 'SMBv1' 'PASS' 'SMBv1 is disabled' '' }
} catch { Add-Result 'SMBv1' 'WARN' 'Could not read SMB configuration' 'Run elevated and check Get-SmbServerConfiguration.' }

# Output
$colors = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red' }
Write-Host ""
Write-Host "Quick Security Check  -  $env:COMPUTERNAME  -  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan
if (-not $isAdmin) { Write-Host "(Not running as administrator: some checks may show WARN)" -ForegroundColor DarkGray }
Write-Host ""
foreach ($r in $results) {
    Write-Host ("[{0}] " -f $r.Status) -ForegroundColor $colors[$r.Status] -NoNewline
    Write-Host ("{0}: {1}" -f $r.Check, $r.Detail)
    if ($r.Fix) { Write-Host ("       Fix: {0}" -f $r.Fix) -ForegroundColor DarkGray }
}
$fails = @($results | Where-Object Status -eq 'FAIL').Count
$warns = @($results | Where-Object Status -eq 'WARN').Count
Write-Host ""
Write-Host ("Summary: {0} pass, {1} warn, {2} fail" -f ($results.Count - $fails - $warns), $warns, $fails) -ForegroundColor Cyan
Write-Host "Full 15-check audit with HTML report: https://toddler644.gumroad.com/l/ebylvl" -ForegroundColor DarkGray

if ($Html) {
    $rows = ($results | ForEach-Object {
        $c = @{ PASS = '#16a34a'; WARN = '#ca8a04'; FAIL = '#dc2626' }[$_.Status]
        "<tr><td style='color:$c;font-weight:700'>$($_.Status)</td><td>$([System.Net.WebUtility]::HtmlEncode($_.Check))</td><td>$([System.Net.WebUtility]::HtmlEncode($_.Detail))</td><td>$([System.Net.WebUtility]::HtmlEncode($_.Fix))</td></tr>"
    }) -join "`n"
    $path = Join-Path $PSScriptRoot ("QuickSecurityCheck-{0}-{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmm'))
    @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Quick Security Check - $env:COMPUTERNAME</title>
<style>body{font-family:Segoe UI,sans-serif;max-width:900px;margin:2rem auto;color:#1e293b}table{border-collapse:collapse;width:100%}td,th{border:1px solid #e2e8f0;padding:.5rem;text-align:left;vertical-align:top}th{background:#f1f5f9}</style></head><body>
<h1>Quick Security Check</h1><p>$env:COMPUTERNAME &middot; $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; $($results.Count - $fails - $warns) pass, $warns warn, $fails fail</p>
<table><tr><th>Status</th><th>Check</th><th>Detail</th><th>Fix</th></tr>
$rows
</table><p style="color:#64748b">Free quick check (6 items). Full audit with 15 checks: <a href="https://toddler644.gumroad.com/l/ebylvl">Windows Endpoint Security Audit</a></p></body></html>
"@ | Set-Content -Path $path -Encoding UTF8
    Write-Host "HTML report saved: $path" -ForegroundColor Cyan
}
