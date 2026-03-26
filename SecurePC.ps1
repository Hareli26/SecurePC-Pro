<#
.SYNOPSIS
    SecurePC — Windows Security Hardening Tool v1.0
.DESCRIPTION
    Scans 18 common Windows security weaknesses.
    Presents each finding with a FIX button — no change is made without your approval.
    Requires Administrator privileges (auto-elevates on launch).
#>
param()
Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

# ═══════════════════════════════════════════════════════════════════════════════
#  SELF-ELEVATE TO ADMINISTRATOR
# ═══════════════════════════════════════════════════════════════════════════════
if (-not ([Security.Principal.WindowsPrincipal]
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" `
        -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
[Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

# ═══════════════════════════════════════════════════════════════════════════════
#  COLOUR PALETTE  (dark cybersecurity theme)
# ═══════════════════════════════════════════════════════════════════════════════
$script:C = @{
    Bg        = [Drawing.Color]::FromArgb( 13,  13,  20)
    Panel     = [Drawing.Color]::FromArgb( 20,  20,  32)
    Card      = [Drawing.Color]::FromArgb( 26,  26,  40)
    Border    = [Drawing.Color]::FromArgb( 44,  44,  68)
    Accent    = [Drawing.Color]::FromArgb( 99, 179, 237)
    Critical  = [Drawing.Color]::FromArgb(245,  85,  85)
    High      = [Drawing.Color]::FromArgb(237, 130,  48)
    Medium    = [Drawing.Color]::FromArgb(246, 220,  80)
    Low       = [Drawing.Color]::FromArgb(100, 210, 140)
    Secure    = [Drawing.Color]::FromArgb( 72, 199, 142)
    Vuln      = [Drawing.Color]::FromArgb(245,  85,  85)
    VulnBg    = [Drawing.Color]::FromArgb( 52,  20,  20)
    SecureBg  = [Drawing.Color]::FromArgb( 16,  38,  28)
    FixedBg   = [Drawing.Color]::FromArgb( 14,  44,  28)
    Text      = [Drawing.Color]::FromArgb(235, 235, 245)
    SubText   = [Drawing.Color]::FromArgb(140, 140, 170)
    BtnScan   = [Drawing.Color]::FromArgb( 38, 120, 200)
    BtnFix    = [Drawing.Color]::FromArgb(200,  50,  50)
    BtnAll    = [Drawing.Color]::FromArgb(112,  80, 200)
    BtnRep    = [Drawing.Color]::FromArgb( 38,  75,  95)
    BtnCncl   = [Drawing.Color]::FromArgb( 65,  65,  85)
    Disabled  = [Drawing.Color]::FromArgb( 48,  48,  65)
    CheckOK   = [Drawing.Color]::FromArgb( 72, 199, 142)
}
$C = $script:C

# ═══════════════════════════════════════════════════════════════════════════════
#  SECURITY CHECKS  —  each entry: Name, Category, Severity, Desc, FixDesc,
#                       Check (scriptblock → @{Vuln=$bool; Info=$string}),
#                       Fix   (scriptblock)
# ═══════════════════════════════════════════════════════════════════════════════
$script:Checks = @(

    # ── 1 ─ Windows Firewall ────────────────────────────────────────────────
    @{
        Name    = 'Windows Firewall'
        Cat     = 'Network'
        Sev     = 'Critical'
        Desc    = 'All firewall profiles (Domain, Private, Public) must be enabled to block unauthorised inbound connections.'
        FixDesc = 'Enable all Windows Firewall profiles'
        Check   = {
            try {
                $off = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }
                if ($off.Count -gt 0) { @{ Vuln=$true;  Info="Disabled profiles: $($off.Name -join ', ')" } }
                else                  { @{ Vuln=$false; Info='All profiles are enabled' } }
            } catch { @{ Vuln=$false; Info='Check unavailable' } }
        }
        Fix = { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True }
    },

    # ── 2 ─ Windows Defender Real-Time Protection ───────────────────────────
    @{
        Name    = 'Windows Defender Real-Time Protection'
        Cat     = 'Anti-Malware'
        Sev     = 'Critical'
        Desc    = 'Real-time AV protection must be active to detect and block malware as it executes.'
        FixDesc = 'Re-enable Windows Defender real-time scanning'
        Check   = {
            try {
                $s = Get-MpComputerStatus -ErrorAction Stop
                if (-not $s.RealTimeProtectionEnabled) { @{ Vuln=$true;  Info='Real-time protection is DISABLED' } }
                else                                   { @{ Vuln=$false; Info='Real-time protection is active' } }
            } catch { @{ Vuln=$false; Info='Defender not available (3rd-party AV may be active)' } }
        }
        Fix = { Set-MpPreference -DisableRealtimeMonitoring $false }
    },

    # ── 3 ─ SMBv1 Protocol ──────────────────────────────────────────────────
    @{
        Name    = 'SMBv1 Protocol (EternalBlue / WannaCry)'
        Cat     = 'Network'
        Sev     = 'Critical'
        Desc    = 'SMBv1 is the obsolete protocol exploited by WannaCry ransomware. Must be disabled system-wide.'
        FixDesc = 'Disable SMBv1 server and optional-feature client'
        Check   = {
            try {
                $smb = Get-SmbServerConfiguration -ErrorAction Stop
                if ($smb.EnableSMB1Protocol) { @{ Vuln=$true;  Info='SMBv1 is ENABLED — high-risk legacy protocol' } }
                else                         { @{ Vuln=$false; Info='SMBv1 is disabled' } }
            } catch { @{ Vuln=$false; Info='Check unavailable' } }
        }
        Fix = {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
        }
    },

    # ── 4 ─ User Account Control (UAC) ──────────────────────────────────────
    @{
        Name    = 'User Account Control (UAC)'
        Cat     = 'Privilege Control'
        Sev     = 'High'
        Desc    = 'UAC blocks unauthorised privilege escalation. Disabling it lets any process silently become SYSTEM.'
        FixDesc = 'Enable UAC with standard elevation prompt'
        Check   = {
            $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -EA SilentlyContinue).EnableLUA
            if ($v -eq 0) { @{ Vuln=$true;  Info='UAC is completely DISABLED' } }
            else          { @{ Vuln=$false; Info="UAC is enabled (EnableLUA=$v)" } }
        }
        Fix = {
            $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            Set-ItemProperty $k EnableLUA                  1 -Type DWord
            Set-ItemProperty $k ConsentPromptBehaviorAdmin 5 -Type DWord
        }
    },

    # ── 5 ─ WDigest Plaintext Credential Caching ────────────────────────────
    @{
        Name    = 'WDigest Plaintext Credential Caching'
        Cat     = 'Credentials'
        Sev     = 'High'
        Desc    = 'WDigest stores credentials in cleartext in LSASS memory, enabling Mimikatz-style credential harvesting.'
        FixDesc = 'Set UseLogonCredential=0 to disable WDigest caching'
        Check   = {
            $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -EA SilentlyContinue).UseLogonCredential
            if ($v -eq 1) { @{ Vuln=$true;  Info='Plaintext caching ENABLED — Mimikatz risk' } }
            else          { @{ Vuln=$false; Info='WDigest caching disabled (secure)' } }
        }
        Fix = {
            $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
            Set-ItemProperty $k UseLogonCredential 0 -Type DWord
        }
    },

    # ── 6 ─ LLMNR Name Poisoning ────────────────────────────────────────────
    @{
        Name    = 'LLMNR Name Poisoning Attack Surface'
        Cat     = 'Network'
        Sev     = 'High'
        Desc    = 'LLMNR allows MITM name-poisoning attacks (Responder tool) for credential relay. Disable via policy.'
        FixDesc = 'Disable LLMNR via Group Policy registry key'
        Check   = {
            $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -EA SilentlyContinue).EnableMulticast
            if ($null -eq $v -or $v -ne 0) { @{ Vuln=$true;  Info='LLMNR is ENABLED (no disabling policy found)' } }
            else                           { @{ Vuln=$false; Info='LLMNR is disabled via policy' } }
        }
        Fix = {
            $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
            Set-ItemProperty $k EnableMulticast 0 -Type DWord
        }
    },

    # ── 7 ─ Remote Desktop (RDP) ────────────────────────────────────────────
    @{
        Name    = 'Remote Desktop Protocol (RDP)'
        Cat     = 'Remote Access'
        Sev     = 'High'
        Desc    = 'RDP exposes port 3389 to brute-force, BlueKeep, and DejaBlue exploits. Disable if not required.'
        FixDesc = 'Disable RDP and block its firewall rule'
        Check   = {
            $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -EA SilentlyContinue).fDenyTSConnections
            if ($v -eq 0) { @{ Vuln=$true;  Info='RDP is ENABLED — listening for connections' } }
            else          { @{ Vuln=$false; Info='RDP is disabled' } }
        }
        Fix = {
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 1 -Type DWord
            Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
        }
    },

    # ── 8 ─ Secure Boot ─────────────────────────────────────────────────────
    @{
        Name    = 'Secure Boot (UEFI)'
        Cat     = 'Firmware'
        Sev     = 'High'
        Desc    = 'Secure Boot prevents unsigned bootloaders and UEFI rootkits from persisting across reboots.'
        FixDesc = 'Enable Secure Boot in UEFI firmware (manual — instructions shown)'
        Check   = {
            try {
                $sb = Confirm-SecureBootUEFI -ErrorAction Stop
                if (-not $sb) { @{ Vuln=$true;  Info='Secure Boot is DISABLED in firmware settings' } }
                else          { @{ Vuln=$false; Info='Secure Boot is enabled' } }
            } catch { @{ Vuln=$false; Info='Secure Boot check unavailable (legacy BIOS?)' } }
        }
        Fix = {
            [Windows.Forms.MessageBox]::Show(
                "Secure Boot requires a manual change in UEFI firmware:`n`n" +
                "1. Restart your PC`n2. Enter BIOS/UEFI setup (Del / F2 / F10 at boot)`n" +
                "3. Navigate to Security or Boot tab`n4. Set Secure Boot → Enabled`n5. Save and exit",
                'Manual Action Required — Secure Boot',
                [Windows.Forms.MessageBoxButtons]::OK,
                [Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        }
    },

    # ── 9 ─ BitLocker Drive Encryption ──────────────────────────────────────
    @{
        Name    = 'BitLocker Drive Encryption'
        Cat     = 'Data Protection'
        Sev     = 'High'
        Desc    = 'Full-disk encryption protects data at rest if the device is physically stolen or cold-booted.'
        FixDesc = 'Initiate BitLocker encryption on the system drive'
        Check   = {
            try {
                $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
                if ($v.ProtectionStatus -ne 'On') { @{ Vuln=$true;  Info="BitLocker status: $($v.ProtectionStatus) on $env:SystemDrive" } }
                else                              { @{ Vuln=$false; Info="BitLocker ON — $env:SystemDrive is encrypted" } }
            } catch { @{ Vuln=$false; Info='BitLocker check unavailable (Home edition?)' } }
        }
        Fix = {
            Start-Process 'manage-bde.exe' "-on $env:SystemDrive -RecoveryPassword" -ErrorAction SilentlyContinue
            [Windows.Forms.MessageBox]::Show(
                "BitLocker encryption has been initiated on $env:SystemDrive.`n`n" +
                "IMPORTANT: Save your recovery key when prompted.`n" +
                "Background encryption may take several hours to complete.",
                'BitLocker Initiated',
                [Windows.Forms.MessageBoxButtons]::OK,
                [Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        }
    },

    # ── 10 ─ Guest Account ───────────────────────────────────────────────────
    @{
        Name    = 'Built-in Guest Account'
        Cat     = 'Access Control'
        Sev     = 'Medium'
        Desc    = 'The Guest account provides unauthenticated local access and should remain disabled at all times.'
        FixDesc = 'Disable the built-in Guest account'
        Check   = {
            try {
                $g = Get-LocalUser -Name 'Guest' -ErrorAction Stop
                if ($g.Enabled) { @{ Vuln=$true;  Info='Guest account is ENABLED' } }
                else            { @{ Vuln=$false; Info='Guest account is disabled' } }
            } catch { @{ Vuln=$false; Info='Guest account not found' } }
        }
        Fix = { Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue }
    },

    # ── 11 ─ AutoRun / AutoPlay ──────────────────────────────────────────────
    @{
        Name    = 'AutoRun / AutoPlay (USB & Optical)'
        Cat     = 'Removable Media'
        Sev     = 'Medium'
        Desc    = 'AutoRun can silently execute malicious code from inserted USB drives or CDs without user interaction.'
        FixDesc = 'Disable AutoRun for all drive types via registry'
        Check   = {
            $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -EA SilentlyContinue).NoDriveTypeAutoRun
            if ($v -ne 255) { @{ Vuln=$true;  Info="NoDriveTypeAutoRun=$v (should be 255)" } }
            else            { @{ Vuln=$false; Info='AutoRun disabled for all drive types' } }
        }
        Fix = {
            $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
            Set-ItemProperty $k NoDriveTypeAutoRun 255 -Type DWord
            Set-ItemProperty $k NoAutorun           1  -Type DWord
        }
    },

    # ── 12 ─ Remote Registry Service ────────────────────────────────────────
    @{
        Name    = 'Remote Registry Service'
        Cat     = 'Attack Surface'
        Sev     = 'Medium'
        Desc    = 'Remote Registry lets remote users read and write the registry over the network — disable unless required.'
        FixDesc = 'Stop and permanently disable the RemoteRegistry service'
        Check   = {
            try {
                $s = Get-Service RemoteRegistry -ErrorAction Stop
                if ($s.Status -eq 'Running' -or $s.StartType -ne 'Disabled') {
                    @{ Vuln=$true;  Info="Service: $($s.Status) / Startup: $($s.StartType)" }
                } else { @{ Vuln=$false; Info='Service stopped and disabled' } }
            } catch { @{ Vuln=$false; Info='Service not found' } }
        }
        Fix = {
            Stop-Service RemoteRegistry -Force -ErrorAction SilentlyContinue
            Set-Service  RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue
        }
    },

    # ── 13 ─ Windows Script Host ─────────────────────────────────────────────
    @{
        Name    = 'Windows Script Host (WSH)'
        Cat     = 'Attack Surface'
        Sev     = 'Medium'
        Desc    = 'WSH enables VBScript/JScript execution — the delivery mechanism for most malicious email attachments.'
        FixDesc = 'Disable Windows Script Host via registry'
        Check   = {
            $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -EA SilentlyContinue).Enabled
            if ($null -eq $v -or $v -ne 0) { @{ Vuln=$true;  Info='Windows Script Host is ENABLED' } }
            else                           { @{ Vuln=$false; Info='Windows Script Host is disabled' } }
        }
        Fix = {
            $k = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'
            if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
            Set-ItemProperty $k Enabled 0 -Type DWord
        }
    },

    # ── 14 ─ PowerShell Script Block Logging ────────────────────────────────
    @{
        Name    = 'PowerShell Script Block Logging'
        Cat     = 'Audit & Logging'
        Sev     = 'Medium'
        Desc    = 'Script block logging records all PowerShell commands executed — critical for forensic investigation.'
        FixDesc = 'Enable PowerShell script block logging via policy key'
        Check   = {
            $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA SilentlyContinue).EnableScriptBlockLogging
            if ($null -eq $v -or $v -ne 1) { @{ Vuln=$true;  Info='Script block logging is NOT enabled' } }
            else                           { @{ Vuln=$false; Info='Script block logging is enabled' } }
        }
        Fix = {
            $parent = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
            $child  = "$parent\ScriptBlockLogging"
            if (-not (Test-Path $parent)) { New-Item $parent -Force | Out-Null }
            if (-not (Test-Path $child))  { New-Item $child  -Force | Out-Null }
            Set-ItemProperty $child EnableScriptBlockLogging 1 -Type DWord
        }
    },

    # ── 15 ─ Audit: Logon Events ─────────────────────────────────────────────
    @{
        Name    = 'Audit Policy — Logon / Logoff Events'
        Cat     = 'Audit & Logging'
        Sev     = 'Medium'
        Desc    = 'Logon success/failure auditing is essential to detect brute-force attacks and lateral movement.'
        FixDesc = 'Enable Success+Failure auditing for Logon subcategory'
        Check   = {
            try {
                $r = & auditpol /get /subcategory:"Logon" 2>&1
                $l = $r | Where-Object { $_ -match 'Logon' } | Select-Object -Last 1
                if ($l -notmatch 'Success and Failure') { @{ Vuln=$true;  Info="Logon audit: $($l.Trim())" } }
                else                                   { @{ Vuln=$false; Info='Logon events: Success and Failure' } }
            } catch { @{ Vuln=$false; Info='Audit check unavailable' } }
        }
        Fix = { & auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null }
    },

    # ── 16 ─ Audit: Account Management ──────────────────────────────────────
    @{
        Name    = 'Audit Policy — Account Management'
        Cat     = 'Audit & Logging'
        Sev     = 'Medium'
        Desc    = 'Account-management auditing detects privilege escalation, new account creation, and group changes.'
        FixDesc = 'Enable Success+Failure auditing for User Account Management'
        Check   = {
            try {
                $r = & auditpol /get /subcategory:"User Account Management" 2>&1
                $l = $r | Where-Object { $_ -match 'User Account Management' } | Select-Object -Last 1
                if ($l -notmatch 'Success and Failure') { @{ Vuln=$true;  Info="Account mgmt audit: incomplete" } }
                else                                   { @{ Vuln=$false; Info='Account management: Success and Failure' } }
            } catch { @{ Vuln=$false; Info='Audit check unavailable' } }
        }
        Fix = { & auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null }
    },

    # ── 17 ─ Screen Saver Password ───────────────────────────────────────────
    @{
        Name    = 'Screen Saver Password on Resume'
        Cat     = 'Physical Security'
        Sev     = 'Low'
        Desc    = 'Screen saver must demand the password on resume to protect an unattended, unlocked workstation.'
        FixDesc = 'Enable screen saver with password-on-resume (5-min timeout)'
        Check   = {
            $v = (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -EA SilentlyContinue).ScreenSaverIsSecure
            if ($v -ne '1') { @{ Vuln=$true;  Info='Screen saver password NOT required on resume' } }
            else            { @{ Vuln=$false; Info='Screen saver password protection is active' } }
        }
        Fix = {
            $k = 'HKCU:\Control Panel\Desktop'
            Set-ItemProperty $k ScreenSaverIsSecure '1'
            Set-ItemProperty $k ScreenSaveActive    '1'
            Set-ItemProperty $k ScreenSaveTimeOut   '300'
        }
    },

    # ── 18 ─ Telnet Client ───────────────────────────────────────────────────
    @{
        Name    = 'Telnet Client (Plaintext Protocol)'
        Cat     = 'Attack Surface'
        Sev     = 'Low'
        Desc    = 'Telnet transmits all data — including credentials — in plaintext. No legitimate modern use case.'
        FixDesc = 'Uninstall the Telnet client optional feature'
        Check   = {
            try {
                $f = Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction Stop
                if ($f.State -eq 'Enabled') { @{ Vuln=$true;  Info='Telnet Client is installed and enabled' } }
                else                        { @{ Vuln=$false; Info='Telnet Client is not installed' } }
            } catch { @{ Vuln=$false; Info='Check unavailable' } }
        }
        Fix = { Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart -ErrorAction SilentlyContinue }
    }
)

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPER — Create a styled flat button
# ═══════════════════════════════════════════════════════════════════════════════
function New-Btn {
    param($Text, $X, $Y, $W, $H, $Bg, $Tag='')
    $b = [Windows.Forms.Button]@{
        Text      = $Text
        Location  = [Drawing.Point]::new($X,$Y)
        Size      = [Drawing.Size]::new($W,$H)
        BackColor = $Bg
        ForeColor = $C.Text
        FlatStyle = 'Flat'
        Font      = [Drawing.Font]::new('Segoe UI',9,[Drawing.FontStyle]::Bold)
        Cursor    = 'Hand'
        Tag       = $Tag
    }
    $b.FlatAppearance.BorderSize = 0
    $b.FlatAppearance.MouseOverBackColor  = [Drawing.Color]::FromArgb([Math]::Min($Bg.R+20,255),[Math]::Min($Bg.G+20,255),[Math]::Min($Bg.B+20,255))
    $b.FlatAppearance.MouseDownBackColor  = [Drawing.Color]::FromArgb([Math]::Max($Bg.R-20,0),[Math]::Max($Bg.G-20,0),[Math]::Max($Bg.B-20,0))
    return $b
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN FORM
# ═══════════════════════════════════════════════════════════════════════════════
$script:form = [Windows.Forms.Form]@{
    Text            = 'SecurePC  —  Windows Security Hardening Tool'
    Size            = [Drawing.Size]::new(960, 720)
    MinimumSize     = [Drawing.Size]::new(820, 580)
    BackColor       = $C.Bg
    ForeColor       = $C.Text
    StartPosition   = 'CenterScreen'
    Font            = [Drawing.Font]::new('Segoe UI',9)
}
$form = $script:form

# ── Bottom button bar ─────────────────────────────────────────────────────────
$btnBar = [Windows.Forms.Panel]@{ Dock='Bottom'; Height=64; BackColor=$C.Panel }
$form.Controls.Add($btnBar)

$script:btnScan   = New-Btn '▶  SCAN SYSTEM'         16  14 175 36 $C.BtnScan
$script:btnFixAll = New-Btn '⚡  FIX ALL VULNERABLE'  204 14 195 36 $C.BtnAll
$script:btnCancel = New-Btn '✕  CANCEL SCAN'          412 14 145 36 $C.BtnCncl
$script:btnReport = New-Btn '📄  SAVE REPORT'          570 14 145 36 $C.BtnRep
$btnBar.Controls.AddRange(@($script:btnScan,$script:btnFixAll,$script:btnCancel,$script:btnReport))
$script:btnFixAll.Enabled = $false
$script:btnCancel.Enabled = $false
$script:btnReport.Enabled = $false

# ── Progress bar ──────────────────────────────────────────────────────────────
$script:progress = [Windows.Forms.ProgressBar]@{
    Dock    = 'Bottom'
    Height  = 5
    Maximum = $script:Checks.Count
    Value   = 0
    Style   = 'Continuous'
}
$form.Controls.Add($script:progress)

# ── Scrollable findings area ──────────────────────────────────────────────────
$script:scroll = [Windows.Forms.Panel]@{
    Dock        = 'Fill'
    AutoScroll  = $true
    BackColor   = $C.Bg
    Padding     = [Windows.Forms.Padding]::new(10,8,10,8)
}
$form.Controls.Add($script:scroll)

# ── Stats bar ─────────────────────────────────────────────────────────────────
$statsBar = [Windows.Forms.Panel]@{ Dock='Top'; Height=30; BackColor=$C.Panel }
$form.Controls.Add($statsBar)

$script:lblStats = [Windows.Forms.Label]@{
    Text      = '  Ready — press Scan System (or F5) to start the security assessment.'
    Font      = [Drawing.Font]::new('Segoe UI',8.5)
    ForeColor = $C.SubText
    Location  = [Drawing.Point]::new(8,7)
    AutoSize  = $true
}
$statsBar.Controls.Add($script:lblStats)

# ── Header ────────────────────────────────────────────────────────────────────
$header = [Windows.Forms.Panel]@{ Dock='Top'; Height=70; BackColor=$C.Panel }
$form.Controls.Add($header)

# Left accent stripe
$stripe = [Windows.Forms.Panel]@{ Location=[Drawing.Point]::new(0,0); Size=[Drawing.Size]::new(6,70); BackColor=$C.Accent }
$header.Controls.Add($stripe)

$lblTitle = [Windows.Forms.Label]@{
    Text      = '  SecurePC — Security Hardening Tool'
    Font      = [Drawing.Font]::new('Segoe UI',15,[Drawing.FontStyle]::Bold)
    ForeColor = $C.Accent
    Location  = [Drawing.Point]::new(14,10)
    AutoSize  = $true
}
$header.Controls.Add($lblTitle)

$lblSub = [Windows.Forms.Label]@{
    Text      = '  Scans 18 Windows security checks and applies targeted remediations — with your explicit approval for each change.'
    Font      = [Drawing.Font]::new('Segoe UI',8.5)
    ForeColor = $C.SubText
    Location  = [Drawing.Point]::new(14,42)
    AutoSize  = $true
}
$header.Controls.Add($lblSub)

# ── Version badge ─────────────────────────────────────────────────────────────
$lblVer = [Windows.Forms.Label]@{
    Text      = "v1.0  |  $($script:Checks.Count) checks  |  $env:COMPUTERNAME"
    Font      = [Drawing.Font]::new('Consolas',7.5)
    ForeColor = $C.SubText
    Anchor    = 'Top,Right'
    AutoSize  = $true
}
$lblVer.Location = [Drawing.Point]::new($header.Width - 260, 52)
$header.Controls.Add($lblVer)

# ═══════════════════════════════════════════════════════════════════════════════
#  FINDING ROWS
# ═══════════════════════════════════════════════════════════════════════════════
$script:FindingPanels = @{}

function New-FindingRow {
    param([int]$Idx)
    $chk = $script:Checks[$Idx]
    $scroll = $script:scroll

    $CARD_H = 76
    $card = [Windows.Forms.Panel]@{
        Width     = $scroll.ClientSize.Width - 24
        Height    = $CARD_H
        Location  = [Drawing.Point]::new(0, $Idx * ($CARD_H + 4))
        BackColor = $C.Card
    }

    # ── Severity badge ────────────────────────────────────────────────────────
    $sevClr = switch ($chk.Sev) {
        'Critical' { $C.Critical } 'High' { $C.High } 'Medium' { $C.Medium } default { $C.Low }
    }
    $sevLabel = [Windows.Forms.Label]@{
        Text      = $chk.Sev.ToUpper()
        Font      = [Drawing.Font]::new('Segoe UI',7,[Drawing.FontStyle]::Bold)
        ForeColor = $sevClr
        Location  = [Drawing.Point]::new(10, 8)
        AutoSize  = $true
    }
    $card.Controls.Add($sevLabel)

    $catLabel = [Windows.Forms.Label]@{
        Text      = $chk.Cat
        Font      = [Drawing.Font]::new('Segoe UI',7)
        ForeColor = $C.SubText
        Location  = [Drawing.Point]::new(10, 24)
        AutoSize  = $true
    }
    $card.Controls.Add($catLabel)

    # Coloured left edge strip indicating severity
    $strip = [Windows.Forms.Panel]@{
        Location  = [Drawing.Point]::new(0,0)
        Size      = [Drawing.Size]::new(4,$CARD_H)
        BackColor = $sevClr
    }
    $card.Controls.Add($strip)

    # ── Name ──────────────────────────────────────────────────────────────────
    $nameLabel = [Windows.Forms.Label]@{
        Text      = $chk.Name
        Font      = [Drawing.Font]::new('Segoe UI',10,[Drawing.FontStyle]::Bold)
        ForeColor = $C.Text
        Location  = [Drawing.Point]::new(115, 8)
        AutoSize  = $true
    }
    $card.Controls.Add($nameLabel)

    # ── Description / result info ─────────────────────────────────────────────
    $infoLabel = [Windows.Forms.Label]@{
        Text      = $chk.Desc
        Font      = [Drawing.Font]::new('Segoe UI',8)
        ForeColor = $C.SubText
        Location  = [Drawing.Point]::new(115, 32)
        Size      = [Drawing.Size]::new($card.Width - 310, 34)
        Anchor    = 'Top,Left,Right'
    }
    $card.Controls.Add($infoLabel)

    # ── Status label ─────────────────────────────────────────────────────────
    $statusLabel = [Windows.Forms.Label]@{
        Text      = 'PENDING'
        Font      = [Drawing.Font]::new('Segoe UI',8,[Drawing.FontStyle]::Bold)
        ForeColor = $C.SubText
        Anchor    = 'Top,Right'
        AutoSize  = $true
    }
    $statusLabel.Location = [Drawing.Point]::new($card.Width - 178, 14)
    $card.Controls.Add($statusLabel)

    # ── FIX button ────────────────────────────────────────────────────────────
    $fixBtn = New-Btn 'FIX' ($card.Width - 86) 22 72 32 $C.BtnFix "$Idx"
    $fixBtn.Enabled = $false
    $fixBtn.Anchor  = 'Top,Right'
    $card.Controls.Add($fixBtn)

    # ── Bottom separator ──────────────────────────────────────────────────────
    $sep = [Windows.Forms.Panel]@{
        Dock      = 'Bottom'
        Height    = 1
        BackColor = $C.Border
    }
    $card.Controls.Add($sep)

    $scroll.Controls.Add($card)

    $script:FindingPanels[$Idx] = @{
        Card        = $card
        StatusLabel = $statusLabel
        InfoLabel   = $infoLabel
        FixBtn      = $fixBtn
        NameLabel   = $nameLabel
    }

    # ── FIX button click — confirmation dialog then apply fix ─────────────────
    $fixBtn.Add_Click({
        param($sender,$e)
        $idx = [int]$sender.Tag
        $chk = $script:Checks[$idx]
        $fp  = $script:FindingPanels[$idx]

        $r = [Windows.Forms.MessageBox]::Show(
            "Apply the following security fix?`n`n" +
            "Finding:  $($chk.Name)`n" +
            "Severity: $($chk.Sev)`n" +
            "Fix:      $($chk.FixDesc)`n`n" +
            "System settings will be modified. This action may require a restart.`n`nProceed?",
            'Confirm Security Fix',
            [Windows.Forms.MessageBoxButtons]::YesNo,
            [Windows.Forms.MessageBoxIcon]::Question,
            [Windows.Forms.MessageBoxDefaultButton]::Button2)

        if ($r -ne [Windows.Forms.DialogResult]::Yes) { return }

        $sender.Enabled   = $false
        $sender.Text      = '...'
        $fp.StatusLabel.Text      = 'APPLYING...'
        $fp.StatusLabel.ForeColor = $C.Accent
        [Windows.Forms.Application]::DoEvents()

        try {
            & $chk.Fix
            $fp.StatusLabel.Text      = '● FIXED'
            $fp.StatusLabel.ForeColor = $C.Secure
            $fp.InfoLabel.Text        = 'Fix applied successfully.'
            $fp.Card.BackColor        = $C.FixedBg
            $sender.Text              = '✓'
            $sender.BackColor         = $C.CheckOK
        } catch {
            $fp.StatusLabel.Text      = '● FIX FAILED'
            $fp.StatusLabel.ForeColor = $C.Critical
            $fp.InfoLabel.Text        = "Error: $($_.Exception.Message)"
            $sender.Text              = 'RETRY'
            $sender.Enabled           = $true
        }
    })
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SCAN BUTTON — run all checks sequentially, update UI live
# ═══════════════════════════════════════════════════════════════════════════════
$script:Cancelled = $false

$script:btnCancel.Add_Click({
    $script:Cancelled = $true
    $script:btnCancel.Enabled  = $false
    $script:lblStats.Text      = '  Scan cancelled.'
})

$script:btnScan.Add_Click({
    # Reset
    $script:Cancelled = $false
    $script:scroll.Controls.Clear()
    $script:FindingPanels.Clear()
    $script:progress.Value = 0

    $script:btnScan.Enabled   = $false
    $script:btnFixAll.Enabled = $false
    $script:btnReport.Enabled = $false
    $script:btnCancel.Enabled = $true
    $script:lblStats.Text     = '  Building check list...'
    [Windows.Forms.Application]::DoEvents()

    # Build all finding rows
    for ($i = 0; $i -lt $script:Checks.Count; $i++) {
        New-FindingRow -Idx $i
    }
    # Initial width pass
    foreach ($ctrl in $script:scroll.Controls) { $ctrl.Width = $script:scroll.ClientSize.Width - 24 }
    [Windows.Forms.Application]::DoEvents()

    $vulnCount = 0; $secureCount = 0

    for ($i = 0; $i -lt $script:Checks.Count; $i++) {
        if ($script:Cancelled) { break }

        $chk = $script:Checks[$i]
        $fp  = $script:FindingPanels[$i]

        $fp.StatusLabel.Text      = 'SCANNING...'
        $fp.StatusLabel.ForeColor = $C.Accent
        # Auto-scroll to keep current row visible
        $script:scroll.ScrollControlIntoView($fp.Card)
        $script:lblStats.Text = "  Scanning ($($i+1) / $($script:Checks.Count))  —  $($chk.Name)"
        [Windows.Forms.Application]::DoEvents()

        try   { $result = & $chk.Check }
        catch { $result = @{ Vuln=$false; Info="Check error: $($_.Exception.Message)" } }

        if ($result.Vuln) {
            $fp.StatusLabel.Text      = '● VULNERABLE'
            $fp.StatusLabel.ForeColor = $C.Vuln
            $fp.Card.BackColor        = $C.VulnBg
            $fp.InfoLabel.Text        = $result.Info
            $fp.FixBtn.Enabled        = $true
            $vulnCount++
        } else {
            $fp.StatusLabel.Text      = '● SECURE'
            $fp.StatusLabel.ForeColor = $C.Secure
            $fp.Card.BackColor        = $C.SecureBg
            $fp.InfoLabel.Text        = $result.Info
            $fp.FixBtn.Enabled        = $false
            $fp.FixBtn.BackColor      = $C.Disabled
            $secureCount++
        }

        $script:progress.Value = $i + 1
        [Windows.Forms.Application]::DoEvents()
    }

    $script:btnScan.Enabled   = $true
    $script:btnCancel.Enabled = $false
    $script:btnReport.Enabled = $true

    if (-not $script:Cancelled) {
        # Count by severity among vulnerables
        $crit = 0; $high = 0; $med = 0; $low = 0
        for ($i = 0; $i -lt $script:Checks.Count; $i++) {
            if ($script:FindingPanels.ContainsKey($i) -and $script:FindingPanels[$i].FixBtn.Enabled) {
                switch ($script:Checks[$i].Sev) {
                    'Critical' { $crit++ } 'High' { $high++ } 'Medium' { $med++ } 'Low' { $low++ }
                }
            }
        }
        $script:btnFixAll.Enabled = ($vulnCount -gt 0)
        $script:lblStats.Text =
            "  Scan complete  |  Vulnerable: $vulnCount   Secure: $secureCount" +
            "   |   Critical: $crit   High: $high   Medium: $med   Low: $low"
        # Scroll back to top
        $script:scroll.AutoScrollPosition = [Drawing.Point]::new(0,0)
    }
})

# ═══════════════════════════════════════════════════════════════════════════════
#  FIX ALL — bulk remediation with single confirmation
# ═══════════════════════════════════════════════════════════════════════════════
$script:btnFixAll.Add_Click({
    $vulnNames = for ($i=0; $i -lt $script:Checks.Count; $i++) {
        if ($script:FindingPanels.ContainsKey($i) -and $script:FindingPanels[$i].FixBtn.Enabled) {
            "  • [$($script:Checks[$i].Sev)]  $($script:Checks[$i].Name)"
        }
    }

    $r = [Windows.Forms.MessageBox]::Show(
        "Apply ALL of the following fixes?`n`n" + ($vulnNames -join "`n") +
        "`n`nMultiple system settings will be modified.`nSome fixes may require a restart to take effect.`n`nProceed with ALL fixes?",
        'Fix All Vulnerable — Final Confirmation',
        [Windows.Forms.MessageBoxButtons]::YesNo,
        [Windows.Forms.MessageBoxIcon]::Warning,
        [Windows.Forms.MessageBoxDefaultButton]::Button2)

    if ($r -ne [Windows.Forms.DialogResult]::Yes) { return }

    $script:btnFixAll.Enabled = $false
    $script:lblStats.Text     = '  Applying all fixes...'

    for ($i=0; $i -lt $script:Checks.Count; $i++) {
        if (-not $script:FindingPanels.ContainsKey($i)) { continue }
        $fp  = $script:FindingPanels[$i]
        if (-not $fp.FixBtn.Enabled) { continue }
        $chk = $script:Checks[$i]

        $fp.FixBtn.Enabled        = $false
        $fp.FixBtn.Text           = '...'
        $fp.StatusLabel.Text      = 'APPLYING...'
        $fp.StatusLabel.ForeColor = $C.Accent
        $script:scroll.ScrollControlIntoView($fp.Card)
        [Windows.Forms.Application]::DoEvents()

        try {
            & $chk.Fix
            $fp.StatusLabel.Text      = '● FIXED'
            $fp.StatusLabel.ForeColor = $C.Secure
            $fp.InfoLabel.Text        = 'Fix applied successfully.'
            $fp.Card.BackColor        = $C.FixedBg
            $fp.FixBtn.Text           = '✓'
            $fp.FixBtn.BackColor      = $C.CheckOK
        } catch {
            $fp.StatusLabel.Text      = '● FIX FAILED'
            $fp.StatusLabel.ForeColor = $C.Critical
            $fp.InfoLabel.Text        = "Error: $($_.Exception.Message)"
            $fp.FixBtn.Text           = 'RETRY'
            $fp.FixBtn.Enabled        = $true
        }
        [Windows.Forms.Application]::DoEvents()
    }

    $script:lblStats.Text = '  All fixes applied. Press Scan System to re-verify the results.'
})

# ═══════════════════════════════════════════════════════════════════════════════
#  SAVE REPORT
# ═══════════════════════════════════════════════════════════════════════════════
$script:btnReport.Add_Click({
    $dlg = [Windows.Forms.SaveFileDialog]@{
        Filter   = 'Text Report (*.txt)|*.txt'
        FileName = "SecurePC_Report_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
        Title    = 'Save Security Assessment Report'
    }
    if ($dlg.ShowDialog() -ne 'OK') { return }

    $lines = @(
        '=' * 72
        'SecurePC — Windows Security Assessment Report'
        "Generated : $(Get-Date -Format 'dddd dd-MMM-yyyy  HH:mm:ss')"
        "Computer  : $env:COMPUTERNAME    User: $env:USERDOMAIN\$env:USERNAME"
        '=' * 72
        ''
    )

    for ($i=0; $i -lt $script:Checks.Count; $i++) {
        if (-not $script:FindingPanels.ContainsKey($i)) { continue }
        $chk = $script:Checks[$i]; $fp = $script:FindingPanels[$i]
        $lines += "[$($chk.Sev.ToUpper().PadRight(8))] $($chk.Name)"
        $lines += "  Status  : $($fp.StatusLabel.Text)"
        $lines += "  Detail  : $($fp.InfoLabel.Text)"
        $lines += ''
    }
    $lines += '=' * 72
    $lines | Set-Content $dlg.FileName -Encoding UTF8

    [Windows.Forms.MessageBox]::Show(
        "Report saved:`n$($dlg.FileName)",
        'Report Saved',
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Information) | Out-Null
})

# ═══════════════════════════════════════════════════════════════════════════════
#  RESIZE — keep card widths flush with the scroll panel
# ═══════════════════════════════════════════════════════════════════════════════
$script:scroll.Add_Resize({
    foreach ($card in $script:scroll.Controls) {
        $card.Width = $script:scroll.ClientSize.Width - 24
    }
})

# ═══════════════════════════════════════════════════════════════════════════════
#  KEYBOARD SHORTCUTS
# ═══════════════════════════════════════════════════════════════════════════════
$form.Add_KeyDown({
    param($s,$e)
    if ($e.KeyCode -eq 'F5' -and $script:btnScan.Enabled)   { $script:btnScan.PerformClick() }
    if ($e.KeyCode -eq 'Escape' -and $script:btnCancel.Enabled) { $script:btnCancel.PerformClick() }
})
$form.KeyPreview = $true

# ═══════════════════════════════════════════════════════════════════════════════
#  LAUNCH
# ═══════════════════════════════════════════════════════════════════════════════
[Windows.Forms.Application]::Run($form)
