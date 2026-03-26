#Requires -Version 5.1
# SecurePC Pro v2.0 - Windows Security Management Console
# Pure ASCII - no Unicode special characters

# Self-elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ============================================================
# GLOBALS
# ============================================================
$script:Findings     = @()
$script:ScanRunning  = $false
$script:StopScan     = $false
$script:NetworkRows  = @{}
$script:ProcessRows  = @{}
$script:StartupRows  = @{}
$script:TaskRows     = @{}
$script:HostsRows    = @{}
$script:AuditResults = @{}
$script:ReportText   = ""
$script:CurrentTab   = 0

# ============================================================
# COLORS
# ============================================================
$cBg       = [System.Drawing.Color]::FromArgb(13,  13,  20)
$cPanel    = [System.Drawing.Color]::FromArgb(20,  20,  32)
$cCard     = [System.Drawing.Color]::FromArgb(26,  26,  40)
$cBorder   = [System.Drawing.Color]::FromArgb(44,  44,  68)
$cAccent   = [System.Drawing.Color]::FromArgb(99,  179, 237)
$cCritical = [System.Drawing.Color]::FromArgb(245, 85,  85)
$cHigh     = [System.Drawing.Color]::FromArgb(237, 130, 48)
$cMedium   = [System.Drawing.Color]::FromArgb(246, 220, 80)
$cLow      = [System.Drawing.Color]::FromArgb(100, 210, 140)
$cSecure   = [System.Drawing.Color]::FromArgb(72,  199, 142)
$cText     = [System.Drawing.Color]::FromArgb(235, 235, 245)
$cSubText  = [System.Drawing.Color]::FromArgb(140, 140, 170)
$cListBg   = [System.Drawing.Color]::FromArgb(18,  18,  28)
$cBtnScan  = [System.Drawing.Color]::FromArgb(38,  120, 200)
$cBtnStop  = [System.Drawing.Color]::FromArgb(180, 50,  50)
$cBtnExport= [System.Drawing.Color]::FromArgb(38,  75,  95)

# ============================================================
# HELPER FUNCTIONS
# ============================================================
function New-StyledButton {
    param($Text, $Width, $BackColor, $ForeColor = $cText)
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text      = $Text
    $btn.Width     = $Width
    $btn.Height    = 34
    $btn.BackColor = $BackColor
    $btn.ForeColor = $ForeColor
    $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btn.FlatAppearance.BorderSize  = 1
    $btn.FlatAppearance.BorderColor = $cBorder
    $btn.Font      = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btn.Cursor    = [System.Windows.Forms.Cursors]::Hand
    return $btn
}

function New-StyledListView {
    param([string[]]$Columns, [int[]]$Widths)
    $lv = New-Object System.Windows.Forms.ListView
    $lv.View          = [System.Windows.Forms.View]::Details
    $lv.BackColor     = $cListBg
    $lv.ForeColor     = $cText
    $lv.GridLines     = $true
    $lv.FullRowSelect = $true
    $lv.HeaderStyle   = [System.Windows.Forms.ColumnHeaderStyle]::Nonclickable
    $lv.BorderStyle   = [System.Windows.Forms.BorderStyle]::None
    $lv.Font          = New-Object System.Drawing.Font("Consolas", 8.5)
    for ($i = 0; $i -lt $Columns.Count; $i++) {
        $col = $lv.Columns.Add($Columns[$i])
        if ($i -lt $Widths.Count) { $col.Width = $Widths[$i] }
    }
    return $lv
}

function Get-SevColor {
    param($Sev)
    switch ($Sev) {
        "Critical" { return $cCritical }
        "High"     { return $cHigh }
        "Medium"   { return $cMedium }
        "Low"      { return $cLow }
        default    { return $cSubText }
    }
}

function Add-Finding {
    param($Sev, $Cat, $Name, $Detail, $Source)
    $script:Findings += @{ Sev=$Sev; Cat=$Cat; Name=$Name; Detail=$Detail; Source=$Source }
}

function Get-SecurityScore {
    $c = ($script:Findings | Where-Object { $_.Sev -eq "Critical" }).Count
    $h = ($script:Findings | Where-Object { $_.Sev -eq "High"     }).Count
    $m = ($script:Findings | Where-Object { $_.Sev -eq "Medium"   }).Count
    $l = ($script:Findings | Where-Object { $_.Sev -eq "Low"      }).Count
    $score = 100 - ($c*25 + $h*10 + $m*5 + $l*2)
    if ($score -lt 0) { $score = 0 }
    return $score
}

function Set-StatusMsg {
    param($msg)
    $script:lblStatus.Text = $msg
    [System.Windows.Forms.Application]::DoEvents()
}

# ============================================================
# MAIN FORM
# ============================================================
$form = New-Object System.Windows.Forms.Form
$form.Text            = "SecurePC Pro v2.0"
$form.Size            = New-Object System.Drawing.Size(1040, 740)
$form.MinimumSize     = New-Object System.Drawing.Size(860, 600)
$form.BackColor       = $cBg
$form.ForeColor       = $cText
$form.StartPosition   = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.KeyPreview      = $true
$form.Font            = New-Object System.Drawing.Font("Segoe UI", 9)

# ============================================================
# HEADER (72px)
# ============================================================
$header = New-Object System.Windows.Forms.Panel
$header.Dock      = [System.Windows.Forms.DockStyle]::Top
$header.Height    = 72
$header.BackColor = $cPanel

$headerAccent = New-Object System.Windows.Forms.Panel
$headerAccent.Width     = 6
$headerAccent.Dock      = [System.Windows.Forms.DockStyle]::Left
$headerAccent.BackColor = $cAccent

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text      = "SecurePC Pro v2.0"
$lblTitle.Font      = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = $cAccent
$lblTitle.AutoSize  = $true
$lblTitle.Location  = New-Object System.Drawing.Point(18, 10)

$lblSubtitle = New-Object System.Windows.Forms.Label
$lblSubtitle.Text      = "Windows Security Management Console"
$lblSubtitle.Font      = New-Object System.Drawing.Font("Segoe UI", 9)
$lblSubtitle.ForeColor = $cSubText
$lblSubtitle.AutoSize  = $true
$lblSubtitle.Location  = New-Object System.Drawing.Point(18, 42)

try { $osVer = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption } catch { $osVer = "Windows" }
$headerInfoTxt = "Host: $env:COMPUTERNAME  |  User: $env:USERNAME  |  OS: $osVer"
$lblHeaderInfo = New-Object System.Windows.Forms.Label
$lblHeaderInfo.Text      = $headerInfoTxt
$lblHeaderInfo.Font      = New-Object System.Drawing.Font("Segoe UI", 8.5)
$lblHeaderInfo.ForeColor = $cSubText
$lblHeaderInfo.AutoSize  = $true
$lblHeaderInfo.Anchor    = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$lblHeaderInfo.Location  = New-Object System.Drawing.Point(530, 28)

$lblCreator = New-Object System.Windows.Forms.Label
$lblCreator.Text      = "Created by Hareli Dudaei"
$lblCreator.Font      = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
$lblCreator.ForeColor = $cAccent
$lblCreator.AutoSize  = $true
$lblCreator.Anchor    = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
$lblCreator.Location  = New-Object System.Drawing.Point(810, 52)

$header.Controls.AddRange(@($headerAccent, $lblTitle, $lblSubtitle, $lblHeaderInfo, $lblCreator))

# ============================================================
# BOTTOM BAR (52px)
# ============================================================
$bottomBar = New-Object System.Windows.Forms.Panel
$bottomBar.Dock      = [System.Windows.Forms.DockStyle]::Bottom
$bottomBar.Height    = 52
$bottomBar.BackColor = $cPanel

$btnScan = New-StyledButton "FULL SCAN (F5)" 160 $cBtnScan
$btnScan.Location = New-Object System.Drawing.Point(10, 9)

$btnStop = New-StyledButton "STOP (Esc)" 120 $cBtnStop
$btnStop.Location = New-Object System.Drawing.Point(178, 9)
$btnStop.Enabled  = $false

$btnExport = New-StyledButton "EXPORT REPORT" 150 $cBtnExport
$btnExport.Location = New-Object System.Drawing.Point(306, 9)

$script:lblStatus = New-Object System.Windows.Forms.Label
$script:lblStatus.Text      = "Ready"
$script:lblStatus.ForeColor = $cSubText
$script:lblStatus.Font      = New-Object System.Drawing.Font("Consolas", 9)
$script:lblStatus.AutoSize  = $true
$script:lblStatus.Anchor    = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$script:lblStatus.Location  = New-Object System.Drawing.Point(470, 18)

$bottomBar.Controls.AddRange(@($btnScan, $btnStop, $btnExport, $script:lblStatus))

# ============================================================
# TAB STRIP (40px)
# ============================================================
$tabStrip = New-Object System.Windows.Forms.Panel
$tabStrip.Dock      = [System.Windows.Forms.DockStyle]::Top
$tabStrip.Height    = 40
$tabStrip.BackColor = $cPanel

# ============================================================
# CONTENT AREA
# ============================================================
$contentArea = New-Object System.Windows.Forms.Panel
$contentArea.Dock      = [System.Windows.Forms.DockStyle]::Fill
$contentArea.BackColor = $cBg

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Dock      = [System.Windows.Forms.DockStyle]::Bottom
$progressBar.Height    = 4
$progressBar.Style     = [System.Windows.Forms.ProgressBarStyle]::Continuous
$progressBar.BackColor = $cPanel
$progressBar.ForeColor = $cAccent
$progressBar.Minimum   = 0
$progressBar.Maximum   = 100
$progressBar.Value     = 0
$contentArea.Controls.Add($progressBar)

# ============================================================
# TAB 1 - DASHBOARD
# ============================================================
$panelDash = New-Object System.Windows.Forms.Panel
$panelDash.Dock      = [System.Windows.Forms.DockStyle]::Fill
$panelDash.BackColor = $cBg
$panelDash.Visible   = $true

# Stat boxes row
$statPanel = New-Object System.Windows.Forms.Panel
$statPanel.Dock      = [System.Windows.Forms.DockStyle]::Top
$statPanel.Height    = 100
$statPanel.BackColor = $cBg
$statPanel.Padding   = New-Object System.Windows.Forms.Padding(8, 8, 8, 0)

$script:StatBoxes = @{}
$statDefs = @(
    @{ Key="Total";  Label="Total Findings"; Color=$cAccent   }
    @{ Key="Crit";   Label="Critical";       Color=$cCritical }
    @{ Key="High";   Label="High";           Color=$cHigh     }
    @{ Key="Med";    Label="Medium";         Color=$cMedium   }
    @{ Key="Low";    Label="Low";            Color=$cLow      }
    @{ Key="Score";  Label="Score / 100";    Color=$cSecure   }
)

$statX = 8
foreach ($sd in $statDefs) {
    $box = New-Object System.Windows.Forms.Panel
    $box.Width     = 140
    $box.Height    = 80
    $box.Location  = New-Object System.Drawing.Point($statX, 8)
    $box.BackColor = $cCard

    $numLbl = New-Object System.Windows.Forms.Label
    $numLbl.Text      = "0"
    $numLbl.Font      = New-Object System.Drawing.Font("Segoe UI", 24, [System.Drawing.FontStyle]::Bold)
    $numLbl.ForeColor = $sd.Color
    $numLbl.AutoSize  = $false
    $numLbl.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $numLbl.Location  = New-Object System.Drawing.Point(0, 5)
    $numLbl.Size      = New-Object System.Drawing.Size(140, 42)

    $catLbl = New-Object System.Windows.Forms.Label
    $catLbl.Text      = $sd.Label
    $catLbl.Font      = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $catLbl.ForeColor = $sd.Color
    $catLbl.AutoSize  = $false
    $catLbl.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $catLbl.Location  = New-Object System.Drawing.Point(0, 50)
    $catLbl.Size      = New-Object System.Drawing.Size(140, 18)

    $box.Controls.AddRange(@($numLbl, $catLbl))
    $statPanel.Controls.Add($box)
    $script:StatBoxes[$sd.Key] = $numLbl
    $statX += 150
}

# Dashboard findings ListView
$script:lvDash = New-StyledListView `
    -Columns @("Severity","Category","Name","Detail","Status") `
    -Widths   @(80, 120, 180, 380, 80)
$script:lvDash.Dock = [System.Windows.Forms.DockStyle]::Fill

$dashLvPanel = New-Object System.Windows.Forms.Panel
$dashLvPanel.Dock    = [System.Windows.Forms.DockStyle]::Fill
$dashLvPanel.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 8)
$dashLvPanel.Controls.Add($script:lvDash)

$panelDash.Controls.Add($dashLvPanel)
$panelDash.Controls.Add($statPanel)

# ============================================================
# TAB 2 - NETWORK
# ============================================================
$panelNet = New-Object System.Windows.Forms.Panel
$panelNet.Dock      = [System.Windows.Forms.DockStyle]::Fill
$panelNet.BackColor = $cBg
$panelNet.Visible   = $false

$lblNetDesc = New-Object System.Windows.Forms.Label
$lblNetDesc.Text      = "Active TCP connections scanned for suspicious ports, foreign IPs, and C2 patterns."
$lblNetDesc.ForeColor = $cSubText
$lblNetDesc.Font      = New-Object System.Drawing.Font("Segoe UI", 9)
$lblNetDesc.Dock      = [System.Windows.Forms.DockStyle]::Top
$lblNetDesc.Height    = 28
$lblNetDesc.Padding   = New-Object System.Windows.Forms.Padding(8, 6, 0, 0)

$script:lvNet = New-StyledListView `
    -Columns @("Status","Local Port","Remote IP","Remote Port","State","Process","PID") `
    -Widths   @(80, 90, 150, 100, 100, 150, 60)
$script:lvNet.Dock = [System.Windows.Forms.DockStyle]::Fill

$netBtnPanel = New-Object System.Windows.Forms.Panel
$netBtnPanel.Dock      = [System.Windows.Forms.DockStyle]::Bottom
$netBtnPanel.Height    = 46
$netBtnPanel.BackColor = $cPanel

$btnBlockIP = New-StyledButton "Block IP (Firewall)" 180 $cBtnStop
$btnBlockIP.Location = New-Object System.Drawing.Point(8, 6)
$netBtnPanel.Controls.Add($btnBlockIP)

$netLvPanel = New-Object System.Windows.Forms.Panel
$netLvPanel.Dock    = [System.Windows.Forms.DockStyle]::Fill
$netLvPanel.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 4)
$netLvPanel.Controls.Add($script:lvNet)

$panelNet.Controls.Add($netBtnPanel)
$panelNet.Controls.Add($netLvPanel)
$panelNet.Controls.Add($lblNetDesc)

# ============================================================
# TAB 3 - MALWARE HUNT
# ============================================================
$panelMal = New-Object System.Windows.Forms.Panel
$panelMal.Dock      = [System.Windows.Forms.DockStyle]::Fill
$panelMal.BackColor = $cBg
$panelMal.Visible   = $false

$script:lvMal = New-StyledListView `
    -Columns @("Severity","Type","Name","Detail","Action") `
    -Widths   @(80, 100, 180, 360, 120)
$script:lvMal.Dock = [System.Windows.Forms.DockStyle]::Fill

$malBtnPanel = New-Object System.Windows.Forms.Panel
$malBtnPanel.Dock      = [System.Windows.Forms.DockStyle]::Bottom
$malBtnPanel.Height    = 46
$malBtnPanel.BackColor = $cPanel

$btnKillProc    = New-StyledButton "Kill Process"    140 $cBtnStop
$btnRemoveStart = New-StyledButton "Remove Startup"  140 $cBtnStop
$btnDisableTask = New-StyledButton "Disable Task"    130 $cBtnExport
$btnDeleteTask  = New-StyledButton "Delete Task"     120 $cBtnStop
$btnViewHosts   = New-StyledButton "View Hosts File" 150 $cBtnExport

$btnKillProc.Location    = New-Object System.Drawing.Point(8,   6)
$btnRemoveStart.Location = New-Object System.Drawing.Point(156, 6)
$btnDisableTask.Location = New-Object System.Drawing.Point(304, 6)
$btnDeleteTask.Location  = New-Object System.Drawing.Point(442, 6)
$btnViewHosts.Location   = New-Object System.Drawing.Point(570, 6)
$malBtnPanel.Controls.AddRange(@($btnKillProc, $btnRemoveStart, $btnDisableTask, $btnDeleteTask, $btnViewHosts))

$malLvPanel = New-Object System.Windows.Forms.Panel
$malLvPanel.Dock    = [System.Windows.Forms.DockStyle]::Fill
$malLvPanel.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 4)
$malLvPanel.Controls.Add($script:lvMal)

$panelMal.Controls.Add($malBtnPanel)
$panelMal.Controls.Add($malLvPanel)

# ============================================================
# TAB 4 - SYSTEM AUDIT
# ============================================================
$panelAudit = New-Object System.Windows.Forms.Panel
$panelAudit.Dock      = [System.Windows.Forms.DockStyle]::Fill
$panelAudit.BackColor = $cBg
$panelAudit.Visible   = $false

$auditScroll = New-Object System.Windows.Forms.Panel
$auditScroll.Dock          = [System.Windows.Forms.DockStyle]::Fill
$auditScroll.AutoScroll    = $true
$auditScroll.BackColor     = $cBg
$auditScroll.Padding       = New-Object System.Windows.Forms.Padding(8)
$panelAudit.Controls.Add($auditScroll)

$script:AuditChecks = @(
    @{ Id=1;  Sev="Critical"; Cat="Firewall";   Name="Windows Firewall"           }
    @{ Id=2;  Sev="Critical"; Cat="Antivirus";  Name="Windows Defender RTP"       }
    @{ Id=3;  Sev="Critical"; Cat="Protocol";   Name="SMBv1 Protocol"             }
    @{ Id=4;  Sev="High";     Cat="UAC";        Name="UAC Enabled"                }
    @{ Id=5;  Sev="High";     Cat="Credential"; Name="WDigest Caching"            }
    @{ Id=6;  Sev="High";     Cat="Network";    Name="LLMNR Protocol"             }
    @{ Id=7;  Sev="High";     Cat="Remote";     Name="RDP Disabled"               }
    @{ Id=8;  Sev="High";     Cat="Boot";       Name="Secure Boot"                }
    @{ Id=9;  Sev="High";     Cat="Encryption"; Name="BitLocker Drive Encryption" }
    @{ Id=10; Sev="Medium";   Cat="Account";    Name="Guest Account Disabled"     }
    @{ Id=11; Sev="Medium";   Cat="AutoRun";    Name="AutoRun Disabled"           }
    @{ Id=12; Sev="Medium";   Cat="Service";    Name="Remote Registry Disabled"   }
    @{ Id=13; Sev="Medium";   Cat="Scripting";  Name="WSH Disabled"               }
    @{ Id=14; Sev="Medium";   Cat="Logging";    Name="PS Script Block Logging"    }
    @{ Id=15; Sev="Medium";   Cat="Audit";      Name="Audit: Logon Events"        }
    @{ Id=16; Sev="Medium";   Cat="Audit";      Name="Audit: Account Management"  }
    @{ Id=17; Sev="Low";      Cat="Screen";     Name="Screen Saver Password"      }
    @{ Id=18; Sev="Low";      Cat="Feature";    Name="Telnet Client Disabled"     }
)

$script:AuditRows = @{}
$auditY = 8
foreach ($chk in $script:AuditChecks) {
    $row = New-Object System.Windows.Forms.Panel
    $row.Width     = 940
    $row.Height    = 38
    $row.Location  = New-Object System.Drawing.Point(0, $auditY)
    $row.BackColor = $cCard
    $row.Anchor    = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

    $sevLbl = New-Object System.Windows.Forms.Label
    $sevLbl.Text      = $chk.Sev
    $sevLbl.Width     = 70
    $sevLbl.Height    = 38
    $sevLbl.Location  = New-Object System.Drawing.Point(4, 0)
    $sevLbl.ForeColor = Get-SevColor $chk.Sev
    $sevLbl.Font      = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $sevLbl.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter

    $catLbl = New-Object System.Windows.Forms.Label
    $catLbl.Text      = $chk.Cat
    $catLbl.Width     = 90
    $catLbl.Height    = 38
    $catLbl.Location  = New-Object System.Drawing.Point(76, 0)
    $catLbl.ForeColor = $cSubText
    $catLbl.Font      = New-Object System.Drawing.Font("Segoe UI", 8)
    $catLbl.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft

    $nameLbl = New-Object System.Windows.Forms.Label
    $nameLbl.Text      = $chk.Name
    $nameLbl.Width     = 240
    $nameLbl.Height    = 38
    $nameLbl.Location  = New-Object System.Drawing.Point(168, 0)
    $nameLbl.ForeColor = $cText
    $nameLbl.Font      = New-Object System.Drawing.Font("Segoe UI", 9)
    $nameLbl.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft

    $statusLbl = New-Object System.Windows.Forms.Label
    $statusLbl.Text      = "PENDING"
    $statusLbl.Width     = 100
    $statusLbl.Height    = 38
    $statusLbl.Location  = New-Object System.Drawing.Point(410, 0)
    $statusLbl.ForeColor = $cSubText
    $statusLbl.Font      = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
    $statusLbl.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter

    $fixBtn = New-StyledButton "FIX" 70 $cBtnScan
    $fixBtn.Height   = 26
    $fixBtn.Location = New-Object System.Drawing.Point(520, 6)
    $fixBtn.Enabled  = $false
    $fixBtn.Tag      = $chk.Id

    $row.Controls.AddRange(@($sevLbl, $catLbl, $nameLbl, $statusLbl, $fixBtn))
    $auditScroll.Controls.Add($row)

    $script:AuditRows[$chk.Id] = @{
        Row       = $row
        StatusLbl = $statusLbl
        FixBtn    = $fixBtn
    }
    $auditY += 42
}
$auditScroll.AutoScrollMinSize = New-Object System.Drawing.Size(0, ($auditY + 10))

# ============================================================
# TAB 5 - REPORT
# ============================================================
$panelReport = New-Object System.Windows.Forms.Panel
$panelReport.Dock      = [System.Windows.Forms.DockStyle]::Fill
$panelReport.BackColor = $cBg
$panelReport.Visible   = $false

$reportBtnPanel = New-Object System.Windows.Forms.Panel
$reportBtnPanel.Dock      = [System.Windows.Forms.DockStyle]::Top
$reportBtnPanel.Height    = 46
$reportBtnPanel.BackColor = $cPanel

$btnRptTxt     = New-StyledButton "Export TXT"        120 $cBtnExport
$btnRptHtml    = New-StyledButton "Export HTML"       120 $cBtnExport
$btnRptClip    = New-StyledButton "Copy to Clipboard" 160 $cBtnExport
$btnRptRebuild = New-StyledButton "Rebuild Report"    150 $cBtnScan

$btnRptTxt.Location     = New-Object System.Drawing.Point(8,   6)
$btnRptHtml.Location    = New-Object System.Drawing.Point(136, 6)
$btnRptClip.Location    = New-Object System.Drawing.Point(264, 6)
$btnRptRebuild.Location = New-Object System.Drawing.Point(432, 6)
$reportBtnPanel.Controls.AddRange(@($btnRptTxt, $btnRptHtml, $btnRptClip, $btnRptRebuild))

$script:rtbReport = New-Object System.Windows.Forms.RichTextBox
$script:rtbReport.Dock        = [System.Windows.Forms.DockStyle]::Fill
$script:rtbReport.BackColor   = $cListBg
$script:rtbReport.ForeColor   = $cText
$script:rtbReport.Font        = New-Object System.Drawing.Font("Consolas", 9)
$script:rtbReport.ReadOnly    = $true
$script:rtbReport.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$script:rtbReport.ScrollBars  = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
$script:rtbReport.Text        = "Run a FULL SCAN to generate the security report."

$panelReport.Controls.Add($script:rtbReport)
$panelReport.Controls.Add($reportBtnPanel)

# ============================================================
# ASSEMBLE CONTENT AREA
# ============================================================
$contentArea.Controls.Add($panelReport)
$contentArea.Controls.Add($panelAudit)
$contentArea.Controls.Add($panelMal)
$contentArea.Controls.Add($panelNet)
$contentArea.Controls.Add($panelDash)

# ============================================================
# TAB SWITCHING
# ============================================================
$script:AllPanels  = @($panelDash, $panelNet, $panelMal, $panelAudit, $panelReport)
$script:TabButtons = @()
$tabNames          = @("DASHBOARD","NETWORK","MALWARE HUNT","SYSTEM AUDIT","REPORT")

function Switch-Tab {
    param([int]$idx)
    for ($i = 0; $i -lt $script:AllPanels.Count; $i++) {
        $script:AllPanels[$i].Visible = ($i -eq $idx)
        if ($i -lt $script:TabButtons.Count) {
            $script:TabButtons[$i].ForeColor = if ($i -eq $idx) { $cAccent } else { $cSubText }
        }
    }
    $script:CurrentTab = $idx
}

$tabX = 0
for ($ti = 0; $ti -lt $tabNames.Count; $ti++) {
    $tb = New-Object System.Windows.Forms.Button
    $tb.Text      = $tabNames[$ti]
    $tb.Width     = 142
    $tb.Height    = 40
    $tb.Location  = New-Object System.Drawing.Point($tabX, 0)
    $tb.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $tb.FlatAppearance.BorderSize  = 0
    $tb.BackColor = $cPanel
    $tb.ForeColor = $cSubText
    $tb.Font      = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $tb.Tag       = $ti
    $tb.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $tabStrip.Controls.Add($tb)
    $script:TabButtons += $tb
    $tabX += 142
}

foreach ($tb in $script:TabButtons) {
    $tb.Add_Click({
        param($s, $e)
        Switch-Tab ([int]$s.Tag)
    })
}

Switch-Tab 0

# ============================================================
# SCAN ENGINE - NETWORK
# ============================================================
function Invoke-NetworkScan {
    Set-StatusMsg "Scanning network connections..."
    $script:lvNet.Items.Clear()
    $suspPorts = @(4444,4445,1234,1337,31337,6666,6667,6668,6669,1080,9050,9051,65535)
    try {
        $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
        foreach ($c in $conns) {
            if ($script:StopScan) { break }
            $suspicious = $false
            $reason     = ""
            $remPort    = $c.RemotePort
            $locPort    = $c.LocalPort
            $remAddr    = $c.RemoteAddress
            $state      = $c.State

            if ($suspPorts -contains $remPort) {
                $suspicious = $true
                $reason = "Suspicious remote port $remPort"
            }
            if ($suspPorts -contains $locPort -and $state -eq "Listen") {
                $suspicious = $true
                $reason = "Listening on suspicious port $locPort"
            }

            $procName = ""
            $pid_ = $c.OwningProcess
            try {
                $p = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
                if ($p) { $procName = $p.ProcessName }
            } catch {}

            $statusTxt = if ($suspicious) { "SUSPICIOUS" } else { "OK" }
            $item = New-Object System.Windows.Forms.ListViewItem($statusTxt)
            $item.ForeColor = if ($suspicious) { $cCritical } else { $cSecure }
            $null = $item.SubItems.Add("$locPort")
            $null = $item.SubItems.Add($remAddr)
            $null = $item.SubItems.Add("$remPort")
            $null = $item.SubItems.Add("$state")
            $null = $item.SubItems.Add($procName)
            $null = $item.SubItems.Add("$pid_")
            $item.Tag = $c
            $script:lvNet.Items.Add($item) | Out-Null

            if ($suspicious) {
                Add-Finding "High" "Network" "Suspicious Connection" "$procName port $remPort -> $remAddr" "Network"
            }
        }
    } catch {
        Add-Finding "Medium" "Network" "Network Scan Error" $_.Exception.Message "Network"
    }
    [System.Windows.Forms.Application]::DoEvents()
}

# ============================================================
# SCAN ENGINE - PROCESSES
# ============================================================
function Invoke-ProcessScan {
    Set-StatusMsg "Scanning processes..."
    $sysNames   = @("svchost","lsass","winlogon","wininit","smss","services","spoolsv","explorer","taskhost","taskhostw","conhost","dllhost","rundll32","regsvr32")
    $singleInst = @("lsass","winlogon","wininit","smss","services")
    $malNames   = @("mimikatz","meterpreter","empire","beacon","njrat","darkcomet","nanocore","quasar","asyncrat","remcos","netcat","ncat","lazagne","pwdump","procdump","rubeus","bloodhound","sharphound")
    $suspPaths  = @("\Temp\","\tmp\","AppData\Local\Temp")

    try {
        # Use WMI Win32_Process for reliable, consistent Win32 paths (not MainModule.FileName
        # which returns non-deterministic NT device paths for protected system processes).
        $wmiProcs   = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
        $pathByPid  = @{}
        foreach ($w in $wmiProcs) {
            # ExecutablePath is always a proper C:\... path or $null - never an NT device path
            $pathByPid[$w.ProcessId] = if ($w.ExecutablePath) { $w.ExecutablePath } else { "" }
        }

        $procs = Get-Process -ErrorAction SilentlyContinue
        $nameCounts = @{}
        foreach ($p in $procs) {
            $n = $p.ProcessName.ToLower()
            if (-not $nameCounts.ContainsKey($n)) { $nameCounts[$n] = 0 }
            $nameCounts[$n]++
        }

        $flaggedSingle = @{}

        foreach ($p in $procs) {
            if ($script:StopScan) { break }
            $name  = $p.ProcessName
            $nameL = $name.ToLower()
            # Reliable path from WMI - empty string if process path cannot be determined
            $path  = if ($pathByPid.ContainsKey($p.Id)) { $pathByPid[$p.Id] } else { "" }

            # Known malware names
            foreach ($m in $malNames) {
                if ($nameL -like "*$m*") {
                    Add-Finding "Critical" "Process" $name "Matches known malware name: $m (PID $($p.Id))" "MalwareHunt"
                    $item = New-Object System.Windows.Forms.ListViewItem("Critical")
                    $item.ForeColor = $cCritical
                    $null = $item.SubItems.Add("Process")
                    $null = $item.SubItems.Add($name)
                    $null = $item.SubItems.Add("Malware name match: $m  PID=$($p.Id)")
                    $null = $item.SubItems.Add("Kill Process")
                    $item.Tag = @{ Type="Process"; PID=$p.Id }
                    $script:lvMal.Items.Add($item) | Out-Null
                    break
                }
            }

            # Suspicious path
            foreach ($sp in $suspPaths) {
                if ($path -like "*$sp*") {
                    Add-Finding "High" "Process" $name "Running from suspicious path: $path (PID $($p.Id))" "MalwareHunt"
                    $item = New-Object System.Windows.Forms.ListViewItem("High")
                    $item.ForeColor = $cHigh
                    $null = $item.SubItems.Add("Process")
                    $null = $item.SubItems.Add($name)
                    $null = $item.SubItems.Add("Suspicious path: $path")
                    $null = $item.SubItems.Add("Kill Process")
                    $item.Tag = @{ Type="Process"; PID=$p.Id }
                    $script:lvMal.Items.Add($item) | Out-Null
                    break
                }
            }

            # System process masquerading
            # Only flag if path is non-empty AND points to a clearly suspicious location.
            # Many legit system processes run under Session 0 and cannot have their
            # path read via MainModule - those return empty string and must NOT be flagged.
            if ($sysNames -contains $nameL -and (-not [string]::IsNullOrEmpty($path))) {
                $isSuspicious = ($path -like "*\Temp\*")            -or
                                ($path -like "*\tmp\*")             -or
                                ($path -like "*\Downloads\*")       -or
                                ($path -like "*\Desktop\*")         -or
                                ($path -like "*\Public\*")          -or
                                ($path -like "*AppData\Local\Temp*")
                if ($isSuspicious) {
                    Add-Finding "Critical" "Process" $name "System process masquerading from suspicious path: $path (PID $($p.Id))" "MalwareHunt"
                    $item = New-Object System.Windows.Forms.ListViewItem("Critical")
                    $item.ForeColor = $cCritical
                    $null = $item.SubItems.Add("Process")
                    $null = $item.SubItems.Add($name)
                    $null = $item.SubItems.Add("Masquerading from suspicious path: $path")
                    $null = $item.SubItems.Add("Kill Process")
                    $item.Tag = @{ Type="Process"; PID=$p.Id }
                    $script:lvMal.Items.Add($item) | Out-Null
                }
            }

            # Single instance check (NOT csrss)
            if ($singleInst -contains $nameL -and $nameCounts[$nameL] -gt 1 -and -not $flaggedSingle.ContainsKey($nameL)) {
                $flaggedSingle[$nameL] = $true
                Add-Finding "High" "Process" $name "Multiple instances ($($nameCounts[$nameL])) of single-instance system process" "MalwareHunt"
                $item = New-Object System.Windows.Forms.ListViewItem("High")
                $item.ForeColor = $cHigh
                $null = $item.SubItems.Add("Process")
                $null = $item.SubItems.Add($name)
                $null = $item.SubItems.Add("$($nameCounts[$nameL]) instances detected (expected 1)")
                $null = $item.SubItems.Add("Investigate")
                $item.Tag = @{ Type="Process"; PID=$p.Id }
                $script:lvMal.Items.Add($item) | Out-Null
            }
        }
    } catch {
        Add-Finding "Medium" "Process" "Process Scan Error" $_.Exception.Message "MalwareHunt"
    }
    [System.Windows.Forms.Application]::DoEvents()
}

# ============================================================
# SCAN ENGINE - STARTUP
# ============================================================
function Invoke-StartupScan {
    Set-StatusMsg "Scanning startup entries..."
    $suspPaths = @("\Temp\","\tmp\","AppData\Local\Temp","\Downloads\","\Public\")
    $regPaths  = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($rp in $regPaths) {
        if ($script:StopScan) { break }
        try {
            $vals = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
            if (-not $vals) { continue }
            $vals.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                $valName = $_.Name
                $valData = "$($_.Value)"
                $suspicious = $false
                foreach ($sp in $suspPaths) {
                    if ($valData -like "*$sp*") { $suspicious = $true; break }
                }
                if ($suspicious) {
                    Add-Finding "High" "Startup" $valName "Startup entry from suspicious path: $valData" "MalwareHunt"
                    $item = New-Object System.Windows.Forms.ListViewItem("High")
                    $item.ForeColor = $cHigh
                    $null = $item.SubItems.Add("Startup")
                    $null = $item.SubItems.Add($valName)
                    $null = $item.SubItems.Add("$rp -> $valData")
                    $null = $item.SubItems.Add("Remove Entry")
                    $item.Tag = @{ Type="Startup"; RegPath=$rp; ValName=$valName }
                    $script:lvMal.Items.Add($item) | Out-Null
                }
            }
        } catch {}
    }
    [System.Windows.Forms.Application]::DoEvents()
}

# ============================================================
# SCAN ENGINE - SCHEDULED TASKS
# ============================================================
function Invoke-TaskScan {
    Set-StatusMsg "Scanning scheduled tasks..."
    $suspPaths = @("\Temp\","\tmp\","AppData\Local\Temp","\Downloads\","\Public\","\Users\Public\")
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            if ($script:StopScan) { break }
            foreach ($a in $t.Actions) {
                $exe = $a.Execute
                if (-not $exe) { continue }
                $suspicious = $false
                foreach ($sp in $suspPaths) {
                    if ($exe -like "*$sp*") { $suspicious = $true; break }
                }
                if ($suspicious) {
                    $tName = $t.TaskName
                    Add-Finding "High" "ScheduledTask" $tName "Task runs from suspicious path: $exe" "MalwareHunt"
                    $item = New-Object System.Windows.Forms.ListViewItem("High")
                    $item.ForeColor = $cHigh
                    $null = $item.SubItems.Add("Task")
                    $null = $item.SubItems.Add($tName)
                    $null = $item.SubItems.Add("Executes: $exe")
                    $null = $item.SubItems.Add("Disable/Delete")
                    $item.Tag = @{ Type="Task"; TaskName=$tName; TaskPath=$t.TaskPath }
                    $script:lvMal.Items.Add($item) | Out-Null
                    break
                }
            }
        }
    } catch {
        Add-Finding "Medium" "Task" "Task Scan Error" $_.Exception.Message "MalwareHunt"
    }
    [System.Windows.Forms.Application]::DoEvents()
}

# ============================================================
# SCAN ENGINE - HOSTS FILE
# ============================================================
function Invoke-HostsScan {
    Set-StatusMsg "Scanning hosts file..."
    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
    try {
        $lines = Get-Content $hostsPath -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed -eq "" -or $trimmed.StartsWith("#")) { continue }
            $parts = $trimmed -split '\s+'
            if ($parts.Count -ge 2) {
                $ip     = $parts[0]
                $domain = $parts[1]
                $suspicious = $false
                $reason     = ""
                if (($ip -eq "0.0.0.0" -or $ip -eq "127.0.0.1") -and
                    $domain -ne "localhost" -and $domain -ne "local" -and $domain -ne "::1") {
                    if ($domain -match "\.(com|net|org|gov|edu|io|co)$") {
                        $suspicious = $true
                        $reason = "Domain $domain redirected to $ip (possible hijack or block)"
                    }
                }
                if ($domain -match "(google|microsoft|windows|update|antivirus|kaspersky|symantec|mcafee|malwarebytes)\." -and
                    $ip -ne "127.0.0.1" -and $ip -ne "0.0.0.0") {
                    $suspicious = $true
                    $reason = "Known security domain $domain redirected to $ip"
                }
                if ($suspicious) {
                    Add-Finding "High" "HostsFile" $domain $reason "MalwareHunt"
                    $item = New-Object System.Windows.Forms.ListViewItem("High")
                    $item.ForeColor = $cHigh
                    $null = $item.SubItems.Add("Hosts")
                    $null = $item.SubItems.Add($domain)
                    $null = $item.SubItems.Add($reason)
                    $null = $item.SubItems.Add("View Hosts")
                    $item.Tag = @{ Type="Hosts" }
                    $script:lvMal.Items.Add($item) | Out-Null
                }
            }
        }
    } catch {}
    [System.Windows.Forms.Application]::DoEvents()
}

# ============================================================
# SCAN ENGINE - WINDOWS EVENT LOG
# Checks: failed logins, audit log clearing, account lockouts
# ============================================================
function Invoke-EventLogScan {
    Set-StatusMsg "Scanning security event log..."
    try {
        $since24h = (Get-Date).AddHours(-24)
        $since7d  = (Get-Date).AddDays(-7)

        # Failed logins in last 24 hours (Event 4625)
        try {
            $failed = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$since24h} -MaxEvents 200 -ErrorAction Stop)
            if ($failed.Count -ge 20) {
                Add-Finding "High" "EventLog" "Brute-Force Attack Detected" "$($failed.Count) failed login attempts in the last 24 hours - possible brute-force attack" "EventLog"
                $item = New-Object System.Windows.Forms.ListViewItem("High")
                $item.ForeColor = $cHigh
                $null = $item.SubItems.Add("EventLog")
                $null = $item.SubItems.Add("Brute-Force Attack Detected")
                $null = $item.SubItems.Add("$($failed.Count) failed logins in 24h - investigate immediately")
                $null = $item.SubItems.Add("View Events")
                $item.Tag = @{ Type="EventLog"; EventId=4625 }
                $script:lvMal.Items.Add($item) | Out-Null
            } elseif ($failed.Count -ge 5) {
                Add-Finding "Medium" "EventLog" "Multiple Failed Login Attempts" "$($failed.Count) failed login attempts in the last 24 hours" "EventLog"
                $item = New-Object System.Windows.Forms.ListViewItem("Medium")
                $item.ForeColor = $cMedium
                $null = $item.SubItems.Add("EventLog")
                $null = $item.SubItems.Add("Multiple Failed Login Attempts")
                $null = $item.SubItems.Add("$($failed.Count) failed logins in 24h")
                $null = $item.SubItems.Add("View Events")
                $item.Tag = @{ Type="EventLog"; EventId=4625 }
                $script:lvMal.Items.Add($item) | Out-Null
            }
        } catch {}

        # Audit log cleared (Event 1102) - indicator of cover-up
        try {
            $cleared = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102;StartTime=$since7d} -MaxEvents 10 -ErrorAction Stop)
            if ($cleared.Count -gt 0) {
                Add-Finding "High" "EventLog" "Security Audit Log Was Cleared" "Audit log cleared $($cleared.Count) time(s) in the last 7 days - possible evidence destruction" "EventLog"
                $item = New-Object System.Windows.Forms.ListViewItem("High")
                $item.ForeColor = $cHigh
                $null = $item.SubItems.Add("EventLog")
                $null = $item.SubItems.Add("Audit Log Cleared")
                $null = $item.SubItems.Add("Log cleared $($cleared.Count)x in 7 days - investigate")
                $null = $item.SubItems.Add("View Events")
                $item.Tag = @{ Type="EventLog"; EventId=1102 }
                $script:lvMal.Items.Add($item) | Out-Null
            }
        } catch {}

        # Account lockouts (Event 4740)
        try {
            $lockouts = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4740;StartTime=$since7d} -MaxEvents 50 -ErrorAction Stop)
            if ($lockouts.Count -gt 0) {
                Add-Finding "Medium" "EventLog" "Account Lockout Events" "$($lockouts.Count) account lockout(s) in the last 7 days" "EventLog"
                $item = New-Object System.Windows.Forms.ListViewItem("Medium")
                $item.ForeColor = $cMedium
                $null = $item.SubItems.Add("EventLog")
                $null = $item.SubItems.Add("Account Lockout Events")
                $null = $item.SubItems.Add("$($lockouts.Count) account lockout(s) in 7 days")
                $null = $item.SubItems.Add("View Events")
                $item.Tag = @{ Type="EventLog"; EventId=4740 }
                $script:lvMal.Items.Add($item) | Out-Null
            }
        } catch {}

        # New user accounts created in last 7 days (Event 4720)
        try {
            $newAccts = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720;StartTime=$since7d} -MaxEvents 20 -ErrorAction Stop)
            if ($newAccts.Count -gt 0) {
                Add-Finding "Medium" "EventLog" "New User Accounts Created" "$($newAccts.Count) new user account(s) created in the last 7 days" "EventLog"
                $item = New-Object System.Windows.Forms.ListViewItem("Medium")
                $item.ForeColor = $cMedium
                $null = $item.SubItems.Add("EventLog")
                $null = $item.SubItems.Add("New User Accounts Created")
                $null = $item.SubItems.Add("$($newAccts.Count) account(s) created in 7 days - verify legitimacy")
                $null = $item.SubItems.Add("View Events")
                $item.Tag = @{ Type="EventLog"; EventId=4720 }
                $script:lvMal.Items.Add($item) | Out-Null
            }
        } catch {}

        # Privilege use - admin rights granted (Event 4672) - flag if excessive
        try {
            $privUse = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672;StartTime=$since24h} -MaxEvents 500 -ErrorAction Stop)
            if ($privUse.Count -gt 100) {
                Add-Finding "Low" "EventLog" "High Privileged Logon Activity" "$($privUse.Count) privileged logon events in 24h - review for anomalies" "EventLog"
                $item = New-Object System.Windows.Forms.ListViewItem("Low")
                $item.ForeColor = $cLow
                $null = $item.SubItems.Add("EventLog")
                $null = $item.SubItems.Add("High Privileged Logon Activity")
                $null = $item.SubItems.Add("$($privUse.Count) special privilege logons in 24h")
                $null = $item.SubItems.Add("View Events")
                $item.Tag = @{ Type="EventLog"; EventId=4672 }
                $script:lvMal.Items.Add($item) | Out-Null
            }
        } catch {}

    } catch {}
}

# ============================================================
# SCAN ENGINE - WINDOWS SERVICES
# Checks for services running from suspicious locations
# ============================================================
function Invoke-ServiceScan {
    Set-StatusMsg "Scanning services..."
    $suspPaths = @("\Temp\", "\tmp\", "AppData\Local\Temp", "\Downloads\", "\Desktop\", "\Public\")
    try {
        $svcs = Get-WmiObject Win32_Service -ErrorAction Stop |
                Where-Object { $_.State -eq 'Running' -and -not [string]::IsNullOrEmpty($_.PathName) }
        foreach ($svc in $svcs) {
            if ($script:StopScan) { break }
            foreach ($sp in $suspPaths) {
                if ($svc.PathName -like "*$sp*") {
                    Add-Finding "High" "Service" $svc.Name "Running service from suspicious path: $($svc.PathName)" "Services"
                    $item = New-Object System.Windows.Forms.ListViewItem("High")
                    $item.ForeColor = $cHigh
                    $null = $item.SubItems.Add("Service")
                    $null = $item.SubItems.Add($svc.Name)
                    $null = $item.SubItems.Add("Runs from suspicious path: $($svc.PathName)")
                    $null = $item.SubItems.Add("Investigate")
                    $item.Tag = @{ Type="Service"; Name=$svc.Name }
                    $script:lvMal.Items.Add($item) | Out-Null
                    break
                }
            }
        }
    } catch {}
}

# ============================================================
# SCAN ENGINE - PASSWORD POLICY
# Checks minimum length, max age, complexity
# ============================================================
function Invoke-PasswordPolicyScan {
    Set-StatusMsg "Checking password policy..."
    try {
        $netAccts = & net accounts 2>&1
        $minLenLine = $netAccts | Where-Object { $_ -match 'Minimum password length' }
        $maxAgeLine = $netAccts | Where-Object { $_ -match 'Maximum password age' }
        $histLine   = $netAccts | Where-Object { $_ -match 'Length of password history' }

        if ($minLenLine) {
            $minLen = ($minLenLine -replace '[^\d]','').Trim()
            if ($minLen -match '^\d+$') {
                $minLenVal = [int]$minLen
                if ($minLenVal -eq 0) {
                    Add-Finding "High" "Policy" "No Minimum Password Length" "Minimum password length is 0 - users can set blank passwords" "Audit"
                } elseif ($minLenVal -lt 8) {
                    Add-Finding "High" "Policy" "Weak Minimum Password Length" "Minimum password length is only $minLenVal characters (recommended: 12+)" "Audit"
                } elseif ($minLenVal -lt 12) {
                    Add-Finding "Medium" "Policy" "Short Minimum Password Length" "Minimum password length is $minLenVal characters (recommended: 12+)" "Audit"
                }
            }
        }

        if ($maxAgeLine) {
            $maxAgeVal = ($maxAgeLine -replace '[^\d]','').Trim()
            if ($maxAgeVal -eq '' -or $maxAgeLine -match 'Unlimited|Never') {
                Add-Finding "Medium" "Policy" "Passwords Never Expire" "Maximum password age is Unlimited - passwords never forced to change" "Audit"
            } elseif ($maxAgeVal -match '^\d+$' -and [int]$maxAgeVal -gt 180) {
                Add-Finding "Low" "Policy" "Long Password Expiry Period" "Passwords expire every $maxAgeVal days (recommended: 90 or less)" "Audit"
            }
        }

        # Password complexity via secedit
        $complexKey = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -EA SilentlyContinue).RequireStrongKey
        $complexPol = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system' -EA SilentlyContinue).PasswordComplexity
        if ($complexPol -eq 0) {
            Add-Finding "High" "Policy" "Password Complexity Disabled" "Windows password complexity requirements are turned off" "Audit"
        }
    } catch {}
}

# ============================================================
# SCAN ENGINE - AUDIT
# ============================================================
function Invoke-AuditScan {
    Set-StatusMsg "Running system audit..."

    function Set-AuditStatus {
        param([int]$id, [string]$status, [string]$detail = "")
        $r = $script:AuditRows[$id]
        if ($status -eq "SECURE") {
            $r.StatusLbl.Text      = "SECURE"
            $r.StatusLbl.ForeColor = $cSecure
            $r.FixBtn.Enabled      = $false
        } elseif ($status -eq "VULNERABLE") {
            $r.StatusLbl.Text      = "VULNERABLE"
            $r.StatusLbl.ForeColor = $cCritical
            $r.FixBtn.Enabled      = $true
            $chkDef = $script:AuditChecks | Where-Object { $_.Id -eq $id }
            if ($chkDef) { Add-Finding $chkDef.Sev "Audit" $chkDef.Name $detail "SystemAudit" }
        } else {
            $r.StatusLbl.Text      = "UNKNOWN"
            $r.StatusLbl.ForeColor = $cSubText
        }
        $script:AuditResults[$id] = $status
        [System.Windows.Forms.Application]::DoEvents()
    }

    # 1 - Firewall
    try {
        $fwp = Get-NetFirewallProfile -ErrorAction Stop
        $allOn = $true
        foreach ($fp in $fwp) { if (-not $fp.Enabled) { $allOn = $false } }
        if ($allOn) { Set-AuditStatus 1 "SECURE" } else { Set-AuditStatus 1 "VULNERABLE" "One or more firewall profiles are disabled" }
    } catch { Set-AuditStatus 1 "UNKNOWN" }

    if ($script:StopScan) { return }

    # 2 - Defender RTP
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.RealTimeProtectionEnabled) { Set-AuditStatus 2 "SECURE" }
        else { Set-AuditStatus 2 "VULNERABLE" "Windows Defender Real-Time Protection is disabled" }
    } catch { Set-AuditStatus 2 "UNKNOWN" }

    if ($script:StopScan) { return }

    # 3 - SMBv1
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        if (-not $smb.EnableSMB1Protocol) { Set-AuditStatus 3 "SECURE" }
        else { Set-AuditStatus 3 "VULNERABLE" "SMBv1 is enabled - major ransomware attack vector" }
    } catch { Set-AuditStatus 3 "UNKNOWN" }

    # 4 - UAC
    try {
        $uac = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction Stop).EnableLUA
        if ($uac -eq 1) { Set-AuditStatus 4 "SECURE" } else { Set-AuditStatus 4 "VULNERABLE" "UAC is disabled" }
    } catch { Set-AuditStatus 4 "UNKNOWN" }

    # 5 - WDigest
    try {
        $wd = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -ErrorAction Stop).UseLogonCredential
        if ($wd -eq 0) { Set-AuditStatus 5 "SECURE" }
        else { Set-AuditStatus 5 "VULNERABLE" "WDigest credential caching enabled - plaintext passwords in memory" }
    } catch { Set-AuditStatus 5 "SECURE" }

    # 6 - LLMNR
    try {
        $ll = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction Stop).EnableMulticast
        if ($ll -eq 0) { Set-AuditStatus 6 "SECURE" }
        else { Set-AuditStatus 6 "VULNERABLE" "LLMNR enabled - susceptible to poisoning attacks" }
    } catch { Set-AuditStatus 6 "VULNERABLE" "LLMNR policy not configured - protocol likely enabled" }

    # 7 - RDP
    try {
        $rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
        if ($rdp -eq 1) { Set-AuditStatus 7 "SECURE" }
        else { Set-AuditStatus 7 "VULNERABLE" "RDP is enabled" }
    } catch { Set-AuditStatus 7 "UNKNOWN" }

    # 8 - Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) { Set-AuditStatus 8 "SECURE" }
        else { Set-AuditStatus 8 "VULNERABLE" "Secure Boot is disabled" }
    } catch { Set-AuditStatus 8 "UNKNOWN" }

    # 9 - BitLocker
    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ($bl.ProtectionStatus -eq "On") { Set-AuditStatus 9 "SECURE" }
        else { Set-AuditStatus 9 "VULNERABLE" "BitLocker not enabled on system drive" }
    } catch { Set-AuditStatus 9 "UNKNOWN" }

    # 10 - Guest Account
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
        if (-not $guest.Enabled) { Set-AuditStatus 10 "SECURE" }
        else { Set-AuditStatus 10 "VULNERABLE" "Guest account is enabled" }
    } catch { Set-AuditStatus 10 "SECURE" }

    # 11 - AutoRun
    try {
        $ar = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -ErrorAction Stop).NoDriveTypeAutoRun
        if ($ar -eq 255) { Set-AuditStatus 11 "SECURE" }
        else { Set-AuditStatus 11 "VULNERABLE" "AutoRun not fully disabled (value=$ar, should be 255)" }
    } catch { Set-AuditStatus 11 "VULNERABLE" "AutoRun policy not configured" }

    # 12 - Remote Registry
    try {
        $rr = Get-Service RemoteRegistry -ErrorAction Stop
        if ($rr.Status -eq "Stopped" -and $rr.StartType -eq "Disabled") { Set-AuditStatus 12 "SECURE" }
        else { Set-AuditStatus 12 "VULNERABLE" "Remote Registry service is not stopped/disabled (Status=$($rr.Status))" }
    } catch { Set-AuditStatus 12 "UNKNOWN" }

    # 13 - WSH
    try {
        $wsh = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -ErrorAction Stop).Enabled
        if ($wsh -eq 0) { Set-AuditStatus 13 "SECURE" }
        else { Set-AuditStatus 13 "VULNERABLE" "Windows Script Host is enabled" }
    } catch { Set-AuditStatus 13 "VULNERABLE" "WSH restriction not set" }

    # 14 - PS Script Block Logging
    try {
        $pslog = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction Stop).EnableScriptBlockLogging
        if ($pslog -eq 1) { Set-AuditStatus 14 "SECURE" }
        else { Set-AuditStatus 14 "VULNERABLE" "PowerShell Script Block Logging is disabled" }
    } catch { Set-AuditStatus 14 "VULNERABLE" "PowerShell Script Block Logging not configured" }

    # 15 - Audit Logon
    try {
        $auditOut = (auditpol /get /subcategory:"Logon" 2>$null) -join " "
        if ($auditOut -match "Success and Failure|Success") { Set-AuditStatus 15 "SECURE" }
        else { Set-AuditStatus 15 "VULNERABLE" "Logon event auditing not fully enabled" }
    } catch { Set-AuditStatus 15 "UNKNOWN" }

    # 16 - Audit Account Management
    try {
        $auditOut2 = (auditpol /get /subcategory:"User Account Management" 2>$null) -join " "
        if ($auditOut2 -match "Success and Failure|Success") { Set-AuditStatus 16 "SECURE" }
        else { Set-AuditStatus 16 "VULNERABLE" "Account management auditing not fully enabled" }
    } catch { Set-AuditStatus 16 "UNKNOWN" }

    # 17 - Screen Saver Password
    try {
        $ssPwd    = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name ScreenSaverIsSecure -ErrorAction Stop).ScreenSaverIsSecure
        $ssActive = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name ScreenSaveActive -ErrorAction Stop).ScreenSaveActive
        if ($ssPwd -eq "1" -and $ssActive -eq "1") { Set-AuditStatus 17 "SECURE" }
        else { Set-AuditStatus 17 "VULNERABLE" "Screen saver password not required" }
    } catch { Set-AuditStatus 17 "VULNERABLE" "Screen saver settings not configured" }

    # 18 - Telnet
    try {
        $telnet = Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction Stop
        if ($telnet.State -eq "Disabled") { Set-AuditStatus 18 "SECURE" }
        else { Set-AuditStatus 18 "VULNERABLE" "Telnet client is installed" }
    } catch { Set-AuditStatus 18 "SECURE" }

    [System.Windows.Forms.Application]::DoEvents()
}

# ============================================================
# REPORT BUILDER
# ============================================================
function Build-Report {
    $sep1 = "=" * 70
    $sep2 = "-" * 70
    $dt   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try { $osC = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption } catch { $osC = "Windows" }

    $c = ($script:Findings | Where-Object { $_.Sev -eq "Critical" }).Count
    $h = ($script:Findings | Where-Object { $_.Sev -eq "High"     }).Count
    $m = ($script:Findings | Where-Object { $_.Sev -eq "Medium"   }).Count
    $l = ($script:Findings | Where-Object { $_.Sev -eq "Low"      }).Count
    $t = $script:Findings.Count
    $s = Get-SecurityScore

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine($sep1)
    $null = $sb.AppendLine("  SECUREPC PRO v2.0 - SECURITY ASSESSMENT REPORT")
    $null = $sb.AppendLine($sep1)
    $null = $sb.AppendLine("  Generated : $dt")
    $null = $sb.AppendLine("  Computer  : $env:COMPUTERNAME")
    $null = $sb.AppendLine("  User      : $env:USERNAME @ $env:COMPUTERNAME")
    $null = $sb.AppendLine("  OS        : $osC")
    $null = $sb.AppendLine($sep1)
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("  EXECUTIVE SUMMARY")
    $null = $sb.AppendLine("  $sep2")
    $null = $sb.AppendLine("  Total Findings  : $t")
    $null = $sb.AppendLine("  Critical        : $c")
    $null = $sb.AppendLine("  High            : $h")
    $null = $sb.AppendLine("  Medium          : $m")
    $null = $sb.AppendLine("  Low             : $l")
    $null = $sb.AppendLine("  Security Score  : $s / 100")
    $null = $sb.AppendLine("  $sep2")
    $null = $sb.AppendLine("")

    $null = $sb.AppendLine("  NETWORK ANALYSIS")
    $null = $sb.AppendLine("  $sep2")
    $netF = $script:Findings | Where-Object { $_.Source -eq "Network" }
    if ($netF.Count -eq 0) { $null = $sb.AppendLine("  No suspicious network connections detected.") }
    else { foreach ($f in $netF) { $null = $sb.AppendLine("  [$($f.Sev)] $($f.Name) - $($f.Detail)") } }
    $null = $sb.AppendLine("")

    $null = $sb.AppendLine("  MALWARE HUNT")
    $null = $sb.AppendLine("  $sep2")
    $malF = $script:Findings | Where-Object { $_.Source -eq "MalwareHunt" }
    if ($malF.Count -eq 0) { $null = $sb.AppendLine("  No suspicious items detected.") }
    else { foreach ($f in $malF) { $null = $sb.AppendLine("  [$($f.Sev)] [$($f.Cat)] $($f.Name) - $($f.Detail)") } }
    $null = $sb.AppendLine("")

    $null = $sb.AppendLine("  SYSTEM AUDIT - HARDENING CHECKS")
    $null = $sb.AppendLine("  $sep2")
    foreach ($chk in $script:AuditChecks) {
        $st = if ($script:AuditResults.ContainsKey($chk.Id)) { $script:AuditResults[$chk.Id] } else { "PENDING" }
        $null = $sb.AppendLine("  [$($chk.Sev)] $($chk.Name): $st")
    }
    $audF = $script:Findings | Where-Object { $_.Source -eq "SystemAudit" }
    if ($audF.Count -gt 0) {
        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("  Audit Vulnerabilities:")
        foreach ($f in $audF) { $null = $sb.AppendLine("    [$($f.Sev)] $($f.Name) - $($f.Detail)") }
    }
    $null = $sb.AppendLine("")

    $null = $sb.AppendLine("  RECOMMENDATIONS (Top Priority Actions)")
    $null = $sb.AppendLine("  $sep2")
    $sevOrd = @("Critical","High","Medium","Low")
    $top5 = $script:Findings | Sort-Object { $sevOrd.IndexOf($_.Sev) } | Select-Object -First 5
    if ($top5.Count -eq 0) { $null = $sb.AppendLine("  No critical recommendations at this time.") }
    else {
        $i = 1
        foreach ($f in $top5) {
            $null = $sb.AppendLine("  $i. [$($f.Sev)] $($f.Cat) - $($f.Name): $($f.Detail)")
            $i++
        }
    }
    $null = $sb.AppendLine("")

    $null = $sb.AppendLine("  FULL FINDINGS LIST")
    $null = $sb.AppendLine("  $sep2")
    if ($script:Findings.Count -eq 0) { $null = $sb.AppendLine("  No findings recorded.") }
    else {
        foreach ($f in ($script:Findings | Sort-Object { $sevOrd.IndexOf($_.Sev) })) {
            $null = $sb.AppendLine("  [$($f.Sev)] [$($f.Cat)] $($f.Name) - $($f.Detail)")
        }
    }
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine($sep1)
    $null = $sb.AppendLine("  END OF REPORT - SecurePC Pro v2.0")
    $null = $sb.AppendLine($sep1)

    $script:ReportText      = $sb.ToString()
    $script:rtbReport.Text  = $script:ReportText
}

# ============================================================
# UPDATE DASHBOARD
# ============================================================
function Update-Dashboard {
    $c = ($script:Findings | Where-Object { $_.Sev -eq "Critical" }).Count
    $h = ($script:Findings | Where-Object { $_.Sev -eq "High"     }).Count
    $m = ($script:Findings | Where-Object { $_.Sev -eq "Medium"   }).Count
    $l = ($script:Findings | Where-Object { $_.Sev -eq "Low"      }).Count
    $t = $script:Findings.Count
    $s = Get-SecurityScore

    $script:StatBoxes["Total"].Text = "$t"
    $script:StatBoxes["Crit"].Text  = "$c"
    $script:StatBoxes["High"].Text  = "$h"
    $script:StatBoxes["Med"].Text   = "$m"
    $script:StatBoxes["Low"].Text   = "$l"
    $script:StatBoxes["Score"].Text = "$s"

    $script:lvDash.Items.Clear()
    $sevOrd = @("Critical","High","Medium","Low")
    foreach ($f in ($script:Findings | Sort-Object { $sevOrd.IndexOf($_.Sev) })) {
        $item = New-Object System.Windows.Forms.ListViewItem($f.Sev)
        $item.ForeColor = Get-SevColor $f.Sev
        $null = $item.SubItems.Add($f.Cat)
        $null = $item.SubItems.Add($f.Name)
        $null = $item.SubItems.Add($f.Detail)
        $null = $item.SubItems.Add("FOUND")
        $script:lvDash.Items.Add($item) | Out-Null
    }
    [System.Windows.Forms.Application]::DoEvents()
}

# ============================================================
# FULL SCAN ORCHESTRATOR
# ============================================================
function Start-FullScan {
    if ($script:ScanRunning) { return }
    $script:ScanRunning = $true
    $script:StopScan    = $false
    $script:Findings    = @()
    $btnScan.Enabled    = $false
    $btnStop.Enabled    = $true
    $progressBar.Value  = 0
    $script:lvMal.Items.Clear()

    foreach ($chk in $script:AuditChecks) {
        $script:AuditRows[$chk.Id].StatusLbl.Text      = "SCANNING"
        $script:AuditRows[$chk.Id].StatusLbl.ForeColor = $cAccent
        $script:AuditRows[$chk.Id].FixBtn.Enabled      = $false
    }
    Switch-Tab 0
    $startTime = Get-Date

    Set-StatusMsg "Network scan..."
    $progressBar.Value = 5
    Invoke-NetworkScan
    $progressBar.Value = 20

    if (-not $script:StopScan) {
        Set-StatusMsg "Process scan..."
        $progressBar.Value = 25
        Invoke-ProcessScan
        $progressBar.Value = 40
    }

    if (-not $script:StopScan) {
        Set-StatusMsg "Startup scan..."
        $progressBar.Value = 45
        Invoke-StartupScan
        $progressBar.Value = 55
    }

    if (-not $script:StopScan) {
        Set-StatusMsg "Scheduled task scan..."
        $progressBar.Value = 58
        Invoke-TaskScan
        $progressBar.Value = 68
    }

    if (-not $script:StopScan) {
        Set-StatusMsg "Hosts file scan..."
        $progressBar.Value = 70
        Invoke-HostsScan
        $progressBar.Value = 75
    }

    if (-not $script:StopScan) {
        Set-StatusMsg "Security event log scan..."
        $progressBar.Value = 70
        Invoke-EventLogScan
        $progressBar.Value = 78
    }

    if (-not $script:StopScan) {
        Set-StatusMsg "Services scan..."
        $progressBar.Value = 80
        Invoke-ServiceScan
        $progressBar.Value = 85
    }

    if (-not $script:StopScan) {
        Set-StatusMsg "Password policy scan..."
        $progressBar.Value = 87
        Invoke-PasswordPolicyScan
        $progressBar.Value = 90
    }

    if (-not $script:StopScan) {
        Set-StatusMsg "System audit..."
        $progressBar.Value = 91
        Invoke-AuditScan
        $progressBar.Value = 98
    }

    Update-Dashboard
    Build-Report

    $progressBar.Value  = 100
    $elapsed            = (Get-Date) - $startTime
    $ts                 = $elapsed.ToString("hh\:mm\:ss")
    $n                  = $script:Findings.Count
    Set-StatusMsg "Scan complete. $n total findings. $ts"
    $btnScan.Enabled    = $true
    $btnStop.Enabled    = $false
    $script:ScanRunning = $false
}

# ============================================================
# BUTTON EVENT HANDLERS
# ============================================================
$btnScan.Add_Click({ Start-FullScan })

$btnStop.Add_Click({
    $script:StopScan = $true
    Set-StatusMsg "Stopping scan..."
})

$btnExport.Add_Click({
    if ($script:ReportText -eq "") {
        [System.Windows.Forms.MessageBox]::Show("No report available. Run a Full Scan first.", "No Report", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    Switch-Tab 4
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter   = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
    $sfd.FileName = "SecurePC-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        [System.IO.File]::WriteAllText($sfd.FileName, $script:ReportText, [System.Text.Encoding]::UTF8)
        [System.Windows.Forms.MessageBox]::Show("Report saved to:`n$($sfd.FileName)", "Saved", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

$form.Add_KeyDown({
    param($s, $e)
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::F5) { Start-FullScan }
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
        if ($script:ScanRunning) {
            $script:StopScan = $true
            Set-StatusMsg "Stopping scan..."
        }
    }
})

$btnBlockIP.Add_Click({
    $sel = $script:lvNet.SelectedItems
    if ($sel.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select a connection to block.", "No Selection", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    $remIP = $sel[0].SubItems[2].Text
    if ($remIP -eq "" -or $remIP -eq "0.0.0.0" -or $remIP -eq "::" -or $remIP -eq "::1") {
        [System.Windows.Forms.MessageBox]::Show("No valid remote IP to block.", "Invalid IP", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    $r = [System.Windows.Forms.MessageBox]::Show("Block IP: $remIP`nAdds Windows Firewall outbound block rule.", "Confirm Block", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
        try {
            New-NetFirewallRule -DisplayName "SecurePC-Block-$remIP" -Direction Outbound -Action Block -RemoteAddress $remIP -ErrorAction Stop | Out-Null
            [System.Windows.Forms.MessageBox]::Show("Firewall rule created to block $remIP.", "Blocked", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$btnKillProc.Add_Click({
    $sel = $script:lvMal.SelectedItems
    if ($sel.Count -eq 0) { return }
    $tag = $sel[0].Tag
    if (-not $tag -or $tag.Type -ne "Process") {
        [System.Windows.Forms.MessageBox]::Show("Select a Process row first.", "Not a Process", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    $pid_  = $tag.PID
    $pname = $sel[0].SubItems[2].Text
    $r = [System.Windows.Forms.MessageBox]::Show("Kill process: $pname (PID $pid_)?`nThis cannot be undone.", "Confirm Kill", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
        try {
            Stop-Process -Id $pid_ -Force -ErrorAction Stop
            [System.Windows.Forms.MessageBox]::Show("Process $pname (PID $pid_) terminated.", "Killed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$btnRemoveStart.Add_Click({
    $sel = $script:lvMal.SelectedItems
    if ($sel.Count -eq 0) { return }
    $tag = $sel[0].Tag
    if (-not $tag -or $tag.Type -ne "Startup") {
        [System.Windows.Forms.MessageBox]::Show("Select a Startup row first.", "Not a Startup Entry", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    $r = [System.Windows.Forms.MessageBox]::Show("Remove startup entry: $($tag.ValName)?", "Confirm Remove", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
        try {
            Remove-ItemProperty -Path $tag.RegPath -Name $tag.ValName -ErrorAction Stop
            [System.Windows.Forms.MessageBox]::Show("Startup entry removed.", "Removed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$btnDisableTask.Add_Click({
    $sel = $script:lvMal.SelectedItems
    if ($sel.Count -eq 0) { return }
    $tag = $sel[0].Tag
    if (-not $tag -or $tag.Type -ne "Task") {
        [System.Windows.Forms.MessageBox]::Show("Select a Task row first.", "Not a Task", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    $r = [System.Windows.Forms.MessageBox]::Show("Disable task: $($tag.TaskName)?", "Confirm Disable", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
        try {
            Disable-ScheduledTask -TaskName $tag.TaskName -TaskPath $tag.TaskPath -ErrorAction Stop | Out-Null
            [System.Windows.Forms.MessageBox]::Show("Task disabled.", "Disabled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$btnDeleteTask.Add_Click({
    $sel = $script:lvMal.SelectedItems
    if ($sel.Count -eq 0) { return }
    $tag = $sel[0].Tag
    if (-not $tag -or $tag.Type -ne "Task") {
        [System.Windows.Forms.MessageBox]::Show("Select a Task row first.", "Not a Task", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    $r = [System.Windows.Forms.MessageBox]::Show("PERMANENTLY DELETE task: $($tag.TaskName)?`nThis cannot be undone.", "Confirm Delete", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
        try {
            Unregister-ScheduledTask -TaskName $tag.TaskName -TaskPath $tag.TaskPath -Confirm:$false -ErrorAction Stop
            [System.Windows.Forms.MessageBox]::Show("Task deleted.", "Deleted", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$btnViewHosts.Add_Click({
    Start-Process "notepad.exe" "C:\Windows\System32\drivers\etc\hosts"
})

$btnRptTxt.Add_Click({
    if ($script:ReportText -eq "") {
        [System.Windows.Forms.MessageBox]::Show("Run a Full Scan first.", "No Report", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter   = "Text Files (*.txt)|*.txt"
    $sfd.FileName = "SecurePC-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        [System.IO.File]::WriteAllText($sfd.FileName, $script:ReportText, [System.Text.Encoding]::UTF8)
        [System.Windows.Forms.MessageBox]::Show("Saved to $($sfd.FileName)", "Saved", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

$btnRptHtml.Add_Click({
    if ($script:ReportText -eq "") {
        [System.Windows.Forms.MessageBox]::Show("Run a Full Scan first.", "No Report", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter   = "HTML Files (*.html)|*.html"
    $sfd.FileName = "SecurePC-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $escaped = [System.Web.HttpUtility]::HtmlEncode($script:ReportText)
        $html = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>SecurePC Pro v2.0 Report</title>" +
                "<style>body{background:#0d0d14;color:#ebebf5;font-family:Consolas,monospace;font-size:13px;padding:20px;}" +
                "pre{white-space:pre-wrap;word-wrap:break-word;}</style></head><body><pre>" +
                $escaped + "</pre></body></html>"
        [System.IO.File]::WriteAllText($sfd.FileName, $html, [System.Text.Encoding]::UTF8)
        [System.Windows.Forms.MessageBox]::Show("HTML saved to $($sfd.FileName)", "Saved", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

$btnRptClip.Add_Click({
    if ($script:ReportText -eq "") {
        [System.Windows.Forms.MessageBox]::Show("Run a Full Scan first.", "No Report", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    [System.Windows.Forms.Clipboard]::SetText($script:ReportText)
    [System.Windows.Forms.MessageBox]::Show("Report copied to clipboard.", "Copied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

$btnRptRebuild.Add_Click({ Build-Report })

# ============================================================
# FIX BUTTON HANDLERS (per audit check)
# ============================================================
foreach ($chkDef in $script:AuditChecks) {
    $script:AuditRows[$chkDef.Id].FixBtn.Add_Click({
        param($s, $e)
        $id = [int]$s.Tag
        $chk = $script:AuditChecks | Where-Object { $_.Id -eq $id }
        $r = [System.Windows.Forms.MessageBox]::Show(
            "Apply fix for: $($chk.Name)?`nThis will modify system settings.",
            "Confirm Fix",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($r -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        try {
            switch ($id) {
                1 {
                    Set-NetFirewallProfile -All -Enabled True
                    [System.Windows.Forms.MessageBox]::Show("All firewall profiles enabled.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                2 {
                    Set-MpPreference -DisableRealtimeMonitoring $false
                    [System.Windows.Forms.MessageBox]::Show("Defender Real-Time Protection enabled.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                3 {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
                    [System.Windows.Forms.MessageBox]::Show("SMBv1 disabled.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                4 {
                    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1
                    [System.Windows.Forms.MessageBox]::Show("UAC enabled. A restart is required.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                5 {
                    if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest")) {
                        New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Force | Out-Null
                    }
                    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 0
                    [System.Windows.Forms.MessageBox]::Show("WDigest credential caching disabled.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                6 {
                    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
                        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
                    }
                    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0
                    [System.Windows.Forms.MessageBox]::Show("LLMNR disabled via group policy.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                7 {
                    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 1
                    [System.Windows.Forms.MessageBox]::Show("RDP disabled.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                8 {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Secure Boot must be enabled in BIOS/UEFI firmware.`nRestart your PC and enter UEFI setup to enable Secure Boot.",
                        "Manual Action Required",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                9 {
                    [System.Windows.Forms.MessageBox]::Show(
                        "To enable BitLocker:`n  1. Open Control Panel > System and Security > BitLocker Drive Encryption`n  2. Click 'Turn on BitLocker' for the system drive`nOr run: Enable-BitLocker -MountPoint C: in an elevated PowerShell.",
                        "BitLocker Setup",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                10 {
                    Disable-LocalUser -Name "Guest" -ErrorAction Stop
                    [System.Windows.Forms.MessageBox]::Show("Guest account disabled.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                11 {
                    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
                        New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
                    }
                    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -Value 255
                    [System.Windows.Forms.MessageBox]::Show("AutoRun disabled for all drive types.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                12 {
                    Stop-Service RemoteRegistry -Force -ErrorAction SilentlyContinue
                    Set-Service RemoteRegistry -StartupType Disabled -ErrorAction Stop
                    [System.Windows.Forms.MessageBox]::Show("Remote Registry stopped and disabled.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                13 {
                    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings")) {
                        New-Item "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Force | Out-Null
                    }
                    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -Value 0
                    [System.Windows.Forms.MessageBox]::Show("Windows Script Host disabled.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                14 {
                    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")) {
                        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
                    }
                    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
                    [System.Windows.Forms.MessageBox]::Show("PowerShell Script Block Logging enabled.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                15 {
                    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
                    [System.Windows.Forms.MessageBox]::Show("Logon event auditing enabled.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                16 {
                    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
                    [System.Windows.Forms.MessageBox]::Show("Account management auditing enabled.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                17 {
                    Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name ScreenSaverIsSecure -Value "1"
                    Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name ScreenSaveActive    -Value "1"
                    Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name ScreenSaveTimeOut   -Value "300"
                    [System.Windows.Forms.MessageBox]::Show("Screen saver with password enabled (5 min timeout).", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
                18 {
                    Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart | Out-Null
                    [System.Windows.Forms.MessageBox]::Show("Telnet client disabled.", "Fix Applied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                }
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error applying fix: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    })
}

# ============================================================
# FORM LAYOUT - Add controls in correct dock order
# ============================================================
$form.SuspendLayout()
$form.Controls.Add($contentArea)
$form.Controls.Add($bottomBar)
$form.Controls.Add($tabStrip)
$form.Controls.Add($header)
$form.ResumeLayout($false)

# ============================================================
# LAUNCH
# ============================================================
[System.Windows.Forms.Application]::Run($form)
