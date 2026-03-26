# ClaudeCode Projects

## SecurePC Pro v2.0 — Security Management Console

A full-featured security management console with 5 navigation panels (Dashboard, Network, Malware Hunt, System Audit, Report), 6 scan engines, threat intelligence matching, and automated remediation.

### Files

| File | Purpose |
|------|---------|
| `SecurePC-Pro.ps1` | SecurePC Pro v2.0 - full security management console (72 KB, 1,523 lines) |
| `Launch-SecurePC-Pro.bat` | One-click launcher for SecurePC Pro v2.0 |
| `SecurePC.ps1` | SecurePC v1.0 — original 18-check hardening tool (46 KB) |
| `Launch-SecurePC.bat` | One-click launcher for SecurePC v1.0 |

### How to Run SecurePC Pro

From an elevated PowerShell terminal:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\SecurePC-Pro.ps1
```
Or right-click > Run with PowerShell (it will auto-elevate to Administrator).

### SecurePC Pro Features

- **5-panel navigation**: Dashboard, Network, Malware Hunt, System Audit, Report
- **6 scan engines**: Network connections, Processes, Startup persistence, Scheduled tasks, Hosts file, Windows Defender
- **Threat intelligence**: Matches against known malware names, suspicious ports, suspicious paths, system process masquerading
- **System Audit**: Same 18 hardening checks as v1.0 with FIX buttons
- **Report builder**: Generates full assessment with executive summary, severity counts, security score, and recommendations
- **Dark cybersecurity theme**: Full dark UI with color-coded severity (Critical/High/Medium/Low)
- **Action buttons**: Kill processes, block IPs via firewall, remove startup entries, disable/delete scheduled tasks
- **Keyboard shortcuts**: `F5` = Full Scan, `Esc` = Stop
- **Export**: TXT and HTML report export

---

## SecurePC v1.0 — Windows Security Hardening Tool

A self-elevating PowerShell GUI application that audits Windows security posture and applies targeted remediations **one at a time, with your approval**.

### Files

| File | Purpose |
|------|---------|
| `SecurePC.ps1` | Main PowerShell script |
| `Launch-SecurePC.bat` | One-click launcher (double-click to run) |

### How to Run

Double-click **`Launch-SecurePC.bat`** — it will prompt for Administrator elevation automatically.

Or from an elevated PowerShell terminal:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\SecurePC.ps1
```

### Features

- **18 security checks** across 7 categories (see below)
- Dark-themed GUI with colour-coded severity badges
- Live scan with per-row status updates
- **Individual FIX buttons** — each fix requires explicit confirmation before any change is made
- **Fix All Vulnerable** — batch remediation with a single confirmation dialog
- **Save Report** — exports plain-text assessment results
- Keyboard shortcuts: `F5` = Scan, `Esc` = Cancel

### Security Checks

| # | Check | Severity | Category |
|---|-------|----------|----------|
| 1 | Windows Firewall (all profiles) | Critical | Network |
| 2 | Windows Defender Real-Time Protection | Critical | Anti-Malware |
| 3 | SMBv1 Protocol (EternalBlue/WannaCry) | Critical | Network |
| 4 | User Account Control (UAC) | High | Privilege Control |
| 5 | WDigest Plaintext Credential Caching | High | Credentials |
| 6 | LLMNR Name Poisoning Attack Surface | High | Network |
| 7 | Remote Desktop Protocol (RDP) | High | Remote Access |
| 8 | Secure Boot (UEFI) | High | Firmware |
| 9 | BitLocker Drive Encryption | High | Data Protection |
| 10 | Built-in Guest Account | Medium | Access Control |
| 11 | AutoRun / AutoPlay | Medium | Removable Media |
| 12 | Remote Registry Service | Medium | Attack Surface |
| 13 | Windows Script Host (WSH) | Medium | Attack Surface |
| 14 | PowerShell Script Block Logging | Medium | Audit & Logging |
| 15 | Audit Policy — Logon Events | Medium | Audit & Logging |
| 16 | Audit Policy — Account Management | Medium | Audit & Logging |
| 17 | Screen Saver Password on Resume | Low | Physical Security |
| 18 | Telnet Client | Low | Attack Surface |

### Requirements

- Windows 10 / Windows 11
- PowerShell 5.1 or later (built-in)
- Administrator privileges (auto-requested at launch)
