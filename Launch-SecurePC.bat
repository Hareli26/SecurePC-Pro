@echo off
:: SecurePC Launcher — runs the hardening tool (auto-elevates to Admin)
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SecurePC.ps1"
