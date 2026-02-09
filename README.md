
# 🔒 Secure-Setup: Windows Security Hardening Script

Automated PowerShell script for hardening Windows systems with comprehensive error handling and audit logging. Built on CIS benchmarks, NIST guidelines, and Microsoft security baselines.

## 🎯 Features

**Core Security Controls**
- **User Account Control (UAC)** - Maximum UAC enforcement for administrative actions
- **Windows Defender** - Real-time protection, cloud-delivered protection, and automatic sample submission
- **Firewall Management** - Enabled across all profiles with default-deny inbound rules
- **Service Hardening** - Disables unnecessary services (RemoteRegistry, RemoteAccess, Telephony)
- **SMBv1 Protocol** - Disabled to prevent legacy protocol exploits
- **PowerShell Security** - RemoteSigned execution policy enforcement

**Operational Features**
- **Comprehensive Logging** - Timestamped audit trail of all operations
- **Error Handling** - Graceful failure recovery with detailed error reporting
- **Success/Failure Tracking** - Real-time counters for operation outcomes
- **Structured Output** - Color-coded console output and persistent log files
- **Non-Destructive** - Checks service existence before attempting modifications

## 📊 Logging & Audit Trail

All operations are logged to:
```
C:\ProgramData\SecureSetup\Logs\SecureSetup_YYYYMMDD_HHMMSS.log
```

Log entries include:
- Timestamp for each operation
- Log level (INFO, SUCCESS, WARNING, ERROR)
- Detailed error messages with stack traces
- System context (hostname, user, PowerShell version)
- Summary statistics (success/failure counts)

**Sample Log Output:**
```
[2025-02-05 14:23:45] [INFO] Starting firewall configuration...
[2025-02-05 14:23:45] [SUCCESS] Windows Firewall enabled successfully
[2025-02-05 14:23:46] [WARNING] Service 'Telephony' not found on this system (skipping)
[2025-02-05 14:23:47] [ERROR] SMBv1 disabling failed: Access denied
```

## ⚙️ Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- Administrator privileges
- Disk space for log files (~1MB per execution)

## 📦 Installation
```powershell
# Clone the repository
git clone https://github.com/yourusername/secure-setup.git
cd secure-setup

# Review the script
Get-Content .\Secure-Setup.ps1

# Set execution policy (one-time setup)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Run PowerShell as Administrator

```

## 🛡️ Security Controls Overview

| Control | Purpose | Impact |
|---------|---------|--------|
| Firewall (All Profiles) | Network-level threat blocking with default-deny | Critical |
| Windows Defender | Real-time malware protection with cloud intelligence | Critical |
| UAC Maximum | Prevents unauthorized privilege escalation | High |
| Service Hardening | Disables RemoteRegistry, RemoteAccess, Telephony | High |
| SMBv1 Disabled | Prevents WannaCry-style legacy exploits | High |
| Error Handling | Ensures script resilience and auditability | Medium |

## 🔍 Verification

**Check script execution results:**
```powershell
# View the most recent log file
Get-Content "C:\ProgramData\SecureSetup\Logs\SecureSetup_*.log" | Select-Object -Last 50

# Check firewall status
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction

# Verify Windows Defender
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IoavProtectionEnabled

# Check service status
Get-Service RemoteRegistry, RemoteAccess, Telephony | Select-Object Name, Status, StartType

# Verify SMBv1 status
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Check UAC level
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"
```

## 📋 Troubleshooting

**Script won't run - Execution Policy error:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**"Access Denied" errors:**
- Ensure PowerShell is running as Administrator
- Check if Group Policy is overriding local settings
- Review log file for specific permission issues

**Services not found warnings:**
- This is normal - not all services exist on every Windows version
- Check log file to see which services were skipped

**View all log files:**
```powershell
Get-ChildItem "C:\ProgramData\SecureSetup\Logs" | Sort-Object LastWriteTime -Descending
```

**Compatibility:**
- ✅ Windows 10/11 Pro/Enterprise
- ✅ Windows Server 2016/2019/2022
- ⚠️ Windows Home (Limited features, some services may not exist)

**⚠️ Security Notice:** This script modifies system security settings. Always test in non-production environments first. The authors assume no liability for system changes or operational impacts.
