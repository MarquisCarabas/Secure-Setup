# 🔒 Secure-Setup: Windows Security Hardening Script

Automated PowerShell script for hardening Windows systems based on CIS benchmarks, NIST guidelines, and Microsoft security baselines.

## 🎯 Features

**Core Security Controls**
- **User Account Control (UAC)** - Maximum UAC enforcement for administrative actions
- **Windows Defender** - Real-time protection, cloud-delivered protection, and automatic sample submission
- **Firewall Management** - Enabled across all profiles (Domain, Private, Public)
- **Windows Update** - Automated security patch deployment
- **RDP Hardening** - Disables Remote Desktop Protocol to reduce attack surface
- **PowerShell Security** - RemoteSigned execution policy enforcement
- **Account Security** - Disables Guest and built-in Administrator accounts
- **Network Hardening** - Disables LLMNR and NetBIOS over TCP/IP (prevents name resolution poisoning)

**Advanced Hardening**
- **BitLocker Encryption** - Drive encryption status verification
- **Credential Guard** - Virtualization-based security for credential protection
- **Secure Boot** - UEFI Secure Boot validation
- **SMBv1 Disabled** - Prevents legacy protocol exploits
- **AutoRun/AutoPlay** - Disabled to prevent automatic media execution
- **Anonymous SID Enumeration** - Blocked for enhanced security

**Administrative Controls**
- **Password Policy** - 14-character minimum password length
- **Account Lockout Policy** - Configurable lockout threshold and duration
- **Audit Logging** - Comprehensive security event logging enabled

## ⚙️ Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- Administrator privileges

## 📦 Installation

```powershell
# Clone the repository
git clone https://github.com/yourusername/secure-setup.git
cd secure-setup

# Review the script
Get-Content .\Secure-Setup.ps1

# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Run the script as Administrator
.\Secure-Setup.ps1
```

## 🛡️ Security Controls Overview

| Control | Purpose | Impact |
|---------|---------|--------|
| UAC Maximum | Prevents unauthorized privilege escalation | High |
| Windows Defender | Real-time malware protection | Critical |
| Firewall Enabled | Network-level threat blocking | Critical |
| RDP Disabled | Reduces remote attack surface | Medium |
| SMBv1 Disabled | Prevents legacy protocol exploits | High |
| LLMNR Disabled | Prevents name resolution attacks | Medium |
| Guest Account Disabled | Eliminates unauthorized access | High |
| Password Policy | Enforces strong authentication | High |
| Audit Logging | Enables security monitoring | Medium |

## 🔍 Verification

```powershell
# Check UAC level
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"

# Check Windows Defender status
Get-MpComputerStatus

# Check Firewall status
Get-NetFirewallProfile | Select-Object Name, Enabled
```

## ⚠️ Important Notes

**Test before production deployment:**
- Create a system restore point
- Test in VM or non-production environment
- Document current settings
- Review Event Viewer after execution

**Compatibility:**
- ✅ Windows 10/11 Pro/Enterprise
- ✅ Windows Server 2016+
- ⚠️ Windows Home (Limited features)

**Known Limitations:**
- BitLocker requires TPM 1.2+
- Credential Guard requires UEFI and virtualization support
- Domain systems may have Group Policy conflicts
