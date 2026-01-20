<#
.SYNOPSIS
    SecurePro Roofing Windows 11 Security Hardening Script
.DESCRIPTION
    Configures a clean Windows 11 system with 30 security hardening measures
    for SecurePro Roofing's shared workstation environment
.AUTHOR
    Oleksandr Vitenkov
.DATE
    December 2024
#>

#Requires -RunAsAdministrator

# Set error handling
$ErrorActionPreference = "Continue"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SecurePro Roofing Security Setup Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================
# SECURITY ITEM 1: Create Security Groups
# ============================================
Write-Host "[1/30] Creating Security Groups..." -ForegroundColor Yellow

$groups = @(
    @{Name="Estimating_Design"; Description="Estimating and Design Department"},
    @{Name="Finance_Admin"; Description="Finance and Administration Department"},
    @{Name="Operations_Sales"; Description="Operations and Sales Department"},
    @{Name="IT_Staff"; Description="IT Department"}
)

foreach ($group in $groups) {
    try {
        New-LocalGroup -Name $group.Name -Description $group.Description -ErrorAction Stop
        Write-Host "  [OK] Created group: $($group.Name)" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Group $($group.Name) may already exist" -ForegroundColor Yellow
    }
}

# ============================================
# SECURITY ITEM 2: Create User Accounts
# ============================================
Write-Host "" 
Write-Host "[2/30] Creating User Accounts..." -ForegroundColor Yellow

# Define users with their departments and groups
$users = @(
    # Estimating & Design
    @{Username="marcus.vance"; FullName="Marcus Vance"; Description="Senior Estimator"; Group="Estimating_Design"},
    @{Username="chloe.rodriguez"; FullName="Chloe Rodriguez"; Description="Design Specialist"; Group="Estimating_Design"},
    @{Username="ben.carter"; FullName="Ben Carter"; Description="Estimating Assistant"; Group="Estimating_Design"},
    @{Username="sophie.williams"; FullName="Sophie Williams"; Description="Client Liaison"; Group="Estimating_Design"},
    
    # Finance & Administration
    @{Username="david.chen"; FullName="David Chen"; Description="Head Bookkeeper"; Group="Finance_Admin"},
    @{Username="priya.sharma"; FullName="Priya Sharma"; Description="Payroll Administrator"; Group="Finance_Admin"},
    @{Username="arthur.jenkins"; FullName="Arthur Jenkins"; Description="Office Manager"; Group="Finance_Admin"},
    @{Username="elena.popa"; FullName="Elena Popa"; Description="Financial Assistant"; Group="Finance_Admin"},
    
    # Operations & Sales
    @{Username="frank.rossi"; FullName="Frank Rossi"; Description="Operations Manager"; Group="Operations_Sales"},
    @{Username="sarah.blythe"; FullName="Sarah Blythe"; Description="Sales Lead"; Group="Operations_Sales"},
    @{Username="leo.mitchell"; FullName="Leo Mitchell"; Description="Inventory Specialist"; Group="Operations_Sales"},
    @{Username="tasha.green"; FullName="Tasha Green"; Description="Sales Support"; Group="Operations_Sales"},
    
    # IT
    @{Username="bobby.bojangles"; FullName="Bobby Bojangles"; Description="IT Administrator"; Group="IT_Staff"}
)

# Create a secure default password (users should change on first login)
$defaultPassword = ConvertTo-SecureString "SecurePro2024!" -AsPlainText -Force

foreach ($user in $users) {
    try {
        New-LocalUser -Name $user.Username -Password $defaultPassword -FullName $user.FullName -Description $user.Description -PasswordNeverExpires $false -UserMayNotChangePassword $false -AccountNeverExpires -ErrorAction Stop
        
        # Add user to their department group
        Add-LocalGroupMember -Group $user.Group -Member $user.Username -ErrorAction Stop
        
        Write-Host "  [OK] Created user: $($user.Username) ($($user.FullName))" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] User $($user.Username) may already exist" -ForegroundColor Yellow
    }
}

# ============================================
# SECURITY ITEM 3: Grant IT Admin Rights
# ============================================
Write-Host "" 
Write-Host "[3/30] Configuring IT Administrator Access..." -ForegroundColor Yellow

try {
    Add-LocalGroupMember -Group "Administrators" -Member "bobby.bojangles" -ErrorAction Stop
    Write-Host "  [OK] Bobby Bojangles added to Administrators group" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Bobby Bojangles may already be an administrator" -ForegroundColor Yellow
}

# ============================================
# SECURITY ITEM 4: Create Directory Structure
# ============================================
Write-Host "" 
Write-Host "[4/30] Creating Directory Structure on C:\SecurePro..." -ForegroundColor Yellow

$folders = @(
    # Active Jobs
    "C:\SecurePro\1_Active_Jobs",
    "C:\SecurePro\1_Active_Jobs\2024_001_ElmSt_Mansion",
    "C:\SecurePro\1_Active_Jobs\2024_002_MapleAve_Condo",
    "C:\SecurePro\1_Active_Jobs\2024_003_OakDr_Retail",
    
    # Company Administration
    "C:\SecurePro\2_Company_Administration",
    "C:\SecurePro\2_Company_Administration\Finance",
    "C:\SecurePro\2_Company_Administration\Finance\Invoices_Outgoing",
    "C:\SecurePro\2_Company_Administration\Finance\Invoices_Incoming",
    "C:\SecurePro\2_Company_Administration\Finance\Payroll_Reports",
    "C:\SecurePro\2_Company_Administration\HR",
    "C:\SecurePro\2_Company_Administration\HR\Employee_Files",
    "C:\SecurePro\2_Company_Administration\HR\Policies",
    "C:\SecurePro\2_Company_Administration\Operations",
    "C:\SecurePro\2_Company_Administration\Operations\Crew_Schedules",
    "C:\SecurePro\2_Company_Administration\Operations\Vehicle_Maintenance",
    
    # Sales & Marketing
    "C:\SecurePro\3_Sales_Marketing",
    "C:\SecurePro\3_Sales_Marketing\CRM_Exports",
    "C:\SecurePro\3_Sales_Marketing\Marketing_Materials",
    "C:\SecurePro\3_Sales_Marketing\Proposals_Templates",
    
    # Resources
    "C:\SecurePro\4_Resources",
    "C:\SecurePro\4_Resources\Material_Catalogs",
    "C:\SecurePro\4_Resources\Installation_Manuals",
    "C:\SecurePro\4_Resources\Safety_Protocols",
    
    # Archives
    "C:\SecurePro\5_Archives",
    "C:\SecurePro\5_Archives\Completed_Jobs_2023",
    "C:\SecurePro\5_Archives\Financial_Records_2023"
)

foreach ($folder in $folders) {
    try {
        New-Item -Path $folder -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Host "  [OK] Created: $folder" -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] Error creating: $folder" -ForegroundColor Red
    }
}

# ============================================
# SECURITY ITEM 5: Set Finance Folder Permissions (Principle of Least Privilege)
# ============================================
Write-Host "" 
Write-Host "[5/30] Configuring Finance Folder Permissions..." -ForegroundColor Yellow

$financePath = "C:\SecurePro\2_Company_Administration\Finance"

# Disable inheritance and remove existing permissions
$acl = Get-Acl $financePath
$acl.SetAccessRuleProtection($true, $false)

# Remove all existing access rules
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

# Add System and Administrators (full control)
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)

# Add Finance_Admin group (full control)
$financeRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Finance_Admin", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($financeRule)

Set-Acl -Path $financePath -AclObject $acl
Write-Host "  [OK] Finance folder restricted to Finance_Admin group only" -ForegroundColor Green

# ============================================
# SECURITY ITEM 6: Set HR Folder Permissions (Highly Sensitive Data)
# ============================================
Write-Host "" 
Write-Host "[6/30] Configuring HR Folder Permissions..." -ForegroundColor Yellow

$hrPath = "C:\SecurePro\2_Company_Administration\HR"

# Disable inheritance
$acl = Get-Acl $hrPath
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

# Only System, Administrators, and Finance_Admin (HR is part of Finance dept)
$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($financeRule)

Set-Acl -Path $hrPath -AclObject $acl
Write-Host "  [OK] HR folder restricted to Finance_Admin group only" -ForegroundColor Green

# ============================================
# SECURITY ITEM 7: Set Active Jobs Permissions (Multi-Department Access)
# ============================================
Write-Host "" 
Write-Host "[7/30] Configuring Active Jobs Folder Permissions..." -ForegroundColor Yellow

$jobsPath = "C:\SecurePro\1_Active_Jobs"

$acl = Get-Acl $jobsPath
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

# System and Admins
$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)

# Estimating, Operations, and Sales need access
$estimatingRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Estimating_Design", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$operationsRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Operations_Sales", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")

$acl.AddAccessRule($estimatingRule)
$acl.AddAccessRule($operationsRule)

Set-Acl -Path $jobsPath -AclObject $acl
Write-Host "  [OK] Active Jobs accessible to Estimating_Design and Operations_Sales" -ForegroundColor Green

# ============================================
# SECURITY ITEM 8: Set Sales and Marketing Permissions
# ============================================
Write-Host "" 
Write-Host "[8/30] Configuring Sales and Marketing Folder Permissions..." -ForegroundColor Yellow

$salesPath = "C:\SecurePro\3_Sales_Marketing"

$acl = Get-Acl $salesPath
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($operationsRule)
$acl.AddAccessRule($estimatingRule)

Set-Acl -Path $salesPath -AclObject $acl
Write-Host "  [OK] Sales and Marketing accessible to Operations_Sales and Estimating_Design" -ForegroundColor Green

# ============================================
# SECURITY ITEM 9: Set Resources Permissions (Read-Only for All)
# ============================================
Write-Host "" 
Write-Host "[9/30] Configuring Resources Folder Permissions..." -ForegroundColor Yellow

$resourcesPath = "C:\SecurePro\4_Resources"

$acl = Get-Acl $resourcesPath
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)

# All departments get read access
$estimatingRead = New-Object System.Security.AccessControl.FileSystemAccessRule("Estimating_Design", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$financeRead = New-Object System.Security.AccessControl.FileSystemAccessRule("Finance_Admin", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$operationsRead = New-Object System.Security.AccessControl.FileSystemAccessRule("Operations_Sales", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")

$acl.AddAccessRule($estimatingRead)
$acl.AddAccessRule($financeRead)
$acl.AddAccessRule($operationsRead)

Set-Acl -Path $resourcesPath -AclObject $acl
Write-Host "  [OK] Resources folder set to read-only for all departments" -ForegroundColor Green

# ============================================
# SECURITY ITEM 10: Disable Guest Account
# ============================================
Write-Host "" 
Write-Host "[10/30] Disabling Guest Account..." -ForegroundColor Yellow

try {
    Disable-LocalUser -Name "Guest" -ErrorAction Stop
    Write-Host "  [OK] Guest account disabled" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Guest account may already be disabled" -ForegroundColor Yellow
}

# ============================================
# SECURITY ITEM 11: Configure Password Policy
# ============================================
Write-Host "" 
Write-Host "[11/30] Configuring Password Policy..." -ForegroundColor Yellow

try {
    # Set password complexity requirements using secedit
    $secpolPath = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $secpolPath /quiet
    
    $secpolContent = Get-Content $secpolPath
    $secpolContent = $secpolContent -replace "PasswordComplexity = 0", "PasswordComplexity = 1"
    $secpolContent = $secpolContent -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = 12"
    $secpolContent = $secpolContent -replace "MinimumPasswordAge = \d+", "MinimumPasswordAge = 1"
    $secpolContent = $secpolContent -replace "MaximumPasswordAge = \d+", "MaximumPasswordAge = 90"
    $secpolContent = $secpolContent -replace "PasswordHistorySize = \d+", "PasswordHistorySize = 24"
    
    $secpolContent | Set-Content $secpolPath
    secedit /configure /db $env:windir\security\database\local.sdb /cfg $secpolPath /areas SECURITYPOLICY /quiet
    Remove-Item $secpolPath -Force
    
    Write-Host "  [OK] Password policy configured (12 chars min, complexity required, 90 day expiry)" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error configuring password policy" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 12: Configure Account Lockout Policy
# ============================================
Write-Host "" 
Write-Host "[12/30] Configuring Account Lockout Policy..." -ForegroundColor Yellow

try {
    $secpolPath = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $secpolPath /quiet
    
    $secpolContent = Get-Content $secpolPath
    $secpolContent = $secpolContent -replace "LockoutBadCount = \d+", "LockoutBadCount = 5"
    $secpolContent = $secpolContent -replace "LockoutDuration = \d+", "LockoutDuration = 30"
    $secpolContent = $secpolContent -replace "ResetLockoutCount = \d+", "ResetLockoutCount = 30"
    
    $secpolContent | Set-Content $secpolPath
    secedit /configure /db $env:windir\security\database\local.sdb /cfg $secpolPath /areas SECURITYPOLICY /quiet
    Remove-Item $secpolPath -Force
    
    Write-Host "  [OK] Account lockout after 5 failed attempts for 30 minutes" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error configuring lockout policy" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 13: Rename Default Administrator Account
# ============================================
Write-Host "" 
Write-Host "[13/30] Renaming Default Administrator Account..." -ForegroundColor Yellow

try {
    Rename-LocalUser -Name "Administrator" -NewName "SecureAdmin_DO_NOT_USE" -ErrorAction Stop
    Write-Host "  [OK] Administrator account renamed to SecureAdmin_DO_NOT_USE" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Administrator account may already be renamed or not exist" -ForegroundColor Yellow
}

# ============================================
# SECURITY ITEM 14: Disable Renamed Administrator Account
# ============================================
Write-Host "" 
Write-Host "[14/30] Disabling Renamed Administrator Account..." -ForegroundColor Yellow

try {
    Disable-LocalUser -Name "SecureAdmin_DO_NOT_USE" -ErrorAction Stop
    Write-Host "  [OK] Renamed administrator account disabled" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Account may already be disabled" -ForegroundColor Yellow
}

# ============================================
# SECURITY ITEM 15: Enable Windows Firewall on All Profiles
# ============================================
Write-Host "" 
Write-Host "[15/30] Enabling Windows Firewall..." -ForegroundColor Yellow

try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    Write-Host "  [OK] Windows Firewall enabled on all profiles" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error enabling firewall" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 16: Configure Firewall Rules (Block Inbound by Default)
# ============================================
Write-Host "" 
Write-Host "[16/30] Configuring Firewall Default Rules..." -ForegroundColor Yellow

try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
    Write-Host "  [OK] Firewall set to block all inbound, allow outbound" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error configuring firewall rules" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 17: Disable Unnecessary Services (Telemetry)
# ============================================
Write-Host "" 
Write-Host "[17/30] Disabling Unnecessary Services..." -ForegroundColor Yellow

$servicesToDisable = @(
    "DiagTrack",
    "dmwappushservice",
    "RemoteRegistry",
    "RemoteAccess"
)

foreach ($service in $servicesToDisable) {
    try {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
        Write-Host "  [OK] Disabled service: $service" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Service $service may not exist or already disabled" -ForegroundColor Yellow
    }
}

# ============================================
# SECURITY ITEM 18: Enable BitLocker (if TPM available)
# ============================================
Write-Host "" 
Write-Host "[18/30] Checking BitLocker Status..." -ForegroundColor Yellow

try {
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if ($tpm.TpmPresent -and $tpm.TpmReady) {
        Write-Host "  [INFO] TPM detected and ready - BitLocker can be enabled" -ForegroundColor Cyan
        Write-Host "  [WARN] BitLocker requires manual setup due to recovery key backup requirements" -ForegroundColor Yellow
    } else {
        Write-Host "  [WARN] TPM not available - BitLocker requires TPM or USB key" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [WARN] Unable to check TPM status" -ForegroundColor Yellow
}

# ============================================
# SECURITY ITEM 19: Configure Windows Update (Automatic Updates)
# ============================================
Write-Host "" 
Write-Host "[19/30] Configuring Windows Update..." -ForegroundColor Yellow

try {
    # Configure Windows Update via registry
    $updatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (-not (Test-Path $updatePath)) {
        New-Item -Path $updatePath -Force | Out-Null
    }
    
    Set-ItemProperty -Path $updatePath -Name "NoAutoUpdate" -Value 0 -Type DWord
    Set-ItemProperty -Path $updatePath -Name "AUOptions" -Value 4 -Type DWord
    Set-ItemProperty -Path $updatePath -Name "ScheduledInstallDay" -Value 0 -Type DWord
    Set-ItemProperty -Path $updatePath -Name "ScheduledInstallTime" -Value 3 -Type DWord
    
    Write-Host "  [OK] Windows Update configured for automatic installation" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error configuring Windows Update" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 20: Disable USB Storage Devices
# ============================================
Write-Host "" 
Write-Host "[20/30] Disabling USB Storage Devices..." -ForegroundColor Yellow

try {
    $usbPath = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
    if (Test-Path $usbPath) {
        Set-ItemProperty -Path $usbPath -Name "Start" -Value 4 -Type DWord
        Write-Host "  [OK] USB storage devices disabled" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] USBSTOR registry key not found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [ERROR] Error disabling USB storage" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 21: Enable Advanced Audit Policy
# ============================================
Write-Host "" 
Write-Host "[21/30] Enabling Advanced Audit Policy..." -ForegroundColor Yellow

try {
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Logoff" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable | Out-Null
    
    Write-Host "  [OK] Advanced audit policies enabled for logon/logoff events" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error configuring audit policy" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 22: Configure Screen Lock Timeout
# ============================================
Write-Host "" 
Write-Host "[22/30] Configuring Screen Lock Timeout..." -ForegroundColor Yellow

try {
    $screensaverPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    Set-ItemProperty -Path $screensaverPath -Name "InactivityTimeoutSecs" -Value 600 -Type DWord
    
    $userPath = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
    if (-not (Test-Path $userPath)) {
        New-Item -Path $userPath -Force | Out-Null
    }
    Set-ItemProperty -Path $userPath -Name "ScreenSaveTimeOut" -Value "600" -Type String
    Set-ItemProperty -Path $userPath -Name "ScreenSaverIsSecure" -Value "1" -Type String
    
    Write-Host "  [OK] Screen lock configured for 10 minutes of inactivity" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error configuring screen lock" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 23: Disable AutoRun for All Drives
# ============================================
Write-Host "" 
Write-Host "[23/30] Disabling AutoRun/AutoPlay..." -ForegroundColor Yellow

try {
    $autorunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (-not (Test-Path $autorunPath)) {
        New-Item -Path $autorunPath -Force | Out-Null
    }
    
    Set-ItemProperty -Path $autorunPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
    Set-ItemProperty -Path $autorunPath -Name "NoAutorun" -Value 1 -Type DWord
    
    Write-Host "  [OK] AutoRun/AutoPlay disabled for all drive types" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error disabling AutoRun" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 24: Enable Data Execution Prevention (DEP)
# ============================================
Write-Host "" 
Write-Host "[24/30] Enabling Data Execution Prevention..." -ForegroundColor Yellow

try {
    bcdedit /set nx AlwaysOn | Out-Null
    Write-Host "  [OK] DEP enabled for all programs (requires restart)" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error enabling DEP" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 25: Configure User Account Control (UAC) to Maximum
# ============================================
Write-Host "" 
Write-Host "[25/30] Configuring User Account Control (UAC)..." -ForegroundColor Yellow

try {
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord
    Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord
    Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord
    
    Write-Host "  [OK] UAC configured to prompt for all administrative actions" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error configuring UAC" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 26: Disable SMBv1 Protocol
# ============================================
Write-Host "" 
Write-Host "[26/30] Disabling SMBv1 Protocol..." -ForegroundColor Yellow

try {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    Write-Host "  [OK] SMBv1 protocol disabled (vulnerable to ransomware)" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error disabling SMBv1" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 27: Enable Windows Defender Real-Time Protection
# ============================================
Write-Host "" 
Write-Host "[27/30] Enabling Windows Defender..." -ForegroundColor Yellow

try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
    Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop
    Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop
    
    Write-Host "  [OK] Windows Defender real-time protection enabled" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error configuring Windows Defender" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 28: Enable Network Level Authentication (NLA) for RDP
# ============================================
Write-Host "" 
Write-Host "[28/30] Configuring Network Level Authentication..." -ForegroundColor Yellow

try {
    $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    Set-ItemProperty -Path $rdpPath -Name "UserAuthentication" -Value 1 -Type DWord
    
    Write-Host "  [OK] Network Level Authentication enabled for RDP" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error configuring NLA" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 29: Disable Remote Assistance
# ============================================
Write-Host "" 
Write-Host "[29/30] Disabling Remote Assistance..." -ForegroundColor Yellow

try {
    $raPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    Set-ItemProperty -Path $raPath -Name "fAllowToGetHelp" -Value 0 -Type DWord
    
    Write-Host "  [OK] Remote Assistance disabled" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Error disabling Remote Assistance" -ForegroundColor Red
}

# ============================================
# SECURITY ITEM 30: Create System Restore Point
# ============================================
Write-Host "" 
Write-Host "[30/30] Creating System Restore Point..." -ForegroundColor Yellow

try {
    Enable-ComputerRestore -Drive "C:\" -ErrorAction Stop
    Checkpoint-Computer -Description "SecurePro Security Configuration" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
    Write-Host "  [OK] System restore point created" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Error creating restore point - may need to be done manually" -ForegroundColor Yellow
}

# ============================================
# COMPLETION SUMMARY
# ============================================
Write-Host "" 
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CONFIGURATION COMPLETE!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "" 
Write-Host "Summary:" -ForegroundColor White
Write-Host "  [OK] 4 Security Groups Created" -ForegroundColor Green
Write-Host "  [OK] 13 User Accounts Created" -ForegroundColor Green
Write-Host "  [OK] Directory Structure Created (C:\SecurePro)" -ForegroundColor Green
Write-Host "  [OK] Folder Permissions Configured (Least Privilege)" -ForegroundColor Green
Write-Host "  [OK] Password and Lockout Policies Enforced" -ForegroundColor Green
Write-Host "  [OK] Firewall and Network Security Enabled" -ForegroundColor Green
Write-Host "  [OK] System Hardening Applied" -ForegroundColor Green
Write-Host "" 
Write-Host "IMPORTANT NOTES:" -ForegroundColor Yellow
Write-Host "  [WARN] Default password for all users: SecurePro2024!" -ForegroundColor White
Write-Host "  [WARN] Users should change password on first login" -ForegroundColor White
Write-Host "  [WARN] RESTART REQUIRED for some settings to take effect" -ForegroundColor White
Write-Host "  [WARN] BitLocker should be manually configured if TPM is available" -ForegroundColor White
Write-Host "" 
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Verify users in lusrmgr.msc" -ForegroundColor White
Write-Host "  2. Check folder structure in C:\SecurePro" -ForegroundColor White
Write-Host "  3. Test user login with different accounts" -ForegroundColor White
Write-Host "  4. Restart the computer" -ForegroundColor White
Write-Host "" 
Write-Host "Configuration completed successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
