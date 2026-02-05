#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION
# ============================================================================

$LogDirectory = "$env:ProgramData\SecureSetup\Logs"
$LogFile = Join-Path $LogDirectory "SecureSetup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ErrorCount = 0
$SuccessCount = 0

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Initialize-Logging {
    <#
    .SYNOPSIS
        Creates log directory and initializes log file
    #>
    try {
        if (-not (Test-Path $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
            Write-Host "[+] Created log directory: $LogDirectory" -ForegroundColor Green
        }
        
        $header = @"
================================================================================
Windows Security Hardening Script
Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Hostname: $env:COMPUTERNAME
User: $env:USERNAME
PowerShell Version: $($PSVersionTable.PSVersion)
================================================================================

"@
        Add-Content -Path $LogFile -Value $header
        Write-Host "[+] Logging initialized: $LogFile" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[-] Failed to initialize logging: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes timestamped messages to log file and console
    .PARAMETER Message
        The message to log
    .PARAMETER Level
        Log level: INFO, SUCCESS, WARNING, ERROR
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO','SUCCESS','WARNING','ERROR')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to file
    try {
        Add-Content -Path $LogFile -Value $logMessage -ErrorAction Stop
    }
    catch {
        Write-Host "[-] Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Write to console with colors
    switch ($Level) {
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
        'WARNING' { Write-Host $logMessage -ForegroundColor Yellow }
        'ERROR'   { Write-Host $logMessage -ForegroundColor Red }
        default   { Write-Host $logMessage -ForegroundColor Cyan }
    }
}

# ============================================================================
# HARDENING FUNCTIONS
# ============================================================================

function Set-FirewallRules {
    <#
    .SYNOPSIS
        Configures Windows Firewall rules
    #>
    Write-Log "Starting firewall configuration..." -Level INFO
    
    try {
        # Enable firewall for all profiles
        Write-Log "Enabling Windows Firewall for all profiles..." -Level INFO
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
        Write-Log "Windows Firewall enabled successfully" -Level SUCCESS
        $script:SuccessCount++
        
        # Block inbound by default
        Write-Log "Setting default inbound action to Block..." -Level INFO
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -ErrorAction Stop
        Write-Log "Default inbound action set to Block" -Level SUCCESS
        $script:SuccessCount++
        
        # Allow outbound by default
        Write-Log "Setting default outbound action to Allow..." -Level INFO
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -ErrorAction Stop
        Write-Log "Default outbound action set to Allow" -Level SUCCESS
        $script:SuccessCount++
        
    }
    catch {
        Write-Log "Firewall configuration failed: $($_.Exception.Message)" -Level ERROR
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
        $script:ErrorCount++
        return $false
    }
    
    return $true
}

function Disable-UnnecessaryServices {
    <#
    .SYNOPSIS
        Disables commonly unnecessary services
    #>
    Write-Log "Starting service hardening..." -Level INFO
    
    # Services to disable (adjust based on your environment)
    $servicesToDisable = @(
        'RemoteRegistry',
        'RemoteAccess',
        'Telephony',
        'TapiSrv'
    )
    
    foreach ($serviceName in $servicesToDisable) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            
            if ($null -eq $service) {
                Write-Log "Service '$serviceName' not found on this system (skipping)" -Level WARNING
                continue
            }
            
            Write-Log "Processing service: $serviceName (Current status: $($service.Status))" -Level INFO
            
            # Stop service if running
            if ($service.Status -eq 'Running') {
                Write-Log "Stopping service: $serviceName..." -Level INFO
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
                Write-Log "Service stopped: $serviceName" -Level SUCCESS
            }
            
            # Disable service
            Write-Log "Disabling service: $serviceName..." -Level INFO
            Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
            Write-Log "Service disabled: $serviceName" -Level SUCCESS
            $script:SuccessCount++
            
        }
        catch {
            Write-Log "Failed to disable service '$serviceName': $($_.Exception.Message)" -Level ERROR
            $script:ErrorCount++
        }
    }
}

function Enable-WindowsDefender {
    <#
    .SYNOPSIS
        Enables and configures Windows Defender
    #>
    Write-Log "Starting Windows Defender configuration..." -Level INFO
    
    try {
        # Enable real-time monitoring
        Write-Log "Enabling real-time monitoring..." -Level INFO
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Write-Log "Real-time monitoring enabled" -Level SUCCESS
        $script:SuccessCount++
        
        # Enable cloud-delivered protection
        Write-Log "Enabling cloud-delivered protection..." -Level INFO
        Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
        Write-Log "Cloud-delivered protection enabled" -Level SUCCESS
        $script:SuccessCount++
        
        # Enable automatic sample submission
        Write-Log "Enabling automatic sample submission..." -Level INFO
        Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction Stop
        Write-Log "Automatic sample submission enabled" -Level SUCCESS
        $script:SuccessCount++
        
        # Update signatures
        Write-Log "Updating malware definitions..." -Level INFO
        Update-MpSignature -ErrorAction Stop
        Write-Log "Malware definitions updated successfully" -Level SUCCESS
        $script:SuccessCount++
        
    }
    catch {
        Write-Log "Windows Defender configuration failed: $($_.Exception.Message)" -Level ERROR
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
        $script:ErrorCount++
        return $false
    }
    
    return $true
}

function Set-UAC {
    <#
    .SYNOPSIS
        Configures User Account Control settings
    #>
    Write-Log "Starting UAC configuration..." -Level INFO
    
    try {
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        
        Write-Log "Setting UAC to always notify..." -Level INFO
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -ErrorAction Stop
        Write-Log "UAC configured successfully" -Level SUCCESS
        $script:SuccessCount++
        
    }
    catch {
        Write-Log "UAC configuration failed: $($_.Exception.Message)" -Level ERROR
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
        $script:ErrorCount++
        return $false
    }
    
    return $true
}

function Disable-SMBv1 {
    <#
    .SYNOPSIS
        Disables SMBv1 protocol
    #>
    Write-Log "Starting SMBv1 disabling..." -Level INFO
    
    try {
        Write-Log "Checking SMBv1 status..." -Level INFO
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        
        if ($smb1.State -eq 'Enabled') {
            Write-Log "SMBv1 is currently enabled, disabling..." -Level INFO
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop
            Write-Log "SMBv1 disabled successfully (restart required)" -Level SUCCESS
            $script:SuccessCount++
        }
        else {
            Write-Log "SMBv1 is already disabled" -Level INFO
        }
        
    }
    catch {
        Write-Log "SMBv1 disabling failed: $($_.Exception.Message)" -Level ERROR
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
        $script:ErrorCount++
        return $false
    }
    
    return $true
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-SecurityHardening {
    <#
    .SYNOPSIS
        Main function to execute all hardening steps
    #>
    
    Write-Host "`n==================================================" -ForegroundColor Cyan
    Write-Host "   Windows Security Hardening Script" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Initialize logging
    if (-not (Initialize-Logging)) {
        Write-Host "[-] Cannot proceed without logging. Exiting." -ForegroundColor Red
        exit 1
    }
    
    Write-Log "=== Starting Security Hardening ===" -Level INFO
    
    # Execute hardening functions
    $tasks = @(
        @{Name="Firewall Configuration"; Function={Set-FirewallRules}},
        @{Name="Service Hardening"; Function={Disable-UnnecessaryServices}},
        @{Name="Windows Defender Setup"; Function={Enable-WindowsDefender}},
        @{Name="UAC Configuration"; Function={Set-UAC}},
        @{Name="SMBv1 Removal"; Function={Disable-SMBv1}}
    )
    
    foreach ($task in $tasks) {
        Write-Log "`n--- $($task.Name) ---" -Level INFO
        try {
            & $task.Function
        }
        catch {
            Write-Log "Unexpected error in $($task.Name): $($_.Exception.Message)" -Level ERROR
            $script:ErrorCount++
        }
    }
    
    # Summary
    Write-Log "`n=== Hardening Complete ===" -Level INFO
    Write-Log "Successful operations: $SuccessCount" -Level SUCCESS
    Write-Log "Failed operations: $ErrorCount" -Level $(if ($ErrorCount -gt 0) {'ERROR'} else {'INFO'})
    Write-Log "Log file location: $LogFile" -Level INFO
    
    Write-Host "`n==================================================" -ForegroundColor Cyan
    Write-Host "   Hardening Summary" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "Successful: $SuccessCount" -ForegroundColor Green
    Write-Host "Failed: $ErrorCount" -ForegroundColor $(if ($ErrorCount -gt 0) {'Red'} else {'Green'})
    Write-Host "Log File: $LogFile" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    
    if ($ErrorCount -gt 0) {
        Write-Host "`n[!] Some operations failed. Review the log file for details." -ForegroundColor Yellow
    }
}

# Run the hardening
Start-SecurityHardening
