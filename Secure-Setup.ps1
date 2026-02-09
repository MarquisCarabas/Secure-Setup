<#
.DESCRIPTION
    Automates basic security hardening with comprehensive logging, error handling, and validation
#>

#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION
# ============================================================================

$LogDirectory = "$env:ProgramData\SecureSetup\Logs"
$LogFile = Join-Path $LogDirectory "SecureSetup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ErrorCount = 0
$SuccessCount = 0
$VerificationResults = @()

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
OS Version: $((Get-CimInstance Win32_OperatingSystem).Caption)
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
        Log level: INFO, SUCCESS, WARNING, ERROR, VERIFY
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO','SUCCESS','WARNING','ERROR','VERIFY')]
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
        'VERIFY'  { Write-Host $logMessage -ForegroundColor Magenta }
        default   { Write-Host $logMessage -ForegroundColor Cyan }
    }
}

# ============================================================================
# VERIFICATION FUNCTIONS
# ============================================================================

function Test-FirewallConfiguration {
    <#
    .SYNOPSIS
        Verifies firewall is properly configured
    #>
    Write-Log "Verifying firewall configuration..." -Level VERIFY
    
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $allEnabled = $true
        $allBlockInbound = $true
        
        foreach ($profile in $profiles) {
            Write-Log "  Profile: $($profile.Name) - Enabled: $($profile.Enabled) - Inbound: $($profile.DefaultInboundAction)" -Level INFO
            
            if (-not $profile.Enabled) {
                $allEnabled = $false
            }
            if ($profile.DefaultInboundAction -ne 'Block') {
                $allBlockInbound = $false
            }
        }
        
        if ($allEnabled -and $allBlockInbound) {
            Write-Log "✓ Firewall verification PASSED: All profiles enabled with inbound blocking" -Level SUCCESS
            return @{Passed=$true; Control="Firewall"; Details="All profiles enabled, default inbound=Block"}
        }
        else {
            Write-Log "✗ Firewall verification FAILED: Not all profiles properly configured" -Level ERROR
            return @{Passed=$false; Control="Firewall"; Details="Configuration incomplete"}
        }
    }
    catch {
        Write-Log "✗ Firewall verification ERROR: $($_.Exception.Message)" -Level ERROR
        return @{Passed=$false; Control="Firewall"; Details="Verification failed: $($_.Exception.Message)"}
    }
}

function Test-ServiceConfiguration {
    <#
    .SYNOPSIS
        Verifies target services are disabled and stopped
    #>
    param(
        [string[]]$ServiceNames
    )
    
    Write-Log "Verifying service configuration..." -Level VERIFY
    
    $allPassed = $true
    $details = @()
    
    foreach ($serviceName in $ServiceNames) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            
            if ($null -eq $service) {
                Write-Log "  Service '$serviceName': Not found (skipped)" -Level INFO
                $details += "$serviceName=NotFound"
                continue
            }
            
            $disabled = (Get-Service -Name $serviceName).StartType -eq 'Disabled'
            $stopped = (Get-Service -Name $serviceName).Status -eq 'Stopped'
            
            if ($disabled -and $stopped) {
                Write-Log "  ✓ Service '$serviceName': Disabled and Stopped" -Level SUCCESS
                $details += "$serviceName=OK"
            }
            else {
                Write-Log "  ✗ Service '$serviceName': Status=$($service.Status), StartType=$($service.StartType)" -Level WARNING
                $allPassed = $false
                $details += "$serviceName=Failed"
            }
        }
        catch {
            Write-Log "  ✗ Service '$serviceName' verification error: $($_.Exception.Message)" -Level ERROR
            $allPassed = $false
            $details += "$serviceName=Error"
        }
    }
    
    if ($allPassed) {
        Write-Log "✓ Service hardening verification PASSED" -Level SUCCESS
    }
    else {
        Write-Log "✗ Service hardening verification FAILED" -Level ERROR
    }
    
    return @{Passed=$allPassed; Control="Services"; Details=($details -join ", ")}
}

function Test-WindowsDefender {
    <#
    .SYNOPSIS
        Verifies Windows Defender is properly configured
    #>
    Write-Log "Verifying Windows Defender configuration..." -Level VERIFY
    
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        
        $checks = @{
            "RealTimeProtection" = $mpStatus.RealTimeProtectionEnabled
            "CloudProtection" = $mpStatus.IoavProtectionEnabled
            "BehaviorMonitor" = $mpStatus.BehaviorMonitorEnabled
            "OnAccessProtection" = $mpStatus.OnAccessProtectionEnabled
        }
        
        $allPassed = $true
        $details = @()
        
        foreach ($check in $checks.GetEnumerator()) {
            if ($check.Value) {
                Write-Log "  ✓ $($check.Key): Enabled" -Level SUCCESS
                $details += "$($check.Key)=Enabled"
            }
            else {
                Write-Log "  ✗ $($check.Key): Disabled" -Level WARNING
                $allPassed = $false
                $details += "$($check.Key)=Disabled"
            }
        }
        
        # Check signature age
        $signatureAge = (Get-Date) - $mpStatus.AntivirusSignatureLastUpdated
        Write-Log "  Signature age: $([math]::Round($signatureAge.TotalHours, 1)) hours" -Level INFO
        
        if ($signatureAge.TotalDays -gt 7) {
            Write-Log "  ⚠ Warning: Signatures older than 7 days" -Level WARNING
            $allPassed = $false
        }
        
        if ($allPassed) {
            Write-Log "✓ Windows Defender verification PASSED" -Level SUCCESS
        }
        else {
            Write-Log "✗ Windows Defender verification FAILED" -Level ERROR
        }
        
        return @{Passed=$allPassed; Control="Windows Defender"; Details=($details -join ", ")}
    }
    catch {
        Write-Log "✗ Windows Defender verification ERROR: $($_.Exception.Message)" -Level ERROR
        return @{Passed=$false; Control="Windows Defender"; Details="Verification failed: $($_.Exception.Message)"}
    }
}

function Test-UACConfiguration {
    <#
    .SYNOPSIS
        Verifies UAC is set to maximum level
    #>
    Write-Log "Verifying UAC configuration..." -Level VERIFY
    
    try {
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $uacValue = Get-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction Stop
        
        $expectedValue = 2
        $actualValue = $uacValue.ConsentPromptBehaviorAdmin
        
        Write-Log "  UAC Level: $actualValue (Expected: $expectedValue)" -Level INFO
        
        if ($actualValue -eq $expectedValue) {
            Write-Log "✓ UAC verification PASSED: Set to 'Always Notify'" -Level SUCCESS
            return @{Passed=$true; Control="UAC"; Details="ConsentPromptBehaviorAdmin=$actualValue"}
        }
        else {
            Write-Log "✗ UAC verification FAILED: Value is $actualValue, expected $expectedValue" -Level ERROR
            return @{Passed=$false; Control="UAC"; Details="Incorrect value: $actualValue"}
        }
    }
    catch {
        Write-Log "✗ UAC verification ERROR: $($_.Exception.Message)" -Level ERROR
        return @{Passed=$false; Control="UAC"; Details="Verification failed: $($_.Exception.Message)"}
    }
}

function Test-SMBv1Status {
    <#
    .SYNOPSIS
        Verifies SMBv1 is disabled
    #>
    Write-Log "Verifying SMBv1 status..." -Level VERIFY
    
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        
        Write-Log "  SMBv1 State: $($smb1.State)" -Level INFO
        
        if ($smb1.State -eq 'Disabled') {
            Write-Log "✓ SMBv1 verification PASSED: Protocol is disabled" -Level SUCCESS
            return @{Passed=$true; Control="SMBv1"; Details="State=Disabled"}
        }
        elseif ($smb1.State -eq 'DisablePending') {
            Write-Log "⚠ SMBv1 verification PENDING: Restart required to complete" -Level WARNING
            return @{Passed=$true; Control="SMBv1"; Details="State=DisablePending (restart required)"}
        }
        else {
            Write-Log "✗ SMBv1 verification FAILED: Protocol is $($smb1.State)" -Level ERROR
            return @{Passed=$false; Control="SMBv1"; Details="State=$($smb1.State)"}
        }
    }
    catch {
        Write-Log "✗ SMBv1 verification ERROR: $($_.Exception.Message)" -Level ERROR
        return @{Passed=$false; Control="SMBv1"; Details="Verification failed: $($_.Exception.Message)"}
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
        
        # Verify configuration
        $verifyResult = Test-FirewallConfiguration
        $script:VerificationResults += $verifyResult
        
        return $verifyResult.Passed
    }
    catch {
        Write-Log "Firewall configuration failed: $($_.Exception.Message)" -Level ERROR
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
        $script:ErrorCount++
        
        # Still try to verify what we have
        $verifyResult = Test-FirewallConfiguration
        $script:VerificationResults += $verifyResult
        
        return $false
    }
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
    
    # Verify all services
    $verifyResult = Test-ServiceConfiguration -ServiceNames $servicesToDisable
    $script:VerificationResults += $verifyResult
    
    return $verifyResult.Passed
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
        
        # Verify configuration
        $verifyResult = Test-WindowsDefender
        $script:VerificationResults += $verifyResult
        
        return $verifyResult.Passed
    }
    catch {
        Write-Log "Windows Defender configuration failed: $($_.Exception.Message)" -Level ERROR
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
        $script:ErrorCount++
        
        # Still try to verify what we have
        $verifyResult = Test-WindowsDefender
        $script:VerificationResults += $verifyResult
        
        return $false
    }
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
        
        # Verify configuration
        $verifyResult = Test-UACConfiguration
        $script:VerificationResults += $verifyResult
        
        return $verifyResult.Passed
    }
    catch {
        Write-Log "UAC configuration failed: $($_.Exception.Message)" -Level ERROR
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
        $script:ErrorCount++
        
        # Still try to verify what we have
        $verifyResult = Test-UACConfiguration
        $script:VerificationResults += $verifyResult
        
        return $false
    }
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
            Write-Log "SMBv1 is already disabled or pending" -Level INFO
        }
        
        # Verify configuration
        $verifyResult = Test-SMBv1Status
        $script:VerificationResults += $verifyResult
        
        return $verifyResult.Passed
    }
    catch {
        Write-Log "SMBv1 disabling failed: $($_.Exception.Message)" -Level ERROR
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
        $script:ErrorCount++
        
        # Still try to verify what we have
        $verifyResult = Test-SMBv1Status
        $script:VerificationResults += $verifyResult
        
        return $false
    }
}

# ============================================================================
# REPORTING FUNCTIONS
# ============================================================================

function Write-VerificationReport {
    <#
    .SYNOPSIS
        Generates a summary report of all verification results
    #>
    Write-Log "`n=== VERIFICATION REPORT ===" -Level INFO
    Write-Log "Verification Summary:" -Level INFO
    
    $passedCount = ($script:VerificationResults | Where-Object {$_.Passed -eq $true}).Count
    $failedCount = ($script:VerificationResults | Where-Object {$_.Passed -eq $false}).Count
    
    Write-Host "`n┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│                  VERIFICATION REPORT                        │" -ForegroundColor Cyan
    Write-Host "├─────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
    
    foreach ($result in $script:VerificationResults) {
        $status = if ($result.Passed) { "✓ PASS" } else { "✗ FAIL" }
        $color = if ($result.Passed) { "Green" } else { "Red" }
        
        $line = "│ {0,-20} {1,-10} {2,-25}│" -f $result.Control, $status, ""
        Write-Host $line -ForegroundColor $color
        
        Write-Log "$status - $($result.Control): $($result.Details)" -Level $(if ($result.Passed) {'SUCCESS'} else {'ERROR'})
    }
    
    Write-Host "├─────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
    Write-Host ("│ PASSED: {0,-10} FAILED: {1,-10}                    │" -f $passedCount, $failedCount) -ForegroundColor Cyan
    Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    
    Write-Log "Verification Results: $passedCount passed, $failedCount failed" -Level INFO
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
    Write-Host "   Windows Security Hardening Script v2.0" -ForegroundColor Cyan
    Write-Host "   With Verification & Validation" -ForegroundColor Cyan
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
    
    # Generate verification report
    Write-VerificationReport
    
    # Summary
    Write-Log "`n=== Hardening Complete ===" -Level INFO
    Write-Log "Successful operations: $SuccessCount" -Level SUCCESS
    Write-Log "Failed operations: $ErrorCount" -Level $(if ($ErrorCount -gt 0) {'ERROR'} else {'INFO'})
    Write-Log "Log file location: $LogFile" -Level INFO
    
    Write-Host "`n==================================================" -ForegroundColor Cyan
    Write-Host "   Hardening Summary" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "Successful Operations: $SuccessCount" -ForegroundColor Green
    Write-Host "Failed Operations: $ErrorCount" -ForegroundColor $(if ($ErrorCount -gt 0) {'Red'} else {'Green'})
    Write-Host "Log File: $LogFile" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    
    if ($ErrorCount -gt 0) {
        Write-Host "`n[!] Some operations failed. Review the log file for details." -ForegroundColor Yellow
    }
    
    # Check if restart is needed
    $needsRestart = ($script:VerificationResults | Where-Object {$_.Details -like "*restart*"}).Count -gt 0
    if ($needsRestart) {
        Write-Host "`n[!] RESTART REQUIRED to complete SMBv1 disabling" -ForegroundColor Yellow
        Write-Log "System restart required to complete all changes" -Level WARNING
    }
}

# Run the hardening
Start-SecurityHardening