<#
    .NOTES
    Created at 22.11.2024
    Fabian Seitz - PARI GmbH
    .SYNOPSIS
    Registers a device with Intune using Windows Autopilot and resets the VM.
    .DESCRIPTION
    This script:
    1. Installs the required PowerShell package provider and script (`get-windowsautopilotinfo`).
    2. Collects and uploads Autopilot information using Entra App Registration credentials.
    3. Resets the VM to complete the setup process.
    .PARAMETER TenantId
    The Tenant ID of your Azure AD.
    .PARAMETER AppId
    The Application ID of the Entra App Registration.
    .PARAMETER AppSecret
    The Client Secret of the Entra App Registration.
    .NOTES
    Ensure this script is run with administrator privileges.
    .EXAMPLE
    .\RegisterVM-ResetLocally.ps1 -TenantId "xxxxx" -AppId "xxxxx" -AppSecret "xxxxx"
    .LINK
    https://github.com/pari-medical-holding-gmbh/Hyper-V-AutoPilot-VM
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId = "CHANGEME!!!!!",

    [Parameter(Mandatory = $false)]
    [string]$AppId = "CHANGEME!!!!!",

    [Parameter(Mandatory = $false)]
    [string]$AppSecret = "CHANGEME!!!!!",

    [Parameter(Mandatory = $False)] [Switch] $ResetOnly = $false
)

# Ensure the script is running with admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an administrator."
    Exit 1
}

# Checking the Internet connection
function Test-InternetConnection {
    try {
        $null = Test-Connection -ComputerName "sysinternals.com" -Count 1 -Quiet
        return $true
    }
    catch {
        return $false
    }
}

if (-not (Test-InternetConnection)) {
    Write-Error "No internet connection available! This script needs a internet connection."
    Exit 5
}

if ($ResetOnly -eq $false) {
    # Step 1: Install required package provider and script
    try {
        Write-Host "Installing NuGet Package Provider..."
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Confirm:$false -Force:$true

        Write-Host "Installing 'get-windowsautopilotinfo' script..."
        Install-Script get-windowsautopilotinfo -Confirm:$false -Force:$true
    }
    catch {
        Write-Error "Failed to install required components: $_"
        Exit 2
    }

    # Step 2: Collect and upload Autopilot information
    try {
        Write-Host "Uploading Autopilot information to Intune..."
        Get-Windowsautopilotinfo -Online -TenantId $TenantId -AppId $AppId -AppSecret $AppSecret
        Write-Host "Autopilot registration completed successfully."
    }
    catch {
        Write-Error "Failed to upload Autopilot information: $_"
        Exit 3
    }
}

# Step 3: Reset the computer locally
try {
    Write-Host "Resetting the VM..."
    #https://call4cloud.nl/2020/04/wipe-your-device-script-without-intune/
    #MDM WMI Bridge part
    $reset =
    @'
$namespaceName = "root\cimv2\mdm\dmmap"
$className = "MDM_RemoteWipe"
$methodName = "doWipeMethod"
$session = New-CimSession
$params = New-Object Microsoft.Management.Infrastructure.CimMethodParametersCollection
$param = [Microsoft.Management.Infrastructure.CimMethodParameter]::Create("param", "", "String", "In")
$params.Add($param)
$instance = Get-CimInstance -Namespace $namespaceName -ClassName $className -Filter "ParentID='./Vendor/MSFT' and InstanceID='RemoteWipe'"
$session.InvokeMethod($namespaceName, $instance, $methodName, $params)
'@

    $start =
    @'
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference= 'silentlycontinue'
$OriginalPref = $ProgressPreference
#Start PowerShell session as system
Write-Host "Starting reset script"
Start-Process -FilePath "c:\ProgramData\CustomScripts\pstools\psexec.exe" -windowstyle hidden -ArgumentList '-i -s cmd /c "powershell.exe -ExecutionPolicy Bypass -file c:\programdata\customscripts\reset.ps1"'
'@

    # Check if folder exists
    If (!(test-path $env:ProgramData\CustomScripts\)) {
        New-Item -ItemType Directory -Force -Path $env:ProgramData\CustomScripts\ >$null 2>&1
    }

    #Export script to programdata folder
    Write-Host "Writing Scripts to $env:ProgramData\CustomScripts\"
    try {
        Out-File -FilePath $(Join-Path $env:ProgramData CustomScripts\reset.ps1) -Encoding unicode -Force -InputObject $reset -Confirm:$false
        Out-File -FilePath $(Join-Path $env:ProgramData CustomScripts\start.ps1) -Encoding unicode -Force -InputObject $start -Confirm:$false
    }
    Catch {
        Write-Error "Failed to write the script to the programdata folder: $_"
        Exit 5
    }

    #Accepteula Psexec
    Write-Host "Accepting psexec EULA"
    reg.exe ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f | out-null

    #Sysinternals download part
    try {
        Invoke-Webrequest -uri: "https://download.sysinternals.com/files/SysinternalsSuite.zip" -outfile "c:\programdata\customscripts\pstools.zip" | out-null
        Expand-Archive c:\programdata\customscripts\pstools.zip -DestinationPath c:\programdata\customscripts\pstools -force | out-null
    }
    Catch {
        Write-Error "Failed to download Sysinternals Suite: $_"
        Exit 6
    }

    #Start Powershell Script as Admin
    Write-Host "Starting reset preparation script"
    Start-Process powershell -ArgumentList '-noprofile -ExecutionPolicy Bypass -file c:\programdata\customscripts\start.ps1' -verb RunAs
}
catch {
    Write-Error "Failed to reset the computer: $_"
    Exit 4
}

Write-Host "Script completed successfully. The VM is now resetting."
Exit 0