<#
    .NOTES
    Created at 08.02.2023
    Fabian Seitz - PARI GmbH
    .DESCRIPTION
    Powershell Script for Intune Package Powershell Windows Feature Enabling
    context type: System context needed (admin permissions) or user context
    .EXAMPLE
    Installation:   "%systemroot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" -noprofile -executionpolicy bypass -file .\Hyper_V_Feature.ps1 -InstallMode Install -AdminPermissions
    Uninstallation: "%systemroot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" -noprofile -executionpolicy bypass -file .\Hyper_V_Feature.ps1 -InstallMode Uninstall -AdminPermissions
    .PARAMETER InstallMode
    Specifies the installation mode (install or uninstall)
    .PARAMETER logpath
    Specifies a custom folder location for the script log files (Default: see variable $logpath)
    WARNING: Seems to break Intune installation for unknown reason. Do not use a custom logpath for now!
    .PARAMETER -AdminPermissions
    Specifies if the script needs administration rights for permissions. If no administrator permissions are needed do not set this parameter
    .LINK
    https://github.com/pari-medical-holding-gmbh/Hyper-V-AutoPilot-VM
#>

param(
    [Parameter(Mandatory = $True)] [ValidateSet("Install", "Uninstall", "install", "uninstall")] [Alias('install')] [String] $InstallMode,
    [Parameter(Mandatory = $False)] [Alias('Path')] [String] $logpath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\",
    [Parameter(Mandatory = $False)] [Switch] $AdminPermissions = $false
)
$ExitCode = 0

# Check if Logfolder exists
If (!(test-path $logpath)) {
    New-Item -ItemType Directory -Force -Path $logpath >$null 2>&1
}

# Log Name will be Log Path provided above + ScriptName
$logpath = $logpath + "PARI-App-System-" + $MyInvocation.MyCommand.Name + ".log"
$logpathAlternative = $logpath + "_alternative.log"

#Check Log file for file length and delete input if file input exceeded limit.
function CheckLogFile ($FilePath, $MaxLineLength) {
    # Check if the file exists
    if (Test-Path $FilePath) {
        # Read the content of the file
        $Lines = Get-Content $FilePath

        if ($Lines.Count -gt $MaxLineLength) {

            # Keep the last 3 lines
            $LinesToKeep = $Lines[-3..-1]

            # Clear content of the file
            Clear-Content $FilePath

            # Append the last three lines back to the file
            Add-Content -Path $FilePath -Value $LinesToKeep
            Write-ToLog -Warning 1 -LogText "Log content cleared, except the last 3 lines, due to exceeding maximum amount of lines."
        }
    }
}

##Log Creation Function
function Write-ToLog {
    param (
        [string]$Warning,
        [string]$LogText
    )
    if ($null -eq $Warning -Or $Warning -eq "1") {
        $WarningText = "INFO:   "
    }
    elseif ($Warning -eq "2") {
        $WarningText = "WARNING:"
    }
    elseif ($Warning -eq "3") {
        $WarningText = "ERROR:  "
    }
    else {
        $WarningText = "        "
    }
    $TimeStr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    if ($Warning -eq "9") {
        Try {
            Add-Content $LogPath "$TimeStr || $WarningText || ##### $LogText #####" -ErrorAction Stop
        }
        Catch {
            Write-Warning "Cannot access log file $LogPath . Writing it to the alternative log file instead:  $LogPathAlternative "
            Add-Content $LogPathAlternative "$TimeStr || $WarningText || ##### $LogText #####"
        }
    }
    else {
        Try {
            Add-Content $LogPath "$TimeStr || $WarningText || $LogText" -ErrorAction Stop
        }
        Catch {
            Write-Warning "Cannot access log file $LogPath . Writing it to the alternative log file instead:  $LogPathAlternative "
            Add-Content $LogPathAlternative "$TimeStr || $WarningText || $LogText"
        }
    }
}

# Default Log Input
$DateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-ToLog -Warning 9 -LogText "Starting Log File of App Installation $($MyInvocation.MyCommand.Name)$AdditionalText from $DateTime"
Write-ToLog -Warning 9 -LogText "############"
Write-ToLog -Warning 1 -LogText "Work Directory: $(Get-Location)"
CheckLogFile -FilePath $LogPath -MaxLineLength 300

#Check for Administrator permissions if needed
if (($AdminPermissions -eq "true") -or ($AdminPermissions -eq "yes")) {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
        Write-ToLog -Warning 3 -LogText "Current user has no administrator permissions, but administrator permissions are needed due to parameter -AdminPermissions $AdminPermissions"
        Exit 2
    }
}

# -----

Write-ToLog -Warning 9 -LogText "Starting $InstallMode"

# ## INSTALLATION
if (($InstallMode -eq "Install") -or ($InstallMode -eq "i")) {

    #Status der Komponenten prüfen
    $WindowsFeatureStatus = (Get-WindowsOptionalFeature -FeatureName "Microsoft-Hyper-V" -Online).state

    #Windows Features aktivieren
    if ($WindowsFeatureStatus -ne 'Enabled') {
        try {
            Enable-WindowsOptionalFeature -FeatureName "Microsoft-Hyper-V" -All -Online -NoRestart
        }
        Catch {
            Write-ToLog -Warning 3 -LogText "Activating Windows Hyper-V Feature failed with error $_"
        }
        #Stauts der Komponenten prüfen
        $WindowsFeatureStatus = (Get-WindowsOptionalFeature -FeatureName "Microsoft-Hyper-V" -Online).state

        #Übergebe den String und Returncodes an DSM
        if ($WindowsFeatureStatus -eq 'Enabled') {
            Write-ToLog -Warning 1 -LogText "Activating Windows Hyper-V Feature succeded"
            $Exitcode = 3010
        }
        else {
            Write-ToLog -Warning 3 -LogText "Activating Windows Hyper-V Feature failed - $WindowsFeatureStatus"
            $Exitcode = 1
        }
    }
    else {
        Write-ToLog -Warning 1 -LogText "Hyper-V Feature is already installed."
        $Exitcode = 0
    }
    $users = (Get-WMIObject -class Win32_ComputerSystem | Select-Object username).username
    $Groupname = (Get-LocalGroup -Name "*Hyper*V*").Name
    $GroupMembers = (Get-LocalGroupMember -Group $Groupname).Name
    ForEach ($user in $users) {
        if (-Not($GroupMembers -contains $user)) {
            Write-ToLog -Warning 1 -LogText "Adding $user to $Groupname."
            Add-LocalGroupMember -Group $Groupname -Member $user
            if ($Exitcode -eq 0) {
                $Exitcode = 3010
            }
        }
    }
}

# ## UNINSTALLATION
if (($InstallMode -eq "Uninstall") -or ($InstallMode -eq "u")) {

    #Status der Komponenten prüfen
    $WindowsFeatureStatus = (Get-WindowsOptionalFeature -FeatureName "Microsoft-Hyper-V" -Online).state

    #Windows Features deaktivieren
    if ($WindowsFeatureStatus -eq 'Enabled') {
        try {
            Disable-WindowsOptionalFeature -FeatureName "Microsoft-Hyper-V" -Online -NoRestart
        }
        Catch {
            Write-ToLog -Warning 3 -LogText "Deactivating Windows Hyper-V Feature failed with error $_"
        }
    }
    else {
        Write-ToLog -Warning 1 -LogText "Hyper-V Feature is no installed - $WindowsFeatureStatus ."
    }
}

Write-ToLog -Warning 1 -LogText "Script finished with Exitcode $Exitcode"
Write-host "Script finished with Exitcode $Exitcode"
Exit $Exitcode