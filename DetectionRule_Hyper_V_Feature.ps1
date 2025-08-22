<#
    .NOTES
    Created at 08.02.2023
    Fabian Seitz - PARI GmbH
    .DESCRIPTION
    Detection Rule script to scan for Hyper V activation
    .LINK
    https://github.com/pari-medical-holding-gmbh/Hyper-V-AutoPilot-VM
#>

if ([String]::IsNullOrEmpty($LogPath)) {
    #If no Log Path was provided use default log path below
    $LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\"
}

# Check if Logfolder exists
If (!(test-path $LogPath)) {
    New-Item -ItemType Directory -Force -Path $LogPath >$null 2>&1
}

# Log Name will be Log Path provided above + ScriptName
$LogPath = $LogPath + "Detect-System-" + "DetectionRule_Windows_HyperV_Feature" + ".log"
$LogPathAlternative = $LogPath + "_alternative.log"

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

# Log Creation Function
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
Write-ToLog -Warning 9 -LogText "Starting Log File of App Hyper-V Feature Detection from $DateTime"
Write-ToLog -Warning 9 -LogText "############"
CheckLogFile -FilePath $LogPath -MaxLineLength 200

#Status der Komponenten prüfen
$WindowsFeatureStatus = (Get-WindowsOptionalFeature -FeatureName "Microsoft-Hyper-V" -Online).state

#Windows Features aktivieren
if ($WindowsFeatureStatus -eq 'Enabled') {
    $Exitcode = 0
    Write-ToLog -Warning 1 -LogText "Feature seems to be installed: $WindowsFeatureStatus"
}
else {
    $Exitcode = 1
    Write-ToLog -Warning 3 -LogText "Feature seems to be not installed: $WindowsFeatureStatus"
}
$Groupname = (Get-LocalGroup -Name "*Hyper*V*").Name
$GroupMembers = (Get-LocalGroupMember -Group $Groupname).Name
$users = (Get-WMIObject -class Win32_ComputerSystem | Select-Object username).username
ForEach ($user in $users) {
    if (-Not($GroupMembers -contains $user)) {
        Write-ToLog -Warning 3 -LogText "$user is missing in group $Groupname. Adding person now."
        Add-LocalGroupMember -Group $Groupname -Member $user
    }
}

Write-ToLog -Warning 1 -LogText "Script finished with Exitcode $ExitCode"
Write-Host "Script finished with Exitcode $ExitCode"
Exit $ExitCode