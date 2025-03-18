<#
    .NOTES
    Created at 05.12.2024
    Fabian Seitz - PARI GmbH
    .DESCRIPTION
    This script helps creating a custom ISO for Hyper-V deployment
    .EXAMPLE
    "%systemroot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" -noprofile -executionpolicy bypass -file .\PrepareISO.ps1
    .LINK
    https://github.com/pari-medical-holding-gmbh/Hyper-V-AutoPilot-VM
#>

# Paths
$Username = "username"
$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\"
$SourceFolder = "C:\Users\$Username\Downloads\W11_EN"
$WIMFile = "$SourceFolder\sources\install.wim"
$MountDir = "C:\Users\$Username\Downloads\ISO_MountedImage"
$GitHubSourceDir = "C:\Users\$Username\GitHub\Intune-packaging\Helpers_Win32Scripts\Autopilot-VM-HyperV"
$ScriptPath = "$GitHubSourceDir\RegisterVM-ResetLocally.ps1"
$autounattendPath = "$GitHubSourceDir\autounattend.xml"
$NewISOPath = "$GitHubSourceDir\Windows11.iso"

# Check if Logfolder exists
If (!(test-path $logpath)) {
    New-Item -ItemType Directory -Force -Path $logpath >$null 2>&1
}

# Log Name will be Log Path provided above + ScriptName
#$logpathfolder = $logpath
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
Write-ToLog -Warning 9 -LogText "Starting Log File of App Installation $($MyInvocation.MyCommand.Name) from $DateTime"
Write-ToLog -Warning 9 -LogText "############"
Write-ToLog -Warning 1 -LogText "Work Directory: $(Get-Location)"
CheckLogFile -FilePath $LogPath -MaxLineLength 200

# Check for Administrator permissions
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Warning "Administrator permissions are required."
    Exit 2
}

# Check if Logfolder exists
If (!(test-path $SourceFolder)) {
    Write-ToLog -Warning 1 -LogText "Connot find sources at $SourceFolder . Please provide the sources (download the ISO and extract it to $SourceFolder)"
    Write-Host "Connot find sources at $SourceFolder . Please provide the sources (download the ISO and extract it to $SourceFolder)"
    Exit 3
}

## It would be prettiest to mount the install.wim, deploy the script and remount, but that never worked, so we will start the script from the "DVD Drive" (ISO)

# Prepare MountDir
#If (Test-Path $MountDir) {
#    Remove-Item -Recurse -Force $MountDir
#}
#New-Item -ItemType Directory -Force -Path $MountDir >$null 2>&1

#Write-Host "Mounting and committing changes from $WIMFile to $MountDir. This may take a while!"
#Write-ToLog -Warning 1 -LogText "Mounting and committing changes from $WIMFile to $MountDir. This may take a while!"

# Mount the WIM
#dism /Mount-Wim /WimFile:$WIMFile /Index:1 /MountDir:$MountDir
#If (!(Test-Path "$MountDir\ProgramData\PARI")) {
#    New-Item -ItemType Directory -Force -Path "$MountDir\ProgramData\PARI" >$null 2>&1
#}
#Copy-Item -Path $ScriptPath -Destination "$MountDir\ProgramData\PARI\" -Force
#dism /Unmount-Wim /MountDir:$MountDir /Commit

# Copy Autounattend.xml into the source folder
Write-Host "Copying autounattend.xml to $SourceFolder..."
Write-ToLog -Warning 1 -LogText "Copying autounattend.xml to $SourceFolder..."
Copy-Item -Path $autounattendPath -Destination $SourceFolder -Force

Write-Host "Copying $ScriptPath to $SourceFolder..."
Write-ToLog -Warning 1 -LogText "Copying $ScriptPath to $SourceFolder..."
Copy-Item -Path $ScriptPath -Destination $SourceFolder -Force

# Überprüfen, ob die Datei im Zielordner vorhanden ist
if (-not (Test-Path "$SourceFolder\autounattend.xml")) {
    Write-Error "autounattend.xml is missing in $SourceFolder after copying??"
    Write-ToLog -Warning 3 -LogText "autounattend.xml is missing in $SourceFolder after copying??"
    Exit 2
}

# Modify boot files
$basePath = "$SourceFolder\efi\microsoft\boot"
$filesToRename = @(
    @{Source = "cdboot.efi"; Target = "cdboot_prompt.efi"; ReplaceWith = "cdboot_noprompt.efi" },
    @{Source = "efisys.bin"; Target = "efisys_prompt.bin"; ReplaceWith = "efisys_noprompt.bin" }
)

foreach ($file in $filesToRename) {
    $sourceFile = Join-Path -Path $basePath -ChildPath $file.Source
    $replacementFile = Join-Path -Path $basePath -ChildPath $file.ReplaceWith
    $targetFile = Join-Path -Path $basePath -ChildPath $file.Target

    if (Test-Path $targetFile) {
        Remove-Item -Path $targetFile -Force
    }

    if (Test-Path $sourceFile) {
        Rename-Item -Path $sourceFile -NewName $file.Target
        Write-ToLog -Warning 1 -LogText "Renamed: $sourceFile -> $($file.Target)"
    }
    else {
        Write-ToLog -Warning 3 -LogText "File not found: $sourceFile"
    }

    if (Test-Path $replacementFile) {
        Rename-Item -Path $replacementFile -NewName $file.Source
        Write-ToLog -Warning 1 -LogText "Renamed: $replacementFile -> $($file.Source)"
    }
    else {
        Write-ToLog -Warning 3 -LogText "File not found: $replacementFile"
    }
}

# Create ISO
if (Test-Path "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe") {
    # Paths to the boot sectors from the source folder
    $etfsbootPath = Join-Path -Path $SourceFolder -ChildPath "boot\etfsboot.com"
    $efisys = "efisys.bin"
    $efisys_noprompt = "efisys_noprompt.bin"
    $efisysPath = Join-Path -Path $SourceFolder -ChildPath "efi\microsoft\boot\$efisys"
    $ADKPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\"

    # Required for BIOS boot
    if (-not (Test-Path $etfsbootPath)) {
        $ADKPathETFSBOOT = Join-Path -Path $ADKPath -ChildPath "etfsboot.com"
        Write-Warning "etfsboot.com not found at $etfsbootPath. Using files from ADK instead: $ADKPathETFSBOOT"
        Write-ToLog -Warning 2 -LogText "etfsboot.com not found at $etfsbootPath. Using files from ADK instead: $ADKPathETFSBOOT"
        if (-not (Test-Path $ADKPathETFSBOOT)) {
            Write-Warning "etfsboot.com not found at $ADKPathETFSBOOT. Please provide the file."
            Write-ToLog -Warning 3 -LogText "etfsboot.com not found at $ADKPathETFSBOOT. Please provide the file."
        }
        else {
            Copy-Item -Path $ADKPathETFSBOOT -Destination $etfsbootPath -Force
        }
    }
    # Required for UEFI Boot
    if (-not (Test-Path $efisysPath)) {
        Write-Warning "$efisys not found at $efisysPath. Using files from ADK instead: $ADKPath$efisys_noprompt"
        Write-ToLog -Warning 3 -LogText "$efisys not found at $efisysPath. Using files from ADK instead: $ADKPath$efisys_noprompt"
        if (-not (Test-Path $ADKPath$efisys_noprompt)) {
            Write-Error "$efisys_noprompt not found at $ADKPath$efisys_noprompt. Please provide the file."
            Write-ToLog -Warning 3 -LogText "$efisys_noprompt not found at $ADKPath$efisys_noprompt. Please provide the file."
            Exit 2
        }
        else {
            Copy-Item -Path $ADKPath$efisys_noprompt -Destination $efisysPath -Force
        }
    }

    If (Test-Path $NewISOPath) {
        Remove-Item -Recurse -Force $NewISOPath
    }

    $parameters = @(
        "-m"
        "-o"
        "-u2"
        "-bootdata:1#pEF,e,b$efisysPath"
        $SourceFolder
        $NewISOPath
    )

    # Create the ISO
    & "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe" $parameters

    #$script = Get-Content -Path .\RegisterVM-ResetLocally.ps1 -Raw
    #$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
    #$encoded = [Convert]::ToBase64String($bytes)
    #Write-Host "RegisterVM-ResetLocally.ps1 RAW Content for autounattend.xml:"
    #Write-ToLog -Warning 1 -LogText "RegisterVM-ResetLocally.ps1 RAW Content for autounattend.xml:"
    #Write-Host "$encoded"
    #Write-ToLog -Warning 1 -LogText "$encoded"

    Write-Host "Script completed. New ISO can be found here: $NewISOPath"
    Write-ToLog -Warning 1 -LogText "New ISO can be found here: $NewISOPath"
}
else {
    Write-Warning "Windows ADK is not installed or oscdimg.exe is missing."
    Write-ToLog -Warning 3 -LogText "Windows ADK is not installed or oscdimg.exe is missing."
}

Write-ToLog -Warning 1 -LogText "Script completed."
Exit 0