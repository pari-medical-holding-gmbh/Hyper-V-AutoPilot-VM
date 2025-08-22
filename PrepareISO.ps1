<#
    .NOTES
    Created at 05.12.2024 // Updated at 22.08.2025
    Fabian Seitz - PARI GmbH

    .LINK
    https://github.com/pari-medical-holding-gmbh/Hyper-V-AutoPilot-VM

    .SYNOPSIS
    PrepareISO - create a customized Windows ISO for Hyper-V AutoPilot deployment.

    .DESCRIPTION
    This script mounts or uses a Windows ISO / extracted source folder, injects autounattend and helper scripts,
    and rebuilds a customized ISO for Hyper-V deployments.

    .PARAMETER Source
    Path to an ISO file (.iso) or to a folder that already contains extracted Windows setup files.
    If omitted the script will search the SearchFolder for suitable Windows 11 ISOs.

    .PARAMETER SearchFolder
    Folder to search for ISOs when -Source is not provided. Default: $env:USERPROFILE\Downloads

    .EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\PrepareISO.ps1 -Source "C:\Users\you\Downloads\en-us_windows_11.iso"

    .EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\PrepareISO.ps1 -SearchFolder "D:\ISO_Archive"
#>

param(
    [string]$Source = "",                                # Path to ISO file (.iso) or folder with extracted sources
    [string]$SearchFolder = "$env:USERPROFILE\Downloads" # folder to search for ISOs when $Source not given
)

# Resolve and prepare paths
$Username = $env:USERNAME
$DefaultSourceFolder = "$env:USERPROFILE\Downloads\W11_EN"
$SourceFolder = $DefaultSourceFolder

# flag: true => folder was created/populated by this script from an ISO and may be removed after completion
$ShouldRemoveSourceFolder = $true

# Use the folder where this script resides for helper files
$GitHubSourceDir = $PSScriptRoot
$ScriptPath = Join-Path -Path $GitHubSourceDir -ChildPath "RegisterVM-ResetLocally.ps1"
$autounattendPath = Join-Path -Path $GitHubSourceDir -ChildPath "autounattend.xml"
$NewISOPath = Join-Path -Path $GitHubSourceDir -ChildPath "Windows_AutoPilot.iso"

# Paths
$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\"

# Check if Logfolder exists
If (!(test-path $logpath)) {
    New-Item -ItemType Directory -Force -Path $logpath >$null 2>&1
}

# Log Name will be Log Path provided above + ScriptName
#$logpathfolder = $logpath
$logpath = $logpath + "App-System-" + $MyInvocation.MyCommand.Name + ".log"
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
    Write-Host "$TimeStr || $WarningText || ##### $LogText #####"
}

# Helper: ensure destination exists and optionally clear if it contains files
function EnsureDestinationFolder {
    param(
        [string]$Dest,
        [bool]$ClearIfContainsFiles = $true
    )
    if (-not (Test-Path $Dest)) {
        New-Item -ItemType Directory -Force -Path $Dest | Out-Null
        Write-ToLog -Warning 1 -LogText "Created destination folder $Dest"
    }
    else {
        $items = Get-ChildItem -Path $Dest -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin '.', '..' }
        if ($items.Count -gt 0 -and $ClearIfContainsFiles) {
            Write-ToLog -Warning 2 -LogText "Destination $Dest contains files. Clearing contents."
            try {
                $items | Remove-Item -Recurse -Force -ErrorAction Stop
                Write-ToLog -Warning 1 -LogText "Cleared contents of $Dest"
            }
            catch {
                Write-ToLog -Warning 3 -LogText "Failed to clear $($Dest): $($_.Exception.Message)"
            }
        }
    }
}

# Helper: wait for ISO mount and return drive root (or $null) by checking for expected files on new drives
function Get-MountedIsoDriveLetter {
    param([string]$IsoPath, [int]$TimeoutSeconds = 30)
    $end = (Get-Date).AddSeconds($TimeoutSeconds)

    # Collect set of current drive roots to ignore
    $known = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root

    while ((Get-Date) -lt $end) {
        # Look for any drive letter that contains Windows setup files (setup.exe or sources\install.wim)
        $volumes = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root
        foreach ($root in $volumes) {
            if ($known -contains $root) { continue } # skip drives we saw before mount (but still check them below)
            # Check for indicators of Windows ISO root
            if ((Test-Path (Join-Path $root "setup.exe")) -or (Test-Path (Join-Path $root "sources\install.wim"))) {
                return $root
            }
        }
        # As fallback check all drives (in case mount reused an existing root)
        foreach ($root in $volumes) {
            if ((Test-Path (Join-Path $root "setup.exe")) -or (Test-Path (Join-Path $root "sources\install.wim"))) {
                return $root
            }
        }
        Start-Sleep -Seconds 1
    }
    return $null
}

# Helper: robust copy with fallback to robocopy on failure (handles file or directory sources, supports wildcard like "D:\*")
function Copy-WithFallback {
    param([string]$Source, [string]$Destination)

    try {
        Copy-Item -Path $Source -Destination $Destination -Recurse -Force -ErrorAction Stop
        return $true
    }
    catch {
        Write-ToLog -Warning 2 -LogText "Copy-Item failed from '$Source' to '$Destination': $($_.Exception.Message). Trying robocopy fallback."

        # Determine source directory and optional filename argument for robocopy
        $srcDir = $null; $fileArg = $null

        if ($Source -match '[\*\?\[]') {
            # wildcard present like D:\*
            $srcDir = Split-Path $Source
            $fileArg = '*'
        }
        elseif (Test-Path $Source -PathType Container) {
            $srcDir = $Source
            $fileArg = '*'
        }
        elseif (Test-Path $Source) {
            # It's a file
            $srcDir = Split-Path $Source -Parent
            $fileArg = Split-Path $Source -Leaf
        }
        else {
            # fallback: try parent segment
            $srcDir = Split-Path $Source -Parent
            $fileArg = '*'
        }

        if (-not (Test-Path $srcDir)) {
            try { New-Item -ItemType Directory -Force -Path $srcDir | Out-Null } catch {}
        }
        if (-not (Test-Path $Destination)) {
            try { New-Item -ItemType Directory -Force -Path $Destination | Out-Null } catch {}
        }

        $robArgs = @($srcDir, $Destination, $fileArg, "/MIR", "/NFL", "/NDL", "/NJH", "/NJS", "/nc", "/ns", "/np")
        try {
            $proc = Start-Process -FilePath "robocopy.exe" -ArgumentList $robArgs -Wait -PassThru -NoNewWindow
            if ($proc.ExitCode -lt 8) {
                Write-ToLog -Warning 1 -LogText "robocopy succeeded (ExitCode $($proc.ExitCode)) copying $srcDir -> $Destination"
                return $true
            }
            else {
                Write-ToLog -Warning 3 -LogText "robocopy failed (ExitCode $($proc.ExitCode)) copying $srcDir -> $Destination"
                return $false
            }
        }
        catch {
            Write-ToLog -Warning 3 -LogText "robocopy fallback failed: $($_.Exception.Message)"
            return $false
        }
    }
}

# Resolve user-provided Source (ISO file or folder) or search for suitable ISO
$resolvedSource = $null
if (-not [string]::IsNullOrWhiteSpace($Source)) {
    $resolved = Resolve-Path -LiteralPath $Source -ErrorAction SilentlyContinue
    if ($resolved) { $resolvedSource = $resolved.Path } else { $resolvedSource = $Source }
}

if ($resolvedSource -and (Test-Path $resolvedSource) -and -not (Get-Item $resolvedSource).PSIsContainer -and ($resolvedSource.ToLower().EndsWith('.iso'))) {
    # User supplied an ISO file path
    $isoPath = (Resolve-Path $resolvedSource).Path
    Write-ToLog -Warning 1 -LogText "ISO provided by user: $isoPath"
    EnsureDestinationFolder -Dest $SourceFolder -ClearIfContainsFiles $true

    try {
        $disk = Mount-DiskImage -ImagePath $isoPath -PassThru -ErrorAction Stop
        Start-Sleep -Seconds 1
        $mountRoot = Get-MountedIsoDriveLetter -IsoPath $isoPath -TimeoutSeconds 20
        # after a successful copy from mounted ISO set the removal flag
        if ($mountRoot) {
            Write-ToLog -Warning 1 -LogText "Copying files from $mountRoot to $SourceFolder"
            $ok = Copy-WithFallback -Source (Join-Path $mountRoot '*') -Destination $SourceFolder
            if ($ok) {
                Write-ToLog -Warning 1 -LogText "Copied ISO contents to $SourceFolder"
                $ShouldRemoveSourceFolder = $true
            }
            else {
                Write-ToLog -Warning 3 -LogText "Failed copying ISO contents from $mountRoot to $SourceFolder"
            }
        }
        else {
            Write-ToLog -Warning 3 -LogText "Could not determine mounted drive for ISO $isoPath"
        }
    }
    catch {
        Write-ToLog -Warning 3 -LogText "Error mounting/copying ISO $($isoPath): $($_.Exception.Message)"
    }
    finally {
        try { Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue } catch {}
    }

    $WIMFile = "$SourceFolder\sources\install.wim"
}
elseif ($resolvedSource -and (Test-Path $resolvedSource) -and (Get-Item $resolvedSource).PSIsContainer) {
    # User supplied a folder
    $folderCount = (Get-ChildItem -Path $resolvedSource -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin '.', '..' } | Measure-Object).Count
    if ($folderCount -gt 0) {
        Write-ToLog -Warning 1 -LogText "Using provided folder as SourceFolder: $resolvedSource"
        $SourceFolder = $resolvedSource
        $WIMFile = "$SourceFolder\sources\install.wim"
    }
    else {
        Write-ToLog -Warning 2 -LogText "Provided folder exists but is empty: $resolvedSource"
        # fall through to search/default behavior below
    }
}
else {
    # No direct input or input not found -> try to search for ISOs in $SearchFolder
    Write-ToLog -Warning 1 -LogText "No valid ISO or populated folder provided. Searching for Windows 11 ISOs in $SearchFolder"
    $isoCandidates = @()
    try {
        if (Test-Path $SearchFolder) {
            # prefer filenames containing windows and 11 (case-insensitive)
            $isoCandidates = Get-ChildItem -Path $SearchFolder -Filter *.iso -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'windows' -and $_.Name -match '11' } |
            Sort-Object LastWriteTime -Descending
        }
    }
    catch {
        Write-ToLog -Warning 2 -LogText "ISO search failed in $($SearchFolder): $($_.Exception.Message)"
    }

    if ($isoCandidates -and $isoCandidates.Count -gt 0) {
        $isoPath = $isoCandidates[0].FullName
        Write-ToLog -Warning 1 -LogText "Found ISO: $isoPath (using newest match)"
        EnsureDestinationFolder -Dest $SourceFolder -ClearIfContainsFiles $true

        try {
            $disk = Mount-DiskImage -ImagePath $isoPath -PassThru -ErrorAction Stop
            Start-Sleep -Seconds 1
            $mountRoot = Get-MountedIsoDriveLetter -IsoPath $isoPath -TimeoutSeconds 30
            if ($mountRoot) {
                $ok = Copy-WithFallback -Source (Join-Path $mountRoot '*') -Destination $SourceFolder
                if ($ok) { Write-ToLog -Warning 1 -LogText "Copied ISO contents to $SourceFolder" } else { Write-ToLog -Warning 3 -LogText "Failed copying ISO contents from $mountRoot to $SourceFolder" }
            }
            else {
                Write-ToLog -Warning 3 -LogText "Could not determine mounted drive for ISO $isoPath"
            }
        }
        catch {
            Write-ToLog -Warning 3 -LogText "Error mounting/copying ISO $($isoPath): $($_.Exception.Message)"
        }
        finally {
            try { Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue } catch {}
        }

        $WIMFile = "$SourceFolder\sources\install.wim"
    }

    # No ISO found - if default source folder exists with files, continue with warning; otherwise behave like previous error
    if ((Test-Path $SourceFolder) -and ((Get-ChildItem -Path $SourceFolder -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin '.', '..' }).Count -gt 0)) {
        Write-ToLog -Warning 2 -LogText "No ISO found; using existing populated folder $SourceFolder"
        Write-Host "Warning: No ISO found, using existing populated folder $SourceFolder"
        $WIMFile = "$SourceFolder\sources\install.wim"
    }
    else {
        Write-ToLog -Warning 1 -LogText "Cannot find ISO or source files. Please provide source ISO or extracted folder."
        Write-Host "Cannot find ISO or source files. Please provide source ISO or extracted folder."
        New-Item -ItemType Directory -Force -Path $SourceFolder >$null 2>&1
        Exit 3
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

# Check if SourceFolder exists
If (!(test-path $SourceFolder)) {
    Write-ToLog -Warning 1 -LogText "Connot find sources at $SourceFolder . Please provide the sources (download the ISO and extract it to $SourceFolder)"
    Write-Host "Connot find sources at $SourceFolder . Please provide the sources (download the ISO and extract it to $SourceFolder)"
    New-Item -ItemType Directory -Force -Path $SourceFolder >$null 2>&1
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
#If (!(Test-Path "$MountDir\ProgramData\HyperV")) {
#    New-Item -ItemType Directory -Force -Path "$MountDir\ProgramData\HyperV" >$null 2>&1
#}
#Copy-Item -Path $ScriptPath -Destination "$MountDir\ProgramData\HyperV\" -Force
#dism /Unmount-Wim /MountDir:$MountDir /Commit

# Copy Autounattend.xml into the source folder
# NOTE: moved autounattend/script copy below after we verified SourceFolder has content
# VERIFY SOURCEFOLDER POPULATED BEFORE COPYING autounattend / script
$hasSetup = Test-Path (Join-Path $SourceFolder "setup.exe")
$hasWim = Test-Path (Join-Path $SourceFolder "sources\install.wim")
if (-not ($hasSetup -or $hasWim)) {
    Write-ToLog -Warning 3 -LogText "SourceFolder appears incomplete: missing setup.exe and sources\install.wim in $SourceFolder. Aborting to avoid creating invalid ISO."
    # Remove partially copied content if any
    try {
        if ((Test-Path $SourceFolder) -and (Get-ChildItem -Path $SourceFolder -Force -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0) {
            Write-ToLog -Warning 2 -LogText "Cleaning up partially populated SourceFolder $SourceFolder"
            Get-ChildItem -Path $SourceFolder -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-ToLog -Warning 2 -LogText "Cleanup of SourceFolder failed: $($_.Exception.Message)"
    }
    Exit 3
}

# Now copy autounattend.xml and Register script into populated SourceFolder (robust copy + logging)
Write-ToLog -Warning 1 -LogText "Copying autounattend.xml to $SourceFolder..."
try {
    $ok = Copy-WithFallback -Source $autounattendPath -Destination (Join-Path $SourceFolder (Split-Path $autounattendPath -Leaf))
    if (-not $ok) { throw "Copy failed" }
}
catch {
    Write-ToLog -Warning 3 -LogText "Failed to copy autounattend.xml into $($SourceFolder): $($_.Exception.Message)"
    Exit 2
}

Write-ToLog -Warning 1 -LogText "Copying $ScriptPath to $SourceFolder..."
try {
    $ok = Copy-WithFallback -Source $ScriptPath -Destination (Join-Path $SourceFolder (Split-Path $ScriptPath -Leaf))
    if (-not $ok) { throw "Copy failed" }
}
catch {
    Write-ToLog -Warning 3 -LogText "Failed to copy $ScriptPath into $($SourceFolder): $($_.Exception.Message)"
    Exit 2
}

# Check if the file exists in the destination folder
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
        try {
            Remove-Item -Path $targetFile -Force
        }
        Catch {
            Write-ToLog -Warning 3 -LogText "Failed to remove $($targetFile): $($_.Exception.Message)"
        }
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
        Write-ToLog -Warning 2 -LogText "etfsboot.com not found at $etfsbootPath. Using files from ADK instead: $ADKPathETFSBOOT"
        if (-not (Test-Path $ADKPathETFSBOOT)) {
            Write-ToLog -Warning 3 -LogText "etfsboot.com not found at $ADKPathETFSBOOT. Please provide the file."
        }
        else {
            # Ensure parent directory exists before copying
            $parent = Split-Path -Parent $etfsbootPath
            if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
            try {
                $ok = Copy-WithFallback -Source $ADKPathETFSBOOT -Destination $etfsbootPath
                if (-not $ok) { Write-ToLog -Warning 3 -LogText "Failed to place etfsboot.com into $etfsbootPath" }
            }
            catch {
                Write-ToLog -Warning 3 -LogText "Error copying etfsboot.com: $($_.Exception.Message)"
            }
        }
    }
    # Required for UEFI Boot
    if (-not (Test-Path $efisysPath)) {
        Write-ToLog -Warning 3 -LogText "$efisys not found at $efisysPath. Using files from ADK instead: $ADKPath$efisys_noprompt"
        if (-not (Test-Path $ADKPath$efisys_noprompt)) {
            Write-ToLog -Warning 3 -LogText "$efisys_noprompt not found at $ADKPath$efisys_noprompt. Please provide the file."
            Exit 2
        }
        else {
            # Ensure parent directory exists before copying
            $parentEfi = Split-Path -Parent $efisysPath
            if (-not (Test-Path $parentEfi)) { New-Item -ItemType Directory -Force -Path $parentEfi | Out-Null }
            try {
                $ok = Copy-WithFallback -Source (Join-Path $ADKPath $efisys_noprompt) -Destination $efisysPath
                if (-not $ok) { Write-ToLog -Warning 3 -LogText "Failed to place $efisys into $efisysPath" }
            }
            catch {
                Write-ToLog -Warning 3 -LogText "Error copying efisys: $($_.Exception.Message)"
            }
        }
    }

    If (Test-Path $NewISOPath) {
        try {
            Remove-Item -Recurse -Force $NewISOPath
        }
        Catch {
            Write-ToLog -Warning 3 -LogText "Failed to remove $($NewISOPath): $($_.Exception.Message)"
            $NewISOPath = Join-Path -Path $GitHubSourceDir -ChildPath "Windows_AutoPilot_new.iso"
            Write-ToLog -Warning 1 -LogText "Writing new ISO to $NewISOPath instead"
        }
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
    $oscdimg = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
    try {
        $procOutput = & $oscdimg @parameters 2>&1
        foreach ($line in $procOutput) { Write-ToLog -Warning 1 -LogText "oscdimg: $line" }
    }
    catch {
        Write-ToLog -Warning 3 -LogText "oscdimg invocation failed: $($_.Exception.Message)"
    }

    # Verify generated ISO size (avoid tiny ISO produced from empty source)
    if (Test-Path $NewISOPath) {
        try {
            $sizeMB = (Get-Item $NewISOPath).Length / 1MB
            if ($sizeMB -lt 100) {
                Write-ToLog -Warning 3 -LogText "Generated ISO $NewISOPath is unexpectedly small (${([math]::Round($sizeMB,2))} MB). Deleting and aborting."
                try { Remove-Item -Path $NewISOPath -Force -ErrorAction SilentlyContinue } catch {}
                Exit 4
            }
        }
        catch {
            Write-ToLog -Warning 2 -LogText "Could not determine ISO size for $($NewISOPath): $($_.Exception.Message)"
        }
    }
    else {
        Write-ToLog -Warning 3 -LogText "oscdimg did not produce an ISO at $NewISOPath"
        Exit 4
    }

    # if we reach here ISO was created successfully -> remove temporary SourceFolder if we created it
    if ($ShouldRemoveSourceFolder) {
        try {
            Write-ToLog -Warning 1 -LogText "Removing temporary SourceFolder $SourceFolder to free disk space."
            Remove-Item -Path $SourceFolder -Recurse -Force -ErrorAction Stop
            Write-ToLog -Warning 1 -LogText "Removed temporary SourceFolder $SourceFolder successfully."
        }
        catch {
            Write-ToLog -Warning 2 -LogText "Failed to remove temporary SourceFolder $($SourceFolder): $($_.Exception.Message). Manual cleanup may be required."
        }
    }
    else {
        Write-ToLog -Warning 1 -LogText "SourceFolder was not created by this script; skipping automatic deletion."
    }

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
    Write-ToLog -Warning 3 -LogText "Windows ADK is not installed or oscdimg.exe is missing."
}

Write-ToLog -Warning 1 -LogText "Script completed."
Exit 0