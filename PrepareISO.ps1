<#
    .NOTES
    Created at 05.12.2024 // Updated at 10.10.2025
    Fabian Seitz - PARI GmbH

    .LINK
    https://github.com/pari-medical-holding-gmbh/Hyper-V-AutoPilot-VM

    .SYNOPSIS
    PrepareISO - create a customized Windows ISO for Hyper-V, Parallels and VMware AutoPilot deployment.

    .DESCRIPTION
    This script uses a single autounattend.xml template. It mounts or uses a Windows ISO, detects
    the architecture, image index, language, and version. It then dynamically updates the XML template
    with all detected information, injects helper scripts and VMware drivers (for amd64), and finally
    rebuilds a fully customized ISO for unattended deployment.

    .PARAMETER Source
    Path to an ISO file (.iso) or to a folder that already contains extracted Windows setup files.
    If omitted the script will search the SearchFolder for suitable Windows 11 ISOs.

    .PARAMETER SearchFolder
    Folder to search for ISOs when -Source is not provided. Default: $env:USERPROFILE\Downloads

    .PARAMETER NoVMWareDriver
    Switch to disable VMware driver injection. Enabled by default.

    .PARAMETER AutounattendOnly
    Switch to only inject autounattend.xml, no VMware drivers, Scripts and more (default: false).

    .EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\PrepareISO.ps1 -Source "C:\Users\you\Downloads\de-de_windows_11_x64.iso"

    .EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\PrepareISO.ps1 -SearchFolder "D:\ISO_Archive"
#>

param(
    [string]$Source = "",                                 # Path to ISO file (.iso) or folder with extracted sources
    [string]$SearchFolder = "$env:USERPROFILE\Downloads", # folder to search for ISOs when $Source not given
    [Switch]$NoVMWareDriver = $false,                     # switch to disable VMware driver injection (default: enabled), will also be disabled if $AutounattendOnly is set to true
    [Switch]$AutounattendOnly = $false,                   # switch to only inject autounattend.xml, no VMware drivers (default: false)
    [string]$OutFileName = "Windows_AutoPilot.iso"        # output file name for the customized ISO
)

# Resolve and prepare paths
$Username = $env:USERNAME
$DefaultSourceFolder = "$env:USERPROFILE\Downloads\W11_Sources"
$SourceFolder = $DefaultSourceFolder

# flag: true => folder was created/populated by this script from an ISO and may be removed after completion
$ShouldRemoveSourceFolder = $true

# Use the folder where this script resides for helper files
$GitHubSourceDir = $PSScriptRoot
$ScriptPath = Join-Path -Path $GitHubSourceDir -ChildPath "RegisterVM-ResetLocally.ps1"
# autounattendPath will be determined dynamically after architecture detection
$autounattendPath = $null
$NewISOPath = Join-Path -Path $GitHubSourceDir -ChildPath $OutFileName

# Paths
$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\"

# Check if Logfolder exists
If (!(test-path $logpath)) {
    New-Item -ItemType Directory -Force -Path $logpath >$null 2>&1
}

# Log Name will be Log Path provided above + ScriptName
$logpath = $logpath + "Script-System-" + $MyInvocation.MyCommand.Name + ".log"
$logpathAlternative = $logpath + "_alternative.log"

#Check Log file for file length and delete input if file input exceeded limit.
function CheckLogFile ($FilePath, $MaxLineLength) {
    if (Test-Path $FilePath) {
        $Lines = Get-Content $FilePath
        if ($Lines.Count -gt $MaxLineLength) {
            $LinesToKeep = $Lines[-3..-1]
            Clear-Content $FilePath
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
    Write-Host "$TimeStr || $WarningText || $LogText"
}

# Default Log Input
$DateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-ToLog -Warning 9 -LogText "Starting Log File of App Installation $($MyInvocation.MyCommand.Name) from $DateTime"
Write-ToLog -Warning 9 -LogText "############"
Write-ToLog -Warning 1 -LogText "Work Directory: $(Get-Location)"
CheckLogFile -FilePath $LogPath -MaxLineLength 200

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
    $known = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root
    while ((Get-Date) -lt $end) {
        $volumes = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root
        foreach ($root in $volumes) {
            if ($known -contains $root) { continue }
            if ((Test-Path (Join-Path $root "setup.exe")) -or (Test-Path (Join-Path $root "sources\install.wim"))) {
                return $root
            }
        }
        foreach ($root in $volumes) {
            if ((Test-Path (Join-Path $root "setup.exe")) -or (Test-Path (Join-Path $root "sources\install.wim"))) {
                return $root
            }
        }
        Start-Sleep -Seconds 1
    }
    return $null
}

# Helper: robust copy with fallback to robocopy on failure
function Copy-WithFallback {
    param([string]$Source, [string]$Destination)
    try {
        Copy-Item -Path $Source -Destination $Destination -Recurse -Force -ErrorAction Stop
        return $true
    }
    catch {
        Write-ToLog -Warning 2 -LogText "Copy-Item failed from '$Source' to '$Destination': $($_.Exception.Message). Trying robocopy fallback."
        $srcDir = $null; $fileArg = $null
        if ($Source -match '[\*\?\[]') {
            $srcDir = Split-Path $Source
            $fileArg = '*'
        }
        elseif (Test-Path $Source -PathType Container) {
            $srcDir = $Source
            $fileArg = '*'
        }
        elseif (Test-Path $Source) {
            $srcDir = Split-Path $Source -Parent
            $fileArg = Split-Path $Source -Leaf
        }
        else {
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
    $isoPath = (Resolve-Path $resolvedSource).Path
    Write-ToLog -Warning 1 -LogText "ISO provided by user: $isoPath"
    EnsureDestinationFolder -Dest $SourceFolder -ClearIfContainsFiles $true
    try {
        $disk = Mount-DiskImage -ImagePath $isoPath -PassThru -ErrorAction Stop
        Start-Sleep -Seconds 1
        $mountRoot = Get-MountedIsoDriveLetter -IsoPath $isoPath -TimeoutSeconds 20
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
    $folderCount = (Get-ChildItem -Path $resolvedSource -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin '.', '..' } | Measure-Object).Count
    if ($folderCount -gt 0) {
        Write-ToLog -Warning 1 -LogText "Using provided folder as SourceFolder: $resolvedSource"
        $SourceFolder = $resolvedSource
        $WIMFile = "$SourceFolder\sources\install.wim"
    }
    else {
        Write-ToLog -Warning 2 -LogText "Provided folder exists but is empty: $resolvedSource"
    }
}
else {
    Write-ToLog -Warning 1 -LogText "No valid ISO or populated folder provided. Searching for Windows 11 ISOs in $SearchFolder"
    $isoCandidates = @()
    try {
        if (Test-Path $SearchFolder) {
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

# Verify Sourcefolder populated
$hasSetup = Test-Path (Join-Path $SourceFolder "setup.exe")
$hasWim = Test-Path (Join-Path $SourceFolder "sources\install.wim")
if (-not ($hasSetup -or $hasWim)) {
    Write-ToLog -Warning 3 -LogText "SourceFolder appears incomplete: missing setup.exe and sources\install.wim in $SourceFolder. Aborting to avoid creating invalid ISO."
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

# Detect Architecture from EFI boot files for reliability
$imageArchitecture = $null
Write-ToLog -Warning 1 -LogText "Detecting architecture from EFI boot files..."
if (Test-Path (Join-Path $SourceFolder "efi\boot\bootx64.efi")) {
    $imageArchitecture = "AMD64"
    Write-ToLog -Warning 1 -LogText "Found bootx64.efi, architecture detected as AMD64."
}
elseif (Test-Path (Join-Path $SourceFolder "efi\boot\bootaa64.efi")) {
    $imageArchitecture = "ARM64"
    Write-ToLog -Warning 1 -LogText "Found bootaa64.efi, architecture detected as ARM64."
}
else {
    Write-ToLog -Warning 3 -LogText "Could not determine architecture. Neither bootx64.efi nor bootaa64.efi found in efi\boot directory."
    Exit 3
}

# Dynamic Image Index, Language and Version Detection
$proImageIndex = $null
$isoLanguage = $null
$imageVersion = $null
try {
    Write-ToLog -Warning 1 -LogText "Scanning for Windows Pro edition in $WIMFile..."
    $allImages = Get-WindowsImage -ImagePath $WIMFile -ErrorAction Stop

    # Prioritize "Windows 11 Pro", then any other "Pro" edition, avoiding "N", "Education", etc.
    $proImage = $allImages | Where-Object { $_.ImageName -eq "Windows 11 Pro" } | Select-Object -First 1
    if (-not $proImage) {
        $proImage = $allImages | Where-Object { $_.ImageName -like "*Pro*" -and $_.ImageName -notlike "*N" -and $_.ImageName -notlike "*Education*" -and $_.ImageName -notlike "*Workstations*" } | Select-Object -First 1
    }

    if ($proImage) {
        $proImageIndex = $proImage.ImageIndex
        Write-ToLog -Warning 1 -LogText "Found '$($proImage.ImageName)' at Index $proImageIndex."

        try {
            Write-ToLog -Warning 1 -LogText "Checking image index $proImageIndex in $WIMFile for language..."
            $imageInfo = Get-WindowsImage -ImagePath $WIMFile -Index $proImageIndex -ErrorAction Stop

            $isoLanguage = $imageInfo.Languages
            Write-ToLog -Warning 1 -LogText "Detected image language(s): $($isoLanguage -join ', '). Choosing first ($($isoLanguage[0])) as primary."
            $isoLanguage = $isoLanguage[0]
        }
        catch {
            Write-ToLog -Warning 3 -LogText "Failed to check languages in WIM file: $($_.Exception.Message)"
            Write-ToLog -Warning 2 -LogText "Could not verify language packs. The installation might fail if en-US is missing."
        }

        if ([string]::IsNullOrWhiteSpace($isoLanguage)) {
            throw "Could not parse default language from wim file."
        }

        $imageVersion = $imageInfo.Version

        if ([string]::IsNullOrWhiteSpace($imageVersion)) {
            Write-ToLog -Warning 2 -LogText "Could not parse version from wim file."
        }
        else {
            Write-ToLog -Warning 1 -LogText "Detected Windows Version via wim file: '$($imageInfo.Version)' from '$($imageInfo.ModifiedTime)'."
        }
    }
    else {
        throw "Could not find a suitable 'Pro' edition inside the WIM file. Please use a different ISO."
    }

    # Define the single autounattend.xml template to use
    $autounattendPath = Join-Path -Path $GitHubSourceDir -ChildPath "autounattend.xml"
    if (-not (Test-Path $autounattendPath)) {
        throw "Required configuration template file not found at $autounattendPath"
    }
    Write-ToLog -Warning 1 -LogText "Using base configuration file: $autounattendPath"
}
catch {
    Write-ToLog -Warning 3 -LogText "Failed during image detection: $($_.Exception.Message)"
    Exit 3
}

# Update autounattend.xml with dynamic architecture, index and language
$tempAutounattendPath = Join-Path $env:TEMP "autounattend_modified.xml"
try {
    Write-ToLog -Warning 1 -LogText "Updating unattended file with dynamic settings..."
    $xml = [xml](Get-Content -Path $autounattendPath -Raw)
    $nsmgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $nsmgr.AddNamespace("ui", "urn:schemas-microsoft-com:unattend")

    # Dynamically set processorArchitecture on all relevant components
    $archNodes = $xml.SelectNodes("//*[@processorArchitecture]", $nsmgr)
    $archValue = $imageArchitecture.ToLower() # The XML wants 'amd64' or 'arm64'
    Write-ToLog -Warning 1 -LogText "Updating processorArchitecture to '$archValue' for $($archNodes.Count) components..."
    foreach ($node in $archNodes) {
        $node.processorArchitecture = $archValue
    }

    # Update Image Index
    $indexNode = $xml.SelectSingleNode("//ui:ImageInstall/ui:OSImage/ui:InstallFrom/ui:MetaData[ui:Key='/IMAGE/INDEX']/ui:Value", $nsmgr)
    if ($indexNode) {
        Write-ToLog -Warning 1 -LogText "Updating image index from '$($indexNode.'#text')' to '$proImageIndex'."
        $indexNode.'#text' = $proImageIndex.ToString()
    }
    else {
        Write-ToLog -Warning 2 -LogText "Could not find the Image Index Value node in the autounattend.xml."
    }

    # Update all language and locale settings
    $languageNodes = @(
        "//ui:settings[@pass='windowsPE']/ui:component[@name='Microsoft-Windows-International-Core-WinPE']/ui:SetupUILanguage/ui:UILanguage",
        "//ui:settings[@pass='windowsPE']/ui:component[@name='Microsoft-Windows-International-Core-WinPE']/ui:InputLocale",
        "//ui:settings[@pass='windowsPE']/ui:component[@name='Microsoft-Windows-International-Core-WinPE']/ui:SystemLocale",
        "//ui:settings[@pass='windowsPE']/ui:component[@name='Microsoft-Windows-International-Core-WinPE']/ui:UILanguage",
        "//ui:settings[@pass='windowsPE']/ui:component[@name='Microsoft-Windows-International-Core-WinPE']/ui:UserLocale",
        "//ui:settings[@pass='oobeSystem']/ui:component[@name='Microsoft-Windows-International-Core']/ui:InputLocale",
        "//ui:settings[@pass='oobeSystem']/ui:component[@name='Microsoft-Windows-International-Core']/ui:SystemLocale",
        "//ui:settings[@pass='oobeSystem']/ui:component[@name='Microsoft-Windows-International-Core']/ui:UILanguage",
        "//ui:settings[@pass='oobeSystem']/ui:component[@name='Microsoft-Windows-International-Core']/ui:UserLocale"
    )

    foreach ($xpath in $languageNodes) {
        $node = $xml.SelectSingleNode($xpath, $nsmgr)
        if ($node) {
            # For InputLocale, Windows Setup accepts the culture name (e.g., de-DE) and maps it to the default keyboard.
            Write-ToLog -Warning 1 -LogText "Updating language node '$($node.LocalName)' from '$($node.'#text')' to '$isoLanguage'."
            $node.'#text' = $isoLanguage
        }
    }

    # Set a safe fallback language
    $fallbackNode = $xml.SelectSingleNode("//ui:settings[@pass='windowsPE']/ui:component[@name='Microsoft-Windows-International-Core-WinPE']/ui:UILanguageFallback", $nsmgr)
    if ($fallbackNode) {
        $fallbackNode.'#text' = "en-US"
        Write-ToLog -Warning 1 -LogText "Set UILanguageFallback to en-US."
    }

    $xml.Save($tempAutounattendPath)
    Write-ToLog -Warning 1 -LogText "Temporarily saved updated configuration to $tempAutounattendPath"
}
catch {
    Write-ToLog -Warning 3 -LogText "Failed to modify the autounattend.xml file: $($_.Exception.Message)"
    Exit 3
}

if (($NoVMWareDriver) -or ($AutounattendOnly)) {
    Write-ToLog -Warning 1 -LogText "VMware driver injection disabled by parameter."
}
elseif ($imageArchitecture -ne 'AMD64') {
    Write-ToLog -Warning 2 -LogText "VMware driver injection skipped. It is only supported for AMD64 architecture. Detected architecture: $imageArchitecture"
}
else {
    # Inject VMware drivers (PVSCSI) from VMware Tools ISO
    Write-ToLog -Warning 9 -LogText "Starting VMware Driver Injection for AMD64"
    $vmwareToolsBaseUrl = "https://packages.vmware.com/tools/releases/latest/windows/"
    $tempDir = Join-Path $env:TEMP "VMwareTools"
    $downloadedIsoPath = Join-Path $tempDir "VMware-tools-windows.iso"
    $driverDestPath = Join-Path $SourceFolder "drivers\pvscsi"
    $vmwareToolsIsoUrl = $null
    try {
        Write-ToLog -Warning 1 -LogText "Searching for the latest VMware Tools ISO at $vmwareToolsBaseUrl..."
        $response = Invoke-WebRequest -Uri $vmwareToolsBaseUrl -UseBasicParsing
        $isoFilename = ($response.Links | Where-Object { $_.href -like 'VMware-tools-windows-*.iso' } | Select-Object -ExpandProperty href | Sort-Object -Descending | Select-Object -First 1)
        if ($isoFilename) {
            $vmwareToolsIsoUrl = $vmwareToolsBaseUrl + $isoFilename
            Write-ToLog -Warning 1 -LogText "Found latest ISO: $isoFilename"
        }
        else {
            Write-ToLog -Warning 2 -LogText "Could not automatically find the latest VMware Tools ISO file."
            # Using a known recent version as a fallback
            $vmwareToolsIsoUrl = "https://packages.vmware.com/tools/releases/latest/windows/VMware-tools-windows-13.0.1-24843032.iso"
            Write-ToLog -Warning 2 -LogText "Falling back to hardcoded URL: $vmwareToolsIsoUrl"
        }
        if (-not (Test-Path $tempDir)) {
            New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
            Write-ToLog -Warning 1 -LogText "Created temp directory for VMware Tools at $tempDir"
        }
        if (-not (Test-Path $downloadedIsoPath)) {
            Write-ToLog -Warning 1 -LogText "Downloading VMware Tools ISO from $vmwareToolsIsoUrl..."
            Write-Host "Downloading VMware Tools ISO, this might take a moment..."
            Invoke-WebRequest -Uri $vmwareToolsIsoUrl -OutFile $downloadedIsoPath
            Write-ToLog -Warning 1 -LogText "Download complete."
        }
        else {
            Write-ToLog -Warning 1 -LogText "VMware Tools ISO already exists at $downloadedIsoPath. Skipping download."
        }
        Write-ToLog -Warning 1 -LogText "Mounting VMware Tools ISO..."
        $mountResult = Mount-DiskImage -ImagePath $downloadedIsoPath -PassThru -ErrorAction Stop
        $driveLetter = ($mountResult | Get-Volume).DriveLetter
        $mountRoot = "$($driveLetter):\"
        if ($mountRoot) {
            Write-ToLog -Warning 1 -LogText "VMware Tools ISO mounted to $mountRoot"
            $driverSourcePath = Join-Path $mountRoot "Program Files\VMware\VMware Tools\Drivers\pvscsi\Win10\amd64"
            if (-not (Test-Path $driverSourcePath)) {
                Write-ToLog -Warning 3 -LogText "PVSCSI driver source path not found at $driverSourcePath. Aborting driver injection."
            }
            else {
                if (-not (Test-Path $driverDestPath)) {
                    New-Item -ItemType Directory -Force -Path $driverDestPath | Out-Null
                }
                Write-ToLog -Warning 1 -LogText "Copying PVSCSI drivers from $driverSourcePath to $driverDestPath"
                $copyOK = Copy-WithFallback -Source "$driverSourcePath\*" -Destination $driverDestPath
                if ($copyOK) {
                    Write-ToLog -Warning 1 -LogText "Successfully copied VMware PVSCSI drivers."
                }
                else {
                    Write-ToLog -Warning 3 -LogText "Failed to copy VMware PVSCSI drivers."
                }
            }
        }
        else {
            Write-ToLog -Warning 3 -LogText "Failed to get drive letter for mounted VMware Tools ISO."
        }
    }
    catch {
        Write-ToLog -Warning 3 -LogText "An error occurred during VMware driver injection: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path $downloadedIsoPath) {
            $mountedImage = Get-DiskImage -ImagePath $downloadedIsoPath -ErrorAction SilentlyContinue
            if ($mountedImage -and $mountedImage.Attached) {
                Write-ToLog -Warning 1 -LogText "Dismounting VMware Tools ISO."
                Dismount-DiskImage -ImagePath $downloadedIsoPath -ErrorAction SilentlyContinue
            }
        }
    }
    Write-ToLog -Warning 9 -LogText "VMware Driver Injection finished"
}

# Now copy the MODIFIED autounattend.xml and Register script into populated SourceFolder
Write-ToLog -Warning 1 -LogText "Copying modified autounattend.xml to $SourceFolder\autounattend.xml..."
try {
    # Always copy to a file named 'autounattend.xml' in the root for Windows Setup to find it
    $ok = Copy-WithFallback -Source $tempAutounattendPath -Destination (Join-Path $SourceFolder "autounattend.xml")
    if (-not $ok) { throw "Copy failed" }
}
catch {
    Write-ToLog -Warning 3 -LogText "Failed to copy autounattend.xml into $($SourceFolder): $($_.Exception.Message)"
    Exit 2
}

if ($AutounattendOnly) {
    Write-ToLog -Warning 1 -LogText "Script injection disabled by AutounattendOnly parameter."
}
else {
    $oemDir = Join-Path -Path $SourceFolder -ChildPath 'sources\$OEM$\$$\System32'
    Write-ToLog -Warning 1 -LogText "Creating OEM directory for script persistence at $oemDir"
    New-Item -ItemType Directory -Path $oemDir -Force | Out-Null
    $destScriptPath = Join-Path $oemDir (Split-Path $ScriptPath -Leaf)
    Write-ToLog -Warning 1 -LogText "Copying $ScriptPath to $destScriptPath for persistence..."
    try {
        $ok = Copy-WithFallback -Source $ScriptPath -Destination $destScriptPath
        if (-not $ok) { throw "Copy failed" }
    }
    catch {
        Write-ToLog -Warning 3 -LogText "Failed to copy $ScriptPath into $($destScriptPath): $($_.Exception.Message)"
        Exit 2
    }
}

if (-not (Test-Path "$SourceFolder\autounattend.xml")) {
    Write-Error "autounattend.xml is missing in $SourceFolder after copying??"
    Write-ToLog -Warning 3 -LogText "autounattend.xml is missing in $SourceFolder after copying??"
    Exit 2
}

if ($AutounattendOnly) {
    Write-ToLog -Warning 1 -LogText "Boot file manipulation disabled by AutounattendOnly parameter."
}
else {
    # Modify boot files to skip "Press any key to boot..."
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
            Write-ToLog -Warning 2 -LogText "File not found for renaming (this might be expected for some ISOs): $sourceFile"
        }
        if (Test-Path $replacementFile) {
            Rename-Item -Path $replacementFile -NewName $file.Source
            Write-ToLog -Warning 1 -LogText "Renamed: $replacementFile -> $($file.Source)"
        }
        else {
            Write-ToLog -Warning 2 -LogText "Replacement file not found (this might be expected): $replacementFile"
        }
    }
}

# Create ISO
if (Test-Path "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe") {
    $etfsbootPath = Join-Path -Path $SourceFolder -ChildPath "boot\etfsboot.com"
    $efisysPath = Join-Path -Path $SourceFolder -ChildPath "efi\microsoft\boot\efisys.bin"
    $ADKPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\"
    if (-not (Test-Path $etfsbootPath)) {
        $ADKPathETFSBOOT = Join-Path -Path $ADKPath -ChildPath "etfsboot.com"
        Write-ToLog -Warning 2 -LogText "etfsboot.com not found at $etfsbootPath. Using file from ADK instead: $ADKPathETFSBOOT"
        if (-not (Test-Path $ADKPathETFSBOOT)) {
            Write-ToLog -Warning 3 -LogText "etfsboot.com not found at $ADKPathETFSBOOT. Please provide the file."
        }
        else {
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
        "-bootdata:2#p0,e,b$etfsbootPath#pEF,e,b$efisysPath"
        $SourceFolder
        $NewISOPath
    )

    $oscdimg = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
    try {
        Write-ToLog -Warning 1 -LogText "Starting ISO creation with oscdimg.exe..."
        $procOutput = & $oscdimg @parameters 2>&1
        $relevantLines = $procOutput | Where-Object { $_ -match 'Scanning source tree|Writing \d+ files|After optimization|Done\.' }
        foreach ($line in $relevantLines) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                Write-ToLog -Warning 1 -LogText "oscdimg: $line"
            }
        }
        Write-ToLog -Warning 1 -LogText "ISO creation process finished."
    }
    catch {
        Write-ToLog -Warning 3 -LogText "oscdimg invocation failed: $($_.Exception.Message)"
    }

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

    if ($ShouldRemoveSourceFolder) {
        try {
            Write-ToLog -Warning 1 -LogText "Removing temporary SourceFolder $SourceFolder to free disk space."
            Remove-Item -Path $SourceFolder -Recurse -Force -ErrorAction Stop
            Remove-Item -Path $tempAutounattendPath -Force -ErrorAction SilentlyContinue
            Write-ToLog -Warning 1 -LogText "Removed temporary SourceFolder $SourceFolder successfully."
        }
        catch {
            Write-ToLog -Warning 2 -LogText "Failed to remove temporary SourceFolder $($SourceFolder): $($_.Exception.Message). Manual cleanup may be required."
        }
    }
    else {
        Write-ToLog -Warning 1 -LogText "SourceFolder was not created by this script; skipping automatic deletion."
    }
    Write-Host "Script completed. New ISO can be found here: $NewISOPath"
    Write-ToLog -Warning 1 -LogText "New ISO can be found here: $NewISOPath"
}
else {
    Write-ToLog -Warning 3 -LogText "Windows ADK is not installed or oscdimg.exe is missing."
}

Write-ToLog -Warning 1 -LogText "Script completed."
Exit 0