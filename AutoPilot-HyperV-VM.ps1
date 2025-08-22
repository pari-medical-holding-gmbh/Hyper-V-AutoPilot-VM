<#
    .NOTES
    Created at 22.11.2024
    Fabian Seitz - PARI GmbH
    .DESCRIPTION
    This script creates a new Hyper V VM and automatically joins it to AutoPilot/Intune
    .EXAMPLE
    Installation:   "%systemroot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" -noprofile -executionpolicy bypass -file .\AutoPilot-HyperV-VM.ps1 -InstallMode Install -AdminPermissions
    Uninstallation: "%systemroot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" -noprofile -executionpolicy bypass -file .\AutoPilot-HyperV-VM.ps1 -InstallMode Uninstall -AdminPermissions
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
    [Parameter(Mandatory = $True)] [ValidateSet("Install", "Uninstall", "install", "uninstall")] [String] $InstallMode,
    [Parameter(Mandatory = $False)] [String] $LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\",
    [Parameter(Mandatory = $False)] [Switch] $AdminPermissions = $false
)

$ExitCode = 0
$DateToday = Get-Date -Format "yyyy-MM-dd"

$ComputerName = (Get-ComputerInfo).CsName
$VMname = "VM-$ComputerName-$DateToday"

# Define standard paths and settings
$BasePath = "C:\ProgramData\HyperV\VMs"
$ISOName = "Windows_AutoPilot.iso"
$BasePathISO = $BasePath + "\" + $ISOName
$ISOPath = ".\" + $ISOName
#$AutounattendFile = ".\autounattend.xml"
$VMdir = "$BasePath\$VMname"
$VMCores = 2
$MinimumMemoryMB = 2048
$DefaultMemoryMB = 4096
$MinimumMemoryBytes = $MinimumMemoryMB * 1MB
$DefaultMemoryBytes = $DefaultMemoryMB * 1MB
$VMDISK = 53GB
$SwitchName = "Default Switch"
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
}

# Default Log Input
$DateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-ToLog -Warning 9 -LogText "Starting Log File of App Installation $($MyInvocation.MyCommand.Name) from $DateTime"
Write-ToLog -Warning 9 -LogText "############"
Write-ToLog -Warning 1 -LogText "Work Directory: $(Get-Location)"
CheckLogFile -FilePath $LogPath -MaxLineLength 200

#Check for Administrator permissions if needed
if (($AdminPermissions -eq $true)) {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
        Write-ToLog -Warning 3 -LogText "Current user has no administrator permissions, but administrator permissions are needed due to parameter -AdminPermissions $AdminPermissions"
        Exit 2
    }
}

# Check if Hyper-V is installed
if ((Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online).State -ne 'Enabled') {
    Write-ToLog -Warning 3 -LogText "Hyper-V is not installed. Please install Hyper-V before using this script."
    Exit 9
}

Write-ToLog -Warning 9 -LogText "Starting $InstallMode"

# Installation process
if ($InstallMode -eq "Install") {
    try {
        Get-Command Get-VM -errorAction Stop
    }
    Catch {
        Write-ToLog -Warning 3 -LogText "Hyper-V CMDlets are not detected. Most likely a restart is missing after Hyper V activation?"
        Exit 9
    }
    if (Get-VM -Name $VMname -ErrorAction SilentlyContinue) {
        Write-ToLog -Warning 2 -LogText "VM $VMname already exists. Skipping VM creation."
    }
    else {
        # Create VM directory if it does not exist
        if (!(Test-Path -Path $VMdir)) {
            New-Item -ItemType Directory -Path $VMdir -Force
        }

        $AvailableRAMMB = [math]::Round((Get-CimInstance -ClassName Win32_OperatingSystem).FreePhysicalMemory / 1KB)
        if ($AvailableRAMMB -lt $DefaultMemoryMB) {
            Write-ToLog -Warning 3 -LogText "There is less than $DefaultMemoryMB MB RAM available! Available RAM: $AvailableRAMMB MB. Stopping for now."
            Exit 1
        }

        # Check if the virtual hard disk already exists
        $VHDPath = "$VMdir\$VMname.vhdx"
        if (Test-Path -Path $VHDPath) {
            Write-ToLog -Warning 2 -LogText "VHD file already exists at $VHDPath. Reusing existing VHD."
        }
        else {
            # Create a new VM
            try {
                New-VM -Name $VMname -MemoryStartupBytes $DefaultMemoryBytes -BootDevice VHD -NewVHDPath $VHDPath `
                    -NewVHDSizeBytes $VMDISK -Generation 2 -SwitchName $SwitchName -Path $VMdir -ErrorAction Stop | Out-Null
                Write-ToLog -Warning 1 -LogText "VM $VMname created successfully with a new VHD."
            }
            Catch {
                Write-ToLog -Warning 3 -LogText "Error $_ while creating VM"
                $ExitCode = 3
            }
        }
    }

    # Dynamic allocation of host RAM (if no errors have occurred yet)
    if ($ExitCode -eq 0) {
        $HostRAMMB = [math]::Round((Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1MB)
        if ($HostRAMMB -ge 16000) {
            $MaxMemoryMB = 8192 # Max. 8 GB for Hosts with >=16 GB
        }
        elseif ($HostRAMMB -ge 8000) {
            $MaxMemoryMB = 6144 # Max. 6 GB for Hosts with >=8 GB
        }
        else {
            $MaxMemoryMB = 4096 # Max. 4 GB for Hosts with <8 GB
        }
        $MaxMemoryBytes = $MaxMemoryMB * 1MB

        Write-ToLog -Warning 1 -LogText "Detected $HostRAMMB MB ($AvailableRAMMB MB currently available) host RAM. Using the following RAM assignments for VM - Max memory: $MaxMemoryMB - Min memory $MinimumMemoryMB - Default memory $DefaultMemoryMB"
        try {
            Set-VM -Name $VMname -ProcessorCount $VMCores -DynamicMemory -MemoryStartupBytes $DefaultMemoryBytes `
                -MemoryMinimumBytes $MinimumMemoryBytes -MemoryMaximumByte $MaxMemoryBytes -CheckpointType Disabled -AutomaticCheckpointsEnabled:$false -ErrorAction Stop | Out-Null
            Write-ToLog -Warning 1 -LogText "VM hardware configuration set successfully."
        }
        Catch {
            Write-ToLog -Warning 3 -LogText "Error $_ while setting VM hardware configurations."
            $ExitCode = 4
        }
    }

    # Set TPM, Secure Boot, DVD Drive, and Start the VM
    if ($ExitCode -eq 0) {
        try {
            Set-VMKeyProtector -VMName $VMname -NewLocalKeyProtector -ErrorAction Stop
            Enable-VMTPM -VMName $VMname -ErrorAction Stop
            Write-ToLog -Warning 1 -LogText "TPM enabled for VM."
        }
        Catch {
            Write-ToLog -Warning 3 -LogText "Error $_ while enabling VM TPM."
            $ExitCode = 5
        }
        if (Test-Path -Path $ISOPath) {
            Copy-Item -Path $ISOPath -Destination $BasePath -Recurse
        }
        else {
            Write-ToLog -Warning 3 -LogText "ISO not found at $ISOPath. Cannot proceed"
            Exit 11
        }
        try {
            Add-VMDvdDrive -VMName $VMname -Path $BasePathISO -ErrorAction Stop
            Write-ToLog -Warning 1 -LogText "Added DVD drive for VM."
        }
        Catch {
            Write-ToLog -Warning 3 -LogText "Error $_ while setting boot order for VM."
            $ExitCode = 6
        }
        try {
            Set-VMDvdDrive -VMName $VMname -Path $BasePathISO -ErrorAction Stop
            Write-ToLog -Warning 1 -LogText "DVD drive set successfully for VM."
        }
        Catch {
            Write-ToLog -Warning 3 -LogText "Error $_ while setting VM drive."
            $ExitCode = 6
        }
        #try {
        #    Set-VMFirmware -VMName $VMname -FirstBootDevice (Get-VMDvdDrive -VMName $VMname) -ErrorAction Stop
        #    Write-ToLog -Warning 1 -LogText "Boot order set successfully: ISO as first boot device."
        #} Catch {
        #    Write-ToLog -Warning 3 -LogText "Error $_ while setting boot order for VM."
        #    $ExitCode = 7
        #}
        try {
            Set-VMFirmware -VMName $VMname -EnableSecureBoot On -ErrorAction Stop
            Write-ToLog -Warning 1 -LogText "Secure boot enabled for VM."
        }
        Catch {
            Write-ToLog -Warning 3 -LogText "Error $_ while enabling secure boot for VM."
            $ExitCode = 7
        }
        try {
            $CurrentBootOrder = Get-VMFirmware -VMName $VMname | Select-Object -ExpandProperty BootOrder
            # Remove network boot
            $FilteredBootOrder = $CurrentBootOrder | Where-Object { $_.BootType -ne 'Network' }
            # Set new Bootorder
            Set-VMFirmware -VMName $VMname -BootOrder $FilteredBootOrder
            Write-ToLog -Warning 1 -LogText "Removed network boot. New bootorder: $FilteredBootOrder"
        }
        catch {
            Write-ToLog -Warning 2 -LogText "Error while removing network boot: $_"
        }

        #Disable Hyper V Advanced Features, otherwise a AutoPilot VM will detect itself as VM machine
        try {
            Set-VMhost -EnableEnhancedSessionMode $False
        }
        catch {
            Write-ToLog -Warning 2 -LogText "Error while disabling advanced features: $_"
        }

        #### The following is not needed, a custom ISO has been created.
        # Define the path for RegisterVM-ResetLocally.ps1 script
        #$RegisterScriptPath = ".\RegisterVM-ResetLocally.ps1"

        # Include RegisterVM-ResetLocally.ps1 in the custom ISO
        #if (Test-Path $RegisterScriptPath) {
        #    Write-ToLog -Warning 1 -LogText "Copying RegisterVM-ResetLocally.ps1 to the ISO folder."

        # Copy the script to the ISO folder
        #    Copy-Item -Path $RegisterScriptPath -Destination "$ISOFolder\Setup\RegisterVM-ResetLocally.ps1"
        #} else {
        #    Write-ToLog -Warning 2 -LogText "RegisterVM-ResetLocally.ps1 not found. Proceeding without it."
        #}

        # Include autounattend.xml in the custom ISO
        #if (Test-Path $AutounattendFile) {
        #    $ISOWithAnswerFile = "$BasePath\Windows11-Autounattend.iso"
        #    if (Test-Path $ISOWithAnswerFile) { Remove-Item $ISOWithAnswerFile -Force }

        #    Write-ToLog -Warning 1 -LogText "Creating a new ISO including autounattend.xml and RegisterVM-ResetLocally.ps1."
        #    try {
        #        $SourceISO = Resolve-Path $ISOPath
        #        $AutounattendXML = Resolve-Path $AutounattendFile
        #        $ISOFolder = "$BasePath\ISOFiles"

        # Prepare folders for custom ISO
        #        if (Test-Path $ISOFolder) { Remove-Item -Recurse -Force $ISOFolder }
        #        New-Item -ItemType Directory -Path $ISOFolder | Out-Null

        # Extract the original ISO
        #        Write-ToLog -Warning 1 -LogText "Extracting the original Windows 11 ISO."
        #        Mount-DiskImage -ImagePath $SourceISO -StorageType ISO | Out-Null
        #        $MountedDrive = (Get-Volume -FileSystemLabel "CCCOMA_X64*" | Select-Object -First 1).DriveLetter + ":\"

        # Copy content to the custom folder
        #        Copy-Item -Path "$MountedDrive*" -Destination $ISOFolder -Recurse
        #        Dismount-DiskImage -ImagePath $SourceISO | Out-Null

        # Add autounattend.xml
        #        Copy-Item -Path $AutounattendXML -Destination "$ISOFolder\autounattend.xml"

        # Create the new ISO
        #        oscdimg.exe -m -o -u2 -udfver102 -bootdata:2#p0,e,b"$ISOFolder\boot\etfsboot.com" "$ISOFolder" "$ISOWithAnswerFile"

        #        Write-ToLog -Warning 1 -LogText "Custom ISO created successfully: $ISOWithAnswerFile"
        #        Set-VMDvdDrive -VMName $VMname -Path $ISOWithAnswerFile
        #    } catch {
        #        Write-ToLog -Warning 3 -LogText "Error creating custom ISO: $_"
        #    }
        #} else {
        #    Write-ToLog -Warning 2 -LogText "autounattend.xml not found. Proceeding without automated installation."
        #    Set-VMDvdDrive -VMName $VMname -Path $ISOPath
        #}

        if ($ExitCode -eq 0) {
            # Start the VM
            try {
                Start-VM -VMName $VMname -ErrorAction Stop
                Write-ToLog -Warning 1 -LogText "VM $VMname started. Windows installation will proceed automatically."
            }
            Catch {
                Write-ToLog -Warning 3 -LogText "Error $_ while booting VM."
                $ExitCode = 8
            }
        }
    }
}

# Uninstallation process
if ($InstallMode -eq "Uninstall") {
    try {
        # Identify all VMs matching the naming pattern
        $VMsToDelete = Get-VM | Where-Object { $_.Name -like "VM-*-*" }
        foreach ($VM in $VMsToDelete) {
            Write-ToLog -Warning 1 -LogText "Removing VM: $($VM.Name)"
            Stop-VM -Name $VM.Name -Force -ErrorAction SilentlyContinue
            Remove-VM -Name $VM.Name -Force
            Remove-Item -Recurse -Force "$BasePath\$($VM.Name)"
        }
        If (Test-Path $BasePathISO) {
            Remove-Item -Recurse -Force $BasePathISO
        }
    }
    catch {
        Write-ToLog -Warning 1 -LogText "Error during uninstallation: $_"
        $ExitCode = 1
    }
}

Write-ToLog -Warning 1 -LogText "Script completed with ExitCode $ExitCode"
Exit $ExitCode