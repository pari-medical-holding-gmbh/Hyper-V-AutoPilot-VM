# Automated Hyper-V AutoPilot VM Deployment

This repository contains all necessary scripts and instructions for automated deployment of a Hyper-V-based AutoPilot VM via Intune / Company Portal. The goal is to streamline provisioning of virtual machines for testing and development. You can also use the generated ISO to automate VM deployment outside of Hyper-V, for example in your ESXi environment.

Important note: AutoPilot enrollment does NOT work for Self-Deploying; use User-Driven instead — otherwise it may fail at "Securing your hardware (0x800705b4)".

## Features
- Fully automated deployment of Windows 10/11 VMs
- Integration with Intune AutoPilot for seamless device provisioning
- Customizable configurations for VM size, OS, and network settings (on Hyper-V)
- Automatic enrollment into Microsoft Endpoint Manager (Intune)
- ISO preparation helper that injects autounattend and helper scripts into an ISO or source folder

## Repository scripts (short overview)
- AutoPilot-HyperV-VM.ps1 — Main script to create a Hyper-V VM, attach the prepared ISO and start the VM (Install / Uninstall modes).
- PrepareISO.ps1 — Creates a customized Windows ISO (or uses an extracted source folder). Copies autounattend.xml and RegisterVM-ResetLocally.ps1 into the source and rebuilds the ISO using oscdimg (Windows ADK). Supports -Source (ISO or folder) and -SearchFolder.
- RegisterVM-ResetLocally.ps1 — Collects Autopilot hardware info and uploads to Intune using an Entra (Azure AD) App Registration, then prepares/resets the VM locally to continue OOBE.
- Hyper_V_Feature.ps1 — Installs / uninstalls the Windows Hyper-V feature (designed for Intune distribution).
- DetectionRule_Hyper_V_Feature.ps1 — Detection script to be used as Intune detection rule for Hyper-V activation.

## Prerequisites on the host (where Hyper-V runs)
- Windows 10/11 Pro, Enterprise, or Server with Hyper-V available
- PowerShell 5.1 or later
- Windows AutoPilot configured in Intune
- Internet access (for downloads and AutoPilot upload)
- (Optional but required to build the ISO) Windows ADK installed to obtain oscdimg.exe (used by PrepareISO.ps1)

## Installation & Usage

### 1. Clone the Repository
```powershell
git clone https://github.com/pari-medical-holding-gmbh/HyperV-AutoPilot-VM.git
cd HyperV-AutoPilot-VM
```

### 2. Change / Update the RegisterVM-ResetLocally.ps1
This script uploads Autopilot data to Intune using an Entra App Registration (application permissions). Edit the following variables inside RegisterVM-ResetLocally.ps1 with your values BEFORE building the ISO (or supply via parameters if you run the script directly):

```powershell
$TenantId = "add your tenant ID here"   # Obtain in Entra ID / Azure AD
$AppId    = "add the app ID here"       # Application (client) ID of your App Registration
$AppSecret= "add the app secret here"   # Client secret created in Certificates & secrets
```

Notes:
- PrepareISO will copy RegisterVM-ResetLocally.ps1 into the root of the prepared media; autounattend.xml will call it during FirstLogon (autologon account PARIAdmin).
- RegisterVM-ResetLocally.ps1 also supports running in ResetOnly mode (to only perform the reset steps) via the -ResetOnly switch. includes parameter placeholders for TenantId / AppId / AppSecret. Downloads Sysinternals on demand to perform the local reset step.
- AutoPilot-HyperV-VM.ps1: creates VMs, copies the prepared ISO to C:\ProgramData\HyperV\VMs and starts the VM; supports uninstall mode to remove created VMs.

### 3. Prepare the ISO / Source for the VM
PrepareISO.ps1 now accepts either a path to an ISO or a folder with extracted Windows setup files. It will:
- If given an ISO, mount it and copy files to a working SourceFolder.
- If given a folder, use it as-is (must contain setup.exe or sources\install.wim).
- If no Source is provided it will search the provided SearchFolder for a matching Windows 11 ISO.
- Copy autounattend.xml and RegisterVM-ResetLocally.ps1 into the source and rebuild a custom ISO using oscdimg.exe (ADK).
- Use Copy-WithFallback (robust Copy-Item with robocopy fallback) to handle copy failures.
- Clean up temporary source folder when appropriate.

Examples:
- Use an ISO file:
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\PrepareISO.ps1 -Source "C:\Users\you\Downloads\en-us_windows_11.iso"
  ```

- Use an extracted folder:
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\PrepareISO.ps1 -Source "D:\ISO_Extracted\Win11"
  ```

- Let the script search your Downloads:
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\PrepareISO.ps1
  ```

Important:
- PrepareISO requires oscdimg.exe from the Windows ADK. If oscdimg is not present it will log an error and will not create the ISO.
- PrepareISO writes logs to %ProgramData%\Microsoft\IntuneManagementExtension\Logs\ (see Logs section).

### 4. Create a Win32 application for Intune
Put the new ISO and AutoPilot-HyperV-VM.ps1 into a folder and create a .intunewin package with the Microsoft Win32 Content Prep Tool.

Upload to Intune and use these commands for install/uninstall:

Install command:
```plaintext
"%systemroot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" -noprofile -executionpolicy bypass -file .\AutoPilot-HyperV-VM.ps1 -InstallMode Install -AdminPermissions
```

Uninstall command:
```plaintext
"%systemroot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" -noprofile -executionpolicy bypass -file .\AutoPilot-HyperV-VM.ps1 -InstallMode Uninstall -AdminPermissions
```

Optional: add Hyper_V_Feature.ps1 as a dependency (see Hyper_V_Feature.ps1 & DetectionRule_Hyper_V_Feature.ps1).

## Logs and Troubleshooting
- Scripts write logs to %ProgramData%\Microsoft\IntuneManagementExtension\Logs\ by default.
- PrepareISO writes detailed logs including oscdimg output; check the most recent App-System-PrepareISO.ps1.log.
- If PrepareISO fails to create an ISO:
  - Ensure Windows ADK is installed and oscdimg.exe is present.
  - Ensure SourceFolder contains setup.exe or sources\install.wim before building.
  - Ensure you have administrator privileges.
- If mounting or copying fails, check:
  - Admin rights
  - The ISO is not corrupted
  - Disk image cmdlets are available (Mount-DiskImage)
  - robocopy is available (used as fallback for robust copying)

## Support
- Use at your own risk. Adapt scripts to your environment and validate carefully.
- Contributions welcome via PRs; issues accepted but not actively watched.