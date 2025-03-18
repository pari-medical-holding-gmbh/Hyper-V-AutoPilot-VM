# Automated Hyper-V AutoPilot VM Deployment

This repository contains all necessary scripts and instructions for the automated deployment of a Hyper-V-based AutoPilot VM via Intune/Company Portal.
The goal is to streamline the provisioning process of virtual machines for testing and development purposes.

## Features
- **Fully automated deployment** of Windows 10/11 VMs on Hyper-V
- **Integration with Intune AutoPilot** for seamless device provisioning
- **Customizable configurations** for VM size, OS, and network settings
- **Automatic enrollment** into Microsoft Endpoint Manager (Intune)

## Prerequisites on the End machine where the Hyper V VM is being used
Before running the scripts, ensure the following requirements are met:

- Windows 10/11 Pro, Enterprise, or Server with Hyper-V enabled
- PowerShell 5.1 or later
- Windows AutoPilot configured in Intune
- Internet access for downloading required files and enrolling the VM

## Installation & Usage

### 1. Clone the Repository
```powershell
git clone https://github.com/pari-medical-holding-gmbh/HyperV-AutoPilot-VM.git
cd HyperV-AutoPilot-VM
```

## Preparations
### Create a new Enterprise Application
Name it anything you like and create the new [Enterprise application](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview). Afterwards switch to the corresponding (named the same) Enterprise Registration -> API permissions and add a new permission:
1. Choose "Microsoft Graph"
2. Select "Application permissions"
3. Add those three permissions: Device.Read.All & DeviceManagementManagedDevices.Read.All & DeviceManagementServiceConfig.ReadWrite.All
4. Create a new secret at "Certificates & secrets"
5. Temporary write down the secret, will be needed afterwards.

### Prepare the ISO
#### Download the latest ISO from Microsoft
I recommend using the latest patched Enterprise ISO from [here](https://my.visualstudio.com/downloads) or from the MS Admin Portal (needs license admin permission and a working contract with Microsoft).

#### Change / Update the autounattend.xml
This should mostly already work, if you rename some scripts, be sure to update the paths at the autounattend.xml too.

#### Change / Update the RegisterVM-ResetLocally.ps1
The script is functional, but the app secrets and credentials need to be provided. So please change those three variables:
```powershell
$TenantId = "add your tenant ID here", # Can be optained [here](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/TenantOverview.ReactView/initialValue//tabId//recommendationResourceId//fromNav/Identity)
$AppId = "add the app ID here", # Add the application ID from the enterprise registration
$AppSecret = "add the app secret here", # Enter the previously created Enterprise registration secret
```

#### Prepare the Windows ISO
##### Install Windows ADK
The Windows Assessment and Deployment Kit (ADK) will be used to access oscdimg.exe for building the ISO. You cann install the ADK with winget for example:
```powershell
winget install Microsoft.WindowsADK
```

##### Run PrepareISO.ps1
First change the # Paths variables in the script to your working paths for the ISO and where the finished ISO should be created at.
Afterwards start a terminal with administrative privileagues and run PrepareISO.ps1

## Create a Win32 application for Intune
Put the new ISO + AutoPilot-HyperV-VM.ps1 into a new folder and then create a new .intunewin file with [Microsoft Win32 Content Prep Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool).

### Upload it to Intune
Upload the file to Intune and use the following commands for install/uninstall:

install: "%systemroot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" -noprofile -executionpolicy bypass -file .\AutoPilot-HyperV-VM.ps1 -InstallMode Install -AdminPermissions

uninstall: "%systemroot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" -noprofile -executionpolicy bypass -file .\AutoPilot-HyperV-VM.ps1 -InstallMode Uninstall -AdminPermissions

### Optional, create a Hyper V package to activate Hyper V as a dependency through Intune
See Hyper_V_Feature.ps1 & DetectionRule_Hyper_V_Feature.ps1

## Logs and Troubleshooting
- Logs are stored in `$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\PARI-App-System-AutoPilot-HyperV-VM.ps1.log`
- If enrollment fails, check Intune Device Management Portal for errors

# Support
This software is provided as it is with absolutly NO support provided! GitHub issues will not be actively watched.