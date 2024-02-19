THIS IS IN DEVELOPMENT


# Unified Labeling Support Tool

* [Introduction](#introduction)
   * [MIT License](#mit-license)
   * [Microsoft Privacy Statement](#microsoft-privacy-statement)
* [Requirements](#requirements)
   * [Internet access](#internet-access)
   * [Exchange Online PowerShell module](#exchange-online-module)
   * [AIPService module](#aipservice-module)
   * [Microsoft Azure Information Protection cmdlets](#aip-cmdlets)
   * [Microsoft Graph PowerShell modules](#graph-modules)
   * [Microsoft PowerShell](#ms-powershell)
* [Installation](#installation)
   * [Manual installation](#manual-installaltion)
   * [Check installation](#check-installation)
* [Uninstall](#uninstall)
* [User experience](#experience)
* [Features](#features)
   * [INFORMATION](#information)
   * [HELP](#help-win)
   * [RESET](#reset)
   * [RECORD PROBLEM](#record-problem)
   * [COLLECT](#collect)
     * [AIP service configuration](#aip-service-config)
     * [Protection templates](#protection-templates)
     * [Endpoint URLs](#endpoint-urls)
     * [Labels and polcies](#labels-and-policies)
     * [DLP rules and policies](#dlp-rules-and-policies)
     * [User license details](#user-license-details)
   * [COMPRESS LOGS](#compress-logs)
   * [EXIT](#exit)
* [Script log file](#script-log-file)
* [Log files and folders](#log-files)
* [Support](#support)
  * [Microsoft Support Policy](#support-policy)
  * [How to file issues and get help](#get-help)
 
## Introduction <a name="introduction"></a>

This information gives you background and usage information for the [UnifiedLabelingSupportTool](https://aka.ms/UnifiedLabelingSupportTool/Latest) PowerShell script module.

If you want to use the 'Unified Labeling Support Tool' on Apple macOS, you can find the corresponding help file [here](Manual-Mac.md).

Have you ever used the Sensitivity button in a [Microsoft 365 App](https://www.microsoft.com/en-us/microsoft-365)? If so, you've either used the [Azure Information Protection client](https://docs.microsoft.com/en-us/azure/information-protection/what-is-information-protection#aip-unified-labeling-client) or [Office's built-in labeling experience](https://docs.microsoft.com/en-us/microsoft-365/compliance/sensitivity-labels-office-apps?view=o365-worldwide). In case something doesn't work as expected or you don't see any labeling at all, the 'Unified Labeling Support Tool' will help you.

> [!important] 
> The Azure Information Protection (AIP) Unified Labeling add-in for Office will be retired on April 11th, 2024.
> 
> **What you need to do to prepare:**
>
> For detailed migration steps, refer to our playbook: [From bolt-on to built-in – Migrate from Azure Information Protection Add-in.](https://microsoft.github.io/ComplianceCxE/playbooks/AIP2MIPPlaybook/)
>
> For the announcement and FAQs of the retirement, refer to our blog: [Retirement notification for the Azure Information Protection Unified Labeling add-in for Office.](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/retirement-notification-for-the-azure-information-protection/ba-p/3791908)

The 'Unified Labeling Support Tool' provides the functionality to reset all corresponding Information Protection client services. Its main purpose is to delete the currently downloaded sensitivity label policies and thus reset all settings, and it can also be used to collect data for error analysis and troubleshooting.

With the 'Unified Labeling Support Tool', you can run the most common options without local administrative privileges:
[RESET](#reset), [RECORD PROBLEM](#record-problem), and COLLECT [Endpoint URLs](#endpoint-urls).

However, if you run the 'Unified Labeling Support Tool' with local administrative privileges, you will get some more collected logs ([RECORD PROBLEM](#record-problem)) and a complete [RESET](#reset) of all settings, instead of just user-specific settings being reset. By the way: The latter option is sufficient in most cases to reset [Microsoft 365 Apps](https://www.microsoft.com/en-us/microsoft-365), while a complete reset is usually useful for all other applications.

## MIT License <a name="mit-license"></a>

Copyright © Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 

## Microsoft Privacy Statement <a name="microsoft-privacy-statement"></a>

Your privacy is important to us. [This privacy statement](https://privacy.microsoft.com/en-US/privacystatement) explains the personal data Microsoft processes, how Microsoft processes it, and for what purposes.

## Requirements <a name="requirements"></a>

Before you can use the 'Unified Labeling Support Tool' make sure that your environment fulfils the following requierements. Please update your environment if necessary.

The 'Unified Labeling Support Tool' supports [Windows PowerShell 5.1](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-5.1) and Microsoft [PowerShell 7.2](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.2) (or higher) on the following operating systems:

   * Microsoft Windows 10, Windows 11, Windows Server 2012/R2, Windows Server 2016, Windows Server 2019, Windows Server 2022 and Apple macOS ([three most recent major versions](https://support.microsoft.com/en-us/office/upgrade-macos-to-continue-receiving-microsoft-365-and-office-for-mac-updates-16b8414f-08ec-4b24-8c91-10a918f649f8)).

The 'Unified Labeling Support Tool' supports the following Microsoft 365/Office versions:

   * Microsoft Office 2016, Microsoft Office 2019, Microsoft Office 2021, Microsoft 365 Apps and Microsoft 365 for Mac ([most recently released version](https://learn.microsoft.com/en-us/officeupdates/update-history-office-for-mac#release-history-for-office-for-mac)).

### Internet access <a name="internet-access"></a>

The 'Unified Labeling Support Tool' uses additional sources and services from the Internet to make its functionality fully available.

Unexpected errors may occur, and some features may be limited, if there is no connection to the Internet.

### Exchange Online PowerShell module <a name="exchange-online-module"></a>

The Microsoft [Exchange Online PowerShell module](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#release-notes) is required to proceed the option [Labels and policies](#labels-and-policies) from the menu [COLLECT](#collect).

If you do not have this module installed, the 'Unified Labeling Support Tool' will try to install the current version from [PowerShell Gallery](https://www.powershellgallery.com/packages/ExchangeOnlineManagement).

### AIPService module <a name="aipservice-module"></a>

The Microsoft [AIPService module](https://learn.microsoft.com/de-de/powershell/module/aipservice/?view=azureipps) is required to proceed the options [AIP service configuration](#aip-service-config), [Protection templates](#protection-templates), and [Endpoint URLs](#endpoint-urls) from the [COLLECT](#collect) menu.

If you do not have this module installed, the 'Unified Labeling Support Tool' will try to install the current version from [PowerShell Gallery](https://www.powershellgallery.com/packages/ExchangeOnlineManagement).

> **Note:**
> 
> Please note that the AIPService module does not support PowerShell 7. Therefore, unexpected errors may occur because the AIPService module run in compatibility mode.

### Microsoft Azure Information Protection cmdlets (optional) <a name="aip-cmdlets"></a>

The Microsoft Azure Information Protection cmdlets are installed with the [Azure Information Protection client](https://www.microsoft.com/en-us/download/details.aspx?id=53018). Please ensure to have the latest version of the "AzureInformationProtection" cmdlets installed by checking its [client version release history](https://docs.microsoft.com/en-us/azure/information-protection/rms-client/unifiedlabelingclient-version-release-history).

> **Note:**
> 
> Please note that the Azure Information Protection cmdlets do not support PowerShell 7. Therefore, unexpected errors may occur because Azure Information Protection cmdlets run in compatibility mode.

### Microsoft Graph PowerShell modules (optional) <a name="graph-modules"></a>

The Microsoft [Graph PowerShell modules](https://www.powershellgallery.com/packages/Microsoft.Graph) are required to proceed the option [User license details](#user-license-details) from the [COLLECT](#collect) menu.

If you do not have this module installed, the 'Unified Labeling Support Tool' will try to install the current version from [PowerShell Gallery](https://www.powershellgallery.com/packages/Microsoft.Graph).

### Microsoft PowerShell (optional) <a name="ms-powershell"></a>

Please follow the instructions for [installing PowerShell on Windows](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.4) to install it using your preferred method if you want to use the 'Unified Labeling Support Tool' on Microsoft PowerShell 7.2 (or higher).

# Installation <a name="installation"></a>

The 'Unified Labeling Support Tool' is available on [PowerShell Gallery](https://www.powershellgallery.com/packages/UnifiedLabelingSupportTool/) and the fastest and easiest way to install it with user privileges is to run the following command in PowerShell:

```
Install-Module -Name UnifiedLabelingSupportTool -Scope CurrentUser
```

If you have local administrative privileges, you can run the following command instead:

```
Install-Module -Name UnifiedLabelingSupportTool
```

> **Note:**
>
> If you do not have a required component installed on your computer, you will be prompted to do so. You may need to confirm the installation of NuGet Provider and PowerShell Gallery as a trusted repository, and you may also need to confirm the installation of [PowerShellGet](https://docs.microsoft.com/en-us/powershell/scripting/gallery/installing-psget?view=powershell-5.1).

#### Allow signed PowerShell scripts <a name="allow-signed-powershell-scripts"></a>

If PowerShell script execution is restricted in your environment, you need to bypass this restriction to run the 'Unified Labeling Support Tool'. To do this, run the "Set-ExecutionPolicy" command with the following parameters:

```
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
```

The 'Unified Labeling Support Tool' is code-signed with a Microsoft certificate.

### Manual Installation <a name="manual-installaltion"></a>

If you’re using the 'Unified Labeling Support Tool' in an environment that does not have internet access, you need to proceed with the manual installation.

To install the 'Unified Labeling Support Tool' manually, you need to create the following folder, and copy/paste all the 'Unified Labeling Support Tool' files (`UnifiedLabelingSupportTool.psm1`, `UnifiedLabelingSupportTool.psd1` and `ULSupportTool-Win.htm`) into this folder:

``` %USERPROFILE%\Documents\WindowsPowerShell\Modules\UnifiedLabelingSupportTool\3.1.2```

This path need to be listed in the [PSModulePath environment variable](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/modifying-the-psmodulepath-installation-path?view=powershell-5.1#to-view-the-psmodulepath-variable).

To verify if the installation was successful, please review the [check installation](#check-installation) section.

> **Note:**
>
> Please also consider point [Allow signed PowerShell scripts](#allow-signed-powershell-scripts).

### Check installation <a name="check-installation"></a>

To verify if the installation was successful, you can call the "Get-Module" cmdlet with the following parameter:

```
Get-Module -ListAvailable
```

If you find an entry like the following, the installation was successful:

```
PS C:\> Get-Module -ListAvailable

    Directory: C:\Users\<UserName>\Documents\WindowsPowerShell\Modules

ModuleType   Version    Name                          ExportedCommands
----------   -------    ----                          ----------------
Script       3.1.2      UnifiedLabelingSupportTool    {UnifiedLabelingSupportTool, ULSupportTool}
```

To verify that an installation was performed using PowerShell Gallery, you can run the following command:

```
Get-InstalledModule -Name UnifiedLabelingSupportTool
```

If you find an entry like the following, the installation was performed by PowerShell Gallery:

```
PS C:\> Get-InstalledModule -Name UnifiedLabelingSupportTool

Version   Name                         Repository     Description
-------   ----                         ----------     -----------
3.1.2     UnifiedLabelingSupportTool   PSGallery      Have you ever used the Sensitivity button in...
```

# Uninstall <a name="uninstall"></a>

If you want to completely uninstall the 'Unified Labeling Support Tool' and it was installed via the PowerShell Gallery, you must execute the following command:

```
Uninstall-Module -Name UnifiedLabelingSupportTool -AllVersions
```

If you want to uninstall a specific version, for example version 3.1.1, you must execute the following command:

```
Uninstall-Module -Name UnifiedLabelingSupportTool -RequiredVersion 3.1.1
```

If the 'Unified Labeling Support Tool' was installed manually, you also need to remove it manually by deleting its installation folder.

> **Note:**
>
> Under certain circumstances, you may need to run the 'Unified Labeling Support Tool' with administrative privileges to perform an uninstall. Please request assistance from your administrator if necessary.

# User experience <a name="experience"></a>

To start the 'Unified Labeling Support Tool', simply type the following command in a PowerShell command window and press enter:

```
UnifiedLabelingSupportTool
```

When you start the 'Unified Labeling Support Tool', you'll see the following menu:

```
UnifiedLabelingSupportTool:

  [I] INFORMATION
  [M] MIT LICENSE
  [H] HELP
  [R] RESET
  [P] RECORD PROBLEM
  [C] COLLECT
  [Z] COMPRESS LOGS
  [X] EXIT MENU
 
Please select an option and press enter:
```

For the most sub-items of the [COLLECT](#collect) menu, you need to run the 'Unified Labeling Support Tool' as a user with local administrative privileges. For option [RESET](#reset), [RECORD PROBLEM](#record-problem), and for sub-item [Endpoint URLs](#endpoint-urls) of the [COLLECT](#collect) menu, you may run as user with local administrative privileges. Please contact your administrator if necessary.

You can also start the 'Unified Labeling Support Tool' within the command line. Use the following command line parameter to see a short summary of all available command line parameters:

```
UnifiedLabelingSupportTool -Information
```

To see a full list of all command line parameters with description, run the following command:

```
Get-Help UnifiedLabelingSupportTool -Detailed
```

To see the help for a single command line parameter, for example for "-CompressLogs", run the following command:

```
Get-Help UnifiedLabelingSupportTool -Parameter CompressLogs
```

# Features <a name="features"></a>

The 'Unified Labeling Support Tool' provides the following features (menu entry / command line parameter):

### [I] INFORMATION / -Information <a name="information"></a>

This shows syntax, description and version information of the 'Unified Labeling Support Tool'.

### [M] MIT LICENSE / -License

This displays the [MIT License](#mit-license).

### [H] HELP / -Help <a name="help-win"></a>

This opens the online manual.

### [R] RESET / -Reset <String> <a name="reset"></a>

**IMPORTANT: Before you proceed with this option, please close all open applications.**

This option removes all relevant policies, labels and settings.

> **Note:**
>
> Reset with the default argument will not reset all settings, but only user-specific settings if you run PowerShell with user privileges. This is sufficient in most cases to reset [Microsoft 365](https://www.microsoft.com/en-us/microsoft-365) Apps, while a complete reset is useful for all other applications.
> 
> If you want a complete reset, you need to run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges.

Valid <String> arguments are: "Default", or "Silent":

**Default:**

When you run PowerShell with user privileges, this argument removes all relevant policies, labels and settings:

```
UnifiedLabelingSupportTool -Reset Default
```

With the above command the following registry keys are cleaned up:

```
[HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\MSIPC]
[HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\AIPMigration]
[HKCU:\SOFTWARE\Classes\Microsoft.IPViewerChildMenu]
[HKCU:\SOFTWARE\Microsoft\Cloud\Office]
[HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\DRM]
[HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\DRM]
[HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\DRM]
[HKCU:\SOFTWARE\Microsoft\XPSViewer\Common\DRM]
[HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Identity]
[HKCU:\SOFTWARE\Microsoft\MSIP]
[HKCU:\SOFTWARE\Microsoft\MSOIdentityCRL]
[HKCR:\AllFilesystemObjects\shell\Microsoft.Azip.Inspect]
[HKCR:\AllFilesystemObjects\shell\Microsoft.Azip.RightClick]
```

The [DRMEncryptProperty](https://docs.microsoft.com/en-us/deployoffice/security/protect-sensitive-messages-and-documents-by-using-irm-in-office#office-2016-irm-registry-key-options) and [OpenXMLEncryptProperty](https://admx.help/?Category=Office2013&Policy=office15.Office.Microsoft.Policies.Windows::L_Protectdocumentmetadataforpasswordprotected) registry settings are purged of the following keys:

```
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Common\Security]
[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security]
```

The [UseOfficeForLabelling](https://docs.microsoft.com/en-us/microsoft-365/compliance/sensitivity-labels-office-apps?view=o365-worldwide#office-built-in-labeling-client-and-other-labeling-solutions) (Use the Sensitivity feature in Office to apply and view sensitivity labels) and [AIPException](https://microsoft.github.io/ComplianceCxE/playbooks/AIP2MIP/AIPException/#configuring-sensitivity-labeling-client-in-m365-apps) (Use the Azure Information Protection add-in for sensitivity labeling) registry setting is purged of the following keys:

```
[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Cloud\Office\16.0\Common\Security\Labels]
[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security\Labels]
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Common\Security\Lables]
```

The following file system folders are cleaned up as well:

```
%LOCALAPPDATA%\Microsoft\Word\MIPSDK\mip
%LOCALAPPDATA%\Microsoft\Excel\MIPSDK\mip
%LOCALAPPDATA%\Microsoft\PowerPoint\MIPSDK\mip
%LOCALAPPDATA%\Microsoft\Outlook\MIPSDK\mip
%LOCALAPPDATA%\Microsoft\Office\DLP\mip
%LOCALAPPDATA%\Microsoft\Office\CLP
%TEMP%\Diagnostics
%LOCALAPPDATA%\Microsoft\MSIP
%LOCALAPPDATA%\Microsoft\MSIPC
%LOCALAPPDATA%\Microsoft\DRM
```

The [Clear-AIPAuthentication](https://docs.microsoft.com/en-us/powershell/module/azureinformationprotection/Clear-AIPAuthentication?view=azureipps) cmdlet is used to reset user settings, if an [Azure Information Protection client](https://www.microsoft.com/en-us/download/details.aspx?id=53018) installation is found.

> **Note:**
>
> Please note that the Microsoft Azure Information Protection cmdlets do not support PowerShell 7. Therefore, unexpected errors may occur because Azure Information Protection cmdlets run in compatibility mode.

When you run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges, the following registry keys are cleaned up in addition:

```
[HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSIPC]
[HKLM:\SOFTWARE\Microsoft\MSIPC]
[HKLM:\SOFTWARE\Microsoft\MSDRM]
[HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSDRM]
[HKLM:\SOFTWARE\WOW6432Node\Microsoft\MSIP]
```

**Silent:**

This command line parameter argument does the same as "-Reset Default", but does not print any output - unless an error occurs when attempting to reset:

```
UnifiedLabelingSupportTool -Reset Silent
```

If a silent reset triggers an error, you can use the additional parameter "-Verbose" to find out more about the cause of the error:

```
UnifiedLabelingSupportTool -Reset Silent -Verbose
```

You can also review the [Script.log](#script-log-file) file for errors of silent reset.

### [P] RECORD PROBLEM / -RecordProblem <a name="record-problem"></a>

**IMPORTANT: Before you proceed with this option, please close all open applications.**

As a first step, this parameter activates the required logging, or tracing mechanisms by implementing registry settings, and enabling some Windows event logs. This process will be reflected by a progress bar “Enable logging...".
In the event that you accidentally close the PowerShell window while logging is enabled, the 'Unified Labeling Support Tool' disables logging the next time you start it.

In a second step asks you to reproduce the problem. While you’re doing so, the 'Unified Labeling Support Tool' collects and records data. Once you have reproduced the problem, all collected files will be stored into the default logs folder (`%temp%\UnifiedLabelingSupportTool`). Every time you call this option, a new unique subfolder will be created in the logs-folder that reflects the date and time when it was created. While the files are being cached, you will see a progress bar “Collecting logs...".

In the last step, the 'Unified Labeling Support Tool' resets all activated log and trace settings to their defaults. This process will be reflected by a progress bar “Disable logging...".

You can then review the [log files](#log-files) in the logs folder.

> **Note:**
>
> Please note that neither CAPI2 or AIP event logs, network trace nor filter drivers are recorded if the 'Unified Labeling Support Tool' is not run in an administrative PowerShell window as a user with local administrative privileges.

### [C] COLLECT / - <a name="collect"></a>

If you select this option, a submenu will be expanded, and you can collapse it by selecting option [C] COLLECT again:

```
  [C] COLLECT
   ├──[A] AIP service configuration
   ├──[T] Protection templates
   ├──[U] Endpoint URLs
   ├──[L] Labels and policies
   ├──[D] DLP rules and policies
   └──[S] User license details
```

> **Note:**
>
> With an exception of the [User license details](#user-license-details) entry, you need to run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges to proceed with any option from this submenu. Please contact your administrator if necessary.
>
> You need to know your [Microsoft 365](https://www.microsoft.com/en-us/microsoft-365) global administrator account information to proceed, as you will be asked for your credentials.
>
> You need to run the 'Unified Labeling Support Tool' as user with local administrative privileges to continue with option [Endpoint URLs](#endpoint-urls), if the corresponding [Microsoft 365](https://www.microsoft.com/en-us/microsoft-365) App is not bootstraped. Please contact your administrator if necessary.

### [A] AIP service configuration / -CollectAIPServiceConfiguration <a name="aip-service-config"></a>

This parameter collects your AIP service configuration information, e.g. [SuperUsers](https://learn.microsoft.com/en-us/azure/information-protection/configure-super-users) or [OnboardingControlPolicy](https://learn.microsoft.com/en-us/powershell/module/aipservice/set-aipserviceonboardingcontrolpolicy?view=azureipps), etc.

Results are written into the log file [AIPServiceConfiguration.log](#aip-service-config-log) in the subfolder "Collect" of the Logs folder.

> **Note:**
>
> Please refer to the note in point [AIPService module](#aipservice-module).

### [T] Protection templates / -CollectProtectionTemplates <a name="protection-templates"></a>

This parameter collects [protection templates](https://learn.microsoft.com/en-us/microsoft-365/compliance/sensitivity-labels-office-apps?view=o365-worldwide#protection-templates-and-sensitivity-labels) of your tenant.

Results are written into the log file [ProtectionTemplates.log](#protection-templates-log) in the subfolder "Collect" of the Logs folder, and an export of each protection template (.xml) into the subfolder "ProtectionTemplates".

> [!TIP]
> You can use this feature to create a backup copy of your protection templates.

> **Note:**
>
> Please refer to the note in point [AIPService module](#aipservice-module).

### [U] Endpoint URLs / -CollectEndpointURLs <a name="endpoint-urls"></a>

This parameter collects important endpoint URLs. The URLs are taken from your local registry or your tenant's AIP service configuration information, and extended by additional relevant URLs.

In a first step, this parameter is used to check whether you can access the URL. In a second step, the issuer of the corresponding certificate of the URL is collected. This process is represented by an output with the Tenant Id, Endpoint name, URL, and Issuer of the certificate. For example:

```
--------------------------------------------------
Tenant Id: 48fc04bd-c84b-44ac-b7991b7-a4c5eefd5ac1
--------------------------------------------------
 
Endpoint: UnifiedLabelingDistributionPointUrl
URL:      https://dataservice.protection.outlook.com
Issuer:   CN=DigiCert Cloud Services CA-1, O=DigiCert Inc, C=US
```

Results are written into log file [EndpointURLs.log](#endpoint-urls-log) in the subfolder "Collect" of the Logs folder. Additionally, an export of each certificate is saved in the "EndpointURLs" subfolder with the Endpoint URL as the file name and the [.ce_ file](#cer-files) extension.

> **Note:**
>
> This parameter uses the AIPService module. Please note that the AIPService module does not support PowerShell 7. Therefore, unexpected errors may occur as the AIPService module can only run in compatibility mode.

### [L] Labels and policies / -CollectLabelsAndPolicies <a name="labels-and-policies"></a>

This parameter collects the labels and policy definitions (with detailled label actions and policy rules) from your [Microsoft Purview compliance portal](https://learn.microsoft.com/en-us/microsoft-365/compliance/microsoft-365-compliance-center?view=o365-worldwide). Those with encryption and those with content marking only.

Results are written into log file [LabelsAndPolicies.log](#labels-and-policies-log) in the subfolder "Collect" of the Logs folder, and you can also have a CLP subfolder with the Office CLP policy.

> [!TIP]
> You can use the resulting log file to create exact copies of the label and policy settings for troubleshooting purposes, e.g. in test environments. 

> **Note:**
>
> The Microsoft Exchange Online PowerShell V3 cmdlets are required to proceed this option. If you do not have this module installed, 'Unified Labeling Support Tool' will try to install it from PowerShell Gallery.

### [D] DLP rules and policies / -CollectDLPRulesAndPolicies <a name="dlp-rules-and-policies"></a>

This parameter collects DLP rules and policies, sensitive information type details, rule packages, keyword dictionaries and exact data match schemas from the [Microsoft Purview compliance portal](https://learn.microsoft.com/en-us/microsoft-365/compliance/microsoft-365-compliance-center?view=o365-worldwide).

Results are written into log file [DLPRulesAndPolicies.log](#dlp-rules-log) in the subfolder "Collect" of the Logs folder.

> **Note:**
>
> The Microsoft Exchange Online PowerShell V3 cmdlets are required to proceed this option. If you do not have this module installed, 'Unified Labeling Support Tool' will try to install it from PowerShell Gallery.

### [S] User license details <a name="user-license-details"></a>

This parameter collects the user license details by [Microsoft Graph](https://learn.microsoft.com/en-us/graph/overview).

Results are written into log file [UserLicenseDetails.log](#user-license-log) in the subfolder "Collect" of the Logs folder.

> **Note:**
>
> The Microsoft [Graph PowerShell cmdlets](https://www.powershellgallery.com/packages/Microsoft.Graph) are required to proceed this option. If you do not have this module installed, 'Unified Labeling Support Tool' will try to install it from PowerShell Gallery.
>
> You must log in with the corresponding [Microsoft 365](https://www.microsoft.com/en-us/microsoft-365) user account for which you want to check the license details.

### [Z] COMPRESS LOGS / -CompressLogs <a name="compress-logs"></a>

This command line parameter should always be used at the very end of a scenario.

This parameter compresses all collected log files and folders into a .zip archive, and the corresponding file is saved to your desktop. In addition, the default logs folder (`%temp%\UnifiedLabelingSupportTool`) is cleaned.

### [X] EXIT / - <a name="exit"></a>

This option will asks you whether you want to exit the menu after a confirmation prompt.

### - / -SkipUpdates <a name="skip-updates"></a>

**IMPORTANT: Use this parameter only if you are sure that all PowerShell modules are up to date.**

This parameter skips the update check mechanism for all entries of the [COLLECT](#collect) menu.

### - / -Menu <a name="menu"></a>

This will start the 'Unified Labeling Support Tool' with the default menu.

# Script log file <a name="script-log-file"></a>

The 'Unified Labeling Support Tool' creates the following log file. The log file gives an overview of the executed commands and provides a control mechanism to review the results.

**Script.log**

This log file collects the actions that has been taken and lists the results. It also logs general environment information from the used client machine, like the Windows edition or Windows PowerShell version.

# Log files and folders <a name="log-files"></a>

The 'Unified Labeling Support Tool' collects the following log files and folders.

Please note that not all log files are collected or recorded at all times. It depends on your environment which logs, or traces can be recorded.

### RECORD PROBLEM <a name="record-problem-logs"></a>

Log files and folders collected by the [RECORD PROBLEM](#record-problem) option when you run the 'Unified Labeling Support Tool' with user privileges:

<ul>
<li>
  
**Tasklist.log**

</li>

This file contains a list of currently running processes on the local computer.<br>

For more information, please see the following documentation: [tasklist](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist).

<li>
  
**WinIPConfig.txt and IPConfigAll.log**

</li>

These files show all current TCP/IP network configuration settings.<br>
  
For more information, please see the following documentation: [ipconfig](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig).

<li>

**WinHTTP.log and WinHTTP_WoW6432.log**

</li>

These files contain the WinHTTP proxy configuration and are collected with Netsh.exe.<br>
  
For more information, please see the following documentation: [Netsh command syntax, contexts, and formatting](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts).

<li>

**AutoConfigURL.log**

</li>

This file contains information of the auto proxy configuration settings.<br>

For more information, please see the following documentation: [Automatic Proxy Detection](https://docs.microsoft.com/en-us/dotnet/framework/network-programming/automatic-proxy-detection), and [Use a proxy server in Windows](https://support.microsoft.com/en-us/windows/use-a-proxy-server-in-windows-03096c53-0554-4ffe-b6ab-8b1deee8dae1).

<li>

**ProblemSteps.zip**

</li>

This file records the exact steps you took when the problem occured. It was created by the Steps Recorder (psr.exe).<br>

For more information, please see the following documentation: [Record steps to reproduce a problem](https://support.microsoft.com/en-us/help/22878/windows-10-record-steps).

<li>
  
**MSIPC/MSIP folders / AIPLogs.zip**

</li>

The following log folders contain MSIP/MSIPC logging information:<br>

```
%LOCALAPPDATA%\Microsoft\MSIP
%LOCALAPPDATA%\Microsoft\MSIPC
```
 
If you have installed and enabled the Azure Information Protection unified labeling client, the folders containing the AIPLogs.zip file are collected.<br>

For more information, please see the following documentation for the used PowerShell command: [Export-AIPLogs](https://docs.microsoft.com/en-us/powershell/module/azureinformationprotection/export-aiplogs?view=azureipps).

<li>

**AIP plugin for Adobe Acrobat logs**

</li>

The following log folders contain logging information:<br>

```
%LOCALAPPDATA%\Microsoft\RMSLocalStorage\MIP\logs
%USERPROFILE%\appdata\locallow\Microsoft\RMSLocalStorage\mip\logs
```

For more information, please see the following information: [Adobe reader and Microsoft Information Protection integration FAQs](https://techcommunity.microsoft.com/t5/microsoft-information-protection/adobe-reader-and-microsoft-information-protection-integration/ba-p/482219).

<li>

**Application.evtx**

</li>

This file is the Application Windows Event Log.

<li>

**System.evtx**

</li>

This file is the System Windows Event Log.

<li>
  
**office.log**

</li>

This file is the Office TCOTrace log.

<li>
  
**Office logging**

</li>

An Office log file collected from the users temp folder. For example:

```
%TEMP%\MACHINENAME-20230209-133005.log
```

The log file name reflects the compuer name, and date and time when the log was created.<br>

For more information, please see the following documentation: [How to enable Microsoft 365 Apps for enterprise ULS logging](https://learn.microsoft.com/en-us/office/troubleshoot/diagnostic-logs/how-to-enable-office-365-proplus-uls-logging) (part "For sign-in or activation issues, add the following registry key").<br><br>
In addition, Office diagnostics data will be collected from the following folder:

```
%TEMP%\Diagnostics
```

<li>
  
**MIPSDK-Word.zip, MIPSDK-Excel.zip, MIPSDK-PowerPoint.zip, and MIPSDK-Outlook.zip**

</li>

A respective .zip file contains the contents of the corresponding MIPSDK log folder collected at the following locations:

```
%LOCALAPPDATA%\Microsoft\Word\MIPSDK\mip
%LOCALAPPDATA%\Microsoft\Excel\MIPSDK\mip
%LOCALAPPDATA%\Microsoft\PowerPoint\MIPSDK\mip
%LOCALAPPDATA%\Microsoft\Outlook\MIPSDK\mip
```

Each .zip file contains multiple .json files. 

<li>

**LabelsAndPolicies.zip**

</li>

This .zip file is created by the option [RECORD PROBLEM](#record-problem).<br>

The file contains the cached labels and policies .xml files from the following folder:<br>

```
%LOCALAPPDATA%\Microsoft\Office\CLP
```

<li>

**CertMachine.log and CertUser.log**

</li>

These files contain certification information and were collected with Certutil.exe.<br>

For more information, please see the following documentation: [certutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil).

<li>

**EnvVar.log**

</li>

This file contains environment variables information from the system ("Get-ChildItem Env:").<br>

For more information about this PowerShell command, please see the following documentation: [Get-ChildItem](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-childitem?view=powershell-5.1).

<li>

**Programs32.log**

</li>

This file contains the installed software (32-bit) from the system. This file were taken from this registry key:

```
[HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall]
```

<li>
  
**Programs64.log**

</li>

This file contains the installed software (64-bit) from the system. This file were taken from this registry key:

```
[HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall]
```

<li>
  
**Registry.log**

</li>

This file contains several regsitry keys related to the Office/Microsoft 365 Apps and Information Protection configuration. The content were taken from these registry keys:

```
[HKLM:\Software\Classes\MSIP.ExcelAddin]
[HKLM:\Software\Classes\MSIP.WordAddin]
[HKLM:\Software\Classes\MSIP.PowerPointAddin]
[HKLM:\Software\Classes\MSIP.OutlookAddin]
[HKLM:\Software\Classes\AllFileSystemObjects\shell\Microsoft.Azip.RightClick]
[HKLM:\Software\Microsoft\MSIPC]
[HKLM:\Software\Microsoft\Office\Word\Addins]
[HKLM:\Software\Microsoft\Office\Excel\Addins]
[HKLM:\Software\Microsoft\Office\PowerPoint\Addins]
[HKLM:\Software\Microsoft\Office\Outlook\Addins]
[HKLM:\Software\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\Word\Addins]
[HKLM:\Software\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\Excel\Addins]
[HKLM:\Software\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\PowerPoint\Addins]
[HKLM:\Software\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\Outlook\Addins]
[HKLM:\Software\WOW6432Node\Microsoft\MSIPC]
[HKLM:\Software\Wow6432Node\Microsoft\Office\Word\Addins]
[HKLM:\Software\Wow6432Node\Microsoft\Office\Excel\Addins]
[HKLM:\Software\Wow6432Node\Microsoft\Office\PowerPoint\Addins]
[HKLM:\Software\Wow6432Node\Microsoft\Office\Outlook\Addins]
[HKCU:\Software\Microsoft\MSIP]
[HKCU:\Software\Microsoft\Office\16.0\Common\DRM]
[HKCU:\Software\Microsoft\Office\16.0\Common\Security]
[HKCU:\Software\Microsoft\Office\16.0\Common\Identity]
[HKCU:\Software\Microsoft\Office\16.0\Common\Internet]
[HKCU:\Software\Microsoft\Office\Word\Addins]
[HKCU:\Software\Microsoft\Office\Excel\Addins]
[HKCU:\Software\Microsoft\Office\PowerPoint\Addins]
[HKCU:\Software\Microsoft\Office\Outlook\Addins]
[HKCU:\Software\Microsoft\Office\16.0\Word\Resiliency]
[HKCU:\Software\Microsoft\Office\16.0\Excel\Resiliency]
[HKCU:\Software\Microsoft\Office\16.0\PowerPoint\Resiliency]
[HKCU:\Software\Microsoft\Office\16.0\Outlook\Resiliency]
[HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC]
[HKCR:\MSIP.ExcelAddin]
[HKCR:\MSIP.WordAddin]
[HKCR:\MSIP.PowerPointAddin]
[HKCR:\MSIP.OutlookAddin]
[HKCR:\Local Settings\Software\Microsoft\MSIPC]
[HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\DRM]
[HKCU:\SOFTWARE\Policies\Microsoft\Cloud\Office\16.0\Common\Security]
[HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security]
[HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security]
[HKCU:\Software\Microsoft\Office\16.0\Common\Licensing\CurrentSkuIdAggregationForApp]
[HKCU:\Software\Microsoft\Office\16.0\Common\Licensing\LastKnownC2RProductReleaseId]
```

<li>

**Gpresult.htm**

</li>

This file contains the Resultant Set of Policy (RSoP) information from the system.<br>

For more information, please see the following documentation: [gpresult](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult).

<li>
  
**BaseUTCOffset.log**

</li>

This file contains time zone offset information.<br>

For more information about this PowerShell command, please see the following documentation: [Get-TimeZone](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-timezone?view=powershell-5.1).

</ul>

Log files and folders additionally collected by the [RECORD PROBLEM](#record-problem) option when you run the 'Unified Labeling Support Tool' with administrative privileges:

<ul>
<li>
  
**CAPI2.evtx**

</li>

This file is the CAPI2 Windows Event Log.<br>

For more information, please see the following documentation: [Saving Events to a Log File](https://docs.microsoft.com/en-us/windows/desktop/WES/saving-events-to-a-log-file).

<li>

**AIP.evtx**

</li>

This file is the Azure Information Protection Windows Event Log.

<li>

**NetMon.etl**

</li>

This file is a network trace recorded by Netsh.exe.<br>

For more information, please see the following documentation: [Netsh command syntax, contexts, and formatting](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts).

<li>

**Filters.log**

</li>

This file contain a list of Windows filter drivers.<br>

For more information about this PowerShell command, please see the following documentation: [Fltmc.exe](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/development-and-testing-tools#fltmcexe-control-program).

</ul>

### COLLECT <a name="collect-logs"></a>

Log files and folders collected via the sub-entries of the [COLLECT](#collect) menu. Results are written in the subfolder "Collect" of the Logs folder:

<ul>
<li>

**AIPServiceConfiguration.log** <a name="aip-service-config-log"></a>

</li>

This file is only collected if you selected [AIP service configuration](#aip-service-config). The file contains the Azure Information Protection service configuration of your tenant.<br>

For more information, please see the following documentation: [Get-AipServiceConfiguration](https://docs.microsoft.com/de-de/powershell/module/aipservice/get-aipserviceconfiguration).

<li>

**ProtectionTemplates.log and .xml files** <a name="protection-templates-log"></a>

</li>

These files are only collected if you selected [Protection templates](#protection-templates).<br>

The ProtectionTemplates.log file contains the Azure Information Protection template details. Additionally, an export of each protection template is saved in the "ProtectionTemplates" subfolder with the protection template ID as the file name and the .xml file extension.<br>

For more information, please see the following documentation: [Get-AipServiceTemplate](https://docs.microsoft.com/en-us/powershell/module/aipservice/get-aipservicetemplate), and [Export-AipServiceTemplate](https://docs.microsoft.com/en-us/powershell/module/aipservice/export-aipservicetemplate?view=azureipps).

<li>

**LabelsAndPolicies.log** <a name="labels-and-policies-log"></a>

</li>

This file is created by the collect option [Labels and policies](#labels-and-policies). If you have not initiated a [RESET](#reset) before collecting logs, you can also have a CLP subfolder with the Office CLP policy folder.<br>

For more information, please see the following documentation: [Get-Label](https://docs.microsoft.com/en-us/powershell/module/exchange/policy-and-compliance/get-label?view=exchange-ps) and [Get-LabelPolicy](https://docs.microsoft.com/en-us/powershell/module/exchange/policy-and-compliance/get-labelpolicy?view=exchange-ps).

<li>

**DLPRulesAndPolicies.log** <a name="dlp-rules-log"></a>

</li>

This file is created by the collect option [DLP rules and policies](#dlp-rules-and-policies).<br>

For more information, please see the following documentation: [Get-DlpCompliancePolicy](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpcompliancepolicy?view=exchange-ps), [Get-DlpComplianceRule](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpcompliancerule?view=exchange-ps), [Get-DlpSensitiveInformationType](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpsensitiveinformationtype), [Get-DlpSensitiveInformationTypeRulePackage](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpsensitiveinformationtyperulepackage), [Get-DlpKeywordDictionary](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpkeyworddictionary), and [Get-DlpEdmSchema](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpedmschema).

<li>

**EndpointURLs.log** <a name="endpoint-urls-log"></a>

</li>

This file contains information for endpoint URLs and the certificate issuer collected by the [Endpoint URLs](#endpoint-urls) option.

<li>

**.cer files (.ce_)** <a name="cer-files"></a>

</li>

These files are created by the option [Endpoint URLs](#endpoint-urls).<br>

> **Note:**
>
> The files are exported with the file extension .ce_ instead of .cer, since some security programs can block these files.

<li>

**UserLicenseDetails.log** <a name="user-license-log"></a>

</li>

This parameter collects the [User license details](#user-license-details) by [Microsoft Graph](https://www.powershellgallery.com/packages/Microsoft.Graph).<br>

For more information, please see the following documentation:
[Get-MgUserLicenseDetail](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.users/get-mguserlicensedetail), [Get-MgSubscribedSku](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.directorymanagement/get-mgsubscribedsku) and [Product names and service plan identifiers for licensing](https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference).

</ul>

# Support <a name="support"></a>

When creating the 'Unified Labeling Support Tool', great care was taken to ensure quality and functionality. Extensive tests were carried out before publication to intercept and handle any errors. However, there is no guarantee that an error will not occur in a wide variety of configurations and environments.

Should you ever encounter a problem with the 'Unified Labeling Support Tool', please visit the [support page](https://github.com/microsoft/UnifiedLabelingSupportTool/blob/main/SUPPORT.md) on the project site.

### Microsoft Support Policy <a name="support-policy"></a>

Under this policy, the 'Unified Labeling Support Tool' remains in support if the following criteria are met:

* You're using the lastet version of the 'Unified Labeling Support Tool'.
* You must be licensed with a product or service that uses [Microsoft Information Protection and Unified Labeling](https://www.microsoft.com/en-us/us-partner-blog/2018/11/05/microsoft-information-protection-and-unified-labeling/).

### How to file issues and get help <a name="get-help"></a>

The 'Unified Labeling Support Tool' uses GitHub [Issues](https://github.com/microsoft/UnifiedLabelingSupportTool/issues) to track problems and feature requests.

Please check for [known issues](https://github.com/microsoft/UnifiedLabelingSupportTool/blob/main/SUPPORT.md#known-issues) before submitting new issues to avoid duplicates.

For new issues, file your bug or feature request as a [new Issue](https://github.com/microsoft/UnifiedLabelingSupportTool/issues/new). Please describe the Issue as detailed as possible. A screenshot of the error and/or a step-by-step description of how to reproduce a problem would be very helpful for this.

<br>
<br>
<br>

Copyright Microsoft® Corporation.
