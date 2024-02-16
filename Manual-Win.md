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
[RESET](#reset), [RECORD PROBLEM](#record-problem), and [COLLECT](#collect) Endpoint URLs.

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

The 'Unified Labeling Support Tool' supports [Windows PowerShell 5.1](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-5.1) (recommended) and Microsoft [PowerShell 7.2](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.2) (or higher) on the following operating systems:

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

The Microsoft AIPService module is required to proceed the options [AIP service configuration](https://microsoft.github.io/UnifiedLabelingSupportTool/#[A]_AIP_service_configuration_/_-CollectAIPServiceConfiguration), [Protection templates](https://microsoft.github.io/UnifiedLabelingSupportTool/#[T]_Protection_templates_/_-CollectProtectionTemplates), and [Endpoint URLs](#endpoint-urls) from the [COLLECT](#collect) menu entry.

If you do not have this module installed, the 'Unified Labeling Support Tool' will try to install the current version from [PowerShell Gallery](https://www.powershellgallery.com/packages/ExchangeOnlineManagement).

*Note:*

Please note that the AIPService module does not support PowerShell 7. Therefore, unexpected errors may occur because the AIPService module run in compatibility mode.

### Microsoft Azure Information Protection cmdlets (optional) <a name="aip-cmdlets"></a>

The Microsoft Azure Information Protection cmdlets are installed with the [Azure Information Protection client](https://www.microsoft.com/en-us/download/details.aspx?id=53018). Please ensure to have the latest version of the "AzureInformationProtection" cmdlets installed by checking its [client version release history](https://docs.microsoft.com/en-us/azure/information-protection/rms-client/unifiedlabelingclient-version-release-history).

*Note:*

Please note that the Azure Information Protection cmdlets do not support PowerShell 7. Therefore, unexpected errors may occur because Azure Information Protection cmdlets run in compatibility mode.

### Microsoft Graph PowerShell modules (optional) <a name="graph-modules"></a>

The Microsoft [Graph PowerShell modules](https://www.powershellgallery.com/packages/Microsoft.Graph) are required to proceed the option [User license details](#user-licens-details) from the [COLLECT](#collect) menu.

If you do not have this module installed, the 'Unified Labeling Support Tool' will try to install the current version from [PowerShell Gallery](https://www.powershellgallery.com/packages/ExchangeOnlineManagement).

### Microsoft PowerShell (optional) <a name="ms-powershell"></a>

Please follow the instructions for [installing PowerShell on Windows](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.3) to install it using your preferred method if you want to use the 'Unified Labeling Support Tool' on Microsoft PowerShell 7.2 (or higher).

# Installation <a name="installation"></a>

The 'Unified Labeling Support Tool' is available on [PowerShell Gallery](https://www.powershellgallery.com/) and the fastest and easiest way to install it with user privileges is to run the following command in PowerShell:

```
Install-Module -Name UnifiedLabelingSupportTool -Scope CurrentUser
```

If you have local administrative privileges, you can run the following command instead:

```
Install-Module -Name UnifiedLabelingSupportTool
```

*Note:*

If you do not have a required component installed on your computer, you will be prompted to do so. You may need to confirm the installation of NuGet Provider and PowerShell Gallery as a trusted repository, and you may also need to confirm the installation of [PowerShellGet](https://docs.microsoft.com/en-us/powershell/scripting/gallery/installing-psget?view=powershell-5.1).

### Allow signed PowerShell scripts <a name="allow-signed-powershell-scripts"></a>

If PowerShell script execution is restricted in your environment, you need to bypass this restriction to run the 'Unified Labeling Support Tool'. To do this, run the "Set-ExecutionPolicy" command with the following parameters:

```
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
```

The 'Unified Labeling Support Tool' is code-signed with a Microsoft certificate.

*Note:*

Please refer to the [known issues](https://github.com/microsoft/UnifiedLabelingSupportTool/blob/main/SUPPORT.md#known-issues).

## Manual Installation <a name="manual-installaltion"></a>

If you’re using the 'Unified Labeling Support Tool' in an environment that does not have internet access, you need to proceed with the manual installation.

To install the 'Unified Labeling Support Tool' manually, you need to create the following folder, and copy/paste all the 'Unified Labeling Support Tool' files (UnifiedLabelingSupportTool.psm1, UnifiedLabelingSupportTool.psd1 and ULSupportTool-Win.htm) into this folder:

``` %USERPROFILE%\Documents\WindowsPowerShell\Modules\UnifiedLabelingSupportTool\3.1.2```

This path need to be listed in the [PSModulePath environment variable](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/modifying-the-psmodulepath-installation-path?view=powershell-5.1#to-view-the-psmodulepath-variable).

To verify if the installation was successful, please review the [check installation](#check-installation) section.

*Note:*

Please also consider point [Allow signed PowerShell scripts](#allow-signed-powershell-scripts).
Please refer to the known issues.
