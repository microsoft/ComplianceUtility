# Compliance Utility
###### Version 3.2.0-BETA (macOS) <br><br>

**Contents**

* [Description](#description)
   * [MIT License](#mit-license)
   * [Microsoft Privacy Statement](#microsoft-privacy-statement)
* [Requirements](#requirements)
   * [Internet access](#internet-access)
   * [PowerShell](#ms-powershell)
   * [Graph PowerShell module](#graph-module)
   * [Exchange Online PowerShell module](#exchange-online-module)
* [Installation](#installation)
   * [Check installation](#check-installation)
* [Uninstall](#uninstall)
* [User experience](#experience)
* [Features / Parameters](#features-parameters)
   * [INFORMATION](#information)
   * [HELP](#help-win)
   * [RESET](#reset)
   * [RECORD PROBLEM](#record-problem)
   * [COLLECT](#collect)
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
 
## Description <a name="description"></a>

The 'Compliance Utility' is a powerful tool that helps troubleshoot and diagnose sensitivity labels, policies, settings and more. Whether you need to fix issues or reset configurations, this tool has you covered.

Have you ever used the Sensitivity button in a [Microsoft 365 App](https://www.microsoft.com/en-us/microsoft-365/products-apps-services)? If so, you've used the [Office's built-in labeling experience](https://docs.microsoft.com/en-us/microsoft-365/compliance/sensitivity-labels-office-apps?view=o365-worldwide). In case something doesn't work as expected or you don't see any labeling at all, the 'Compliance Utility' will help you.

> **Note**
> 
> If you want to use the 'Compliance Utility' on Microsoft Windows, you can find the corresponding online manual [here](Manual-Win.md).

### MIT License <a name="mit-license"></a>

Copyright © Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 

### Microsoft Privacy Statement <a name="microsoft-privacy-statement"></a>

Your privacy is important to us. [This privacy statement](https://privacy.microsoft.com/en-US/privacystatement) explains the personal data Microsoft processes, how Microsoft processes it, and for what purposes.

## Requirements <a name="requirements"></a>

Before you can use the 'Compliance Utility' make sure that your environment fulfils the following requierements. Please update your environment if necessary.

The 'Compliance Utility' supports the following operating systems:

* Apple macOS ([three most recent major versions](https://support.microsoft.com/en-us/office/upgrade-macos-to-continue-receiving-microsoft-365-and-office-for-mac-updates-16b8414f-08ec-4b24-8c91-10a918f649f8))

The 'Compliance Utility' supports the following Office and Microsoft 365 editions:

* Microsoft 365 for Mac ([most recently released version](https://learn.microsoft.com/en-us/officeupdates/update-history-office-for-mac#release-history-for-office-for-mac))
* Microsoft Office 2021 for Mac
* Microsoft Office 2019 for Mac

> **Note**
> 
> Please refer to the [Microsoft product lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/?expanded=m365&terms=mac&products=office) page to find out which versions of Office are still supported.

### Internet access <a name="internet-access"></a>

The 'Compliance Utility' uses additional sources from the Internet to make its functionality fully available.

> [!WARNING]
> Unexpected errors may occur, and some features may be limited, if there is no connection to the Internet.

### PowerShell <a name="ms-powershell"></a>

Please follow the instructions for [installing PowerShell on macOS](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-macos?view=powershell-7.4) to install it using your preferred method. Nevertheless the [installation via direct download](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-macos?view=powershell-7.4#installation-via-direct-download) is recommended.

> **Note**
> 
> PowerShell must be installed with local administrative privileges. Please request assistance from your administrator if necessary.

### Graph PowerShell module <a name="graph-module"></a>

The [Graph PowerShell module](https://www.powershellgallery.com/packages/Microsoft.Graph) is required to proceed the option [User license details](#user-license-details) from the [COLLECT](#collect) menu.

If you do not have this module installed, the 'Compliance Utility' will try to install the current version from [PowerShell Gallery](https://www.powershellgallery.com/packages/Microsoft.Graph).

### Exchange Online PowerShell module <a name="exchange-online-module"></a>

The [Exchange Online PowerShell module](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps) is required to proceed the options [Labels and policies](#labels-and-policies) and [DLP rules and policies](#dlp-rules-and-policies) from the menu [COLLECT](#collect).

If you do not have this module installed, the 'Compliance Utility' will try to install the current version from [PowerShell Gallery](https://www.powershellgallery.com/packages/ExchangeOnlineManagement).

# Installation <a name="installation"></a>

The 'Compliance Utility' is available on [PowerShell Gallery](https://www.powershellgallery.com/packages/ComplianceUtility/). To start the installation, you must first execute the `pwsh` command in a Terminal window to start a PowerShell session. Then type the following command and press enter to start the installation of the 'Compliance Utility':

```
Install-Module -Name ComplianceUtility -Scope CurrentUser
```

If you have local administrative privileges, you can run the following command instead:

```
Install-Module -Name ComplianceUtility -Scope AllUsers
```

> **Note**
> 
> If you do not have a required component installed on your computer, you will be prompted to do so. You may need to confirm the installation of PowerShell Gallery as a trusted repository.

#### Allow signed PowerShell scripts <a name="allow-signed-powershell-scripts"></a>

If PowerShell script execution is restricted in your environment, you must first remove this restriction in order to be able to run the 'Compliance Utility'. To do this, run the `Set-ExecutionPolicy` command with the following parameters:

```
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
```

The 'Compliance Utility' is code-signed with a Microsoft certificate.

### Check installation <a name="check-installation"></a>

To verify if the installation was successful, you can call the `Get-Module` cmdlet with the following parameter:

```
Get-Module -Name ComplianceUtility -ListAvailable
```

If you find an entry like the following, the installation was successful:

```
    Directory: C:\Users\<UserName>\Documents\WindowsPowerShell\Modules

ModuleType Version    Name                     ExportedCommands
---------- -------    ----                     ----------------
Script     3.2.0      ComplianceUtility        {ComplianceUtility, CompUtil, UnifiedLabelingSupportTool}
```

# Uninstall <a name="uninstall"></a>

If you want to completely uninstall the 'Compliance Utility', you must execute the following command:

```
Uninstall-Module -Name ComplianceUtility -AllVersions
```

> **Note**
> 
> Under certain circumstances, you may need to run the uninstallation with administrator privileges. Please request assistance from your administrator if necessary.

# User experience <a name="experience"></a>

First you need to execute the command `pwsh` in a Terminal window to start a PowerShell session. Then type the following command and press enter to start the 'Compliance Utility':

```
ComplianceUtility
```

When you start the 'Compliance Utility', you'll see the following menu:

```
ComplianceUtility:

  [I] INFORMATION
  [M] MIT LICENSE
  [H] HELP
  [R] RESET
  [P] RECORD PROBLEM
  [C] COLLECT
  [Z] COMPRESS LOGS
  [X] EXIT
 
Please select an option and press enter:
```

> [!TIP]
> For better readability, it is recommended to change the Terminal/PowerShell window settings to the "Pro" profile.

> **Note**
>
> When the 'Compliance Utility' is started for the first time and an installation of the 'Unified Labeling Support Tool' is found, it is removed.

If you select `[C] COLLECT`, a submenu will be expanded, and you can collapse it by selecting option `[C] COLLECT` again: <a name="collect"></a>

```
  [C] COLLECT
   ├──[L] Labels and policies
   ├──[D] DLP rules and policies
   └──[U] User license details
```

> **Note**
>
> * With an exception of the [User license details](#user-license-details) entry, you need to run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges to proceed with any option from this submenu. Please contact your administrator if necessary.
> * You need to know your Microsoft 365 global administrator account information to proceed, as you will be asked for your credentials.

You can also start the 'Compliance Utility' within the command line. Use the following command line parameter to see a short summary of all available command line parameters:

```
ComplianceUtility -Information
```

To see a complete list of all command line parameters with description, execute the following command (command line help): <a name="command-line-help"></a>

```
Get-Help ComplianceUtility -Detailed
```

To see the help for a single command line parameter, for example for `-CompressLogs`, run the following command:

```
Get-Help ComplianceUtility -Parameter CompressLogs
```

# Features / Parameters <a name="features-parameters"></a>

The 'Compliance Utility' provides the following parameters:

**Syntax:**

```
ComplianceUtility
       [-Information]
       [-License]
       [-Help]
       [-Reset] <String>
       [-RecordProblem]
       [-CollectAIPServiceConfiguration]
       [-CollectProtectionTemplates]
       [-CollectEndpointURLs]
       [-CollectLabelsAndPolicies]
       [-CollectDLPRulesAndPolicies]
       [-CollectUserLicenseDetails]
       [-SkipUpdates]
       [-CompressLogs]
       [-Menu]
       <CommonParameters>
```

> **Note**
>
> Features/Parameters `-CollectAIPServiceConfiguration`, `-CollectProtectionTemplates` and `-CollectEndpointURLs` are not available. They would require the [AIPService module](https://learn.microsoft.com/en-us/powershell/module/aipservice/?view=azureipps), which PowerShell 7.x does not yet support on Apple macOS.

Description of all features and parameters (feature / parameter):

### [I] INFORMATION / -Information <a name="information"></a>

This shows syntax, description and version information.

### [M] MIT LICENSE / -License

This displays the [MIT License](#mit-license).

### [H] HELP / -Help <a name="help-win"></a>

This opens the online manual.

### [R] RESET / -Reset <String> <a name="reset"></a>

> [!IMPORTANT]
> Before you proceed with this option, please close all open applications.

This option removes all relevant policies, labels and settings.

Valid <String> arguments are: "Default", or "Silent":

**Default:**

This argument removes all relevant policies, labels and settings:

```
ComplianceUtility -Reset Default
```

With the above command the following file folders will be cleaned up:

```
~/Library/Containers/com.microsoft.Word/Data/Library/Application Support/Microsoft/Office/CLP
~/Library/Containers/com.microsoft.Excel/Data/Library/Application Support/Microsoft/Office/CLP
~/Library/Containers/com.microsoft.PowerPoint/Data/Library/Application Support/Microsoft/Office/CLP
~/Library/Containers/com.microsoft.Outlook/Data/Library/Application Support/Microsoft/Office/CLP
~/Library/Containers/com.microsoft.Word/Data/Library/Logs
~/Library/Containers/com.microsoft.Excel/Data/Library/Logs
~/Library/Containers/com.microsoft.PowerPoint/Data/Library/Logs
~/Library/Containers/com.microsoft.Outlook/Data/Library/Logs
~/Library/Containers/com.microsoft.protection.rms-sharing-mac/Data/Library/Logs
~/Library/Group Containers/UBF8T346G9.Office/mip_policy/mip/logs
```

**Silent:**

This command line parameter argument does the same as `-Reset Default`, but does not print any output - unless an error occurs when attempting to reset:

```
ComplianceUtility -Reset Silent
```

If a silent reset triggers an error, you can use the additional parameter `-Verbose` to find out more about the cause of the error:

```
ComplianceUtility -Reset Silent -Verbose
```

You can also review the [Script.log](#script-log-file) file for errors of silent reset.

### [P] RECORD PROBLEM / -RecordProblem <a name="record-problem"></a>

> [!IMPORTANT]
> Before you proceed with this option, please close all open applications.

As a first step, this parameter activates the required logging and then prompts you to reproduce the problem. While you’re doing so, the 'Compliance Utility' collects and records data. Once you have reproduced the problem, all collected files will be stored into the default logs folder (`~/Documents/ComplianceUtility`). Every time you call this option, a new unique subfolder will be created in the logs-folder that reflects the date and time when it was created.

In the event that you accidentally close the PowerShell window while logging is enabled, the 'Compliance Utility' disables logging the next time you start it.

### [L] Labels and policies / -CollectLabelsAndPolicies <a name="labels-and-policies"></a>

This parameter collects Information Protection labels, policies (with detailled actions and rules), auto-label policies and rules from your [Microsoft Purview compliance portal](https://learn.microsoft.com/en-us/microsoft-365/compliance/microsoft-365-compliance-center?view=o365-worldwide) by using the [Exchange Online PowerShell module](#exchange-online-module).

The results are written to the log files ([Labels.xml](#labels-and-policies-xml), [LabelsDetailedActions.xml](#labels-and-policies-xml), [LabelPolicies.xml](#labels-and-policies-xml), [LabelRules.xml](#labels-and-policies-xml), [AutoLabelPolicies.xml](#labels-and-policies-xml) and [AutoLabelRules.xml](#labels-and-policies-xml)) in the subfolder "Collect\LabelsAndPolicies" of the Logs folder.

> [!TIP]
> You can use the resulting .xml files to create exact copies of the label and policy settings for troubleshooting purposes, e.g. in test environments. 

### [D] DLP rules and policies / -CollectDLPRulesAndPolicies <a name="dlp-rules-and-policies"></a>

This parameter collects DLP rules and policies, sensitive information type details, rule packages, keyword dictionaries and exact data match schemas from the [Microsoft Purview compliance portal](https://learn.microsoft.com/en-us/microsoft-365/compliance/microsoft-365-compliance-center?view=o365-worldwide) by using the [Exchange Online PowerShell module](#exchange-online-module).

The results are written to the log files [DlpPolicy.xml](#dlp-rules-xml), [DlpRule.xml](#dlp-rules-xml), [DlpPolicyDistributionStatus.xml](#dlp-rules-xml), [DlpSensitiveInformationType.xml](#dlp-rules-xml), [DlpSensitiveInformationTypeRulePackage.xml](#dlp-rules-xml), [DlpKeywordDictionary.xml](#dlp-rules-xml) and [DlpEdmSchema.xml](#dlp-rules-xml) in the subfolder "Collect\DLPRulesAndPolicies" of the Logs folder.

### [U] User license details <a name="user-license-details"></a>

This parameter collects the user license details by the [Graph PowerShell module](#graph-module).

The results are written to the log file [UserLicenseDetails.log](#user-license-log) in the subfolder "Collect" of the Logs folder.

> **Note**
>
> You must log in with the corresponding Microsoft 365 user account for which you want to check the license details.

### [Z] COMPRESS LOGS / -CompressLogs <a name="compress-logs"></a>

This command line parameter should always be used at the very end of a scenario.

This parameter compresses all collected log files and folders into a .zip archive, and the corresponding file is saved to your desktop. In addition, the default logs folder (`~/Documents/ComplianceUtility`) is cleaned.

### [X] EXIT / - <a name="exit"></a>

This option will asks you whether you want to exit the menu after a confirmation prompt.

### - / -SkipUpdates <a name="skip-updates"></a>

> [!IMPORTANT]
> Use this parameter only if you are sure that all PowerShell modules are up to date.

This parameter skips the update check mechanism for entries of the [COLLECT](#collect) menu.

### - / -Menu <a name="menu"></a>

This will start the 'Compliance Utility' with the default menu.

### \<CommonParameters>

The 'Compliance Utility' supports the common parameters: Verbose, Debug, ErrorAction, ErrorVariable, WarningAction, WarningVariable, OutBuffer, PipelineVariable, and OutVariable. For more information, see [about_CommonParameters](https:/go.microsoft.com/fwlink/?LinkID=113216).

# Script log file <a name="script-log-file"></a>

The 'Compliance Utility' creates the following log file. The log file gives an overview of the executed commands and provides a control mechanism to review the results.

**Script.log**

This log file collects the actions that has been taken and lists the results. It also logs general environment information from the used client machine, like the Apple macOS edition or PowerShell version.

# Log files and folders <a name="log-files"></a>

The 'Compliance Utility' collects the following log files and folders.

> **Note**
>
> Not all log files are collected or recorded at all times. It depends on your environment which logs, or traces can be recorded.

**RECORD PROBLEM** <a name="record-problem-logs"></a>

<ul>
<li>
  
Folders collected by the [RECORD PROBLEM](#record-problem) option:

```
~/Library/Containers/com.microsoft.Word/Data/Library/Application Support/Microsoft/Office/CLP
~/Library/Containers/com.microsoft.Excel/Data/Library/Application Support/Microsoft/Office/CLP
~/Library/Containers/com.microsoft.PowerPoint/Data/Library/Application Support/Microsoft/Office/CLP
~/Library/Containers/com.microsoft.Outlook/Data/Library/Application Support/Microsoft/Office/CLP
~/Library/Containers/com.microsoft.Word/Data/Library/Logs
~/Library/Containers/com.microsoft.Excel/Data/Library/Logs
~/Library/Containers/com.microsoft.PowerPoint/Data/Library/Logs
~/Library/Containers/com.microsoft.Outlook/Data/Library/Logs
~/Library/Containers/com.microsoft.protection.rms-sharing-mac/Data/Library/Logs
~/Library/Group Containers/UBF8T346G9.Office/mip_policy/mip/logs
```

</li>
<li>

**SystemInformation.log**

</li>

This file contains basic system information.<br>

For more information, please see the following documentation: [system_profiler](https://en.wikipedia.org/wiki/System_profiler).

</ul>

**COLLECT** <a name="collect-logs"></a>

Log files collected by the sub-entries of the [COLLECT](#collect) menu. Results are written in the subfolder "Collect" of the Logs folder:

<ul>
<li>

**Labels.xml, LabelsDetailedActions.xml, LabelPolicies.xml, LabelRules.xml, AutoLabelPolicies.xml, AutoLabelRules.xml** <a name="labels-and-policies-xml"></a>

</li>

These files are created by the collect option [Labels and policies](#labels-and-policies).<br>

For more information, please see the following documentation: [Get-Label](https://docs.microsoft.com/en-us/powershell/module/exchange/policy-and-compliance/get-label?view=exchange-ps), [Get-LabelPolicy](https://docs.microsoft.com/en-us/powershell/module/exchange/policy-and-compliance/get-labelpolicy?view=exchange-ps), [Get-AutoSensitivityLabelPolicy](https://learn.microsoft.com/en-us/powershell/module/exchange/get-autosensitivitylabelpolicy) and [Get-AutoSensitivityLabelRule](https://learn.microsoft.com/en-us/powershell/module/exchange/get-autosensitivitylabelrule).

<li>

**DlpPolicy.xml, DlpRule.xml, DlpPolicyDistributionStatus.xml, DlpSensitiveInformationType.xml, DlpSensitiveInformationTypeRulePackage.xml, DlpKeywordDictionary.xml and DlpEdmSchema.xml** <a name="dlp-rules-xml"></a>

</li>

These files are created by the collect option [DLP rules and policies](#dlp-rules-and-policies).<br>

For more information, please see the following documentation: [Get-DlpCompliancePolicy](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpcompliancepolicy?view=exchange-ps), [Get-DlpComplianceRule](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpcompliancerule?view=exchange-ps), [Get-DlpSensitiveInformationType](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpsensitiveinformationtype), [Get-DlpSensitiveInformationTypeRulePackage](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpsensitiveinformationtyperulepackage), [Get-DlpKeywordDictionary](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpkeyworddictionary), and [Get-DlpEdmSchema](https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpedmschema).

<li>

**UserLicenseDetails.log**

</li>

This parameter collects the [User license details](#user-license-details) by [Microsoft Graph](https://www.powershellgallery.com/packages/Microsoft.Graph).<br>

For more information, please see the following documentation:
[Get-MgUserLicenseDetail](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.users/get-mguserlicensedetail), [Get-MgSubscribedSku](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.directorymanagement/get-mgsubscribedsku) and [Product names and service plan identifiers for licensing](https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference).

</ul>

# Support <a name="support"></a>

When creating the 'Compliance Utility', great care was taken to ensure quality and functionality. Extensive tests were carried out before publication to intercept and handle any errors. However, there is no guarantee that an error will not occur in a wide variety of configurations and environments.

Should you ever encounter a problem with the 'Compliance Utility', please visit the [support page](https://github.com/microsoft/ComplianceUtility/blob/main/SUPPORT.md) on the project site.

### Microsoft Support Policy <a name="support-policy"></a>

Under this policy, the 'Compliance Utility' remains in support if the following criteria are met:

* You're using the [lastet version](https://aka.ms/ComplianceUtility/Latest) of the 'Compliance Utility'.
* You must be licensed with a product or service that uses a [Microsoft Information Protection subscription](https://learn.microsoft.com/en-us/office365/servicedescriptions/azure-information-protection#available-plans).

### How to file issues and get help <a name="get-help"></a>

The 'Compliance Utility' uses GitHub [Issues](https://github.com/microsoft/ComplianceUtility/issues) to track problems and feature requests.

Please check for [known issues](https://github.com/microsoft/ComplianceUtility/blob/main/SUPPORT.md#known-issues) before submitting new issues to avoid duplicates.

For new issues, file your bug or feature request as a [new Issue](https://github.com/microsoft/ComplianceUtility/issues/new). Please describe the Issue as detailed as possible. A screenshot of the error and/or a step-by-step description of how to reproduce a problem would be very helpful for this.

<br>
<br>
<br>

Copyright Microsoft® Corporation.
