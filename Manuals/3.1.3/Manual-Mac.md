# Unified Labeling Support Tool 
###### Version 3.1.3-BETA (macOS) <br><br>

**Contents**

* [Introduction](#introduction)
   * [MIT License](#mit-license)
   * [Microsoft Privacy Statement](#microsoft-privacy-statement)
* [Requirements](#requirements)
   * [Internet access](#internet-access)
   * [Microsoft PowerShell](#ms-powershell)
   * [Microsoft Graph PowerShell modules](#graph-modules)
* [Installation](#installation)
   * [Check installation](#check-installation)
* [Uninstall](#uninstall)
* [User experience](#experience)
* [Features](#features)
   * [INFORMATION](#information)
   * [HELP](#help-win)
   * [RESET](#reset)
   * [RECORD PROBLEM](#record-problem)
   * [COLLECT](#collect)
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

If you want to use the 'Unified Labeling Support Tool' on Microsoft Windows, you can find the corresponding help file [here](Manual-Win.md).

Have you ever used the Sensitivity button in a [Microsoft 365 App](https://www.microsoft.com/en-us/microsoft-365)? If so, you've used the [Office's built-in labeling experience](https://docs.microsoft.com/en-us/microsoft-365/compliance/sensitivity-labels-office-apps?view=o365-worldwide). In case something doesn't work as expected or you don't see any labeling at all, the 'Unified Labeling Support Tool' will help you.

The 'Unified Labeling Support Tool' provides the functionality to reset all corresponding Information Protection client services. Its main purpose is to delete the currently downloaded sensitivity label policies and thus reset all settings, and it can also be used to collect data for error analysis and troubleshooting.

## MIT License <a name="mit-license"></a>

Copyright © Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 

## Microsoft Privacy Statement <a name="microsoft-privacy-statement"></a>

Your privacy is important to us. [This privacy statement](https://privacy.microsoft.com/en-US/privacystatement) explains the personal data Microsoft processes, how Microsoft processes it, and for what purposes.

## Requirements <a name="requirements"></a>

Before you can use the 'Unified Labeling Support Tool' make sure that your environment fulfils the following requierements. Please update your environment if necessary.

The 'Unified Labeling Support Tool' supports:

* Apple macOS ([three most recent major versions](https://support.microsoft.com/en-us/office/upgrade-macos-to-continue-receiving-microsoft-365-and-office-for-mac-updates-16b8414f-08ec-4b24-8c91-10a918f649f8)).

The 'Unified Labeling Support Tool' supports the following Office/Microsoft 365 versions:

* Microsoft 365 for Mac ([most recently released version](https://learn.microsoft.com/en-us/officeupdates/update-history-office-for-mac#release-history-for-office-for-mac)), Microsoft Office 2019 for Mac and Microsoft Office 2021 for Mac .

### Internet access <a name="internet-access"></a>

The 'Unified Labeling Support Tool' uses additional sources and services from the Internet to make its functionality fully available.

Unexpected errors may occur, and some features may be limited, if there is no connection to the Internet.

### Microsoft PowerShell <a name="ms-powershell"></a>

Please follow the instructions for [installing PowerShell on macOS](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-macos?view=powershell-7.3) to install it using your preferred method. Nevertheless the [installation via direct download](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-macos?view=powershell-7.3&viewFallbackFrom=powershell-7.1#installation-via-direct-download) is recommended.

> **Note:**
>
> Microsoft PowerShell must be installed with local administrative privileges. Please request assistance from your administrator if necessary.

### Microsoft Graph PowerShell modules (optional) <a name="graph-modules"></a>

The Microsoft [Graph PowerShell modules](https://www.powershellgallery.com/packages/Microsoft.Graph) are required to proceed the option [User license details](#user-license-details) from the [COLLECT](#collect) menu.

If you do not have this module installed, the 'Unified Labeling Support Tool' will try to install the current version from [PowerShell Gallery](https://www.powershellgallery.com/packages/Microsoft.Graph).

# Installation <a name="installation"></a>

The 'Unified Labeling Support Tool' is available on [PowerShell Gallery](https://www.powershellgallery.com/packages/UnifiedLabelingSupportTool/) and the fastest and easiest way to install it with user privileges is to run the following command in PowerShell:

```
Install-Module -Name UnifiedLabelingSupportTool -Scope CurrentUser
```

If you have local administrative privileges, you can run the following command instead:

```
Install-Module -Name UnifiedLabelingSupportTool -Scope AllUsers
```

> **Note:**
>
> If you do not have a required component installed on your computer, you will be prompted to do so. You may need to confirm the installation of PowerShell Gallery as a trusted repository.

#### Allow signed PowerShell scripts <a name="allow-signed-powershell-scripts"></a>

If PowerShell script execution is restricted in your environment, you need to bypass this restriction to run the 'Unified Labeling Support Tool'. To do this, run the "Set-ExecutionPolicy" command with the following parameters:

```
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
```

The 'Unified Labeling Support Tool' is code-signed with a Microsoft certificate.

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
Script       3.1.3      UnifiedLabelingSupportTool    {UnifiedLabelingSupportTool, ULSupportTool}
```

# Uninstall <a name="uninstall"></a>

If you want to completely uninstall the 'Unified Labeling Support Tool', you must execute the following command:

```
Uninstall-Module -Name UnifiedLabelingSupportTool -AllVersions
```

If you want to uninstall a specific version, for example version 3.1.2, you must execute the following command:

```
Uninstall-Module -Name UnifiedLabelingSupportTool -RequiredVersion 3.1.2
```

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

> [!TIP]
>
> For better readability, it is recommended to change the Terminal/PowerShell window settings to the "Pro" profile.

You can also start the 'Unified Labeling Support Tool' within the command line. Use the following command line parameter to see a short summary of all available command line parameters:

```
UnifiedLabelingSupportTool -Information
```

To see a complete list of all command line parameters with description, execute the following command (command line help): <a name="command-line-help"></a>

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

> **Note:**
>
> If you do not have internet access, please use the [command line help](#command-line-help).

### [R] RESET / -Reset <String> <a name="reset"></a>

**IMPORTANT: Before you proceed with this option, please close all open applications.**

This option removes all relevant policies, labels and settings.

Valid <String> arguments are: "Default", or "Silent":

**Default:**

This argument removes all relevant policies, labels and settings:

```
UnifiedLabelingSupportTool -Reset Default
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

This parameter asks you to reproduce the problem. While you’re doing so, the 'Unified Labeling Support Tool' collects and records data. Once you have reproduced the problem, all collected files will be stored into the default logs folder (`~/Documents/UnifiedLabelingSupportTool`). Every time you call this option, a new unique subfolder will be created in the logs-folder that reflects the date and time when it was created. While the files are being cached, you will see a progress bar “Collecting logs...".

You can then review the [log files](#log-files) in the logs folder.

### [C] COLLECT / - <a name="collect"></a>

If you select this option, a submenu will be expanded, and you can collapse it by selecting option [C] COLLECT again:

```
  [C] COLLECT
   └──[S] User license details
```

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

This parameter compresses all collected log files and folders into a .zip archive, and the corresponding file is saved to your desktop. In addition, the default logs folder (`~/Documents/UnifiedLabelingSupportTool`) is cleaned.

### [X] EXIT / - <a name="exit"></a>

This option will asks you whether you want to exit the menu after a confirmation prompt.

### - / -SkipUpdates <a name="skip-updates"></a>

**IMPORTANT: Use this parameter only if you are sure that all PowerShell modules are up to date.**

This parameter skips the update check mechanism for entries of the [COLLECT](#collect) menu.

### - / -Menu <a name="menu"></a>

This will start the 'Unified Labeling Support Tool' with the default menu.

# Script log file <a name="script-log-file"></a>

The 'Unified Labeling Support Tool' creates the following log file. The log file gives an overview of the executed commands and provides a control mechanism to review the results.

**Script.log**

This log file collects the actions that has been taken and lists the results. It also logs general environment information from the used client machine, like the Apple macOS edition or PowerShell version.

# Log files and folders <a name="log-files"></a>

The 'Unified Labeling Support Tool' collects the following log files and folders.

Please note that not all log files are collected or recorded at all times. It depends on your environment which logs, or traces can be recorded.


<ul>
<li>

**Log folders**

</li>

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

<li>

**UserLicenseDetails.log**

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

* You're using the [lastet version](https://aka.ms/UnifiedLabelingSupportTool/Latest) of the 'Unified Labeling Support Tool'.
* You must be licensed with a product or service that uses a [Microsoft Information Protection subscription](https://learn.microsoft.com/en-us/office365/servicedescriptions/azure-information-protection#available-plans).

### How to file issues and get help <a name="get-help"></a>

The 'Unified Labeling Support Tool' uses GitHub [Issues](https://github.com/microsoft/UnifiedLabelingSupportTool/issues) to track problems and feature requests.

Please check for [known issues](https://github.com/microsoft/UnifiedLabelingSupportTool/blob/main/SUPPORT.md#known-issues) before submitting new issues to avoid duplicates.

For new issues, file your bug or feature request as a [new Issue](https://github.com/microsoft/UnifiedLabelingSupportTool/issues/new). Please describe the Issue as detailed as possible. A screenshot of the error and/or a step-by-step description of how to reproduce a problem would be very helpful for this.

<br>
<br>
<br>

Copyright Microsoft® Corporation.