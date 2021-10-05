#Requires -Version 5.1

<# ╔══════════════════════════════════════════════════════════════════════════════════════════╗
   ║ WARNING: DO NOT MODIFY OR DELETE ANY COMPONENT OF THE 'Unified Labeling Support Tool' OR ║
   ║ THE RESULTING TRACE FILES, AS THIS WILL RESULT IN INCORRECT INFORMATION WHEN ANALYZING   ║
   ║ YOUR ENVIRONMENT.                                                                        ║
   ╚══════════════════════════════════════════════════════════════════════════════════════════╝ #>

# Copyright (c) Microsoft Corporation
# Licensed under the MIT License

<# Global variables #>
[Version]$Global:strVersion = "3.0.0" <# Define version #>
$Global:strDefaultWindowTitle = $Host.UI.RawUI.WindowTitle <# Caching window title #>
$Global:host.UI.RawUI.WindowTitle = "Unified Labeling Support Tool ($Global:strVersion)" <# Set window title #>
$Global:MenuCollectExtended = $false <# Define variable for COLLECT menu handling #>
$Global:bolCommingFromMenu = $false <# Define control variable for menu handling inside function calls #>
$Global:bolSkipRequiredUpdates = $false <# Define control variable for handling required updates function calls #>
$Global:FormatEnumerationLimit = -1 <# Define variable to show full Format-List for arrays #>

<# Initialize environment settings #>
Function fncInitialize{

    <# Defining variables #>
    $Global:strUserLogPath | Out-Null

    <# Detect Windows #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# Define variable for Windows version #>
        $Global:strOSVersion = (Get-CimInstance Win32_OperatingSystem).Caption

        <# Check for supported Windows versions #>
        If ($Global:strOSVersion -like "*Windows 8.1*" -Or
            $Global:strOSVersion -like "*Windows 10*" -Or
            $Global:strOSVersion -like "*Windows 11*" -Or
            $Global:strOSVersion -like "*2012*" -Or
            $Global:strOSVersion -like "*Server 2016*" -Or
            $Global:strOSVersion -like "*Server 2019*" -Or
            $Global:strOSVersion -like "*Server 2022*"){

            <# Defining variables #>
            $Global:strTempFolder = (Get-Item Env:"Temp").Value <# Define variable for user temp folder #>
            $Global:strUserLogPath = New-Item -ItemType Directory -Force -Path "$Global:strTempFolder\UnifiedLabelingSupportTool" <# Define default user log path #>
            $Global:bolRunningPrivileged = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups -match "S-1-5-32-544") <# Define control variable for privileges checks #>
            
        }
        Else { <# Action, when running on unsupported Windows system #>

            <# Clear global variables #>
            $Global:strOSVersion = $null

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncInitialize" -strLogDescription "Unsupported operating system" -strLogValue $true

            <# Console output #>
            Write-Output (Write-Host "ATTENTION: The 'Unified Labeling Support Tool' does not support the operating system you're using.`nPlease ensure to use one of the following supported operating systems:`nMicrosoft Windows 8.1, Windows 10, Windows 11, Windows Server 2012, Windows Server 2012 R2, Windows Server 2016, Windows Server 2019 and Windows Server 2022.`n" -ForegroundColor Red)

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit function #>
            Break

        }

        <# Verbose/Logging: Windows edition and version #>
        fncLogging -strLogFunction "fncInitialize" -strLogDescription "OS edition" -strLogValue $Global:strOSVersion 
        fncLogging -strLogFunction "fncInitialize" -strLogDescription "OS version" -strLogValue $([System.Environment]::OSVersion.Version)

    }

    <# Detect macOS #>
    If ($IsMacOS -eq $true) {

        <# Defining variables #>
        $Global:strOSVersion = $(sw_vers -productVersion) <# Define and set variable for macOS version #>

        <# Check for unsupported macOS version #>
        If ($Global:strOSVersion -lt "10.15") {

            <# Clear global variables #>
            $Global:strOSVersion = $null

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncInitialize" -strLogDescription "Unsupported operating system" -strLogValue $true

            <# Console output #>
            Write-Output (Write-Host "ATTENTION: The 'Unified Labeling Support Tool' does not support the operating system you're using.`nPlease ensure to use a supported operating system:`nApple macOS 10.15 (Catalina) or higher.`n" -ForegroundColor Red)

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit function #>
            Break

        }
        Else { <# Actions on supported macOS versions #>

            <# Defining variables #>
            $Global:strUserLogPath = New-Item -ItemType Directory -Force -Path "$(printenv HOME)\Documents\UnifiedLabelingSupportTool" <# Define variable for default user log path #>
            
            <# Detect if user is in admin group (80) #>
            If ($(id -G) -match "80"){

                <# Define control variable for privileges checks #>
                $Global:bolRunningPrivileged = $true

            }
            Else {

                <# Define control variable for privileges checks #>
                $Global:bolRunningPrivileged = $false

            }

        }

        <# Create default log entries for macOS #>
        fncLogging -strLogFunction "fncInitialize" -strLogDescription "OS edition" -strLogValue "Apple $(sw_vers -productName) ($(uname -s))"
        fncLogging -strLogFunction "fncInitialize" -strLogDescription "OS version" -strLogValue $Global:strOSVersion
        fncLogging -strLogFunction "fncInitialize" -strLogDescription "OS kernel" -strLogValue $(uname -v)

    }

    <# Create default log entries for Windows and macOS #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "OS 64-Bit" -strLogValue $([System.Environment]::Is64BitOperatingSystem) <# Verbose/Logging: architecture #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "Script module version" -strLogValue "$Global:strVersion" <# Verbose/Logging: Script module version #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "Username" -strLogValue $([System.Environment]::UserName) <# Username #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "Machine name" -strLogValue $([System.Environment]::MachineName) <# Machine name #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "PowerShell Host" -strLogValue $($Host.Name.ToString()) <# PowerShell host #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "PowerShell Version" -strLogValue $($Host.Version.ToString()) <# PowerShell version #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "PowerShell Edition" -strLogValue $($PSVersionTable.PSEdition.ToString()) <# PowerShell edition #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "PowerShell Current culture" -strLogValue $($Host.CurrentCulture.ToString()) <# PowerShell current culture #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "PowerShell Current UI culture" -strLogValue $($Host.CurrentUICulture.ToString()) <# PowerShell current UI culture #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "Running privileged" -strLogValue $Global:bolRunningPrivileged <# Logging if running with local administrative privileges #>

    <# Check for supported PowerShell versions #>
    If ([Version]::new($PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor) -cnotmatch [Version]::new("5.1") -and [Version]::new($PSVersionTable.PSVersion.Major) -cnotmatch [Version]::new("7")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncInitialize" -strLogDescription "Unsupported PowerShell version" -strLogValue $true

        <# Console output #>
        Write-Output (Write-Host "ATTENTION: The version of PowerShell that is required by the 'Unified Labeling Support Tool' does not match the currently running version of PowerShell $($PSVersionTable.PSVersion).`n" -ForegroundColor Red)

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Exit function #>
        Break

    }

}

<# Core function definitions #>
Function UnifiedLabelingSupportTool {

    <#
    .SYNOPSIS
        The 'Unified Labeling Support Tool' provides the functionality to reset all corresponding client services (UL, AIP, MIP, etc.). Its main purpose is to delete the currently downloaded sensitivity label policies and thus reset all settings, and it can also be used to collect data for failure analysis and problem solving.

    .DESCRIPTION
        Have you ever used the Sensitivity button in a Microsoft 365 App? If so, you've either used the Azure Information Protection client or Office's built-in labeling solution. In case something doesn't work as expected or you don't see any labeling at all, the 'Unified Labeling Support Tool' will help you.

    .NOTES
        Please find more information on this website about how to use the 'Unified Labeling Support Tool':

        https://aka.ms/UnifiedLabelingSupportTool

        Note:

        - Please only run 'Unified Labeling Support Tool' if you have been prompted to do so by a Microsoft support engineer.
        - Do not modify any component of the 'Unified Labeling Support Tool' in any kind, as this will result in incorrect information in the analysis of your environment.
        - Nomenclature: 
            UL = Unified Labeling.
            AIP = Azure Information Protection.
            MSIP/MIP = Microsoft Information Protection.
            MSIPC = Microsoft Information Protection Client.

        MIT LICENSE
        
        Copyright (c) Microsoft Corporation.

        Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
        
        VERSION
        3.0.0
        
        CREATE DATE
        10/05/2021

        AUTHOR
        Claus Schiroky
        Customer Service & Support | EMEA Modern Work Team
        Microsoft Deutschland GmbH

        HOMEPAGE
        https://aka.ms/UnifiedLabelingSupportTool

        SPECIAL THANKS TO
        Simone Götze-Lewicki
        Customer Service & Support | EMEA Modern Work Team
        Microsoft Deutschland GmbH

        PRIVACY STATEMENT
        https://privacy.microsoft.com/PrivacyStatement

        COPYRIGHT
        Copyright (c) Microsoft Corporation.

    .PARAMETER Information
        This shows syntax, description and version information of the 'Unified Labeling Support Tool'.

    .PARAMETER License
        This displays the MIT License.

    .PARAMETER Help
        This opens the help file.
        'ULSupportTool-Win.htm' for Windows and 'ULSupportTool-Mac.htm' for macOS.

    .PARAMETER Reset
        IMPORTANT: Before you proceed with this option, please close all open applications.
        This option removes all relevant policies, labels and settings.

        Before, the 'Unified Labeling Support Tool' creates a backup copy of existing custom configurations from the following registry key:
        
        [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSIPC\ServiceLocation]
        
        The name of the backup file is ServiceLocationBackup.reg.

        Note:

        - Reset with the default argument will not reset all settings, but only user-specific settings if you run PowerShell with user privileges. This is sufficient in most cases to reset Microsoft 365 Apps, while a complete reset is useful for all other applications.
        - If you want a complete reset, you must run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges.
        - When an Office 2013 installation is detected, modern authentication (ADAL) is automatically enabled as a precaution.
        
        Valid <String> arguments are: "Default", or "Silent":

        Default:

        When you run PowerShell with user privileges, this argument removes all relevant policies, labels and settings:

        UnifiedLabelingSupportTool -Reset Default

        All group policy settings are reapplied by "gpupdate /force", and the following registry keys are cleaned up:

        [HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\MSIPC]
        [HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\AIPMigration]
        [HKCU:\SOFTWARE\Classes\Microsoft.IPViewerChildMenu]
        [HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\DRM]
        [HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\DRM]
        [HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Common\DRM]
        [HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\DRM]
        [HKCU:\SOFTWARE\Microsoft\XPSViewer\Common\DRM]
        [HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Identity]
        [HKCU:\SOFTWARE\Microsoft\MSIP]
        [HKCU:\SOFTWARE\Microsoft\MSOIdentityCRL]
        [HKCR:\AllFilesystemObjects\shell\Microsoft.Azip.Inspect]
        [HKCR:\AllFilesystemObjects\shell\Microsoft.Azip.RightClick]

        The DRMEncryptProperty and OpenXMLEncryptProperty registry settings are purged of the following keys:

        [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\15.0\Common\Security]
        [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Common\Security]
        [HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Office\15.0\Common\Security]
        [HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security]

        The UseOfficeForLabelling (Use the Sensitivity feature in Office to apply and view sensitivity labels) registry setting is purged of the following keys:

        [HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Cloud\Office\16.0\Common\Security\Labels]
        [HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security\Labels]
        [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Common\Security\Lables]

        The following file system folders are cleaned up as well:

        %LOCALAPPDATA%\Microsoft\Office\DLP\mip
        %TEMP%\Diagnostics
        %LOCALAPPDATA%\Microsoft\MSIP
        %LOCALAPPDATA%\Microsoft\MSIPC
        %LOCALAPPDATA%\Microsoft\DRM

        The Clear-AIPAuthentication cmdlet is used to reset user settings, if an Azure Information Protection client installation is found.

        Note:

        - Please note that the Microsoft Azure Information Protection cmdlets do not support PowerShell 7. Therefore, unexpected errors may occur because Azure Information Protection cmdlets run in compatibility mode.

        When you run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges, the following registry keys are cleaned up in addition:

        [HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSIPC]
        [HKLM:\SOFTWARE\Microsoft\MSIPC]
        [HKLM:\SOFTWARE\Microsoft\MSDRM]
        [HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSDRM]
        [HKLM:\SOFTWARE\WOW6432Node\Microsoft\MSIP]

        Silent:

        This command line-parameter argument does the same as "-Reset Default", but does not print any output - unless an error occurs when attempting to reset:

        UnifiedLabelingSupportTool -Reset Silent

        If a silent reset triggers an error, you can use the additional parameter "-Verbose" to find out more about the cause of the error:

        UnifiedLabelingSupportTool -Reset Silent -Verbose

        You can also review the Script.log file for errors of silent reset.

        On Apple macOS, the following folders will be cleaned up:

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

    .PARAMETER RecordProblem
        IMPORTANT: Before you proceed with this option, please close all open applications.

        Note:

        - When you run PowerShell with user privileges, neither CAPI2 or AIP event logs, network trace, nor filter drivers are recorded.
        - If you want a complete record, you must run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges.
        
        As a first step, this parameter cleans up existing MSIP/MSIPC log folders, then it activates the required logging, tracing or debugging mechanisms by implementing registry settings, and enabling some Windows event logs. This process will be reflected by a progress bar “Enable logging...".
        In the event that you accidentally close the PowerShell window while logging is enabled, the 'Unified Labeling Support Tool' disables logging the next time you start it.

        In a second step asks you to reproduce the problem. While you’re doing so, the 'Unified Labeling Support Tool' collects and records data. Once you have reproduced the problem, all collected files will be stored into the default logs folder (%temp%\UnifiedLabelingSupportTool). Every time you call this option, a new unique subfolder will be created in the logs-folder that reflects the date and time when it was created. While the files are being cached, you will see a progress bar “Collecting logs...".

        In the last step, the 'Unified Labeling Support Tool' resets all activated log, trace, and debug settings to their defaults. This process will be reflected by a progress bar “Disable logging...".

        You can then review the log files in the logs folder.

        On Apple macOS:
        
        This parameter asks you to reproduce the problem. While you’re doing so, the 'Unified Labeling Support Tool' collects and records data. Once you have reproduced the problem, all collected files will be stored into the default logs folder (~/Documents/UnifiedLabelingSupportTool). Every time you call this option, a new unique subfolder will be created in the logs-folder that reflects the date and time when it was created. While the files are being cached, you will see a progress bar “Collecting logs...".

    .PARAMETER CollectAIPServiceConfiguration
        This parameter collects AIP service configuration information of your tenant.

        Results are written into the log file AIPServiceConfiguration.log in the subfolder "Collect" of the Logs folder. 

        Note:

        - You must run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges to continue with this option. Please contact your administrator if necessary.
        - You need to know your Microsoft 365 global administrator account information to proceed with this option, as you will be asked for your credentials.
        - Please note that the AIPService module does not support PowerShell 7. Therefore, unexpected errors may occur as the AIPService module can only run in compatibility mode.
        - This feature is not available on Apple macOS.

    .PARAMETER CollectAIPServiceTemplates
        This parameter collects AIP service templates of your tenant.

        Results are written into the log file AIPServiceTemplates.log in the subfolder "Collect" of the Logs folder, and an export of each service template (.xml) into the subfolder "AIPServiceTemplates".

        Note:

        - You must run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges to continue with this option. Please contact your administrator if necessary.
        - You need to know your Microsoft 365 global administrator account information to proceed with this option, as you will be asked for your credentials.
        - Please note that the AIPService module does not support PowerShell 7. Therefore, unexpected errors may occur as the AIPService module can only run in compatibility mode.
        - This feature is not available on Apple macOS.

    .PARAMETER CollectEndpointURLs
        This parameter collects important enpoint URLs.
        The URLs are taken from your local registry or your tenant's AIP service configuration information, and extended by additional relevant URLs.

        In a first step, this parameter is used to check whether you can access the URL.

        In a second step, the issuer of the corresponding certificate of the URL is validated. 
        This process is represented by an output with the Tenant Id, Endpoint name, URL, and Issuer of the certificate. For example:

        --------------------------------------------------
        Tenant Id: 48fc04bd-c84b-44ac-b7991b7-a4c5eefd5ac1
        --------------------------------------------------

        Endpoint: UnifiedLabelingDistributionPointUrl
        URL:      https://dataservice.protection.outlook.com
        Issuer:   CN=DigiCert Cloud Services CA-1, O=DigiCert Inc, C=US

        In addition, results are written into log file EndpointURLs.log in the subfolder "Collect" of the Logs folder.

        Note:

        - You must run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges to continue with this option, if the corresponding Microsoft 365 App is not bootstraped. Please contact your administrator if necessary.
        - You need to know your Microsoft 365 global administrator account information to proceed with this option, as you will be asked for your credentials.
        - This feature is not available on Apple macOS.

    .PARAMETER CollectLabelsAndPolicies
        This parameter collects the labels and policy definitions from your Microsoft 365 compliance center. Those with encryption and those with content marking only.

        Results are written into log file LabelsAndPolicies.log in the subfolder "Collect" of the Logs folder.

        Note:

        - You must run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges to continue with this option. Please contact your administrator if necessary.
        - You need to know your Microsoft 365 global administrator account information to proceed with this option, as you will be asked for your credentials.
        - The Microsoft Exchange Online PowerShell V2 cmdlets are required to proceed this option. If you do not have this module installed, 'Unified Labeling Support Tool' will try to install it from PowerShell Gallery.
        - This parameter uses the AIPService module. Please note that the AIPService module does not support PowerShell 7. Therefore, unexpected errors may occur as the AIPService module can only run in compatibility mode.
        - This feature is not available on Apple macOS.

    .PARAMETER CheckForUpdate
        This parameter checks if a new version of the 'Unified Labeling Support Tool' is available.

        If you run the 'Unified Labeling Support Tool' on Windows with administrative privileges, it automatically performs each new update.

        Note:

        - Under certain circumstances, you may need to run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges to perform an update.
        - If the 'Unified Labeling Support Tool' was not installed via PowerShell Gallery, any older version must first be removed before an update or installation can be performed.

    .PARAMETER CompressLogs
        This command line parameter should always be used at the very end of a scenario.

        IMPORTANT: Do not modify or delete any of the resulting trace files, as this will result in incorrect information when analyzing your environment.

        This parameter compresses all collected log files and folders into a .zip archive, and the corresponding file is saved to your desktop. In addition, the default logs folder (for Windows: '%temp%\UnifiedLabelingSupportTool' and '~/Documents/UnifiedLabelingSupportTool' on Apple macOS) is cleaned.

        After this step you can send/upload the .zip file for the Microsoft support engineer.

    .PARAMETER Menu
        This will start the 'Unified Labeling Support Tool' with the default menu.

    .PARAMETER SkipUpdates
        IMPORTANT: Use this parameter only if you are sure that all PowerShell modules are up to date.

        This parameter skips the update check mechanism for all entries of the COLLECT menu.

        Note:

        - This feature is not available on Apple macOS.

    .EXAMPLE
        UnifiedLabelingSupportTool -Information
        This shows syntax and description.

    .EXAMPLE
        UnifiedLabelingSupportTool -License
        This displays the MIT License.
        Please read it carefully, and act accordingly.

    .EXAMPLE
        UnifiedLabelingSupportTool -Help
        This parameter opens the help file.

    .EXAMPLE
        UnifiedLabelingSupportTool -Reset Default
        This parameter removes all relevant policies, labels and settings.

    .EXAMPLE
        UnifiedLabelingSupportTool -Reset Silent
        This parameter removes all relevant policies, labels and settings without any output.

    .EXAMPLE
        UnifiedLabelingSupportTool -RecordProblem
        This parameter cleans up existing MSIP/MSIPC log folders, then it removes all relevant policies, labels and settings, and starts recording data.

    .EXAMPLE
        UnifiedLabelingSupportTool -CollectAIPServiceConfiguration
        This parameter collects AIP service configuration information of your tenant.

    .EXAMPLE
        UnifiedLabelingSupportTool -CollectAIPServiceTemplates
        This parameter collects AIP service templates of your tenant.

    .EXAMPLE
        UnifiedLabelingSupportTool -CollectLabelsAndPolicies
        This parameter collects the labels and policy definitions from your Microsoft 365 compliance center.

    .EXAMPLE
        UnifiedLabelingSupportTool -CollectEndpointURLs
        This parameter collects important enpoint URLs, and the results are written into a log file.
        
    .EXAMPLE
        UnifiedLabelingSupportTool -CompressLogs
        This parameter compress all collected logs files into a .zip archive, and the corresponding path and file name is displayed.

    .EXAMPLE
        UnifiedLabelingSupportTool -CheckForUpdate
        This parameter checks if a new version is available for the 'Unified Labeling Support Tool'.

    .EXAMPLE
        UnifiedLabelingSupportTool -RecordProblem -CompressLogs
        This parameter cleans up existing MSIP/MSIPC log folders, then it removes all relevant policies, labels and settings, starts recording data, and compress all collected logs files to a .zip archive in the users desktop folder.

    .EXAMPLE
        UnifiedLabelingSupportTool -Menu
        This will start the 'Unified Labeling Support Tool' with the default menu.

    .LINK
        https://aka.ms/UnifiedLabelingSupportTool

    #>

    <# Define CmdletBinding for parameter settings #>
    [CmdletBinding (
        HelpURI = "https://aka.ms/UnifiedLabelingSupportTool", <# URL for help file; used with parameter Help #>
        PositionalBinding = $false, <# Parameters in the function are not positional #>
        DefaultParameterSetName = "Menu" <# If no parameter has been selected, this will be the default #>
    )]
    [Alias("ULSupportTool")]

    <# Parameter definitions #>
    Param (
        
        <# Parameter definition for Information #>
        [Alias("i")]
        [Parameter(ParameterSetName = "Information")]
        [switch]$Information,

        <# Parameter definition for License #>
        [Alias("m")]
        [Parameter(ParameterSetName = "License")]
        [switch]$License,

        <# Parameter definition for Help #>
        [Alias("h")]
        [Parameter(ParameterSetName = "Help")]
        [switch]$Help,

        <# Parameter definition for Reset #>
        [Alias("r")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [ValidateSet("Default", "Silent")]
        [string]$Reset="Default",

        <# Parameter definition for RecordProblem #>
        [Alias("p")]
        [parameter(ParameterSetName = "Reset and logging")]
        [switch]$RecordProblem,

        <# Parameter definition for CollectAIPServiceConfiguration #>
        [Alias("a")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CollectAIPServiceConfiguration,

        <# Parameter definition for CollectAIPServiceTemplates #>
        [Alias("t")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CollectAIPServiceTemplates,

        <# Parameter definition for CollectLabelsAndPolicies #>
        [Alias("l")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CollectLabelsAndPolicies,

        <# Parameter definition for CollectEndpointURLs #>
        [Alias("u")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CollectEndpointURLs,

        <# Parameter definition for required update checks #>
        [Parameter(ParameterSetName = "Menu")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$SkipUpdates,

        <# Parameter definition for CheckForUpdate #>
        [Parameter(ParameterSetName = "Update")]
        [switch]$CheckForUpdate,

        <# Parameter definition for CompressLogs, with preset. #>
        [Alias("z")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CompressLogs,

        <# Parameter definition for Menu #>
        [Parameter(ParameterSetName = "Menu")]
        [switch]$Menu

    )

    <# Action if the parameter '-Information' has been selected #>
    If ($PsCmdlet.ParameterSetName -eq "Information") {

        <# Call information function #>
        fncInformation

        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "Information" -strLogValue "Proceeded"

    } 

    <# Action if the parameter '-License' has been selected #>
    If ($PSBoundParameters.ContainsKey("License")) {

        <# Call License function #>
        fncLicense
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "License" -strLogValue "Proceeded"

    }
    
    <# Action if the parameter '-Help' has been selected #>
    If ($PSBoundParameters.ContainsKey("Help")) {

        <# Call help function #>
        fncHelp

        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "Help" -strLogValue "Proceeded"

    }

    <# Action if the parameter '-Reset' has been selected #>
    If ($PSBoundParameters.ContainsKey("Reset")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "Parameter Reset" -strLogValue "Triggered"                

        <# Call reset function #>
        fncReset -strResetMethod $Reset

    }

    <# Action if the parameter '-RecordProblem' has been selected #>
    If ($PSBoundParameters.ContainsKey("RecordProblem")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "Parameter RecordProblem" -strLogValue "Triggered"       

        <# Call record problem function #>
        fncRecordProblem

    }

    <# Define message variable for COLLECT features on macOS #>
    $Private:strNotAvailableOnMac = "Unfortunately, this feature is not available on Apple macOS."

    <# Action if the parameter '-SkipUpdates' has been selected #>
    If ($PSBoundParameters.ContainsKey("SkipUpdates")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "Parameter SkipUpdates" -strLogValue "Triggered"

        <# Consider feature on Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {
            
            <# Define variable #>
            $Global:bolSkipRequiredUpdates | Out-Null

            <# Set global variable for disabling updates check #>
            $Global:bolSkipRequiredUpdates = $true

        }
        Else {

            <# Not supported message on macOS #>
            Write-Output $Private:strNotAvailableOnMac

        }

    }

    <# Action if the parameter '-CollectAIPServiceConfiguration' has been selected #>
    If ($PSBoundParameters.ContainsKey("CollectAIPServiceConfiguration")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "Parameter CollectAIPServiceConfiguration" -strLogValue "Triggered"

        <# Consider feature on Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

            <# Call function to collect AIP configuration #>
            fncCollectAIPServiceConfiguration

        }
        Else {

            <# Not supported message on macOS #>
            Write-Output $Private:strNotAvailableOnMac

        }

    }

    <# Action if the parameter '-CollectAIPServiceTemplates' has been selected #>
    If ($PSBoundParameters.ContainsKey("CollectAIPServiceTemplates")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "Parameter CollectAIPServiceTemplates" -strLogValue "Triggered"

        <# Consider feature on Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

            <# Call function to collect AIP Service Templates #>
            fncCollectAIPServiceTemplates

        }
        Else {

            <# Not supported message on macOS #>
            Write-Output $Private:strNotAvailableOnMac

        }

    }

    <# Action if the parameter '-CollectLabelsAndPolicies' has been selected #>
    If ($PSBoundParameters.ContainsKey("CollectLabelsAndPolicies")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "Parameter CollectLabelsAndPolicies" -strLogValue "Triggered"

        <# Consider feature on Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

            <# Call function to collect labels and policies #>
            fncCollectLabelsAndPolicies

        }
        Else {

            <# Not supported message on macOS #>
            Write-Output $Private:strNotAvailableOnMac

        }

    }

    <# Action if the parameter '-CollectEndpointURLs' has been selected #>
    If ($PSBoundParameters.ContainsKey("CollectEndpointURLs")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "Parameter CollectEndpointsURLs" -strLogValue "Triggered"

        <# Consider feature on Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

            <# Call Collect Endpoint URLs function #>
            fncCollectEndpointURLs

        }
        Else {

            <# Not supported message on macOS #>
            Write-Output $Private:strNotAvailableOnMac

        }

    }

    <# Action if the parameter '-CheckForUpdate' has been selected #>
    If ($PSBoundParameters.ContainsKey("CheckForUpdate")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "Parameter CheckForUpdate" -strLogValue "Triggered"

        <# Call CheckForUpdate function #>
        fncCheckForUpdate

    }

    <# Action if the parameter '-CompressLogs' has been selected #>
    If ($PSBoundParameters.ContainsKey("CompressLogs")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "Parameter CompressLogs" -strLogValue "Triggered"

        <# Call function to compress all logs into a zip archive #>
        fncCompressLogs

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Exit function #>
        Break

    }

    <# Action if the parameter '-Menu' has been selected; default without any parameter #>
    If ($PsCmdlet.ParameterSetName -eq "Menu") {

        <# Call function to show menu #>
        fncShowMenu

        <# Verbose/Logging #>
        fncLogging -strLogFunction "UnifiedLabelingSupportTool" -strLogDescription "Menu" -strLogValue "Proceeded"

    }

}

<# Check for latest version of the script module #>
Function fncCheckForUpdate { 

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Update" -strLogValue "Initiated"

    <# Console output #>
    Write-Output "CHECK FOR UPDATE:`n"
    Write-Output "Searching for new version..."

    <# Define default message for outdated version #>
    $Private:strOutdatedVersionMessage = "ATTENTION: You're using an outdated version of the 'Unified Labeling Support Tool'.`nPlease update your environment by running the following command:`n`nPS C:\> Update-Module -Name UnifiedLabelingSupportTool -Force`n`nNote:`n`n- Under certain circumstances, you may need to run the 'Unified Labeling Support Tool' as user with local administrative privileges to perform an update.`n- If the 'Unified Labeling Support Tool' was not installed via PowerShell Gallery, any older version must first be removed before an update or installation can be performed."
    
    <# Validate connection to PowerShell Gallery #>
    If (Find-Module -Name UnifiedLabelingSupportTool -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) { <# Actions, if PowerShell Gallery can be reached #>

        <# Filling variable with online version information #>
        [Version]$Private:strOnlineVersion = (Find-Module -Name UnifiedLabelingSupportTool -Repository PSGallery).Version

        # Comparing local version vs. latest (online) version #>
        If ([Version]::new($Private:strOnlineVersion.Major, $Private:strOnlineVersion.Minor, $Private:strOnlineVersion.Build) -gt [Version]::new($Global:strVersion.Major, $Global:strVersion.Minor, $Global:strVersion.Build) -eq $true) {

            <# Detect Windows #>
            If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

                <# Action, if running as administrator #>
                If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $true) {

                    <# Update module only if the existing version was installed by PowerShell Gallery #>
                    If ((Get-InstalledModule -Name UnifiedLabelingSupportTool -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) -eq $true) {

                        <# Console output #>
                        Write-Output "A new version of the 'Unified Labeling Support Tool' is available."
                        Write-Output "Updating, please wait..."

                        <# Updating 'Unified Labeling Support Tool' #>
                        Update-Module -Name UnifiedLabelingSupportTool -Force

                        <# Internet availalbe: Console output #>
                        Write-Output (Write-Host "ATTENTION: A new version of the 'Unified Labeling Support Tool' has been installed.`nThe 'Unified Labeling Support Tool' is now terminated.`nPlease restart with a new PowerShell session/window." -ForegroundColor Red)

                        <# Verbose/Logging #>
                        fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Script module version" -strLogValue "Updated"

                    }
                    Else { <# Action, if module was not installed via PowerShell Gallery #>

                        <# Console output #>
                        Write-Output (Write-Host $Private:strOutdatedVersionMessage -ForegroundColor Red)

                        <# Verbose/Logging #>
                        fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Script module version" -strLogValue "Outdated"

                    }

                }
                Else { <# Actions, if running without administrative privileges #>

                    <# Console output #>
                    Write-Output (Write-Host $Private:strOutdatedVersionMessage -ForegroundColor Red)

                    <# Verbose/Logging #>
                    fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Script module version" -strLogValue "Outdated"

                }

            }

            <# Detect macOS #>
            If ($IsMacOS -eq $true) {
                    
                <# Console output #>
                Write-Output (Write-Host "ATTENTION: A new version of the 'Unified Labeling Support Tool' is available.`nPlease update your environment by running the following command:`n`nPS /Users/<username>> Update-Module -Name UnifiedLabelingSupportTool -Force`n`nNote:`n`n- Under certain circumstances, you may need to run the 'Unified Labeling Support Tool' as user with local administrative privileges to perform an update. Please request assistance from your administrator if necessary." -ForegroundColor Red)    

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Script module version" -strLogValue "Outdated"

            }

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Update" -strLogValue "Proceeded"
            fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Exit script module" -strLogValue $true

            <# Releasing private variable #>
            [Version]$Private:strOnlineVersion = $null

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Console output #>
            Write-Output (Write-Host "CHECK FOR UPDATE: Proceeded.`n" -ForegroundColor Green)

            <# Exit function #>
            Break

        }
        Else {

            <# Console output #>
            Write-Output "You're using the latest version of the 'Unified Labeling Support Tool'."

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Script module version" -strLogValue "Latest"

            <# Console output #>
            Write-Output (Write-Host "CHECK FOR UPDATE: Proceeded.`n" -ForegroundColor Green)

        }

    }
    Else { <# Actions, if PowerShell Gallery can not be reached (no internet connection) #>

        <# Console output #>
        Write-Output (Write-Host "ATTENTION: Check for update could not be performed.`nEither the website cannot be reached or there is no connection to the Internet.`n`nYou are using version: $Global:strVersion.`n`nPlease check on the following website if you are using the latest version of the 'Unified Labeling Support Tool', and update if necessary:`nhttps://aka.ms/UnifiedLabelingSupportTool/Latest" -ForegroundColor Red)

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Update" -strLogValue "No internet connection"

        <# Console output #>
        Write-Output (Write-Host "CHECK FOR UPDATE: Proceeded.`n" -ForegroundColor Green)

        <# Exit function #>
        Break

    }

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Update" -strLogValue "Proceeded"

    <# Releasing private variables #>
    [Version]$Private:strOnlineVersion = $null

}

<# Create log entries for log file and verbose output #>
Function fncLogging ($strLogFunction, $strLogDescription, $strLogValue) {

    <# Check if path exist and create it, if not #>
    If ($(Test-Path -Path $Global:strUserLogPath) -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath | Out-Null <# Define default user log path #>

    }

    <# Verbose output #>
    Write-Verbose "$(Get-Date -UFormat "%Y-%m-%d"), $(Get-Date -UFormat "%H:%M"), $strLogFunction, $strLogDescription, $strLogValue"

    <# Write (append) verbose output to log file #>
    Write-Verbose "$(Get-Date -UFormat "%Y-%m-%d"), $(Get-Date -UFormat "%H:%M"), $strLogFunction, $strLogDescription, $strLogValue" -ErrorAction SilentlyContinue -Verbose 4>> "$Global:strUserLogPath\Script.log" 

}

<# Show information #>
Function fncInformation {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncInformation" -strLogDescription "Information" -strLogValue "Called"

    <# Action, if function was called from command line #>
    If ($Global:bolCommingFromMenu -eq $false) {

        <# Call Information #>
        Get-Help -Verbose:$false UnifiedLabelingSupportTool

    }

    <# Action, if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {
    
        <# Console output #>
        Write-Output "NAME:`nUnifiedLabelingSupportTool`n`nDESCRIPTION:`nThe 'Unified Labeling Support Tool' provides the functionality to reset all corresponding client services (UL, AIP, MIP, etc.). Its main purpose is to delete the currently downloaded sensitivity label policies and thus reset all settings, and it can also be used to collect data for failure analysis and problem solving.`n`nVERSION:`n$Global:strVersion`n`nAUTHOR:`nClaus Schiroky`nCustomer Service & Support - EMEA Modern Work Team`nMicrosoft Deutschland GmbH`n`nHOMEPAGE:`nhttps://aka.ms/UnifiedLabelingSupportTool`n`nSPECIAL THANKS TO:`nSimone Götze-Lewicki`nCustomer Service & Support | EMEA Modern Work Team`nMicrosoft Deutschland GmbH`n`nPRIVACY STATEMENT:`nhttps://privacy.microsoft.com/PrivacyStatement`n`nCOPYRIGHT:`nCopyright (c) Microsoft Corporation.`n"

    }

}

<# Show License #>
Function fncLicense {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncLicense" -strLogDescription "License" -strLogValue "Called"

    <# Console output #>
    Write-Output (Write-Host "MIT License`n`nCopyright (c) Microsoft Corporation.`n`nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the `"Software`"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:`n`nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.`n`nTHE SOFTWARE IS PROVIDED `"AS IS`", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.`n")

}

<# Show help file #>
Function fncHelp {

    <# Detect Windows #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# Action if help file can be found in script module folder #>
        If ($(Test-Path $Private:PSScriptRoot"\ULSupportTool-Win.htm") -Eq $true) {

            <# Open help file #>
            Invoke-Item $Private:PSScriptRoot"\ULSupportTool-Win.htm"
            
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncHelp" -strLogDescription "Help" -strLogValue "Called"

        }

        <# Action if help file can't be found in script module folder #>
        If ($(Test-Path $Private:PSScriptRoot"\ULSupportTool-Win.htm") -Eq $false) {

            <# Check if internet connection is available #>
            If ($(fncTestInternetAccess "github.com") -Eq $true) {

                <# Call online help; Set by HelpURI in CmdletBinding #>
                Get-Help -Verbose:$false UnifiedLabelingSupportTool -Online

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncHelp" -strLogDescription "Help" -strLogValue "Called"

            }
            Else { <# Action if web site is unavailable or if there's no internet connection #>

                <# Console output #>
                Write-Output (Write-Host "ATTENTION: The help file (ULSupportTool-Win.htm) could not be found.`nEither the website cannot be reached or there is no internet connection.`n`nNote:`n`n- If you’re working in an environment that does not have internet access, you must download the file manually, before proceeding the 'Unified Labeling Support Tool'.`n- You must place the file to the location where you have stored the 'Unified Labeling Support Tool' files.`n- Please download the file from the following hyperlink (from a machine where you have internet access):`n  https://aka.ms/UnifiedLabelingSupportTool/Latest`n" -ForegroundColor Red)

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncHelp" -strLogDescription "Help" -strLogValue "No internet connection"

            }

        }

    }

    <# Detect and open help file on macOS #>
    If ($IsMacOS -eq $true) {

        <# Action if help file can be found in script module folder #>
        If ($(Test-Path "$Private:PSScriptRoot/ULSupportTool-Mac.htm") -Eq $true) {

            Open "$Private:PSScriptRoot/ULSupportTool-Mac.htm" <# Open help file #>

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncHelp" -strLogDescription "Help" -strLogValue "Called"

        }
        Else { <# Action if the help file cannot be found #>

            <# Console output #>
            Write-Output (Write-Host "ATTENTION: The help file (ULSupportTool-Mac.htm) could not be found.`n`nNote:`n`n- You must place the file to the location where you have installed the 'Unified Labeling Support Tool'.`n- Please download the file from the following location or reinstall:`n  https://aka.ms/UnifiedLabelingSupportTool/Latest`n" -ForegroundColor Red)

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncHelp" -strLogDescription "Help" -strLogValue "Not found"

        }

    }

}

<# Detect and delete a registry setting #>
Function fncDeleteRegistrySetting ($strRegistryKey, $strRegistrySetting) {

    <# Check if key exist #>
    If ($(Test-Path -Path $strRegistryKey) -Eq $true) {

        <# Validate registry setting by parameters #>
        If (Get-ItemProperty -Path $strRegistryKey | Select-Object -ExpandProperty $strRegistrySetting -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Try to remove registry setting #>
            Try {

                <# Remove registry setting #>
                Remove-ItemProperty -Path $strRegistryKey -Name $strRegistrySetting -Force -ErrorAction Stop -WarningAction SilentlyContinue
                
                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncDeleteRegistrySetting" -strLogDescription $strRegistrySetting -strLogValue "Removed"

            }
            Catch [System.Management.Automation.ItemNotFoundException] {

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncDeleteRegistrySetting" -strLogDescription $strRegistrySetting -strLogValue "Requested registry access is not allowed or setting does not exist."

            }
            Catch {

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncDeleteRegistrySetting" -strLogDescription $strRegistrySetting -strLogValue "ERROR: Failed"

            }

        }

    }
  
}

<# Reset Microsoft UL/AIP/MIP/etc. services for the current user #>
Function fncReset ($strResetMethod) {

    <# Action if function was not called with default #>
    If ($strResetMethod -notmatch "Silent") {

        <# Console output #>
        Write-Output "RESET:"
        Write-Output (Write-Host "ATTENTION: Before you proceed with this option, please close all open applications." -ForegroundColor Red)
        $Private:ReadHost = Read-Host "Only if the above is true, please press [Y]es to continue, or [N]o to cancel"

        <# Actions if "No" (cancel) was selected #>
        If ($Private:ReadHost -eq "N") {

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncReset" -strLogDescription "Reset" -strLogValue "Canceled"

            <# Action if function was called from command line #>
            If ($Global:bolCommingFromMenu -eq $false) {

                <# Set back window title to default #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                <# Exit function #>
                Break

            }

            <# Action if function was called from the menu #>
            If ($Global:bolCommingFromMenu -eq $true) {

                <# Clear console #>
                Clear-Host

                <# Call show menu function #>
                fncShowMenu    

            }

        }

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "Reset Default" -strLogValue "Initiated"

        <# Console output #>
        Write-Output "Resetting, please wait..."

    }
    Else { <# Action if function was called with silent argument #>

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "Reset Silent" -strLogValue "Initiated"

    }

    <# Detect Windows and run actions to reset #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# If "registry overrides" exist, create a backup copy #>
        If ($(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\MSIPC\ServiceLocation") -Eq $true) {

            <# Backup registry settings to a reg file #>
            REG EXPORT "HKLM\SOFTWARE\Microsoft\MSIPC\ServiceLocation" $Private:PSScriptRoot\ServiceLocationBackup.reg /Y | Out-Null

            <# Console output #>
            Write-Output "Your ServiceLocation registry settings were stored to"$Private:PSScriptRoot\ServiceLocationBackup.reg

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncReset" -strLogDescription "Export ServiceLocation backup" -strLogValue "ServiceLocationBackup.reg"

        }

        <# Force update group policy settings #>
        Write-Output Y | gpupdate /force | Out-Null

        <# Clean user registry keys #>
        fncDeleteItem "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\MSIPC"
        fncDeleteItem "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\AIPMigration"
        fncDeleteItem "HKCU:\SOFTWARE\Classes\Microsoft.IPViewerChildMenu"
        fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Cloud\Office"
        fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\DRM"
        fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\DRM"
        fncDeleteItem "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Common\DRM"
        fncDeleteItem "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\DRM"
        fncDeleteItem "HKCU:\SOFTWARE\Microsoft\XPSViewer\Common\DRM"
        fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Identity"
        fncDeleteItem "HKCU:\SOFTWARE\Microsoft\MSIP"
        fncDeleteItem "HKCU:\SOFTWARE\Microsoft\MSOIdentityCRL"

        <# Clean registry settings #>
        fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Cloud\Office\16.0\Common\Security\Labels" -strRegistrySetting "UseOfficeForLabelling"
        fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security\Labels" -strRegistrySetting "UseOfficeForLabelling"
        fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security\Lables" -strRegistrySetting "UseOfficeForLabelling"
        fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security" -strRegistrySetting "OpenXMLEncryptProperty"
        fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security" -strRegistrySetting "OpenXMLEncryptProperty"
        fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\Common\Security" -strRegistrySetting "DRMEncryptProperty"
        fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security" -strRegistrySetting "DRMEncryptProperty"
        fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Security" -strRegistrySetting "DRMEncryptProperty"
        fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security" -strRegistrySetting "DRMEncryptProperty"

        <# Clean client classes registry keys #>
        fncDeleteItem "HKCR:\AllFilesystemObjects\shell\Microsoft.Azip.Inspect"
        fncDeleteItem "HKCR:\AllFilesystemObjects\shell\Microsoft.Azip.RightClick"

        <# Clean client folders in file system #>
        fncDeleteItem "$env:LOCALAPPDATA\Microsoft\Office\DLP\mip"
        fncDeleteItem "$env:TEMP\Diagnostics"
        fncDeleteItem "$env:LOCALAPPDATA\Microsoft\MSIP"
        fncDeleteItem "$env:LOCALAPPDATA\Microsoft\MSIPC"
        fncDeleteItem "$env:LOCALAPPDATA\Microsoft\DRM"

        <# Additional actions to proceed administrative reset #>
        If ($Global:bolRunningPrivileged -eq $true) {

            # Clean machine registry keys #>
            fncDeleteItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSIPC"
            fncDeleteItem "HKLM:\SOFTWARE\Microsoft\MSIPC"
            fncDeleteItem "HKLM:\SOFTWARE\Microsoft\MSDRM"
            fncDeleteItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSDRM"
            fncDeleteItem "HKLM:\SOFTWARE\WOW6432Node\Microsoft\MSIP"

        }

        <# Check for Office 2013, and enable modern authentication if installed #>
        If ($(fncCheckForOffice2013) -Eq $true) { 

            <# Check for Office 2013 registry key #>
            If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0") -Eq $true) {
        
                <# Create registry key (overwrite) #>
                New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Identity" -ErrorAction SilentlyContinue | Out-Null
        
                <# Implement registry settings to enable modern authentication for Office 2013 #>
                New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Identity" -Name "EnableADAL" -Value 1 -PropertyType DWord -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Identity" -Name "Version" -Value 1 -PropertyType DWord -ErrorAction SilentlyContinue | Out-Null
        
                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncReset" -strLogDescription "ADAL for Office 2013" -strLogValue "Enabled"

            }

        }

        <# Actions on PowerShell 7.1 (or higher) for compatibility mode #>
        If ([Version]::new($PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor) -ge [Version]::new("7.1") -eq $true) {

            <# Remove AIPService and AzureInformationProtection module, because it's not compatible with PowerShell 7.1 (or higher) #>
            Remove-Module -Name AzureInformationProtection -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

            <# Import AIPService and AzureInformationProtection module in compatiblity mode #>
            Import-Module -Name AzureInformationProtection -UseWindowsPowerShell -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncReset" -strLogDescription "AzureInformationProtection compatiblity mode" -strLogValue $true

        }

        <# Clear user settings #>
        If (Get-Module -ListAvailable -Name AzureInformationProtection) { <# Check for installed AIP client #>
    
            <# Clear user settings #>
            Clear-AIPAuthentication -ErrorAction SilentlyContinue | Out-Null

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncReset" -strLogDescription "AIPAuthentication" -strLogValue "Cleared"

        }

    }

    <# Reset for macOS #>
    If ($IsMacOS -eq $true) {

        <# Clean Office client folders/*.policy.xml file #>
        fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.Word/Data/Library/Application Support/Microsoft/Office/CLP" <# Word #>
        fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.Excel/Data/Library/Application Support/Microsoft/Office/CLP" <# Excel #>
        fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.PowerPoint/Data/Library/Application Support/Microsoft/Office/CLP" <# PowerPoint #>
        fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.Outlook/Data/Library/Application Support/Microsoft/Office/CLP" <# Outlook #>

        <# Clean Office log folders (ULS, MIP) #>
        fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.Word/Data/Library/Logs" <# Word #>
        fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.Excel/Data/Library/Logs" <# Excel #>
        fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.PowerPoint/Data/Library/Logs" <# PowerPoint #>
        fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.Outlook/Data/Library/Logs" <# Outlook #>

        <# Clean RMS Sharing App log folders #>
        fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.protection.rms-sharing-mac/Data/Library/Logs" <# Outlook #>

        <# Clean Office MIP SDK #>
        fncDeleteItem "$(printenv HOME)/Library/Group Containers/UBF8T346G9.Office/mip_policy/mip/logs" <# MIP #>

    }

    <# Action if function was not called silent from command line #>
    If ($strResetMethod -notmatch "Silent") {

        <# Console output #>
        Write-Output (Write-Host "RESET: Proceeded.`n" -ForegroundColor Green)

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "Reset Default" -strLogValue "Proceeded"

    }
    Else { <# Action if function was called with the silent argument #>

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "Reset Silent" -strLogValue "Proceeded"

    }

}

<# Check, if Office 2013 is installed; used to enable ADAL at reset #>
Function fncCheckForOffice2013 {

    <# Loop through uninstall registry key to find any Office application #>
    Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -Name | ForEach-Object {

        <# Check for Office applications/GUIDs #>
        If ($_.ToString() -like "*0000000FF1CE}") {

            <# Check for major version "15" = Office 2013 #>
            If (Get-ItemProperty $_.PSPath | Where-Object {$_.VersionMajor -eq "15"}) {
                

                <# Return "true", if an Office 2013 applictation was found #>
                Return $true

                <# Set back window title to default #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle                

                <# Leaving ForEach loop #>
                Break

            }
            Else {

                <# Return "false", if no Office 2013 applictation was found #>
                Return $false

                <# Set back window title to default #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle
                
                <# Leaving loop #>
                Break

            }

        }

    }

}

<# Delete item/s or folders (with IO error handling) #>
Function fncDeleteItem ($Private:objItem) {

    <# Check if key, file or folder exist #>
    If ($(Test-Path -Path $Private:objItem) -Eq $true) {

        <# Try to delete item/s or folders #>
        Try {
            
            <# Detect Windows #>
            If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

                <# Delete folder or registry key #>
                Get-ChildItem -Path $Private:objItem -Exclude "Telemetry", "powershell.exe", "powershell" -Force | Remove-Item -Recurse -Force -ErrorAction Stop | Out-Null

            }
            
            <# Detect macOS #>
            If ($IsMacOS -eq $true) {

                <# Delete folder or file #>
                Remove-item -Path $Private:objItem -Recurse -Force -ErrorAction Stop | Out-Null

            }

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncDeleteItem" -strLogDescription "Item deleted" -strLogValue $Private:objItem

        }
        Catch [System.IO.IOException] { <# Actions if files or folders cannot be accessed, because they are locked/used by another process <#>

            <# Console output #>
            Write-Output (Write-Host "WARNING: Some items or folders are still used by another process.`nIMPORTANT: Please close all applications, restart the PowerShell session (or restart machine) and try again." -ForegroundColor Red)

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncDeleteItem" -strLogDescription "Item locked" -strLogValue $Private:objItem
            fncLogging -strLogFunction "fncDeleteItem" -strLogDescription "Reset" -strLogValue "ERROR: Reset failed"

            <# Release private variable #>
            $Private:objItem = $null

            <# Action if function was not called from the menu #>
            If ($Global:bolCommingFromMenu -eq $false) {

                <# Console output #>
                Write-Output (Write-Host "RESET: Failed.`n" -ForegroundColor Red)

                <# Set back window title to default #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                <# Interrupting Reset #>
                Break

            }
            <# Action if function was called from the menu #>
            If ($Global:bolCommingFromMenu -eq $true) {

                <# Console output #>
                Write-Output (Write-Host "RESET: Failed.`n" -ForegroundColor Red)

                <# Console output with pause #>
                fncPause

                <# Call menu #>
                fncShowMenu

            }

        }

    }

    <# Release private variable #>
    $Private:objItem = $null

}

<# Copy item/s for fncCollectLogging #>
Function fncCopyItem ($Private:objItem, $Private:strDestination, $Private:strFileName) {

    <# Try to copy item/s #>
    Try {

        <# Check if path exist and proceed with file copy #>
        If ($(Test-Path -Path $Private:objItem) -Eq $true) {

            <# Copy item/s #>
            Copy-Item -Path $Private:objItem -Destination $Private:strDestination -Recurse -Force -ErrorAction Stop | Out-Null
            
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCopyItem" -strLogDescription "Item copied" -strLogValue $Private:strFileName

        }

    }
    Catch [System.IO.IOException] { <# Action if file cannot be accessed, because it's locked/used by another process <#>

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCopyItem" -strLogDescription "Item locked" -strLogValue "ERROR: "$Private:objItem

        <# Release private variables #>
        $Private:objItem = $null
        $Private:strDestination = $null

    }

    <# Release private variables #>
    $Private:objItem = $null
    $Private:strDestination = $null

}

<# Check for internet access #>
Function fncTestInternetAccess ($Private:strURL) {

    <# Check if internet access is available #>
    If ($(Test-Connection $Private:strURL -Count 1 -Quiet) -Eq $true) {

        <# Return true, if we have internet access #>
        Return $true
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncTestInternetAccess" -strLogDescription "Internet access" -strLogValue $true

    }
    Else {

        <# Return false, if we do not have internet access #>
        Return $false
       
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncTestInternetAccess" -strLogDescription "Internet access" -strLogValue $false

    }

    <# Release private variable #>
    $Private:strURL = $null

}

<# Record data/problem #>
Function fncRecordProblem {

    <# Console output #>
    Write-Output "RECORD PROBLEM:"
    Write-Output (Write-Host "ATTENTION: Before you proceed with this option, please close all open applications." -ForegroundColor Red)
    $Private:ReadHost = Read-Host "Only if the above is true, please press [Y]es to continue, or [N]o to cancel"

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "Record Problem" -strLogValue "Initiated"

    <# Actions if yes was selected #>
    If ($Private:ReadHost -Eq "Y") {

        <# Detect Windows and record problem #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

            <# Check if not running as administrator #>
            If ($Global:bolRunningPrivileged -eq $false) {

                <# Verbose/Logging #>
                Write-Output (Write-Host "ATTENTION: Please note that neither CAPI2 or AIP event logs, network trace nor filter drivers are recorded.`nIf you want a complete record, you must run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges." -ForegroundColor Red)

            }
        
            <# Console output #>
            Write-Output "Initializing, please wait..."

            <# Variables for unique log folder #>    
            $Private:strUniqueFolderName = (Get-Date -Verbose:$false -UFormat "%y%m%d-%H%M%S")
            $Global:strUniqueLogFolder = $Global:strUserLogPath.ToString() + "\" +  $Private:strUniqueFolderName.ToString()

            <# Create unique log folder #>
            New-Item -ItemType Directory -Force -Path $Global:strUniqueLogFolder | Out-Null
    
            <# Verbose/Logging #>
            fncLogging "fncRecordProblem" -strLogDescription "New log folder created" -strLogValue $Private:strUniqueFolderName

            <# Clean MSIP/MSIPC client folders in file system #>
            fncDeleteItem "$env:LOCALAPPDATA\Microsoft\MSIP"
            fncDeleteItem "$env:LOCALAPPDATA\Microsoft\MSIPC"

            <# Call function to enable logging #>
            fncEnableLogging

            <# Console output, after privileges check #>
            If ($Global:bolRunningPrivileged -eq $false) {

                <# Console output, if not running with administrative privileges #>
                Write-Output "Record problem is now activated for user `"$Env:UserName`"."

            }
            Else {

                <# Console output if running with administrative privileges #>
                Write-Output "Record problem is now activated for administrator `"$Env:UserName`"."

            }

            <# Console output #>
            Write-Output (Write-Host "IMPORTANT: Now start to reproduce your problem, but leave this window open." -ForegroundColor Red)
            Read-Host "After reproducing the problem, close all applications you have used for, then come back here and press enter to continue"

            <# Console output #>
            Write-Output "Collecting logs, please wait...`n"

            <# Call function to collect log files #>
            fncCollectLogging
        
            <# Call function to disable/rool back logging settings #>
            fncDisableLogging

        }

        <# Detect macOS and record problem #>
        If ($IsMacOS -eq $true) {

            <# Console output #>
            Write-Output "Initializing, please wait..."

            <# Variables for unique log folder #>    
            $Private:strUniqueFolderName = (Get-Date -Verbose:$false -UFormat "%y%m%d-%H%M%S")
            $Global:strUniqueLogFolder = $Global:strUserLogPath.ToString() + "\" +  $Private:strUniqueFolderName.ToString()

            <# Create unique log folder #>
            New-Item -ItemType Directory -Force -Path $Global:strUniqueLogFolder | Out-Null
    
            <# Verbose/Logging #>
            fncLogging "fncRecordProblem" -strLogDescription "New log folder created" -strLogValue $Private:strUniqueFolderName

            <# Console output #>
            Write-Output (Write-Host "IMPORTANT: Now start to reproduce your problem, but leave this window open." -ForegroundColor Red)
            Read-Host "After reproducing the problem, close all applications you have used for, then come back here and press enter to continue"

            <# Console output #>
            Write-Output "Collecting logs, please wait...`n"

            <# Call function to collect log files #>
            fncCollectLogging

        }

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "Record Problem" -strLogValue "Proceeded" 

        <# Console output #>
        Write-Output "Log files: $Global:strUniqueLogFolder"
        Write-Output (Write-Host "RECORD PROBLEM: Proceeded.`n" -ForegroundColor Green)

        <# Release variable #>
        $Global:strUniqueLogFolder = $null

    }
    <# Actions if "No" (cancel) was selected #>
    ElseIf ($Private:ReadHost -eq "N") {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "Record Problem" -strLogValue "Canceled"

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Clear console #>
            Clear-Host

            <# Call show menu function #>
            fncShowMenu    

        }

    }
    Else { <# Actions if any other key was pressed #>

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "Record Problem" -strLogValue "Canceled"

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {
 
            <# Clear console #>
            Clear-Host
 
            <# Call show menu function #>
            fncShowMenu    
 
        }

    }

    <# Release private variable #>
    $Private:ReadHost = $null

}

<# Initialize/enable logging #>
Function fncEnableLogging {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Enable logging" -strLogValue "Triggered"

    <# Implement registry key for function fncValidateForActivatedLogging to check whether logging was left enabled (for problem record) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\UnifiedLabelingSupportTool") -Eq $false) { <# Check, if path exist (to check for logging enabled), and create it if not #>

        <# Create registry key, if does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\UnifiedLabelingSupportTool" -Force | Out-Null

    }

    <# Implement registry key to check for enabled logging on next start, and rollback settings if necessary #>
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\UnifiedLabelingSupportTool" -Name "LoggingActivated" -Value $true -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null

    <# Progress bar #>
    Write-Progress -Activity " Enable logging..." -PercentComplete 0
    
    <# Check if running with administrative privileges, and enabling corresponding logs #>
    If ($Global:bolRunningPrivileged -eq $true) {

        <# Progress bar update #>
        Write-Progress -Activity " Enable logging: CAPI2 event logging..." -PercentComplete (100/8 * 1)

        <# Enable CAPI2 event log #>
        Write-Output Y | wevtutil set-log Microsoft-Windows-CAPI2/Operational /enabled:True

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "CAPI2 event log" -strLogValue "Enabled"

        <# Clear CAPI2 event log #>
        wevtutil.exe clear-log Microsoft-Windows-CAPI2/Operational
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "CAPI2 event log" -strLogValue "Cleared"


        <# Progress bar update #>
        Write-Progress -Activity " Enable logging: Starting network trace..." -PercentComplete (100/8 * 2)

        <# Start network trace #>
        netsh.exe trace start capture=yes scenario=NetConnection,InternetClient sessionname="UnifiedLabelingSupportTool-Trace" report=disabled maxsize=1024, tracefile="$Global:strUniqueLogFolder\NetMon.etl" | Out-Null
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Network trace" -strLogValue "Started"

    }

    <# Progress bar update #>
    Write-Progress -Activity " Enable logging: Office logging..." -PercentComplete (100/8 * 3)

    <# Enable Office logging for 2013 (15.0), 2016 (16.0) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Logging") -Eq $false) {

        <# Create registry key, if does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Logging" -Force | Out-Null

    }

    <# Check for registry key "Logging" (2013) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Logging") -Eq $false) {

        <# Create registry key, if does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Logging" -Force | Out-Null

    }

    <# Check for registry key "Logging" (2016 x64) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\Logging") -Eq $false) {

        <# Create registry key, if does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\Logging" -Force | Out-Null

    }

    <# Check for registry key "Logging" (2013 x64) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Common\Logging") -Eq $false) {

        <# Create logging registry key, if it does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Common\Logging" -Force | Out-Null

    }

    <# Implement registry settings to enable logging for the different Office versions #>
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Logging" -Name "EnableLogging" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Logging" -Name "EnableLogging" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Common\Logging" -Name "EnableLogging" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\Logging" -Name "EnableLogging" -Value 1 -PropertyType DWord -Force | Out-Null

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office Logging" -strLogValue "Enabled"

    <# Progress bar update #>
    Write-Progress -Activity " Enable logging: Office TCOTrace..." -PercentComplete (100/8 * 4)

    <# Enable Office TCOTrace logging for Office 2013 (15.0), 2016 (16.0) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Debug") -Eq $false) { <# Check for registry key "Debug" (2016) #>

        <# Create registry key if it does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Debug" -Force | Out-Null

    }
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Debug" -Name "TCOTrace" -Value 1 -PropertyType DWord -Force | Out-Null

    <# Check for registry key "Debug" (2013) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Debug") -Eq $false) { <# Check for registry key "Debug" (2013) #>

        <# Create registry key if it does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Debug" -Force | Out-Null

    }
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Debug" -Name "TCOTrace" -Value 1 -PropertyType DWord -Force | Out-Null

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office TCOTrace" -strLogValue "Enabled"

    <# Progress bar update #>
    Write-Progress -Activity " Enable logging: Cleaning MSIP/MSIPC logs..." -PercentComplete (100/8 * 5)

    <# Clean MSIP/MSIPC/AIP v2 logs folder #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\MSIP\Logs) -Eq $true) { <# If foler exist #>

        <# Clean MSIP/AIP v1/2 log folder content #>
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\MSIP\Logs" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "MSIP log folder" -strLogValue "Cleared"

    }

    <# Check if MSIPC folder exist #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\MSIPC\Logs) -Eq $true) {

        <# Clean MSIPC log folder content #>
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\MSIPC\Logs" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "MSIPC log folder" -strLogValue "Cleared"

    }

    <# Check if MSIP folder exist #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\MSIP\mip) -Eq $true) {

        <# Clean MIP SDK/AIP v2 log folder #>
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\MSIP\mip" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "MIP log folder" -strLogValue "Cleared"

    }

    <# Check if MIP folder exist #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\Office\DLP\mip) -Eq $true) {

        <# Clean Office DLP/MIP log folder content #>
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Office\DLP\mip" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office DLP/MIP log folder" -strLogValue "Cleared"

    }

    <# If foler exist #>
    If ($(Test-Path -Path $env:TEMP\Diagnostics) -Eq $true) {

        <# Clean Office Diagnostics folder #>
        Remove-Item -Path "$env:TEMP\Diagnostics" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office Diagnostics log folder" -strLogValue "Cleared"

    }

    <# Progress bar update #>
    Write-Progress -Activity " Enable logging: Flushing DNS..." -PercentComplete (100/8 * 6)

    <# Flush DNS #>
    ipconfig.exe /flushdns | Out-Null
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Flush DNS" -strLogValue "Called"

    <# Progress bar update #>
    Write-Progress -Activity " Enable logging: Starting PSR..." -PercentComplete (100/8 * 7)

    <# Start PSR #>
    psr.exe /gui 0 /start /output "$Global:strUniqueLogFolder\ProblemSteps.zip"
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "PSR" -strLogValue "Started"

    <# Clean temp folder for office.log (TCOTrace) #>
    If ($(Test-Path $Global:strTempFolder"\office.log") -Eq $true) {
    
        <# Remove file office.log #>
        Remove-Item -Path "$Global:strTempFolder\office.log" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office TCOTrace temp file" -strLogValue "Cleared"
    
    }

    <# Clean temp folder for office log (machine name) #>
    If ($(Test-Path "$Global:strTempFolder\$([System.Environment]::MachineName)*.log") -Eq $true) {
    
        <# Remove file office.log #>
        Remove-Item -Path "$Global:strTempFolder\$([System.Environment]::MachineName)*.log" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office log temp file" -strLogValue "Cleared"
    
    }

    <# Progress bar update #>
    Write-Progress -Activity "  Logging enabled" -Completed

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Enable logging" -strLogValue "Proceeded" 

}

<# Disable/rool back all logging settings #>
Function fncDisableLogging {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "Disable logging" -strLogValue "Triggered" 

    <# Progress bar #>
    Write-Progress -Activity " Disable logging..." -PercentComplete 0

    <# Check if running with administrative privileges, and enabling admininistrative actions #>
    If ($Global:bolRunningPrivileged -eq $true) {

        <# Progress bar update #>
        Write-Progress -Activity " Disable logging: CAPI2 event log..." -PercentComplete (100/6 * 1) 

        <# Disable CAPI2 event log #>
        wevtutil.exe set-log Microsoft-Windows-CAPI2/Operational /enabled:false
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "CAPI2 event log" -strLogValue "Disabled"

        <# Progress bar update #>
        Write-Progress -Activity " Disable logging: Network trace..." -PercentComplete (100/6 * 2)

        <# Stopping network trace #>
        netsh.exe trace stop sessionname="UnifiedLabelingSupportTool-Trace" | Out-Null
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "Network trace" -strLogValue "Disabled"

    }

    <# Progress bar update #>
    Write-Progress -Activity " Disable logging: Office logging..." -PercentComplete (100/6 * 3)

    <# Disable Office logging for  2013 (15.0), 2016 (16.0) #>
    fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Logging"
    fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Logging"
    fncDeleteItem "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Common\Logging"
    fncDeleteItem "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\Logging"

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "Office Logging" -strLogValue "Disabled"

    <# Progress bar update #>
    Write-Progress -Activity " Disable logging: Office TCOTrace..." -PercentComplete (100/6 * 4)

    <# Disable Office TCOTrace logging for Office 2013 (15.0), 2016 (16.0) #>
    fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Debug"
    fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Debug"

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "Office TCOTrace" -strLogValue "Disabled"

    <# Progress bar update #>
    Write-Progress -Activity " Disable logging: PSR..." -PercentComplete (100/6 * 5)

    <# Stop PSR #>
    psr.exe /stop
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "PSR" -strLogValue "Disabled"

    <# Implement registry key for function fncValidateForActivatedLogging to check whether logging was left enabled (for problem record) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\UnifiedLabelingSupportTool") -Eq $false) { <# Check, if path exist (to check for logging enabled), and create it if not #>

        <# Create registry key if it does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\UnifiedLabelingSupportTool" -Force | Out-Null

    }

    <# Implement registry key to check for enabled logging on next start, and rollback settings if necessary #>
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\UnifiedLabelingSupportTool" -Name "LoggingActivated" -Value $false -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null

    <# Progress bar update #>
    Write-Progress -Activity " Logging disabled" -Completed

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "Disable logging" -strLogValue "Proceeded" 

}

<# Check whether logging (for problem record) was left enabled #>
Function fncValidateForActivatedLogging {

    <# Detect Windows #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# Read registry key to check for enabled logging. Used in fncEnableLogging, and fncDisableLogging #>
        If ((Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\UnifiedLabelingSupportTool" -Name LoggingActivated -ErrorAction SilentlyContinue).LoggingActivated -eq $true) {

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncValidateForActivatedLogging" -strLogDescription "Disable logging" -strLogValue "Initiated" 
            
            <# Function call to disable/rool back all logging settings #>
            fncDisableLogging

        }

    }

}

<# Finalize and collect/export logging data #>
Function fncCollectLogging {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Collecting logs" -strLogValue "Triggered" 

    <# Progress bar #>
    Write-Progress -Activity " Collecting logs..." -PercentComplete 0

    <# Detect Windows and collect logs #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# Check if running with administrative permissons, and enabling admininistrative actions #>
        If ($Global:bolRunningPrivileged -eq $true) {

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: CAPI2 event log..." -PercentComplete (100/25 * 1)

            <# Export CAPI2 event log #>
            wevtutil.exe export-log Microsoft-Windows-CAPI2/Operational "$Global:strUniqueLogFolder\CAPI2.evtx" /overwrite:true
        
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export CAPI2 event log" -strLogValue "CAPI2.evtx"

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: AIP event log..." -PercentComplete (100/25 * 2)

            <# Actions when AIP event log exist #>
            If ([System.Diagnostics.EventLog]::Exists("Azure Information Protection") -Eq $true) {

                <# Export AIP event log #>
                wevtutil.exe export-log "Azure Information Protection" "$Global:strUniqueLogFolder\AIP.evtx" /overwrite:true
            
                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export AIP event log" -strLogValue "AIP.evtx"

            }

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: Network trace..." -PercentComplete (100/25 * 3)

            <# Stop network trace #>
            netsh.exe trace stop sessionname="UnifiedLabelingSupportTool-Trace" | Out-Null

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Network trace" -strLogValue "Stopped"
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export network trace" -strLogValue "NetMon.etl"

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: Filter drivers..." -PercentComplete (100/25 * 4)

            <# Export filter drivers #>
            fltmc.exe filters > "$Global:strUniqueLogFolder\Filters.log"

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export filter drivers" -strLogValue "Filters.log"

        }

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: PSR recording..." -PercentComplete (100/25 * 5)

        <# Stop PSR #>
        psr.exe /stop

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "PSR" -strLogValue "Stopped"
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export PSR" -strLogValue "ProblemSteps.zip"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Application event log..." -PercentComplete (100/25 * 6)

        <# Export Application event log #>
        wevtutil.exe export-log Application "$Global:strUniqueLogFolder\Application.evtx" /overwrite:true

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Application event log" -strLogValue "Application.evtx"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: System event log..." -PercentComplete (100/25 * 7)

        <# Export System event log #>
        wevtutil.exe export-log System "$Global:strUniqueLogFolder\System.evtx" /overwrite:true
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export System event log" -strLogValue "System.evtx"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Office log files..." -PercentComplete (100/25 * 8)

        <# Check for Office log path and create it, if it not exist #>
        If ($(Test-Path -Path "$Global:strUniqueLogFolder\Office") -Eq $false) {

            <# Create Office log folder #>
            New-Item -ItemType Directory -Force -Path "$Global:strUniqueLogFolder\Office" | Out-Null
            
            <# Check for Office MIP path, and create it only if no AIP client is installed; because with AIP client we collect already the mip folder with the AIPLogs.zip #>
            If (-not (Get-Module -ListAvailable -Name AzureInformationProtection)) { <# Check for AIP client #>

                <# Create Office MIP log folder #>
                New-Item -ItemType Directory -Force -Path "$Global:strUniqueLogFolder\Office\mip" | Out-Null

                <# Export Office MIP content to logs folder #>
                fncCopyItem $env:LOCALAPPDATA\Microsoft\Office\DLP\mip "$Global:strUniqueLogFolder\Office" "mip\*"

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Office MIP logs" -strLogValue "\Office\mip"

            }

        }

        <# Copy Office Diagnostics folder from temp folder to Office logs folder #>
        fncCopyItem $env:TEMP\Diagnostics "$Global:strUniqueLogFolder\Office" "Diagnostics\*"

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Office Diagnostics logs" -strLogValue "\Office\Diagnostics"

        <# Copy office log files from temp folder to logs folder #>
        fncCopyItem $Global:strTempFolder"\office.log" "$Global:strUniqueLogFolder\Office\office.log" "office.log"

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Office log" -strLogValue "office.log"

        <# Copy Office logging files for 2013 (15.0), 2016 (16.0) to logs folder #>
        fncCopyItem "$Global:strTempFolder\$([System.Environment]::MachineName)*.log" "$Global:strUniqueLogFolder\Office" "Office\$([System.Environment]::MachineName)*.log"

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Office log" -strLogValue "\Office"

        <# Clean Office log files from temp folder #>
        fncDeleteItem "$Global:strTempFolder\$([System.Environment]::MachineName)*.log"
        fncDeleteItem "$Global:strTempFolder\Office.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: AIP/MSIP/MSIPC/MIP logs..." -PercentComplete (100/25 * 9)

        <# Export MIP/MSIP/MSIPC folders (and more) to logs folder #>
        If (Get-Module -ListAvailable -Name AzureInformationProtection) { <# Check for AIP client and collecting folder content #>

            <# Feed variable with AIP client version information #>
            $strAIPClientVersion = $((Get-Module -ListAvailable -Name AzureInformationProtection).Version).ToString()

            <# Action with AIPv1 client #>
            If ($strAIPClientVersion.StartsWith("1") -eq $true) {
                
                <# Copy MSIP content to logs folder #>
                fncCopyItem $env:LOCALAPPDATA\Microsoft\MSIP "$Global:strUniqueLogFolder\MSIP" "MSIP\*"

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export MSIP content" -strLogValue "\MSIP"

                <# Copy MSIPC content to logs folder #>
                fncCopyItem $env:LOCALAPPDATA\Microsoft\MSIPC "$Global:strUniqueLogFolder\MSIPC" "MSIPC\*"

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export MSIPC content" -strLogValue "\MSIPC"

            }
            <# Action with AIPv2 client #>
            ElseIf ($strAIPClientVersion.StartsWith("2") -eq $true) {

                <# Remember default progress bar status: 'Continue' #>
                $Private:strOriginalPreference = $Global:ProgressPreference 
                $Global:ProgressPreference = "SilentlyContinue" <# Hiding progress bar #>

                <# Try to export AIP log folders with authentication #>
                Try {

                    <# Export AIP log folders with existing authentication #>
                    Export-AIPLogs -FileName "$Global:strUniqueLogFolder\AIPLogs.zip" | Out-Null
            
                }
                Catch { <# Actions with no authentication #>
                    
                    <# Check for AzureInformationProtection module #>
                    If (Get-Module -ListAvailable -Name AzureInformationProtection) {

                        <# Informative output #>
                        Write-Output "Please authenticate with your user credentials to retrieve your AIP logs folders."

                        <# Actions on PowerShell 7.1 (or higher) for compatibility mode #>
                        If ([Version]::new($PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor) -ge [Version]::new("7.1") -eq $true) {

                            <# Remove AIPService and AzureInformationProtection module, because it's not compatible with PowerShell 7.1 (or higher) #>
                            Remove-Module -Name AzureInformationProtection -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

                            <# Import AIPService and AzureInformationProtection module in compatiblity mode #>
                            Import-Module -Name AzureInformationProtection -UseWindowsPowerShell -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

                            <# Verbose/Logging #>
                            fncLogging -strLogFunction "fncReset" -strLogDescription "AzureInformationProtection compatiblity mode" -strLogValue $true

                        }

                        <# Authenticate for accessing logs #>
                        Set-AIPAuthentication

                        <# Export AIP log folders #>
                        Export-AIPLogs -FileName "$Global:strUniqueLogFolder\AIPLogs.zip" | Out-Null

                        <# Clear authentication #>
                        Clear-AIPAuthentication -ErrorAction SilentlyContinue | Out-Null

                        <# Verbose/Logging #>
                        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "AIPAuthentication" -strLogValue "Cleared"

                    }                
            
                }

                <# Set back progress bar to previous setting #>
                $Global:ProgressPreference = $Private:strOriginalPreference    

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export AIP Log folders" -strLogValue $true

            }

        }
        Else {<# Action without any AIP client #>

            <# Export Office MIP content to logs folder #>
            fncCopyItem $env:LOCALAPPDATA\Microsoft\Office\DLP\mip "$Global:strUniqueLogFolder\Office" "mip\*"

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Office MIP content" -strLogValue "\Office"

            <# Export Office Diagnostics content to logs folder #>
            fncCopyItem $env:TEMP\Diagnostics "$Global:strUniqueLogFolder\Office" "Diagnostics\*"

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Office Diagnostics content" -strLogValue "\Office"

            <# Export MSIP/MSIPC content to logs folder #>
            fncCopyItem $env:LOCALAPPDATA\Microsoft\MSIP "$Global:strUniqueLogFolder\MSIP" "MSIP\*"

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export MSIP content" -strLogValue "\MSIP"

            <# Copy files to logs folder #>
            fncCopyItem $env:LOCALAPPDATA\Microsoft\MSIPC "$Global:strUniqueLogFolder\MSIPC" "MSIPC\*"

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export MSIPC content" -strLogValue "\MSIPC"

        }

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: WinHTTP..." -PercentComplete (100/25 * 10)

        <# Export WinHTTP #>
        netsh.exe winhttp show proxy > "$Global:strUniqueLogFolder\WinHTTP.log"
        
        <# Verbose/Logging #>
        fncLOgging -strLogFunction "fncCollectLogging" -strLogDescription "Export WinHTTP" -strLogValue "WinHTTP.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: WinHTTP (WoW6432)..." -PercentComplete (100/25 * 11)

        <# Export WinHTTP_WoW6432 (only 64-bit OS) #>
        If ((Get-CimInstance Win32_OperatingSystem  -Verbose:$false).OSArchitecture -eq "64-bit") {

            & $env:WINDIR\SysWOW64\netsh.exe winhttp show proxy > "$Global:strUniqueLogFolder\WinHTTP_WoW6432.log"
        
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export WinHTTP_WoW6432" -strLogValue "WinHTTP_WoW6432.log"

        }

        <# Export IE AutoConfigURL if available #>
        If ((Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\" -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL) {

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: AutoConfigURL..." -PercentComplete (100/25 * 12)

            <# Windows version and release ID #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export IE AutoConfigURL" -strLogValue "AutoConfigURL.log"

            <# Export IE AutoConfigURL #>
            Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object AutoConfigURL > "$Global:strUniqueLogFolder\AutoConfigURL.log"

        }

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Machine certificates..." -PercentComplete (100/25 * 13)

        <# Export machine certificates #>
        certutil.exe -silent -store my > "$Global:strUniqueLogFolder\CertMachine.log"
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export machine certificates" -strLogValue "CertMachine.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: User certificates..." -PercentComplete (100/25 * 14)

        <# Export user certificates #>
        certutil.exe -silent -user -store my > "$Global:strUniqueLogFolder\CertUser.log"
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export user certificates" -strLogValue "CertUser.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Credentials information..." -PercentComplete (100/25 * 15)

        <# Export Credential Manager data #>
        cmdkey.exe /list > "$Global:strUniqueLogFolder\CredMan.log"
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Credential Manager" -strLogValue "CredMan.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: IP configuration..." -PercentComplete (100/25 * 16)

        <# Export IP configuration #>
        ipconfig.exe /all > "$Global:strUniqueLogFolder\IPConfigAll.log"
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export ipconfig" -strLogValue "IPConfigAll.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: DNS..." -PercentComplete (100/25 * 17)

        <# Export DNS configuration  #>
        ipconfig.exe /displaydns > "$Global:strUniqueLogFolder\WinIPConfig.txt" | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export DNS" -strLogValue "WinIPConfig.txt"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Environment information..." -PercentComplete (100/25 * 18)

        <# Export environment variables #>
        Get-ChildItem Env: | Out-File "$Global:strUniqueLogFolder\EnvVar.log"
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export environment variables" -strLogValue "EnvVar.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Group policy report..." -PercentComplete (100/25 * 19)
        
        <# Export group policy results #>
        gpresult /f /h "$Global:strUniqueLogFolder\Gpresult.htm" | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export group policy report" -strLogValue "Gpresult.htm"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Time zone information..." -PercentComplete (100/25 * 20)

        <# Export timezone offse (UTC) #>
        (Get-Timezone).BaseUTCOffset.Hours | Out-File "$Global:strUniqueLogFolder\BaseUTCOffset.log"
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export timezone offset" -strLogValue "BaseUTCOffset.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Tasklist..." -PercentComplete (100/25 * 21)

        <# Export Tasklist #>
        Tasklist.exe /svc > "$Global:strUniqueLogFolder\Tasklist.log"
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Tasklist" -strLogValue "Tasklist.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Programs and Features..." -PercentComplete (100/25 * 22)

        <# Export Programs and Features (32) #>
        If ($(Test-Path -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") -Eq $true) {

            <# Programs32 #>
            Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-CSV "$Global:strUniqueLogFolder\Programs32.log" -ErrorAction SilentlyContinue

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Programs (x86)" -strLogValue "Programs32.log" 

        }
        
        <# Export Programs and Features (64) #>
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-CSV "$Global:strUniqueLogFolder\Programs64.log" -ErrorAction SilentlyContinue

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Programs (x64)" -strLogValue "Programs64.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: AIP registry keys..." -PercentComplete (100/25 * 24)
        
        <# Export AIP plugin Adobe Acrobat RMS logs #>
        If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\RMSLocalStorage\MIP\logs) -Eq $true) {

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: Adobe logs..." -PercentComplete (100/25 * 24)

            <# Export MSIP/MSIPC content to logs folder #>
            fncCopyItem $env:LOCALAPPDATA\Microsoft\RMSLocalStorage\MIP\logs "$Global:strUniqueLogFolder\Adobe\LOCALAPPDATA" "Adobe\LOCALAPPDATA\*"

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Adobe logs" -strLogValue "\Adobe"

        }

        <# Export AIP plugin Adobe Acrobat RMS logs #>
        If ($(Test-Path -Path $env:USERPROFILE\appdata\locallow\Microsoft\RMSLocalStorage\mip\logs) -Eq $true) {

            <# Export MSIP/MSIPC content to logs folder #>
            fncCopyItem $env:USERPROFILE\appdata\locallow\Microsoft\RMSLocalStorage\mip\logs "$Global:strUniqueLogFolder\Adobe\USERPROFILE" "Adobe\USERPROFILE\*"

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Adobe logs" -strLogValue "\Adobe"

        }

        <# Export several registry keys: Define an array and feeding it with related registry keys #>
        $Private:arrRegistryKeys = "HKLM:\Software\Classes\MSIP.ExcelAddin", 
                                "HKLM:\Software\Classes\MSIP.WordAddin",
                                "HKLM:\SOFTWARE\Classes\MSIP.PowerPointAddin",
                                "HKLM:\SOFTWARE\Classes\MSIP.OutlookAddin",
                                "HKLM:\SOFTWARE\Classes\AllFileSystemObjects\shell\Microsoft.Azip.RightClick",
                                "HKLM:\SOFTWARE\Microsoft\MSIPC",
                                "HKLM:\SOFTWARE\Microsoft\Office\Word\Addins",
                                "HKLM:\SOFTWARE\Microsoft\Office\Excel\Addins",
                                "HKLM:\SOFTWARE\Microsoft\Office\PowerPoint\Addins",
                                "HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins",
                                "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\SOFTWARE\Microsoft\Office\Word\Addins",
                                "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\SOFTWARE\Microsoft\Office\Excel\Addins",
                                "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\SOFTWARE\Microsoft\Office\PowerPoint\Addins",
                                "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\SOFTWARE\Microsoft\Office\Outlook\Addins",
                                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\MSIPC",
                                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\Word\Addins",
                                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\Excel\Addins",
                                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\PowerPoint\Addins",
                                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\Outlook\Addins",
                                "HKCU:\SOFTWARE\Microsoft\MSIP",
                                "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security",
                                "HKCU:\Software\Microsoft\Office\16.0\Common\Identity",
                                "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Internet",
                                "HKCU:\SOFTWARE\Microsoft\Office\Word\Addins",
                                "HKCU:\SOFTWARE\Microsoft\Office\Excel\Addins",
                                "HKCU:\SOFTWARE\Microsoft\Office\PowerPoint\Addins",
                                "HKCU:\SOFTWARE\Microsoft\Office\Outlook\Addins",
                                "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Resiliency",
                                "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Resiliency",
                                "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Resiliency",
                                "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Resiliency",
                                "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Resiliency",
                                "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\MSIPC",
                                "HKCR:\MSIP.ExcelAddin",
                                "HKCR:\MSIP.WordAddin",
                                "HKCR:\MSIP.PowerPointAddin",
                                "HKCR:\MSIP.OutlookAddin",
                                "HKCR:\Local Settings\SOFTWARE\Microsoft\MSIPC"

        <# Loop though array and cache to a temp file #>
        ForEach ($_ in $Private:arrRegistryKeys) {

            If ($(Test-Path -Path $_) -Eq $true) {

                $Private:strTempFile = $Private:strTempFile + 1
                & REG EXPORT $_.Replace(":", $null) "$Global:strTempFolder\$Private:strTempFile.reg" /Y | Out-Null <# Remove ":" for export (replace) #>

            }

        }

        <# Insert first information; create log file #>
        "Windows Registry Editor Version 5.00" | Set-Content "$Global:strUniqueLogFolder\Registry.log"

        <# Read data from cached temp file, and add it to the logfile #>
        (Get-Content "$Global:strTempFolder\*.reg" | Where-Object {$_ -ne "Windows Registry Editor Version 5.00"} | Add-Content "$Global:strUniqueLogFolder\Registry.log")

        <# Clean temp folder of cached files #>
        Remove-Item "$Global:strTempFolder\*.reg" -Force -ErrorAction SilentlyContinue | Out-Null

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export AIP registry keys" -strLogValue "Registry.log"




    }

    <# Detect macOS and copy logs #>
    If ($IsMacOS -eq $true) {

        <# Copy policy files #>
        fncCopyItem "$(printenv HOME)/Library/Containers/com.microsoft.Word/Data/Library/Application Support/Microsoft/Office/CLP" "$Global:strUniqueLogFolder/Word" "$(printenv HOME)/Library/Containers/com.microsoft.Word/Data/Library/Application Support/Microsoft/Office/CLP/*" <# Word #>
        fncCopyItem "$(printenv HOME)/Library/Containers/com.microsoft.Excel/Data/Library/Application Support/Microsoft/Office/CLP" "$Global:strUniqueLogFolder/Excel" "$(printenv HOME)/Library/Containers/com.microsoft.Excel/Data/Library/Application Support/Microsoft/Office/CLP/*" <# Excel #>
        fncCopyItem "$(printenv HOME)/Library/Containers/com.microsoft.PowerPoint/Data/Library/Application Support/Microsoft/Office/CLP" "$Global:strUniqueLogFolder/PowerPoint" "$(printenv HOME)/Library/Containers/com.microsoft.PowerPoint/Data/Library/Application Support/Microsoft/Office/CLP/*" <# PowerPoint #>
        fncCopyItem "$(printenv HOME)/Library/Containers/com.microsoft.Outlook/Data/Library/Application Support/Microsoft/Office/CLP" "$Global:strUniqueLogFolder/Outlook" "$(printenv HOME)/Library/Containers/com.microsoft.Outlook/Data/Library/Application Support/Microsoft/Office/CLP/*" <# Outlook #>

        <# Copy log files #>
        fncCopyItem "$(printenv HOME)/Library/Containers/com.microsoft.Word/Data/Library/Logs" "$Global:strUniqueLogFolder/Word/Logs" "$(printenv HOME)/Library/Containers/com.microsoft.Word/Data/Library/Logs/*" <# Word #>
        fncCopyItem "$(printenv HOME)/Library/Containers/com.microsoft.Excel/Data/Library/Logs" "$Global:strUniqueLogFolder/Excel/Logs" "$(printenv HOME)/Library/Containers/com.microsoft.Excel/Data/Library/Logs/*" <# Excel #>
        fncCopyItem "$(printenv HOME)/Library/Containers/com.microsoft.PowerPoint/Data/Library/Logs" "$Global:strUniqueLogFolder/PowerPoint/Logs" "$(printenv HOME)/Library/Containers/com.microsoft.PowerPoint/Data/Library/Logs/*" <# PowerPoint #>
        fncCopyItem "$(printenv HOME)/Library/Containers/com.microsoft.Outlook/Data/Library/Logs" "$Global:strUniqueLogFolder/Outlook/Logs" "$(printenv HOME)/Library/Containers/com.microsoft.Outlook/Data/Library/Logs/*" <# Outlook #>
        fncCopyItem "$(printenv HOME)/Library/Containers/com.microsoft.protection.rms-sharing-mac/Data/Library/Logs" "$Global:strUniqueLogFolder/rms-sharing-mac/Logs" "$(printenv HOME)/Library/Containers/com.microsoft.protection.rms-sharing-mac/Data/Library/Logs/*" <# RMS Sharing App #>

        <# Copy Office MIP SDK logs #>
        fncCopyItem "$(printenv HOME)/Library/Group Containers/UBF8T346G9.Office/mip_policy/mip/logs" "$Global:strUniqueLogFolder/mip/Logs" "$(printenv HOME)/Library/Group Containers/UBF8T346G9.Office/mip_policy/mip/logs/*"

    }

    <# Progress bar update #>
    Write-Progress -Activity " Logs collected" -Completed

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Collecting logs" -strLogValue "Proceeded" 

}

<# Function to remove previous versions of this tool #>
Function fncRemovePreviousVersions {

    <# Try to find and remove previous versions of this tool #>
    Try {

        <# Check for previous versions of the RMS_Support_Tool and uninstalling it #>
        If (Get-Module -ListAvailable -Name RMS_Support_Tool) {
        
            <# Unstall RMS_Support_Tool #>
            Uninstall-Module -Verbose:$false -Name RMS_Support_Tool | Out-Null 
        
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncRemovePreviousVersions" -strLogDescription "RMS_Support_Tool" -strLogValue "Removed"
        
        }

    }
    Catch { 

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncRemovePreviousVersions" -strLogDescription "RMS_Support_Tool remove" -strLogValue "Omitted"

    }

}

<# Check and update needed modules for PowerShellGallery.com #>
Function fncUpdateRequiredModules {

    <# Check for powershellgallery.com as trusted repository #>
    If (-not(Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {

        <# Define powershellgallery.com as trusted location, if it's not trusted yet. To be able to install AIPService module #>
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose:$false | Out-Null

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "PSGallery trust" -strLogValue "Set"

    }

    <# Remember default progress bar status: "Continue" #>
    $Private:strOriginalPreference = $Global:ProgressPreference 
    $Global:ProgressPreference = "SilentlyContinue" <# Hiding progress bar #>

    <# Validate connection to PowerShell Gallery by Find-Module on PowerShell 5.1. Not available on PowerShell 7.1 #>
    If ([Version]::new($PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor) -eq [Version]::new("5.1")) {

        <# Actions if PowerShell Gallery can be reached #>
        If (Find-PackageProvider -Name NuGet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Install/update nuGet provider to be able to install the latest modules #>
            Install-PackageProvider -Name NuGet -MinimumVersion "2.8.5.208" -ForceBootstrap -Scope CurrentUser -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose:$false | Out-Null

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "NuGet version" -strLogValue (Find-PackageProvider -Verbose:$false -Name NuGet).Version

        }
        Else { <# Actions if PowerShell Gallery can not be reached (no internet connection) #>

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "NuGet update" -strLogValue "Failed"

        }
    }
    Else {

            <# Verbose/Logging on PowerShell 7.1 (or higher) #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "NuGet update" -strLogValue "Not Applicable"

    }

    <# Set back progress bar to previous setting #>
    $Global:ProgressPreference = $Private:strOriginalPreference

    <# Validate connection to PowerShell Gallery #>
    If (Get-Module -ListAvailable -Name "AIPService") {

        <# Update AIPService if we can connect to PowerShell Gallery #>
        If (Find-Module -Name AIPService -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Fill variables with version information #>
            [Version]$Private:strAIPOnlineVersion = (Find-Module -Name AIPService -Repository PSGallery).Version
            [Version]$Private:strAIPLocalVersion = (Get-Module -ListAvailable -Name "AIPService").Version | Select-Object -First 1

            <# Compare local version vs. online version #>
            If ([Version]::new($Private:strAIPOnlineVersion.Major, $Private:strAIPOnlineVersion.Minor, $Private:strAIPOnlineVersion.Build, $Private:strAIPOnlineVersion.Revision) -gt [Version]::new($Private:strAIPLocalVersion.Major, $Private:strAIPLocalVersion.Minor, $Private:strAIPLocalVersion.Build, $Private:strAIPLocalVersion.Revision) -eq $true) {

                <# Console output #>
                Write-Output "Updating AIPService module..."

                <# Update AIPService PowerShell module #>
                Update-Module -Verbose:$false -Name AIPService -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService module" -strLogValue "Updated"

            }

            <# Release private variables #>
            [Version]$Private:strAIPOnlineVersion = $null
            [Version]$Private:strAIPLocalVersion = $null

        }
        Else { <# Actions if we can't connect to PowerShell Gallery (no internet connection) #>

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService module update" -strLogValue "Failed"

        }

    }

    <# Actions if AIPService module isn't installed #>
    If (-Not (Get-Module -ListAvailable -Name "AIPService")) {

        <# Install AIPService if we can connect to PowerShell Gallery #>
        If (Find-Module -Name AIPService -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Console output #>
            Write-Output "Installing AIPService module..."

            <# Install AIPService PowerShell module #>
            Install-Module -Verbose:$false -Name AIPService -Repository PSGallery -Scope CurrentUser -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService module" -strLogValue "Installed"

            <# Console output #>
            Write-Output "AIPService module installed."

            <# Console output #>
            Write-Output (Write-Host "ATTENTION: To use AIPService cmdlets, you must close this window and run a new instance of PowerShell for it to work.`nThe 'Unified Labeling Support Tool' is now terminated." -ForegroundColor Red)

            <# Call pause function #>
            fncPause
    
            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Interrupt, because of module not loaded into PowerShell instance #>
            Break

        }
        Else { <# Actions if we can't connect to PowerShell Gallery (no internet connection) #>

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService module installation" -strLogValue "Failed"

        }

    }

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService version" -strLogValue (Get-Module -Verbose:$false -ListAvailable -Name AIPService).Version

}

<# Collect AIP service configuration #>
Function fncCollectAIPServiceConfiguration {

    <# Console output #>
    Write-Output "COLLECT AIP SERVICE CONFIGURATION:"

    <# Check if not running as administrator #>
    If ($Global:bolRunningPrivileged -eq $false) {

        <# Console output #>
        Write-Output (Write-Host "ATTENTION: You must run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges to continue with this option.`nCOLLECT AIP SERVICE CONFIGURATION: Failed.`n" -ForegroundColor Red)

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call pause function #>
            fncPause

            <# Clear console #>
            Clear-Host

            <# Call show menu function #>
            fncShowMenu    

        }

    }

    <# Console output #>
    Write-Output "Initializing, please wait..."

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "Collect AIP service configuration" -strLogValue "Initiated"

    <# Action if -SkipUpdates was called from command line #>
    If ($Global:bolSkipRequiredUpdates -eq $false) {

        <# Call function to check and update needed modules #>
        fncUpdateRequiredModules

    }

    <# Console output #>
    Write-Output "Connecting to AIPService..."

    <# Actions on PowerShell 7.1 (or higher) for compatibility mode #>
    If ([Version]::new($PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor) -ge [Version]::new("7.1") -eq $true) {

        <# Remove AIPService module, because it's not compatible with PowerShell 7 (or higher) #>
        Remove-Module -Name AIPService -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

        <# Import AIPService module in compatiblity mode #>
        Import-Module -Name AIPService -UseWindowsPowerShell -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "AIPService compatiblity mode" -strLogValue $true

    }

    <# Connect/logon to AIPService #>
    If (Connect-AIPService -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) { <# Action if AIPService connection was opened #>

        <# Console output #> 
        Write-Output "AIPService connected."

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "AIPService connected" -strLogValue $true

    }
    Else{ <# Action if AIPService connection failed #>

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "AIPService connected" -strLogValue $false 
        fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "Collect AIP service configuration" -strLogValue "Login failed"
    
        <# Console output #>
        Write-Output (Write-Host "COLLECT AIP SERVICE CONFIGURATION: Login failed. Please try again.`n" -ForegroundColor Red)

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call pause function #>
            fncPause

            <# Clear console #>
            Clear-Host

            <# Call show menu function #>
            fncShowMenu    

        }

    }

    <# Check if "Collect"-folder exist and create it, if it not exist #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect" | Out-Null <# Define Collect path #>

    }

    <# Check for existing AIPService log file and create it, if it not exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log") -Eq $false) {

        <# Create AIPService logging file #>
        Out-File -FilePath $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Encoding UTF8 -Append -Force

    }

    <# Console output #> 
    Write-Output "Collecting AIP service configuration..."

    <# Check for existing AIPService logging file, and extend it if it exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log") -Eq $true) { <# Exporting AIP service configuration and output result: #>
            
        <# Timestamp #>
        $Private:Timestamp = (Get-Date -Verbose:$false -UFormat "%y%m%d-%H%M%S") <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("Date/Timestamp                            : " + $Private:Timestamp) <# Extend log file #>
        Write-Output (Write-Host ("Date/Timestamp                            : $Private:Timestamp") -ForegroundColor Yellow) <# Console output #> 
        $Private:Timestamp = $null <# Releasing variable #>
            
        <# AIPService Module version #>
        $Private:AIPServiceModule = (Get-Module -Verbose:$false -ListAvailable -Name AIPService).Version <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("Module version                            : $Private:AIPServiceModule") <# Extend log file #>
        Write-Output (Write-Host ("Module version                            : $Private:AIPServiceModule") -ForegroundColor Yellow) <# Console output #> 
        $Private:AIPServiceModule = $null <# Releasing variable #>

        <# BPOSId #>
        $Private:BPOSId = (Get-AipServiceConfiguration).BPOSId <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("BPOSId                                    : $Private:BPOSId") <# Extend log file #>
        Write-Output (Write-Host ("BPOSId                                    : $Private:BPOSId") -ForegroundColor Yellow) <# Console output #> 
        $Private:BPOSId = $null <# Releasing variable #>

        <# RightsManagementServiceId #>
        $Private:RightsManagementServiceId = (Get-AipServiceConfiguration).RightsManagementServiceId <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("RightsManagementServiceId                 : $Private:RightsManagementServiceId") <# Extend log file #>
        Write-Output (Write-Host ("RightsManagementServiceId                 : $Private:RightsManagementServiceId") -ForegroundColor Yellow) <# Console output #> 
        $Private:RightsManagementServiceId = $null <# Releasing variable #>

        <# LicensingIntranetDistributionPointUrl #>
        $Private:LicensingIntranetDistributionPointUrl = ($Private:AIPServiceModule).LicensingIntranetDistributionPointUrl <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("LicensingIntranetDistributionPointUrl     : $Private:LicensingIntranetDistributionPointUrl") <# Extend log file #>
        Write-Output (Write-Host ("LicensingIntranetDistributionPointUrl     : $Private:LicensingIntranetDistributionPointUrl") -ForegroundColor Yellow) <# Console output #> 
        $Private:LicensingIntranetDistributionPointUrl = $null <# Releasing variable #>

        <# LicensingExtranetDistributionPointUrl #>
        $Private:LicensingExtranetDistributionPointUrl = (Get-AipServiceConfiguration).LicensingExtranetDistributionPointUrl <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("LicensingExtranetDistributionPointUrl     : $Private:LicensingExtranetDistributionPointUrl") <# Extend log file #>
        Write-Output (Write-Host ("LicensingExtranetDistributionPointUrl     : $Private:LicensingExtranetDistributionPointUrl") -ForegroundColor Yellow) <# Console output #> 
        $Private:LicensingExtranetDistributionPointUrl = $null <# Releasing variable #>

        <# CertificationIntranetDistributionPointUrl #>
        $Private:CertificationIntranetDistributionPointUrl = (Get-AipServiceConfiguration).CertificationIntranetDistributionPointUrl <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("CertificationIntranetDistributionPointUrl : $Private:CertificationIntranetDistributionPointUrl") <# Extend log file #>
        Write-Output (Write-Host ("CertificationIntranetDistributionPointUrl : $Private:CertificationIntranetDistributionPointUrl") -ForegroundColor Yellow) <# Console output #> 
        $Private:CertificationIntranetDistributionPointUrl = $null <# Releasing variable #>

        <# CertificationExtranetDistributionPointUrl #>
        $Private:CertificationExtranetDistributionPointUrl = (Get-AipServiceConfiguration).CertificationExtranetDistributionPointUrl <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("CertificationExtranetDistributionPointUrl : $Private:CertificationExtranetDistributionPointUrl") <# Extend log file #>
        Write-Output (Write-Host ("CertificationExtranetDistributionPointUrl : $Private:CertificationExtranetDistributionPointUrl") -ForegroundColor Yellow) <# Console output #> 
        $Private:CertificationExtranetDistributionPointUrl = $null <# Releasing variable #>

        <# AdminConnectionUrl #>
        $Private:AdminConnectionUrl = (Get-AipServiceConfiguration).AdminConnectionUrl <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AdminConnectionUrl                        : $Private:AdminConnectionUrl") <# Extend log file #>
        Write-Output (Write-Host ("AdminConnectionUrl                        : $Private:AdminConnectionUrl") -ForegroundColor Yellow) <# Console output #> 
        $Private:AdminConnectionUrl = $null <# Releasing variable #>

        <# AdminV2ConnectionUrl #>
        $Private:AdminV2ConnectionUrl = (Get-AipServiceConfiguration).AdminV2ConnectionUrl <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AdminV2ConnectionUrl                      : $Private:AdminV2ConnectionUrl") <# Extend log file #>
        Write-Output (Write-Host ("AdminV2ConnectionUrl                      : $Private:AdminV2ConnectionUrl") -ForegroundColor Yellow) <# Console output #> 
        $Private:AdminV2ConnectionUrl = $null <# Releasing variable #>

        <# OnPremiseDomainName #>
        $Private:OnPremiseDomainName = (Get-AipServiceConfiguration).OnPremiseDomainName <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("OnPremiseDomainName                       : $Private:OnPremiseDomainName") <# Extend log file #>
        Write-Output (Write-Host ("OnPremiseDomainName                       : $Private:OnPremiseDomainName") -ForegroundColor Yellow) <# Console output #> 
        $Private:OnPremiseDomainName = $null <# Releasing variable #>

        <# Keys #>
        $Private:Keys = (Get-AipServiceConfiguration).Keys <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("Keys                                      : $Private:Keys") <# Extend log file #>
        Write-Output (Write-Host ("Keys                                      : $Private:Keys") -ForegroundColor Yellow) <# Console output #> 
        $Private:Keys = $null <# Releasing variable #>

        <# CurrentLicensorCertificateGuid #>
        $Private:CurrentLicensorCertificateGuid = (Get-AipServiceConfiguration).CurrentLicensorCertificateGuid <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("CurrentLicensorCertificateGuid            : $Private:CurrentLicensorCertificateGuid") <# Extend log file #>
        Write-Output (Write-Host ("CurrentLicensorCertificateGuid            : $Private:CurrentLicensorCertificateGuid") -ForegroundColor Yellow) <# Console output #> 
        $Private:CurrentLicensorCertificateGuid = $null <# Releasing variable #>

        <# Templates #>
        $Private:Templates = (Get-AipServiceConfiguration).Templates <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("Template IDs                              : $Private:Templates") <# Extend log file #>
        Write-Output (Write-Host ("Template IDs                              : $Private:Templates") -ForegroundColor Yellow) <# Console output #> 
        $Private:Templates = $null <# Releasing variable #>

        <# FunctionalState #>
        $Private:FunctionalState = (Get-AipServiceConfiguration).FunctionalState <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("FunctionalState                           : $Private:FunctionalState") <# Extend log file #>
        Write-Output (Write-Host ("FunctionalState                           : $Private:FunctionalState") -ForegroundColor Yellow) <# Console output #> 
        $Private:FunctionalState = $null <# Releasing variable #>

        <# SuperUsersEnabled #>
        $Private:SuperUsersEnabled = (Get-AipServiceConfiguration).SuperUsersEnabled <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("SuperUsersEnabled                         : $Private:SuperUsersEnabled") <# Extend log file #>
        Write-Output (Write-Host ("SuperUsersEnabled                         : $Private:SuperUsersEnabled") -ForegroundColor Yellow) <# Console output #> 
        $Private:SuperUsersEnabled = $null <# Releasing variable #>

        <# SuperUsers #>
        $Private:SuperUsers = (Get-AipServiceConfiguration).SuperUsers <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("SuperUsers                                : $Private:SuperUsers") <# Extend log file #>
        Write-Output (Write-Host ("SuperUsers                                : $Private:SuperUsers") -ForegroundColor Yellow) <# Console output #> 
        $Private:SuperUsers = $null <# Releasing variable #>

        <# AdminRoleMembers #>
        $Private:AdminRoleMembers = (Get-AipServiceConfiguration).AdminRoleMembers <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AdminRoleMembers                          : $Private:AdminRoleMembers") <# Extend log file #>
        Write-Output (Write-Host ("AdminRoleMembers                          : $Private:AdminRoleMembers") -ForegroundColor Yellow) <# Console output #> 
        $Private:AdminRoleMembers = $null <# Releasing variable #>

        <# KeyRolloverCount #>
        $Private:KeyRolloverCount = (Get-AipServiceConfiguration).KeyRolloverCount <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("KeyRolloverCount                          : $Private:KeyRolloverCount") <# Extend log file #>
        Write-Output (Write-Host ("KeyRolloverCount                          : $Private:KeyRolloverCount") -ForegroundColor Yellow) <# Console output #> 
        $Private:KeyRolloverCount = $null <# Releasing variable #>

        <# ProvisioningDate #>
        $Private:ProvisioningDate = (Get-AipServiceConfiguration).ProvisioningDate <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("ProvisioningDate                          : $Private:ProvisioningDate") <# Extend log file #>
        Write-Output (Write-Host ("ProvisioningDate                          : $Private:ProvisioningDate") -ForegroundColor Yellow) <# Console output #> 
        $Private:ProvisioningDate = $null <# Releasing variable #>

        <# IPCv3ServiceFunctionalState #>
        $Private:IPCv3ServiceFunctionalState = (Get-AipServiceConfiguration).IPCv3ServiceFunctionalState <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("IPCv3ServiceFunctionalState               : $Private:IPCv3ServiceFunctionalState") <# Extend log file #>
        Write-Output (Write-Host ("IPCv3ServiceFunctionalState               : $Private:IPCv3ServiceFunctionalState") -ForegroundColor Yellow) <# Console output #> 
        $Private:IPCv3ServiceFunctionalState = $null <# Releasing variable #>

        <# DevicePlatformState #>
        $Private:DevicePlatformState = (Get-AipServiceConfiguration).DevicePlatformState <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("DevicePlatformState                       : $Private:DevicePlatformState") <# Extend log file #>
        Write-Output (Write-Host ("DevicePlatformState                       : $Private:DevicePlatformState") -ForegroundColor Yellow) <# Console output #> 
        $Private:DevicePlatformState = $null <# Releasing variable #>

        <# FciEnabledForConnectorAuthorization #>
        $Private:FciEnabledForConnectorAuthorization = (Get-AipServiceConfiguration).FciEnabledForConnectorAuthorization <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("FciEnabledForConnectorAuthorization       : $Private:FciEnabledForConnectorAuthorization") <# Extend log file #>
        Write-Output (Write-Host ("FciEnabledForConnectorAuthorization       : $Private:FciEnabledForConnectorAuthorization") -ForegroundColor Yellow) <# Console output #> 
        $Private:FciEnabledForConnectorAuthorization = $null <# Releasing variable #>

        <# AIP service templates details log file #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AIP service templates                     : AipServiceTemplates.log")
            
        <# AipServiceDocumentTrackingFeature #>
        $Private:AipServiceDocumentTrackingFeature = Get-AipServiceDocumentTrackingFeature <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AipServiceDocumentTrackingFeature         : $Private:AipServiceDocumentTrackingFeature") <# Extend log file #>
        Write-Output (Write-Host ("AipServiceDocumentTrackingFeature         : $Private:AipServiceDocumentTrackingFeature") -ForegroundColor Yellow) <# Console output #> 
        $Private:AipServiceDocumentTrackingFeature = $null <# Releasing variable #>

        <# AipServiceOnboardingControlPolicy #>
        $Private:AipServiceOnboardingControlPolicy = ("{[UseRmsUserLicense, " + $(Get-AipServiceOnboardingControlPolicy).UseRmsUserLicense +"], [SecurityGroupObjectId, " + $(Get-AipServiceOnboardingControlPolicy).SecurityGroupObjectId + "], [Scope, " + $(Get-AipServiceOnboardingControlPolicy).Scope + "]}") <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AipServiceOnboardingControlPolicy         : $Private:AipServiceOnboardingControlPolicy") <# Extend log file #>
        Write-Output (Write-Host ("AipServiceOnboardingControlPolicy         : $Private:AipServiceOnboardingControlPolicy") -ForegroundColor Yellow) <# Console output #> 
        $Private:AipServiceOnboardingControlPolicy = $null <# Releasing variable #>

        <# AipServiceDoNotTrackUserGroup #>
        $Private:AipServiceDoNotTrackUserGroup = Get-AipServiceDoNotTrackUserGroup <# Filling private variable #>

        <# Actions if AipServiceDoNotTrackUserGroup variable value is not empty #>
        If ($Private:AipServiceDoNotTrackUserGroup) {

            Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AipServiceDoNotTrackUserGroup             : $Private:AipServiceDoNotTrackUserGroup") <# Extend log file #>
            Write-Output (Write-Host ("AipServiceDoNotTrackUserGroup             : $Private:AipServiceDoNotTrackUserGroup") -ForegroundColor Yellow) <# Console output #> 

        }
        Else { <# Actions if variable value is empty #>
            
            Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AipServiceDoNotTrackUserGroup             :") <# Extend log file #>
            Write-Output (Write-Host ("AipServiceDoNotTrackUserGroup             :") -ForegroundColor Yellow) <# Console output #> 

        }
            
        <# Release AipServiceDoNotTrackUserGroup variable #>
        $Private:AipServiceDoNotTrackUserGroup = $null 

        <# AipServiceRoleBasedAdministrator #>
        $Private:AipServiceRoleBasedAdministrator = Get-AipServiceRoleBasedAdministrator <# Filling private variable #>

        <# Actions if AipServiceRoleBasedAdministrator variable value is not empty #>
        If ($Private:AipServiceRoleBasedAdministrator) {

            Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AipServiceRoleBasedAdministrator          : $Private:AipServiceRoleBasedAdministrator") <# Extend log file #>
            Write-Output (Write-Host ("AipServiceRoleBasedAdministrator          : $Private:AipServiceRoleBasedAdministrator") -ForegroundColor Yellow) <# Console output #> 

        }
        Else { <# Actions if variable value is empty #>
            
            Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AipServiceRoleBasedAdministrator          :") <# Extend log file #>
            Write-Output (Write-Host ("AipServiceRoleBasedAdministrator          :") -ForegroundColor Yellow) <# Console output #> 

        }
            
        <# Release AipServiceRoleBasedAdministrator variable #>
        $Private:AipServiceRoleBasedAdministrator = $null 

    }

    <# Disconnect from AIPService #>
    Disconnect-AIPService | Out-Null

    <# Console output #>
    Write-Output "AIPService disconnected.`n"

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectAipServiceConfiguration" -strLogDescription "AIPService disconnected" -strLogValue $true
    fncLogging -strLogFunction "fncCollectAipServiceConfiguration" -strLogDescription "Export AIP service configuration" -strLogValue "AIPServiceConfiguration.log"
    fncLogging -strLogFunction "fncCollectAipServiceConfiguration" -strLogDescription "Collect AIP service configuration" -strLogValue "Proceeded"

    <# Console output #> 
    Write-Output "Log file: $Global:strUserLogPath\Collect\AIPServiceConfiguration.log"
    Write-Output (Write-Host "COLLECT AIP SERVICE CONFIGURATION: Proceeded.`n" -ForegroundColor Green)

    <# Action if function was called from command line #>
    If ($Global:bolCommingFromMenu -eq $false) {

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Release global variable back to default (updates active) #>
        $Global:bolSkipRequiredUpdates = $false

        <# Exit function #>
        Break

    }

    <# Action if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {

        <# Call pause function #>
        fncPause

        <# Clear console #>
        Clear-Host

        <# Call show menu function #>
        fncShowMenu    

    }

}

<#  Collect AIP service templates #>
Function fncCollectAIPServiceTemplates {

    <# Console output #>
    Write-Output "COLLECT AIP SERVICE TEMPLATES:"

    <# Check if not running as administrator #>
    If ($Global:bolRunningPrivileged -eq $false) {

        <# Console output #>
        Write-Output (Write-Host "ATTENTION: You must run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges to continue with this option.`nCOLLECT AIP SERVICE TEMPLATES: Failed.`n" -ForegroundColor Red)

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call pause function #>
            fncPause

            <# Clear console #>
            Clear-Host

            <# Call show menu function #>
            fncShowMenu    

        }

    }

    <# Console output #>
    Write-Output "Initializing, please wait..."

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectAIPServiceTemplates" -strLogDescription "Collect AIP service templates" -strLogValue "Initiated"

    <# Action if -SkipUpdates was called from command line #>
    If ($Global:bolSkipRequiredUpdates -eq $false) {

        <# Call function to check and update needed modules #>
        fncUpdateRequiredModules

    }

    <# Console output #>
    Write-Output "Connecting to AIPService..."

    <# Actions on PowerShell 7.1 (or higher) for compatibility mode #>
    If ([Version]::new($PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor) -ge [Version]::new("7.1") -eq $true) {

        <# Remove AIPService module, because it's not compatible with PowerShell 7 (or higher) #>
        Remove-Module -Name AIPService -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

        <# Import AIPService module in compatiblity mode #>
        Import-Module -Name AIPService -UseWindowsPowerShell -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectAIPServiceTemplates" -strLogDescription "AIPService compatiblity mode" -strLogValue $true

    }

    <# Connect/logon to AIPService #>
    If (Connect-AIPService -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) { <# Action if AIPService connection was opened #>

        <# Console output #> 
        Write-Output "AIPService connected."

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectAIPServiceTemplates" -strLogDescription "AIPService connected" -strLogValue $true

    }
    Else{ <# Action if AIPService connection failed #>

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectAIPServiceTemplates" -strLogDescription "AIPService connected" -strLogValue $false 
        fncLogging -strLogFunction "fncCollectAIPServiceTemplates" -strLogDescription "Collect AIP service templates" -strLogValue "Login failed"
    
        <# Console output #>
        Write-Output (Write-Host "COLLECT AIP SERVICE TEMPLATES: Login failed. Please try again.`n" -ForegroundColor Red)

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false    

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call pause function #>
            fncPause

            <# Clear console #>
            Clear-Host

            <# Call show menu function #>
            fncShowMenu    

        }

    }

    <# Check if "Collect"-folder exist and create it, if not #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect" | Out-Null <# Define Collect path #>

    }

    <# Check for existing log file and create it, if it not exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\AIPServiceTemplates.log") -Eq $false) {

        <# Create AIPService logging file #>
        Out-File -FilePath $Global:strUserLogPath"\Collect\AIPServiceTemplates.log" -Encoding UTF8 -Append -Force

    }

    <# Console output #> 
    Write-Output "Collecting AIP service templates..."
    
    <# Check for existing log file and extend it, if it exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\AIPServiceTemplates.log") -Eq $true) { <# Exporting AIP service templates and output result: #>

        <# Collect AIP service templates #>
        $Private:Timestamp = (Get-Date -Verbose:$false -UFormat "%y%m%d-%H%M%S") <# Filling private variable with date/time #>
        ("Date/Timestamp               : " + $Private:Timestamp) | Out-File $Global:strUserLogPath"\Collect\AIPServiceTemplates.log" -Encoding UTF8 -Append <# Extend log file with date/time #>
            
        <# Release date/time variable #>
        $Private:Timestamp = $null 

        <# Add template details #>
        Get-AipServiceConfiguration | Select-Object -ExpandProperty Templates | Out-File $Global:strUserLogPath"\Collect\AIPServiceTemplates.log" -Encoding UTF8 -Append <# Extending log file with template summary #>
        Get-AIPServicetemplate | Format-List * | Out-File $Global:strUserLogPath"\Collect\AIPServiceTemplates.log" -Encoding UTF8 -Append <# Extending log file with template details #>

    }
    
    <# Check if "Collect\Service Templates" folder exist and create it, if not #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect\AIPServiceTemplates") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect\AIPServiceTemplates" | Out-Null <# Define Service Templates path #>

    }

    <# Detect Service Template IDs for backup #>
    ForEach ($Private:ServiceTemplate in (Get-AIPServicetemplate).TemplateID) {

        <# Backup Service Template to XML #>
        Export-AipServiceTemplate -Path $Global:strUserLogPath"\Collect\AIPServiceTemplates\$Private:ServiceTemplate.xml" -TemplateId $Private:ServiceTemplate -Force

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectAIPServiceTemplates" -strLogDescription "Service Template exported" -strLogValue "$Private:ServiceTemplate.xml"

    } 

    <# Disconnect from AIPService #>
    Disconnect-AIPService | Out-Null

    <# Console output #>
    Write-Output "AIPService disconnected.`n"

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectAIPServiceTemplates" -strLogDescription "AIPService disconnected" -strLogValue $true
    fncLogging -strLogFunction "fncCollectAIPServiceTemplates" -strLogDescription "Export AIP Templates" -strLogValue "AIPServiceTemplates.log"
    fncLogging -strLogFunction "fncCollectAIPServiceTemplates" -strLogDescription "Collect AIP service templates" -strLogValue "Proceeded"

    <# Console output #> 
    Write-Output "AIP service templates: $Global:strUserLogPath\Collect\AIPServiceTemplates"    
    Write-Output "Log file: $Global:strUserLogPath\Collect\AIPServiceTemplates.log"
    Write-Output (Write-Host "COLLECT AIP SERVICE TEMPLATES: Proceeded.`n" -ForegroundColor Green)

    <# Action if function was called from command line #>
    If ($Global:bolCommingFromMenu -eq $false) {

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Release global variable back to default (updates active) #>
        $Global:bolSkipRequiredUpdates = $false

        <# Exit function #>
        Break

    }

    <# Action if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {

        <# Call pause function #>
        fncPause

        <# Clear console #>
        Clear-Host

        <# Call show menu function #>
        fncShowMenu    

    }

}

<# Collect labels and policies #>
Function fncCollectLabelsAndPolicies {

    <# Console output #>
    Write-Output "COLLECT LABELS AND POLICIES:"

    <# Check if not running as administrator #>
    If ($Global:bolRunningPrivileged -eq $false) {

        <# Console output #>
        Write-Output (Write-Host "ATTENTION: You must run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges to continue with this option.`nCOLLECT LABELS AND POLICIES: Failed.`n" -ForegroundColor Red)

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call pause function #>
            fncPause

            <# Clear console #>
            Clear-Host

            <# Call show menu function #>
            fncShowMenu    

        }

    }

    <# Console output #>
    Write-Output "Initializing, please wait..."

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Collect labels and policies" -strLogValue "Initiated"

    <# Action if -SkipUpdates was called from command line #>
    If ($Global:bolSkipRequiredUpdates -eq $false) {

        <# Call function to check and update needed modules #>
        fncUpdateRequiredModules

        <# Actions if ExchangeOnlineManagement module is installed #>
        If (Get-Module -ListAvailable -Name "ExchangeOnlineManagement") {

            <# Update ExchangeOnlineManagement, if we can connect to PowerShell Gallery #>
            If (Find-Module -Name ExchangeOnlineManagement -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

                <# Fill variables with version information #>
                [Version]$Private:strEOPOnlineVersion = (Find-Module -Name ExchangeOnlineManagement -Repository PSGallery).Version
                [Version]$Private:strEOPLocalVersion = (Get-Module -ListAvailable -Name "AIPService").Version | Select-Object -First 1

                <# Compare local version vs. online version #>
                If ([Version]::new($Private:strEOPPOnlineVersion.Major, $Private:strEOPPOnlineVersion.Minor, $Private:strEOPPOnlineVersion.Build) -gt [Version]::new($Private:strEOPLocalVersion.Major, $Private:strEOPLocalVersion.Minor, $Private:strEOPLocalVersion.Build) -eq $true) {

                    <# Console output #>
                    Write-Output "Updating Exchange Online PowerShell V2 module..."

                    <# Update AIPService PowerShell module #>
                    Update-Module -Verbose:$false -Name ExchangeOnlineManagement -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

                    <# Verbose/Logging #>
                    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Exchange Online PowerShell V2 module" -strLogValue "Updated"

                }

                <# Release private variables #>
                [Version]$Private:strEOPOnlineVersion = $null
                [Version]$Private:strEOPLocalVersion = $null

            }
            Else { <# Actions if we can't connect to PowerShell Gallery (no internet connection) #>

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Exchange Online PowerShell V2 module update" -strLogValue "Failed"

            }

        }

    }

    <# Actions if ExchangeOnlineManagement module isn't installed #>
    If (-Not (Get-Module -ListAvailable -Name "ExchangeOnlineManagement")) {

        <# Install ExchangeOnlineManagement if we can connect to PowerShell Gallery #>
        If (Find-Module -Name ExchangeOnlineManagement -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Console output #>
            Write-Output "Installing Exchange Online PowerShell V2 module..."

            <# Install ExchangeOnlineManagement PowerShell module #>
            Install-Module -Verbose:$false -Name ExchangeOnlineManagement -Scope CurrentUser -Repository PSGallery -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Exchange Online PowerShell V2 module" -strLogValue "Installed"

            <# Console output #>
            Write-Output "Exchange Online PowerShell V2 module installed."
            Write-Output (Write-Host "ATTENTION: To use Exchange Online PowerShell V2 cmdlets, you must close this window and run a new instance of PowerShell for it to work.`nThe 'Unified Labeling Support Tool' is now terminated." -ForegroundColor Red)

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Call pause function #>
            fncPause
    
            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Interrupting, because of module not loaded into PowerShell instance #>
            Break

        }
        Else { <# Actions if we can't connect to PowerShell Gallery (no internet connection) #>

            <# Console output #>
            Write-Output (Write-Host "ATTENTION: Collecting labels and policies could not be performed.`nEither PowerShell Gallery cannot be reached or there is no connection to the Internet.`n`nYou must have Exchange Online PowerShell V2 module installed to proceed.`n`nPlease check the following website and install the latest version of the ExchangeOnlineManagement modul:`nhttps://www.powershellgallery.com/packages/ExchangeOnlineManagement`n" -ForegroundColor Red)

            <# Console output #>
            Write-Output (Write-Host "COLLECT LABELS AND POLICIES: Failed.`n" -ForegroundColor Red)

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Exchange Online PowerShell V2 module installation" -strLogValue "Failed"

            <# Action if function was called from the menu #>
            If ($Global:bolCommingFromMenu -eq $true) {

                <# Call pause function #>
                fncPause
    
                <# Clear console #>
                Clear-Host

                <# Call show menu function #>
                fncShowMenu

            }

            <# Action if function was called from command line #>
            If ($Global:bolCommingFromMenu -eq $false) {
   
                <# Release global variable back to default (updates active) #>
                $Global:bolSkipRequiredUpdates = $false

                <# Set back window title to default #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                <# Interrupt, because of missing internet connection #>
                Break

            }

        }

    }

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Exchange Online PowerShell V2 module version" -strLogValue (Get-Module -Verbose:$false -ListAvailable -Name ExchangeOnlineManagement).Version

    <# Console output #>
    Write-Output "Connecting to Microsoft 365 compliance center..."

    <# Remember default progress bar status: "Continue" #>
    $Private:strOriginalPreference = $Global:ProgressPreference 
    $Global:ProgressPreference = "SilentlyContinue" <# Hiding progress bar #>

    <# Try to connect/logon to compliance center #>
    Try {

        <# Connect/logon to Microsoft 365 compliance center #>
        Connect-IPPSSession -Verbose:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

    }
    Catch { <# Catch action for any error that occur on connect/logon #>

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Microsoft 365 compliance center connected" -strLogValue $false 
        fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Microsoft 365 compliance center" -strLogValue "Login failed"
    
        <# Console output #>
        Write-Output (Write-Host "COLLECT LABELS AND POLICIES: Login failed. Please try again.`n" -ForegroundColor Red)

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call pause function #>
            fncPause
    
            <# Clear console #>
            Clear-Host

            <# Call show menu function #>
            fncShowMenu

        }

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false           

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Interrupt, because of missing internet connection #>
            Break

        }

    }

    <# Console output #> 
    Write-Output "Microsoft 365 compliance center connected."

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Microsoft 365 compliance center connected" -strLogValue $true
    
    <# Console output #> 
    Write-Output "Collecting labels and policies..."

    <# Check if "Collect"-folder exist and create it, if not #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect" | Out-Null <# Define Collect path #>

    }

    <# Check for existing LabelsAndPolicies.log file and create it, if it not exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\LabelsAndPolicies.log") -Eq $false) {

        <# Create CollectLabels.log logging file #>
        Out-File -FilePath $Global:strUserLogPath"\Collect\LabelsAndPolicies.log" -Encoding UTF8 -Append -Force

    }

    <# Check for existing CollectLabels.log file and extend it, if it exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\LabelsAndPolicies.log") -Eq $true) {

        <# Collecting data #>
        Add-Content -Path $Global:strUserLogPath"\Collect\LabelsAndPolicies.log" -Value "CURRENT POLICY:`n"
        (Get-LabelPolicy).Name | Format-Table -AutoSize | Out-File $Global:strUserLogPath"\Collect\LabelsAndPolicies.log" -Encoding UTF8 -Append -Force | Format-List 
        Add-Content -Path $Global:strUserLogPath"\Collect\LabelsAndPolicies.log" -Value "`nALL LABELS:"
        Get-Label | Format-Table -AutoSize | Out-File $Global:strUserLogPath"\Collect\LabelsAndPolicies.log" -Encoding UTF8 -Append -Force
        Add-Content -Path $Global:strUserLogPath"\Collect\LabelsAndPolicies.log" -Value "ALL LABELS WITH DETAILS:"
        Get-Label | Format-List * | Out-File $Global:strUserLogPath"\Collect\LabelsAndPolicies.log" -Encoding UTF8 -Append -Force
        Add-Content -Path $Global:strUserLogPath"\Collect\LabelsAndPolicies.log" -Value "LABEL POLICIES:"
        Get-LabelPolicy | Out-File $Global:strUserLogPath"\Collect\LabelsAndPolicies.log" -Encoding UTF8 -Append -Force

    }

    <# Disconnect from Exchange Online Protection (EOP) #>
    Remove-PSSession -ComputerName (Get-PSSession).ComputerName

    <# Set back progress bar to previous default #>
    $Global:ProgressPreference = $Private:strOriginalPreference

    <# Console output #>
    Write-Output "Microsoft 365 compliance center disconnected."

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Microsoft 365 compliance center disconnected" -strLogValue $true
    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Export labels and policy" -strLogValue "LabelsAndPolicies.log"
    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Collect labels and policies" -strLogValue "Proceeded"

    <# Console output #> 
    Write-Output "`nLog file: $Global:strUserLogPath\Collect\LabelsAndPolicies.log"
    Write-Output (Write-Host "COLLECT LABELS AND POLICIES: Proceeded.`n" -ForegroundColor Green)

    <# Action if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {

        <# Call pause function #>
        fncPause
    
        <# Clear console #>
        Clear-Host

        <# Call show menu function #>
        fncShowMenu

    }

    <# Action if function was called from command line #>
    If ($Global:bolCommingFromMenu -eq $false) {

        <# Release global variable back to default (updates active) #>
        $Global:bolSkipRequiredUpdates = $false        

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Interrupt, because of missing internet connection #>
        Break

    }

}
        
<# Collect Endpoint URLs #>
Function fncCollectEndpointURLs {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "Collect endpoint URLs" -strLogValue "Initiated"

    <# Console output #>
    Write-Output "COLLECT ENDPOINT URLs:"

    <# Define and fill variables with static URLs #>
    $Private:MyUnifiedLabelingDistributionPointUrl = "dataservice.protection.outlook.com"
    $Private:MyTelemetryDistributionPointUrl = "self.events.data.microsoft.com"
    $Private:MyAIPv1PolicyDistributionPointUrl = "api.informationprotection.azure.com"

    <# Define and fill variable with date/time for unique log folder #>
    $Private:MyTimestamp = (Get-Date -Verbose:$false -UFormat "%y%m%d-%H%M%S")
    $Private:strCertLogPath = "$Global:strUserLogPath\Collect\EndpointURLs"

    <# Function to check if "EndpointURLs"-folder and log file exist #>
    Function fncCreateLogFileAndFolder ($Private:strCertLogPath) {

        <# Check if "EndpointURLs"-folder exist and create it, if not #>
        If ($(Test-Path -Path $Private:strCertLogPath) -Eq $false) {

            New-Item -ItemType Directory -Force -Path $Private:strCertLogPath | Out-Null <# Define EndpointURLs path #>

        }

        <# Check for existing EndpointURLs.log file and create it, if it not exist #>
        If ($(Test-Path $Global:strUserLogPath"\Collect\EndpointURLs.log") -Eq $false) {

            Out-File -FilePath $Global:strUserLogPath"\Collect\EndpointURLs.log" -Encoding UTF8 -Append -Force

        }
        
    }

    <# Check for COLLECT Endpoints URLs [MSIPC] if bootstrap was done/running with user privileges/reading URLs from registry #>
    If ($(Test-Path -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC") -Eq $true) {

        <# Console output #>
        Write-Output "Initializing, please wait..."
        Write-Output "Verifying endpoint URLs...`n"

        <# Check if "EndpointURLs"-folder and log file exist and create it, if not #>
        fncCreateLogFileAndFolder $Private:strCertLogPath

        <# Read URLs from registry #>
        Get-ChildItem -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC" | ForEach-Object {

            <# Read Tenant Id #>
            $Private:strMainKey = $_.Name.Substring(75).ToString()
         
            <# Actions if it's about ".aadrm.com", but not about "discover.aadrm.com" #>
            If ($Private:strMainKey -like "*.aadrm.com" -and $Private:strMainKey -notmatch "discover.aadrm.com") {

                <# Private variabel definition for Tenant Id string #>
                $Private:strTenantId = $Private:strMainKey.Remove(36)

                <# Console output #> 
                Write-Output (Write-Host "-------------------------------------------------`nTenant Id:  $Private:strTenantId`n-------------------------------------------------`n" -ForegroundColor Magenta)

                <# Create Tenant Id as first log entry #>
                Add-Content -Path $Global:strUserLogPath"\Collect\EndpointURLs.log" -Value "-----------------------------------------------`nTenant Id: $Private:strTenantId`n-----------------------------------------------"

                <# Define and filling variables with URLs #>
                $Private:MyLicensingIntranetDistributionPointUrl = (Get-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC\$Private:strMainKey\Identities" -ErrorAction SilentlyContinue).InternalUrl
                $Private:MyLicensingExtranetDistributionPointUrl = (Get-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC\$Private:strMainKey\Identities" -ErrorAction SilentlyContinue).ExternalUrl

                <# Trimm start of "https://", and end of "/_wmcs/licensing" #>
                $Private:MyLicensingIntranetDistributionPointUrl = $Private:MyLicensingIntranetDistributionPointUrl.substring($Private:MyLicensingIntranetDistributionPointUrl.length - 69, $Private:MyLicensingIntranetDistributionPointUrl.length - 24)
                $Private:MyLicensingExtranetDistributionPointUrl = $Private:MyLicensingExtranetDistributionPointUrl.substring($Private:MyLicensingExtranetDistributionPointUrl.length - 69, $Private:MyLicensingExtranetDistributionPointUrl.length - 24)

                <# Define and fill variables: Extending colledted registry key #>
                $Private:MyCertificationDistributionPointUrl = $Private:strMainKey

                <# Create Timestamp #>
                Add-Content -Path $Global:strUserLogPath"\Collect\EndpointURLs.log" -Value ("Date/Timestamp: " + (Get-Date -Verbose:$false -UFormat "$Private:MyTimestamp"))
                
                <# Add read mode #>
                Add-Content -Path $Global:strUserLogPath"\Collect\EndpointURLs.log" -Value ("Read from registry [MSIPC]:`n")

                <# Call function to verify endpoint and certificate issuer #>
                fncVerifyIssuer -strCertURL $Private:MyLicensingIntranetDistributionPointUrl -strEndpointName "LicensingIntranetDistributionPointUrl" -strLogPath $Private:strCertLogPath
                fncVerifyIssuer -strCertURL $Private:MyLicensingExtranetDistributionPointUrl -strEndpointName "LicensingExtranetDistributionPointUrl" -strLogPath $Private:strCertLogPath
                fncVerifyIssuer -strCertURL $Private:MyCertificationDistributionPointUrl -strEndpointName "CertificationDistributionPointUrl" -strLogPath $Private:strCertLogPath
                fncVerifyIssuer -strCertURL $Private:MyUnifiedLabelingDistributionPointUrl -strEndpointName "UnifiedLabelingDistributionPointUrl" -strLogPath $Private:strCertLogPath
                fncVerifyIssuer -strCertURL $Private:MyTelemetryDistributionPointUrl -strEndpointName "TelemetryDistributionPointUrl" -strLogPath $Private:strCertLogPath
                fncVerifyIssuer -strCertURL $Private:MyAIPv1PolicyDistributionPointUrl -strEndpointName "AIPv1PolicyDistributionPointUrl" -strLogPath $Private:strCertLogPath

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "Export endpoint URLs" -strLogValue "EndpointURLs.log"
                fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "Collect endpoint URLs" -strLogValue "Proceeded"

            }
            
        }

        <# Check for COLLECT Endpoints URLs [MSIP] if bootstrap was done/running in "non-admin mode"/reading URLs from registry #>
        If ($(Test-Path -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC\MSIP") -Eq $true) {

            <# Check if "EndpointURLs"-folder and log file exist and create it, if not #>
            fncCreateLogFileAndFolder $Private:strCertLogPath

            <# Read URLs from registry #>
            Get-ChildItem -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC\MSIP" | ForEach-Object {

                <# Read Tenant Id #>
                $Private:strMainKey = $_.Name.Substring(80).ToString()
         
                <# Actions if it's about ".aadrm.com", but not about "discover.aadrm.com" #>
                If ($Private:strMainKey -like "*.aadrm.com" -and $Private:strMainKey -notmatch "discover.aadrm.com") {

                    <# Private variabel definition for Tenant Id string #>
                    $Private:strTenantId = $Private:strMainKey.Remove(36)

                    <# Console output #> 
                    Write-Output (Write-Host "------------------------------------------------`nTenant Id:  $Private:strTenantId`n------------------------------------------------`n" -ForegroundColor Magenta)

                    <# Create Tenant Id as first log entry #>
                    Add-Content -Path $Global:strUserLogPath"\Collect\EndpointURLs.log" -Value "------------------------------------------------`nTenant Id: $Private:strTenantId`n------------------------------------------------"

                    <# Define and fill variables with URLs #>
                    $Private:MyLicensingIntranetDistributionPointUrl = (Get-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC\MSIP\$Private:strMainKey\Identities" -ErrorAction SilentlyContinue).InternalUrl
                    $Private:MyLicensingExtranetDistributionPointUrl = (Get-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC\MSIP\$Private:strMainKey\Identities" -ErrorAction SilentlyContinue).ExternalUrl

                    <# Trimm start of "https://", and end of "/_wmcs/licensing" #>
                    $Private:MyLicensingIntranetDistributionPointUrl = $Private:MyLicensingIntranetDistributionPointUrl.substring($Private:MyLicensingIntranetDistributionPointUrl.length - 69, $Private:MyLicensingIntranetDistributionPointUrl.length - 24)
                    $Private:MyLicensingExtranetDistributionPointUrl = $Private:MyLicensingExtranetDistributionPointUrl.substring($Private:MyLicensingExtranetDistributionPointUrl.length - 69, $Private:MyLicensingExtranetDistributionPointUrl.length - 24)

                    <# Define and fill variables: Extending colledted registry key #>
                    $Private:MyCertificationDistributionPointUrl = $Private:strMainKey

                    <# Create Timestamp #>
                    Add-Content -Path $Global:strUserLogPath"\Collect\EndpointURLs.log" -Value ("Date/Timestamp: " + (Get-Date -Verbose:$false -UFormat "$Private:MyTimestamp"))
                
                    <# Add read mode #>
                    Add-Content -Path $Global:strUserLogPath"\Collect\EndpointURLs.log" -Value ("Read from registry [MSIP]:`n")

                    <# Call function to verify endpoint and certificate issuer #>
                    fncVerifyIssuer -strCertURL $Private:MyLicensingIntranetDistributionPointUrl -strEndpointName "LicensingIntranetDistributionPointUrl" -strLogPath $Private:strCertLogPath
                    fncVerifyIssuer -strCertURL $Private:MyLicensingExtranetDistributionPointUrl -strEndpointName "LicensingExtranetDistributionPointUrl" -strLogPath $Private:strCertLogPath
                    fncVerifyIssuer -strCertURL $Private:MyCertificationDistributionPointUrl -strEndpointName "CertificationDistributionPointUrl" -strLogPath $Private:strCertLogPath
                    fncVerifyIssuer -strCertURL $Private:MyUnifiedLabelingDistributionPointUrl -strEndpointName "UnifiedLabelingDistributionPointUrl" -strLogPath $Private:strCertLogPath
                    fncVerifyIssuer -strCertURL $Private:MyTelemetryDistributionPointUrl -strEndpointName "TelemetryDistributionPointUrl" -strLogPath $Private:strCertLogPath
                    fncVerifyIssuer -strCertURL $Private:MyTelemetryDistributionPointUrl -strEndpointName "AIPv1PolicyDistributionPointUrl" -strLogPath $Private:strCertLogPath
                    
                }
            
            }
 
        }

    }
    Else { <# Actions for COLLECT Endpoints URLs, if bootstrap has failed/reading URLs from portal/running administrative #>

        <# Actions if running administrative #>
        If ($Global:bolRunningPrivileged -eq $true) {

            <# Console output #>
            Write-Output "Initializing, please wait..."

            <# Action if -SkipUpdates was called from command line #>
            If ($Global:bolSkipRequiredUpdates -eq $false) {

                <# Call function to check and update needed modules #>
                fncUpdateRequiredModules

            }

            <# Console output #>
            Write-Output "Connecting to AIPService..."

            <# Actions on PowerShell 7.1 (or higher) for compatibility mode #>
            If ([Version]::new($PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor) -ge [Version]::new("7.1") -eq $true) {

                <# Remove AIPService module, because it's not compatible with PowerShell 7 (or higher) #>
                Remove-Module -Name AIPService -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

                <# Import AIPService module in compatiblity mode #>
                Import-Module -Name AIPService -UseWindowsPowerShell -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "AIPService compatiblity mode" -strLogValue $true

            }

            <# Connect/logon to AIPService #>
            If (Connect-AIPService -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) { <# Action if AIPService connection was opened #>

                <# Console output #> 
                Write-Output "AIPService connected"

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "AIPService connected" -strLogValue $true

            }
            Else{ <# Action if AIPService connection failed #>

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "AIPService connected" -strLogValue $false 
                fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "Collect enpoint URLs" -strLogValue "Login failed"
            
                <# Console output #>
                Write-Output (Write-Host "COLLECT ENDPOINT URLs: Login failed. Please try again.`n" -ForegroundColor Red)

                <# Action if function was called from command line #>
                If ($Global:bolCommingFromMenu -eq $false) {

                    <# Set back window title to default #>
                    $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                    <# Release global variable back to default (updates active) #>
                    $Global:bolSkipRequiredUpdates = $false

                    <# Exit function #>
                    Break

                }

                <# Action if function was called from the menu #>
                If ($Global:bolCommingFromMenu -eq $true) {

                    <# Call pause function #>
                    fncPause

                    <# Clear console #>
                    Clear-Host

                    <# Call show menu function #>
                    fncShowMenu    

                }

            }

            <# Console output #>
            Write-Output "Verifying endpoint URLs...`n"

            <# Private variabel definition for Tenant Id string #>
            $Private:strTenantId = (Get-AipServiceConfiguration).RightsManagementServiceId

            <# Console output #> 
            Write-Output (Write-Host "------------------------------------------------`nTenant Id:  $Private:strTenantId`n------------------------------------------------`n" -ForegroundColor Magenta)

            <# Define and fill variables with URLs #>
            $Private:MyLicensingIntranetDistributionPointUrl = (Get-AipServiceConfiguration).LicensingIntranetDistributionPointUrl.ToString()
            $Private:MyLicensingExtranetDistributionPointUrl = (Get-AipServiceConfiguration).LicensingExtranetDistributionPointUrl.ToString()
            $Private:MyCertificationDistributionPointUrl = (Get-AipServiceConfiguration).CertificationExtranetDistributionPointUrl.ToString()

            <# Trimm start of "https://", and end of "/_wmcs/licensing" #>
            $Private:MyLicensingIntranetDistributionPointUrl = $Private:MyLicensingIntranetDistributionPointUrl.substring($Private:MyLicensingIntranetDistributionPointUrl.length - 69, $Private:MyLicensingIntranetDistributionPointUrl.length - 24)
            $Private:MyLicensingExtranetDistributionPointUrl = $Private:MyLicensingExtranetDistributionPointUrl.substring($Private:MyLicensingExtranetDistributionPointUrl.length - 69, $Private:MyLicensingExtranetDistributionPointUrl.length - 24)
            
            <# Trimm start of "https://", and end of "/_wmcs/certification" #>
            $Private:MyCertificationDistributionPointUrl = $Private:MyCertificationDistributionPointUrl.substring($Private:MyCertificationDistributionPointUrl.length - 73, $Private:MyCertificationDistributionPointUrl.length - 28)

            <# Check if "EndpointURLs"-folder and log file exist and create it, if not #>
            fncCreateLogFileAndFolder $Private:strCertLogPath

            <# Create Tenant Id as first log entry #>
            Add-Content -Path $Global:strUserLogPath"\Collect\EndpointURLs.log" -Value "------------------------------------------------`nTenant Id: $Private:strTenantId`n------------------------------------------------"

            <# Create Timestamp #>
            Add-Content -Path $Global:strUserLogPath"\Collect\EndpointURLs.log" -Value ("Date/Timestamp: " + (Get-Date -Verbose:$false -UFormat "$Private:MyTimestamp"))

            <# Add read mode #>
            Add-Content -Path $Global:strUserLogPath"\Collect\EndpointURLs.log" -Value ("Read from portal:`n")

            <# Call function to verify endpoint and certificate issuer #>
            fncVerifyIssuer -strCertURL $Private:MyLicensingIntranetDistributionPointUrl -strEndpointName "LicensingIntranetDistributionPointUrl" -strLogPath $Private:strCertLogPath
            fncVerifyIssuer -strCertURL $Private:MyLicensingExtranetDistributionPointUrl -strEndpointName "LicensingExtranetDistributionPointUrl" -strLogPath $Private:strCertLogPath
            fncVerifyIssuer -strCertURL $Private:MyCertificationDistributionPointUrl -strEndpointName "CertificationDistributionPointUrl" -strLogPath $Private:strCertLogPath
            fncVerifyIssuer -strCertURL $Private:MyUnifiedLabelingDistributionPointUrl -strEndpointName "UnifiedLabelingDistributionPointUrl" -strLogPath $Private:strCertLogPath
            fncVerifyIssuer -strCertURL $Private:MyTelemetryDistributionPointUrl -strEndpointName "TelemetryDistributionPointUrl" -strLogPath $Private:strCertLogPath
            fncVerifyIssuer -strCertURL $Private:MyAIPv1PolicyDistributionPointUrl -strEndpointName "AIPv1PolicyDistributionPointUrl" -strLogPath $Private:strCertLogPath

            <# Disconnect from AIPService #>
            Disconnect-AIPService | Out-Null

            <# Console output #>
            Write-Output "AIPService disconnected`n"
    
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "AIPService disconnected" -strLogValue $true
            fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "Export endpoint URLs" -strLogValue "EndpointURLs.log"
            fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "Collect endpoint URLs" -strLogValue "Proceeded"

            <# Release private variable #>
            $Private:strTenantId = $null

        }
        Else { <# Actions if running with user privileges #>

            <# Console output #>
            Write-Output (Write-Host "ATTENTION: You must run the 'Unified Labeling Support Tool' in an administrative PowerShell window as a user with local administrative privileges to continue with this option." -ForegroundColor Red)
    
            <# Verbose/Logging on PowerShell 5.1 #>
            If ([Version]::new($PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor) -eq [Version]::new("5.1")) {
                
                <# Console output #>
                Write-Output (Write-Host "Alternatively, you can start (bootstrap) any Microsoft 365 App and try again." -ForegroundColor Red)
                
            }    
            
             <# Console output #>
             Write-Output (Write-Host "COLLECT ENDPOINT URLs: Failed.`n" -ForegroundColor Red)

            <# Action if function was called from command line #>
            If ($Global:bolCommingFromMenu -eq $false) {

                <# Set back window title to default #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                <# Release global variable back to default (updates active) #>
                $Global:bolSkipRequiredUpdates = $false

                <# Exit function #>
                Break

            }

            <# Action if function was called from the menu #>
            If ($Global:bolCommingFromMenu -eq $true) {

                <# Call pause function #>
                fncPause

                <# Clear console #>
                Clear-Host

                <# Call show menu function #>
                fncShowMenu    

            }

        }

    }

    <# Console output #>
    Write-Output "Log file: $Global:strUserLogPath\Collect\EndpointURLs.log"
    Write-Output (Write-Host "COLLECT ENDPOINT URLs: Proceeded.`n" -ForegroundColor Green)
    
    <# Release private variables #>
    $Private:MyLicensingIntranetDistributionPointUrl = $null
    $Private:MyLicensingExtranetDistributionPointUrl = $null
    $Private:MyCertificationDistributionPointUrl = $null
    $Private:MyTimestamp = $null
    $Private:strTenantId = $null
    $Private:strMainKey = $null
    $Private:strCertLogPath = $null
        
}

<# Verify certificates issuer #>
Function fncVerifyIssuer ($strCertURL, $strEndpointName, $strLogPath) {

    <# Define variabel for TCP client/SSL stream #>
    $Private:MyClient = $Private:MySSLtream = $null

    <# Try to verify certificates issuer #>
    Try {
    
        <# Create TCP client #>
        $Private:MyClient = New-Object System.Net.Sockets.TcpClient
        $Private:MyClient.ReceiveTimeout = 5000
        $Private:MyClient.SendTimeout = 5000
        $Private:MyClient.Connect($strCertURL, 443)

        <# Create SSL stream #>
        $Private:MySSLtream = [System.Net.Security.SslStream]::new($Private:MyClient.GetStream(), $false, {$true}, $null)
        $Private:MySSLtream.AuthenticateAsClient(
            $strCertURL,
            $null, <# No athentication #>
            "Tls, Tls11, Tls12", <# Enabled protocols #>
            $false <# Revocation check #>
        )

        <# Define certificate file conditions #>
        $Private:MyWebCert = $Private:MySSLtream.RemoteCertificate

        <# Export web certificate #>
        $Private:MyCertBinaries = $Private:MyWebCert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        [System.IO.File]::WriteAllBytes("$strLogPath\$strEndpointName.ce_", $Private:MyCertBinaries)

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncVerifyIssuer" -strLogDescription "Export certificate" -strLogValue "$strEndpointName.ce_"

        <# Feed variable/certificate data with issuer #>
        $Private:MyWebCert = $Private:MyWebCert.Issuer

        <# Console output #> 
        Write-Output (Write-Host "Endpoint: $strEndpointName" -ForegroundColor Yellow)
        Write-Output (Write-Host "URL:      https://$strCertURL" -ForegroundColor Yellow)
        Write-Output (Write-Host "Issuer:   $Private:MyWebCert`n" -ForegroundColor Yellow)

        <# Check for existing EndpointURLs.log file and extend it, if it exist #>
        If ($(Test-Path $Global:strUserLogPath"\Collect\EndpointURLs.log") -Eq $true) {

            <# Exporting result #>
            Add-Content -Path $Global:strUserLogPath"\Collect\EndpointURLs.log" -Value "Endpoint: $strEndpointName"
            Add-Content -Path $Global:strUserLogPath"\Collect\EndpointURLs.log" -Value "URL:      https://$strCertURL"
            Add-Content -Path $Global:strUserLogPath"\Collect\EndpointURLs.log" -Value "Issuer:   $Private:MyWebCert`n"

        }

    }
    Finally {

        <# Closing SSL streamt #> 
        If ($Private:MySSLtream) {
            $Private:MySSLtream.Close()
        }

        <# Closing TCP client #>
        If ($Private:MyClient) {
            $Private:MyClient.Close()
        }

    }

    <# Release private variables #>
    $Private:MyWebCert = $null
    $Private:MyCertBinaries = $null
    $Private:MySSLtream= $null
    $Private:MyClient = $null

}

<# Compress all log files into a .zip archive #>
Function fncCompressLogs {

    <# Console output #> 
    Write-Output "COMPRESS LOGS:`nCompressing logs, please wait...`n"

    <# Define default zip folder path #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# Define default zip folder path for Windows #>
        $Global:strZipSourcePath = $Global:strTempFolder + "\UnifiedLabelingSupportTool"

    }

    <# Define default zip folder path for macOS #>
    If ($IsMacOS -eq $true) {

        <# Define default zip folder path for macOS #>
        $Global:strZipSourcePath = $Global:strUserLogPath

    }

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Compress logs" -strLogValue "Initiated"
    fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Zip source path" -strLogValue $Global:strZipSourcePath

    <# Compress all files into a .zip file #>
    If ($(Test-Path -Path $Global:strZipSourcePath) -Eq $true) { <# Actions, if path exist #>

        <# Define .zip file name #>
        $Private:strZipFile = "UnifiedLabelingSupportTool (" + $([System.Environment]::USERNAME) + (Get-Date -UFormat "-%H%M%S") + ").zip".ToString()

        <# Define user desktop path #>
        $Private:DesktopPath = [Environment]::GetFolderPath("Desktop")

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Zip destination path" -strLogValue $Private:DesktopPath
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Zip file name" -strLogValue $Private:strZipFile
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Compress logs" -strLogValue "Proceeded"

        <# Compress all files and logs into zip file (overwrites) #>
        Compress-Archive -Path $Global:strZipSourcePath"\*" -DestinationPath "$Private:DesktopPath\$Private:strZipFile" -Force -ErrorAction SilentlyContinue

    }

    <# Console output #> 
    Write-Output "Zip file: $Private:DesktopPath\$Private:strZipFile"
    Write-Output (Write-Host "COMPRESS LOGS: Proceeded.`n" -ForegroundColor Green)

    <# Clean Logs folders if .zip archive is on the desktop #>
    If ($(Test-Path -Path $Private:DesktopPath\$Private:strZipFile) -Eq $true) { <# Actions, if file exist on desktop #>

        <# Clean Logs folders #>
        Remove-Item "$Global:strZipSourcePath" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Log folders cleaned" -strLogValue $true

    }
    Else{

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Log folders cleaned" -strLogValue $false

    }

    <# Release private variable #>
    $Private:strZipFile = $null
    $Private:DesktopPath = $null

    <# Release global variable #>
    $Global:strZipSourcePath = $null

}

<# Pause menu for message display #>
Function fncPause {

    <# Define and fill variables #>
    $Private:strPauseMessage = "Press any key to continue" <# Pause message #>
    $Private:strValue | Out-Null

    <# Pause the script module with a message #>
    If ($Global:psISE) { <# Actions, if running in PowerShell ISE #>

        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$Private:strPauseMessage")

    }
    Else { <# Actions if running in PowerShell command window #>

        <# Console output #> 
        Write-Output (Write-Host $Private:strPauseMessage -ForegroundColor Yellow)
        $Private:strValue = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    }

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncPause" -strLogDescription "Pause" -strLogValue "Called"

}

<# Script module menu #>
Function fncShowMenu {

    <# Clear console #>
    Clear-Host

    <# Define variables #>
    $Global:bolCommingFromMenu | Out-Null
    $Global:bolSkipRequiredUpdates | Out-Null

    <# Helper variable to control menu handling inside function calls #>
    $Global:bolCommingFromMenu = $true

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncShowMenu" -strLogDescription "Main menu" -strLogValue "Called"

    <# Menu output #>
    Write-Output "UnifiedLabelingSupportTool:`n"
    Write-Output (Write-Host "  [I] INFORMATION" -ForegroundColor Green)
    Write-Output (Write-Host "  [M] MIT LICENSE" -ForegroundColor Green)
    Write-Output (Write-Host "  [H] HELP" -ForegroundColor Green)
    Write-Output (Write-Host "  [R] RESET" -ForegroundColor Yellow)
    Write-Output (Write-Host "  [P] RECORD PROBLEM" -ForegroundColor Yellow)
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") { <# Detect Windows/hide unsupported features on macOS #>
        Write-Output (Write-Host "  [C] COLLECT" -ForegroundColor Yellow)
        If (@($Global:MenuCollectExtended) -Match $true) {
            Write-Output (Write-Host "   ├──[A] AIP service configuration" -ForegroundColor Yellow)
            Write-Output (Write-Host "   ├──[T] AIP service templates" -ForegroundColor Yellow)
            Write-Output (Write-Host "   ├──[U] Endpoint URLs" -ForegroundColor Yellow)
            Write-Output (Write-Host "   └──[L] Labels and policies" -ForegroundColor Yellow)
        }
    }
    Write-Output (Write-Host "  [Z] COMPRESS LOGS" -ForegroundColor Yellow)
    Write-Output (Write-Host "  [X] EXIT`n" -ForegroundColor Green)

    <# Define menu selection variable #>
    $Private:intMenuSelection = Read-Host "Please select an option and press enter"

    <# Actions for information menu selected #>
    If ($Private:intMenuSelection -Eq "I") {
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[I] INFORMATION" -strLogValue "Selected"
        
        <# Clear console #>
        Clear-Host
        
        <# Call information function #>
        fncInformation
        
        <# Call pause function #>
        fncPause

    }

    <# Actions for License menu selected #>
    If ($Private:intMenuSelection -Eq "M") {
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[M] MIT LICENSE" -strLogValue "Selected"
        
        <# Clear console #>
        Clear-Host

        <# Call License function #>
        fncLicense

        <# Call pause function #>
        fncPause
    }
   
    <# Actions for help menu selected #>
    If ($Private:intMenuSelection -Eq "H") {
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[H] HELP" -strLogValue "Selected"
        
        <# Clear console #>
        Clear-Host

        <# Call help function #>
        fncHelp

    }
    
    <# Actions for reset menu selected #>
    If ($Private:intMenuSelection -Eq "R") {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[R] RESET" -strLogValue "Selected"
        
        <# Clear console #>
        Clear-Host

        <# Call reset function #>
        fncReset

        <# Call pause function #>
        fncPause

    }

    <# Actions for record problem menu selected #>
    If ($Private:intMenuSelection -Eq "P") {
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[P] RECORD PROBLEM" -strLogValue "Selected"
        
        <# Clear console #>
        Clear-Host
        
        <# Call user logging function #>
        fncRecordProblem
        
        <# Call pause function #>
        fncPause

    }

    <# Detect Windows/disable unsupported menus for macOS #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# Actions for collect menu selected #>
        If ($Private:intMenuSelection -Eq "C") {
        
            <# Show/Hide menu extenstion  #>
            If (@($Global:MenuCollectExtended) -Match $true) {$Global:MenuCollectExtended = $false}
            Else {$Global:MenuCollectExtended = $true}

        }

        <# Actions for AIP service configuration menu selected #>
        If ($Private:intMenuSelection -Eq "A") {
        
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[A] AIP service configuration" -strLogValue "Selected"
            
            <# Clear console #>
            Clear-Host
            
            <# Call function to collect AIP service configuration #>
            fncCollectAipServiceConfiguration
            
            <# Call pause function #>
            fncPause

        }

        <# Actions for AIP service templates menu selected #>
        If ($Private:intMenuSelection -Eq "T") {
        
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[T] AIP service templates" -strLogValue "Selected"
            
            <# Clear console #>
            Clear-Host
            
            <# Call function to collect AIP service templates #>
            fncCollectAIPServiceTemplates
            
            <# Call pause function #>
            fncPause

        }

        <# Actions for labels and policies menu selected #>
        If ($Private:intMenuSelection -Eq "L") {
        
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[L] Labels and policies" -strLogValue "Selected"
            
            <# Clear console #>
            Clear-Host
            
            <# Call Labels and Policies function #>
            fncCollectLabelsAndPolicies
            
            <# Call pause function #>
            fncPause

        }

        <# Actions for CollectEndpointURLs menu selected #>
        If ($Private:intMenuSelection -Eq "U") {
        
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[U] Endpoint URLs" -strLogValue "Selected"
            
            <# Clear console #>
            Clear-Host
            
            <# Call CollectEndpointURLs function #>
            fncCollectEndpointURLs
            
            <# Call pause function #>
            fncPause
            
        }

    }

    <# Actions for compress logs menu selected #>
    If ($Private:intMenuSelection -Eq "Z") {
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[Z] COMPRESS LOGS" -strLogValue "Selected"
        
        <# Clear console #>
        Clear-Host
        
        <# Call compress logs function #>
        fncCompressLogs
        
        <# Call pause function #>
        fncPause
        
    }

    <# Actions for exit menu selected #>
    If ($Private:intMenuSelection -Eq "X") {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[X] EXIT" -strLogValue "Selected"

        <# Clear global variables #>
        $Global:bolCommingFromMenu = $false

        <# Release global variable back to default (updates active) #>
        $Global:bolSkipRequiredUpdates = $false

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle
        
        <# Exit function #>
        Break
        
    }
    Else {

        <# Clear console #>
        Clear-Host

        <# Call show menu function #>
        fncShowMenu

    }

}

<# Initialize OS environment settingss #>
fncInitialize

<# Check whether logging was left enabled #>
fncValidateForActivatedLogging

<# Check and remove previous versions #>
fncRemovePreviousVersions

<# Export functions for script module manifest #>
Export-ModuleMember -Alias "ULSupportTool" -Function UnifiedLabelingSupportTool
