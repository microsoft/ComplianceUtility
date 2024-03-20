#Requires -Version 5.1

# Copyright (c) Microsoft Corporation
# Licensed under the MIT License

<# Variables #>
$Global:strVersion = "3.2.0" <# Version #>
$Global:strDefaultWindowTitle = $Host.UI.RawUI.WindowTitle <# Caching window title #>
$Global:host.UI.RawUI.WindowTitle = "Compliance Utility ($Global:strVersion)" <# Set window title #>
$Global:bolMenuCollectExtended = $false <# Variable for COLLECT menu handling #>
$Global:bolCommingFromMenu = $false <# Variable for menu handling inside functions #>
$Global:bolSkipRequiredUpdates = $false <# Variable for handling updates #>
$Global:FormatEnumerationLimit = -1 <# Variable to show full Format-List for arrays #>

Function fncInitialize{

    <# Variable for user log path #>
    $Global:strUserLogPath | Out-Null

    <# Detect Windows #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# Variable for Windows version #>
        $Global:strOSVersion = (Get-CimInstance Win32_OperatingSystem).Caption

        <# Check for supported Windows versions #>
        If ($Global:strOSVersion -like "*Windows 10*" -Or
            $Global:strOSVersion -like "*Windows 11*" -Or
            $Global:strOSVersion -like "*2012*" -Or
            $Global:strOSVersion -like "*Server 2016*" -Or
            $Global:strOSVersion -like "*Server 2019*" -Or
            $Global:strOSVersion -like "*Server 2022*"){

            <# Variables #>
            $Global:strTempFolder = (Get-Item Env:"Temp").Value <# User temp folder #>
            $Global:strUserLogPath = New-Item -ItemType Directory -Force -Path "$Global:strTempFolder\ComplianceUtility" <# Default user log path #>
            $Global:bolRunningPrivileged = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups -match "S-1-5-32-544") <# Control variable for privilege checks #>
            
        }
        Else { <# Actions, when running on unsupported Windows #>

            <# Variable #>
            $Global:strOSVersion = $null

            <# Logging #>
            fncLogging -strLogFunction "fncInitialize" -strLogDescription "Unsupported operating system" -strLogValue $true

            <# Output #>
            Write-ColoredOutput Red "ATTENTION: The 'Compliance Utility' does not support the operating system you're using.`nPlease ensure to use one of the following supported operating systems:`nMicrosoft Windows 11, Windows 10, Windows Server 2022, Windows Server 2019, Windows Server 2016, and Windows Server 2012/R2.`n"

            <# Set back window title #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit #>
            Break

        }

        <# Logging Windows edition and version #>
        fncLogging -strLogFunction "fncInitialize" -strLogDescription "OS edition" -strLogValue $Global:strOSVersion 
        fncLogging -strLogFunction "fncInitialize" -strLogDescription "OS version" -strLogValue $([System.Environment]::OSVersion.Version)

    }

    <# Detect macOS #>
    If ($IsMacOS -eq $true) {

        <# Variables #>
        $Global:strOSVersion = $(sw_vers -productVersion) <# Apple macOS version #>

        <# Check for unsupported macOS #>
        If ($Global:strOSVersion -lt "12.5") {

            <# Variable #>
            $Global:strOSVersion = $null

            <# Logging #>
            fncLogging -strLogFunction "fncInitialize" -strLogDescription "Unsupported operating system" -strLogValue $true

            <# Output #>
            Write-ColoredOutput Red "ATTENTION: The 'Compliance Utility' does not support the operating system you're using.`nPlease ensure to use a supported operating system:`nApple macOS 12.5 (Monterey) or higher.`n"

            <# Set back window title #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit #>
            Break

        }
        Else { <# Actions on supported macOS versions #>

            <# Variable #>
            $Global:strUserLogPath = New-Item -ItemType Directory -Force -Path "$(printenv HOME)\Documents\ComplianceUtility" <# Default user log path #>
            
            <# Detect if user is in admin group (80) #>
            If ($(id -G) -match "80"){

                <# Control variable for privileges checks #>
                $Global:bolRunningPrivileged = $true

            }
            Else {

                <# Control variable for privileges checks #>
                $Global:bolRunningPrivileged = $false

            }

        }

        <# Logging: macOS #>
        fncLogging -strLogFunction "fncInitialize" -strLogDescription "OS edition" -strLogValue "Apple $(sw_vers -productName) ($(uname -s))"
        fncLogging -strLogFunction "fncInitialize" -strLogDescription "OS version" -strLogValue $Global:strOSVersion
        fncLogging -strLogFunction "fncInitialize" -strLogDescription "OS kernel" -strLogValue $(uname -v)

    }

    <# Logging: Default entries for Windows and macOS #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "OS 64-Bit" -strLogValue $([System.Environment]::Is64BitOperatingSystem) <# Architecture #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "Module version" -strLogValue "$Global:strVersion" <# Module version #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "Username" -strLogValue $([System.Environment]::UserName) <# Username #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "Machine name" -strLogValue $([System.Environment]::MachineName) <# Machine name #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "PowerShell Host" -strLogValue $($Host.Name.ToString()) <# PowerShell host #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "PowerShell Version" -strLogValue $($Host.Version.ToString()) <# PowerShell version #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "PowerShell Edition" -strLogValue $($PSVersionTable.PSEdition.ToString()) <# PowerShell edition #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "PowerShell Current culture" -strLogValue $($Host.CurrentCulture.ToString()) <# PowerShell culture #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "PowerShell Current UI culture" -strLogValue $($Host.CurrentUICulture.ToString()) <# PowerShell UI culture #>
    fncLogging -strLogFunction "fncInitialize" -strLogDescription "Running privileged" -strLogValue $Global:bolRunningPrivileged <# Administrative privileges #>

    <# Variable to check for unsupported PowerShell #>
    $Global:bolSupportedPowerShell | Out-Null
    $Global:bolSupportedPowerShell = $true

    <# Detect PowerShell Destkop 5.1 #>
    If ($PSVersionTable.PSEdition.ToString() -eq "Desktop" -and [Version]::new($PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor) -ne [Version]::new("5.1")) {
   
        <# Set unsupported PowerShell #>
        $Global:bolSupportedPowerShell = $false

    }

    <# Detect PowerShell Core 7.4 (or less) #>
    If ($PSVersionTable.PSEdition.ToString() -eq "Core" -and [Version]::new($PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor) -lt [Version]::new("7.4")) {

        <# Set unsupported PowerShell #>
        $Global:bolSupportedPowerShell = $false

    }

    <# Check for supported PowerShell #>
    If ($Global:bolSupportedPowerShell -eq $false) {

        <# Logging #>
        fncLogging -strLogFunction "fncInitialize" -strLogDescription "Supported PowerShell version" -strLogValue $false

        <# Output #>
        Write-ColoredOutput Red "ATTENTION: The version of PowerShell that is required by the 'Compliance Utility' does not match the currently running version of PowerShell $($PSVersionTable.PSVersion).`n"

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Exit #>
        Break

    }

    <# Release variable #>
    $Global:bolSupportedPowerShell = $null

}

<# Core definitions #>
Function ComplianceUtility {

    <#
    .SYNOPSIS
        The 'Compliance Utility' is a powerful tool that helps troubleshoot and diagnose sensitivity labels, policies, settings and more. Whether you need to fix issues or reset configurations, this tool has you covered.

        .DESCRIPTION
        Have you ever used the Sensitivity button in a Microsoft 365 App or applied a sensitivity label by right-clicking on a file? If so, you've either used the Office's built-in labeling experience or the Purview Information Protection client. If something is not working as expected with your DLP policies, sensitivity labels or you don't see any labels at all the 'Compliance Utility' will help you.

        INTERNET ACCESS
        The 'Compliance Utility' uses additional sources from the Internet to make its functionality fully available.
        WARNING: Unexpected errors may occur, and some features may be limited, if there is no connection to the Internet.

    .NOTES
        MIT LICENSE
        
        Copyright (c) Microsoft Corporation.

        Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
        
        VERSION
        3.2.0
        
        CREATE DATE
        03/20/2024

        AUTHOR
        Claus Schiroky
        Customer Service & Support | EMEA Modern Work Team
        Microsoft Deutschland GmbH

        HOMEPAGE
        https://aka.ms/ComplianceUtility

        PRIVACY STATEMENT
        https://privacy.microsoft.com/PrivacyStatement

        COPYRIGHT
        Copyright (c) Microsoft Corporation.

    .PARAMETER Information
        This shows syntax, description and version information.

    .PARAMETER License
        This displays the MIT License.

    .PARAMETER Help
        This opens the online manual.

    .PARAMETER Reset
        IMPORTANT: Before you proceed with this option, please close all open applications.

        This option removes all relevant policies, labels and settings.

        Valid arguments are: "Default", or "Silent".

        On Microsoft Windows:

        Note:
        - Reset with the default argument will not reset all settings, but only user-specific settings if you run PowerShell with user privileges. This is sufficient in most cases to reset Microsoft 365 Apps, while a complete reset is useful for all other applications.
        - If you want a complete reset, you need to run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges.

        Default:

        When you run PowerShell with user privileges, this argument removes all relevant policies, labels and settings:

        ComplianceUtility -Reset Default
       
        With the above command the following registry keys are cleaned up:

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

        The DRMEncryptProperty and OpenXMLEncryptProperty registry settings are purged of the following keys:

        [HKCU:\SOFTWARE\Policies\Microsoft\Cloud\Office\16.0\Common\Security]
        [HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security]
        [HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security]        

        The UseOfficeForLabelling (Use the Sensitivity feature in Office to apply and view sensitivity labels) and AIPException (Use the Azure Information Protection add-in for sensitivity labeling) registry setting is purged of the following keys:

        [HKCU:\SOFTWARE\Policies\Microsoft\Cloud\Office\16.0\Common\Security\Labels]
        [HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security\Labels]
        [HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security\Labels]

        The following file system folders are cleaned up as well:

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

        The Clear-AIPAuthentication cmdlet is used to reset user settings, if a Purview Information Protection (aka 'Azure Information Protection') installation is found.

        When you run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges, the following registry keys are cleaned up in addition:

        [HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSIPC]
        [HKLM:\SOFTWARE\Microsoft\MSIPC]
        [HKLM:\SOFTWARE\Microsoft\MSDRM]
        [HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSDRM]
        [HKLM:\SOFTWARE\WOW6432Node\Microsoft\MSIP]

        Silent:

        This command line parameter argument does the same as "-Reset Default", but does not print any output - unless an error occurs when attempting to reset:

        ComplianceUtility -Reset Silent

        If a silent reset triggers an error, you can use the additional parameter "-Verbose" to find out more about the cause of the error:

        ComplianceUtility -Reset Silent -Verbose

        You can also review the Script.log file for errors of silent reset.

        On Apple macOS:

        The following file folders will be cleaned with Default argument:

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
        
        Silent:

        This command line parameter argument does the same as "-Reset Default", but does not print any output - unless an error occurs when attempting to reset:

        ComplianceUtility -Reset Silent

        If a silent reset triggers an error, you can use the additional parameter "-Verbose" to find out more about the cause of the error:

        ComplianceUtility -Reset Silent -Verbose

        You can also review the Script.log file for errors of silent reset.

    .PARAMETER RecordProblem
        IMPORTANT: Before you proceed with this option, please close all open applications.

        As a first step, this parameter activates the required logging and then prompts you to reproduce the problem. While you’re doing so, the 'Compliance Utility' collects and records data. Once you have reproduced the problem, all collected files will be stored into the default logs folder (on Windows: '%temp%\ComplianceUtility', on macOS: '~/Documents/ComplianceUtility'). Every time you call this option, a new unique subfolder will be created in the logs-folder that reflects the date and time when it was created.

        In the event that you accidentally close the PowerShell window while logging is enabled, the 'Compliance Utility' disables logging the next time you start it.

        Note (for Windows user):
        - Neither CAPI2 or AIP event logs, network trace nor filter drivers are recorded if the 'Compliance Utility' is not run in an administrative PowerShell window as a user with local administrative privileges.

        Note (for Apple macOS user):
        - When collecting basic system information, the message "'Terminal' wants to access data from other applications" may appear. Since no personal information is collected, only hardware and software data, it has no effect on how you confirm the message.

    .PARAMETER CollectAIPServiceConfiguration
        This parameter collects your AIP service configuration information (e.g. SuperUsers or OnboardingControlPolicy, etc.) by using the AIPService module.

        The results are written to the log file AIPServiceConfiguration.log in the subfolder "Collect" of the Logs folder.
        
        Note (for Windows user):
        - You must run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges to continue with this option. Please contact your administrator if necessary.
        - You need to know your Microsoft 365 global administrator account information to proceed, as you will be asked for your credentials.
        - The AIPService module does not yet support PowerShell 7.x. Therefore, unexpected errors may occur because the AIPService module is executed in compatibility mode in PowerShell 7.x.

        Note (for Apple macOS user):
        - This parameter is not available. It would require the AIPService module, which is not yet supported on PowerShell 7.x.

    .PARAMETER CollectProtectionTemplates
        This parameter collects protection templates of your tenant by using the AIPService module.

        The results are written to the log files ProtectionTemplates.xml and ProtectionTemplateDetails.xml in the subfolder "Collect\ProtectionTemplates" of the Logs folder, and an export of each protection template (.xml) into the subfolder "ProtectionTemplatesBackup".

        TIP: You can use this feature to create a backup copy of your protection templates.

        Note (for Windows user):
        - You must run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges to continue with this option. Please contact your administrator if necessary.
        - You need to know your Microsoft 365 global administrator account information to proceed, as you will be asked for your credentials.
        - The AIPService module does not yet support PowerShell 7.x. Therefore, unexpected errors may occur because the AIPService module is executed in compatibility mode in PowerShell 7.x.

        Note (for Apple macOS user):
        - This parameter is not available. It would require the AIPService module, which is not yet supported on PowerShell 7.x.

    .PARAMETER CollectEndpointURLs
        This parameter collects important endpoint URLs. The URLs are taken from your local registry or your tenant's AIP service configuration information (by using the AIPService module), and extended by additional relevant URLs.

        In a first step, this parameter is used to check whether you can access the URL. In a second step, the issuer of the corresponding certificate of the URL is collected. This process is represented by an output with the Tenant Id, Endpoint name, URL, and Issuer of the certificate. For example:

        --------------------------------------------------
        Tenant Id: 48fc04bd-c84b-44ac-b7991b7-a4c5eefd5ac1
        --------------------------------------------------

        Endpoint: UnifiedLabelingDistributionPointUrl
        URL:      https://dataservice.protection.outlook.com
        Issuer:   CN=DigiCert Cloud Services CA-1, O=DigiCert Inc, C=US

        In addition, results are written into log file EndpointURLs.log in the subfolder "Collect" of the Logs folder.

        Note (for Windows user):
        - You must run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges to continue with this option, if the corresponding Microsoft 365 App is not bootstraped. Please contact your administrator if necessary.
        - You need to know your Microsoft 365 global administrator account information to proceed, as you will be asked for your credentials.
        - The AIPService module does not yet support PowerShell 7.x. Therefore, unexpected errors may occur because the AIPService module is executed in compatibility mode in PowerShell 7.x.

        Note (for Apple macOS user):
        - This parameter is not available. It would require the AIPService module, which is not yet supported on PowerShell 7.x.       

    .PARAMETER CollectLabelsAndPolicies
        This parameter collects Information Protection labels, policies (with detailled actions and rules), auto-label policies and rules from your Microsoft Purview compliance portal by using the Exchange Online PowerShell module.

        The results are written to the log files Labels.xml, LabelsDetailedActions.xml, LabelPolicies.xml, LabelRules.xml, AutoLabelPolicies.xml and AutoLabelRules.xml in the subfolder "Collect\LabelsAndPolicies" of the Logs folder, and on Windows you can also have a CLP subfolder with the Office CLP policy.

        TIP: You can use the resulting log file to create exact copies of the label and policy settings for troubleshooting purposes, e.g. in test environments.

        Note:
        - You must run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges to continue with this option. Please contact your administrator if necessary.
        - You need to know your Microsoft 365 global administrator account information to proceed with this option, as you will be asked for your credentials.
        - The Microsoft Exchange Online Management module is required to proceed this option. If you do not have this module installed, 'Compliance Utility' will try to install it from PowerShell Gallery.

    .PARAMETER CollectDLPRulesAndPolicies
        This parameter collects DLP rules and policies, sensitive information type details, rule packages, keyword dictionaries and exact data match schemas from the Microsoft Purview compliance portal by using the Exchange Online PowerShell module.

        The results are written to the log files DlpPolicy.xml, DlpRule.xml, DlpPolicyDistributionStatus.xml, DlpSensitiveInformationType.xml, DlpSensitiveInformationTypeRulePackage.xml, DlpKeywordDictionary.xml and DlpEdmSchema.xml in the subfolder "Collect\DLPRulesAndPolicies" of the Logs folder.

        Note:
        - You must run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges to continue with this option. Please contact your administrator if necessary.
        - You need to know your Microsoft 365 global administrator account information to proceed with this option, as you will be asked for your credentials.
        - The Microsoft Exchange Online Management module is required to proceed this option. If you do not have this module installed, 'Compliance Utility' will try to install it from PowerShell Gallery.

    .PARAMETER CollectUserLicenseDetails
        This parameter collects the user license details by the Graph PowerShell module.

        The results are written to the log file UserLicenseDetails.log in the subfolder "Collect" of the Logs folder.

        Note:
        - You must log in with the corresponding Microsoft 365 user account for which you want to check the license details.
        - The Microsoft Graph PowerShell modules are required to proceed this option. If you do not have this module installed, 'Compliance Utility' will try to install it from PowerShell Gallery.

    .PARAMETER CompressLogs
        This command line parameter should always be used at the very end of a scenario.

        This parameter compresses all collected log files and folders into a .zip archive, and the corresponding file is saved to your desktop. In addition, the default logs folder (on Windows: '%temp%\ComplianceUtility', on macOS: '~/Documents/ComplianceUtility') is cleaned.

    .PARAMETER Menu
        This will start the 'Compliance Utility' with the default menu.

    .PARAMETER SkipUpdates
        IMPORTANT: Use this parameter only if you are sure that all PowerShell modules are up to date.

        This parameter skips the update check mechanism for all entries of the COLLECT menu.

    .EXAMPLE
        ComplianceUtility -Information
        This shows syntax and description.

    .EXAMPLE
        ComplianceUtility -License
        This displays the MIT License.

    .EXAMPLE
        ComplianceUtility -Help
        This parameter opens the online manual.

    .EXAMPLE
        ComplianceUtility -Reset Default
        This parameter removes all relevant policies, labels and settings.

    .EXAMPLE
        ComplianceUtility -Reset Silent
        This parameter removes all relevant policies, labels and settings without any output.

    .EXAMPLE
        ComplianceUtility -RecordProblem
        This parameter cleans up existing MSIP/MSIPC log folders, then it removes all relevant policies, labels and settings, and starts recording data.

    .EXAMPLE
        ComplianceUtility -CollectAIPServiceConfiguration
        This parameter collects AIP service configuration information of your tenant.

    .EXAMPLE
        ComplianceUtility -CollectProtectionTemplates
        This parameter collects protection templates of your tenant.

    .EXAMPLE
        ComplianceUtility -CollectLabelsAndPolicies
        This parameter collects the labels and policy definitions from the Microsoft Purview compliance portal.

    .EXAMPLE
        ComplianceUtility -CollectEndpointURLs
        This parameter collects important enpoint URLs.

    .EXAMPLE
        ComplianceUtility -CollectDLPRulesAndPolicies
        This parameter collects DLP rules and policies from the Microsoft Purview compliance portal.

    .EXAMPLE
        ComplianceUtility -CollectUserLicenseDetails
        This parameter collects the user license details by Microsoft Graph.
        
    .EXAMPLE
        ComplianceUtility -CompressLogs
        This parameter compress all collected logs files into a .zip archive, and the corresponding path and file name is displayed.

    .EXAMPLE
        ComplianceUtility -Reset Default -RecordProblem -CompressLogs
        This parameter removes all relevant policies, labels and settings, starts recording data, and compress all collected logs files to a .zip archive on the desktop.

    .EXAMPLE
        ComplianceUtility -Menu
        This will start the 'Compliance Utility' with the default menu.

    .LINK
        https://github.com/microsoft/ComplianceUtility

    #>

    <# Binding for parameters #>
    [CmdletBinding (
        HelpURI = "https://github.com/microsoft/ComplianceUtility/blob/main/Manuals/3.2.0/Manual-Win.md", <# URL for online manual #>
        PositionalBinding = $false, <# None-positional parameters #>
        DefaultParameterSetName = "Menu" <# Default start parameter #>
    )]
    [Alias("CompUtil","UnifiedLabelingSupportTool")]

    <# Parameter definitions #>
    Param (
        
        <# Information #>
        [Alias("i")]
        [Parameter(ParameterSetName = "Information")]
        [switch]$Information,

        <# License #>
        [Alias("m")]
        [Parameter(ParameterSetName = "License")]
        [switch]$License,

        <# Help #>
        [Alias("h")]
        [Parameter(ParameterSetName = "Help")]
        [switch]$Help,

        <# Reset #>
        [Alias("r")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [ValidateSet("Default", "Silent")]
        [string]$Reset="Default",

        <# RecordProblem #>
        [Alias("p")]
        [parameter(ParameterSetName = "Reset and logging")]
        [switch]$RecordProblem,

        <# CollectAIPServiceConfiguration #>
        [Alias("a")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CollectAIPServiceConfiguration,

        <# CollectProtectionTemplates #>
        [Alias("t")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CollectProtectionTemplates,

        <# CollectEndpointURLs #>
        [Alias("e")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CollectEndpointURLs,

        <# CollectLabelsAndPolicies #>
        [Alias("l")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CollectLabelsAndPolicies,

        <# CollectDLPPoliciesAndRules #>
        [Alias("d")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CollectDLPRulesAndPolicies,        

        <# CollectUserLicenseDetails #>
        [Alias("u")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CollectUserLicenseDetails,       

        <# SkipUPdates #>
        [Parameter(ParameterSetName = "Menu")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$SkipUpdates,

        <# CompressLogs #>
        [Alias("z")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CompressLogs,

        <# Menu #>
        [Parameter(ParameterSetName = "Menu")]
        [switch]$Menu

    )

    <# Actions for Information #>
    If ($PsCmdlet.ParameterSetName -eq "Information") {

        <# Call Information #>
        fncInformation

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "INFORMATION" -strLogValue "Proceeded"

    } 

    <# Actions for License #>
    If ($PSBoundParameters.ContainsKey("License")) {

        <# Call License #>
        fncLicense
    
        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "LICENSE" -strLogValue "Proceeded"

    }
    
    <# Actions for Help #>
    If ($PSBoundParameters.ContainsKey("Help")) {

        <# Call Help #>
        fncHelp

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "HELP" -strLogValue "Proceeded"

    }

    <# Actions for Reset #>
    If ($PSBoundParameters.ContainsKey("Reset")) {

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "Parameter Help" -strLogValue "Triggered"                

        <# Call Reset #>
        fncReset -strResetMethod $Reset

    }

    <# Actions for RecordProblem #>
    If ($PSBoundParameters.ContainsKey("RecordProblem")) {

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "Parameter RecordProblem" -strLogValue "Triggered"       

        <# Call RecordProblem #>
        fncRecordProblem

    }

    <# Variable for unavailable COLLECT features on macOS #>
    $Private:strNotAvailableOnMac = "This feature is not yet available on Apple macOS."

    <# Actions for SkipUpdates #>
    If ($PSBoundParameters.ContainsKey("SkipUpdates")) {

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "Parameter SkipUpdates" -strLogValue "Triggered"
          
        <# Define variable #>
        $Global:bolSkipRequiredUpdates | Out-Null

        <# Disabling updates check #>
        $Global:bolSkipRequiredUpdates = $true

    }

    <# Actions CollectAIPServiceConfiguration #>
    If ($PSBoundParameters.ContainsKey("CollectAIPServiceConfiguration")) {

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "Parameter CollectAIPServiceConfiguration" -strLogValue "Triggered"

        <# Consider Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

            <# Call CollectAIPServiceConfiguration #>
            fncCollectAIPServiceConfiguration

        }
        Else {

            <# Message on macOS #>
            Write-Output $Private:strNotAvailableOnMac

        }

    }

    <# Actions for CollectProtectionTemplates #>
    If ($PSBoundParameters.ContainsKey("CollectProtectionTemplates")) {

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "Parameter CollectProtectionTemplates" -strLogValue "Triggered"

        <# Consider Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

            <# Call CollectProtectionTemplates #>
            fncCollectProtectionTemplates

        }
        Else {

            <# Message on macOS #>
            Write-Output $Private:strNotAvailableOnMac

        }

    }

    <# Actions for CollectUserLicenseDetails #>
    If ($PSBoundParameters.ContainsKey("CollectUserLicenseDetails")) {

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "Parameter CollectUserLicenseDetails" -strLogValue "Triggered"

        <# Call CollectUserLicenseDetails #>
        fncCollectUserLiceneseDetails

    }

    <# Actions for CollectLabelsAndPolicies #>
    If ($PSBoundParameters.ContainsKey("CollectLabelsAndPolicies")) {

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "Parameter CollectLabelsAndPolicies" -strLogValue "Triggered"

        <# Call CollectLabelsAndPolicies #>
        fncCollectLabelsAndPolicies

    }

    <# Actions for CollectEndpointURLs #>
    If ($PSBoundParameters.ContainsKey("CollectEndpointURLs")) {

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "Parameter CollectEndpointsURLs" -strLogValue "Triggered"

        <# Consider Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

            <# Call CollectEndpointURLs #>
            fncCollectEndpointURLs

        }
        Else {

            <# Message on macOS #>
            Write-Output $Private:strNotAvailableOnMac

        }

    }

    <# Actions for  CollectDLPRulesAndPolicies #>
    If ($PSBoundParameters.ContainsKey("CollectDLPRulesAndPolicies")) {

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "Parameter CollectDLPRulesAndPolicies" -strLogValue "Triggered"

        <# Call CollectDLPRulesAndPolicies #>
        fncCollectDLPRulesAndPolicies

    }

    <# Actions for CompressLogs #>
    If ($PSBoundParameters.ContainsKey("CompressLogs")) {

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "Parameter CompressLogs" -strLogValue "Triggered"

        <# Call CompressLogs #>
        fncCompressLogs

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Exit #>
        Break

    }

    <# Actions for ShowMenu #>
    If ($PsCmdlet.ParameterSetName -eq "Menu") {

        <# Logging #>
        fncLogging -strLogFunction "ComplianceUtility" -strLogDescription "MENU" -strLogValue "Triggered"

        <# Call ShowMenu #>
        fncShowMenu

    }

}

Function fncLogging ($strLogFunction, $strLogDescription, $strLogValue) {

    <# Detect/create UserLogPath #>
    If ($(Test-Path -Path $Global:strUserLogPath) -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath | Out-Null <# Define UserLogPath #>

    }

    <# Output #>
    Write-Verbose "$(Get-Date -UFormat "%Y-%m-%d"), $(Get-Date -UFormat "%H:%M"), $strLogFunction, $strLogDescription, $strLogValue"

    <# Append output #>
    Write-Verbose "$(Get-Date -UFormat "%Y-%m-%d"), $(Get-Date -UFormat "%H:%M"), $strLogFunction, $strLogDescription, $strLogValue" -ErrorAction SilentlyContinue -Verbose 4>> "$Global:strUserLogPath\Script.log" 

}

Function fncInformation {

    <# Logging #>
    fncLogging -strLogFunction "fncInformation" -strLogDescription "INFORMATION" -strLogValue "Called"

    <# Command line actions #>
    If ($Global:bolCommingFromMenu -eq $false) {

        <# Call Information #>
        Get-Help -Verbose:$false ComplianceUtility

    }

    <# Menu Actions #>
    If ($Global:bolCommingFromMenu -eq $true) {
    
        <# Output #>
        Write-Output "NAME:`nComplianceUtility`n`nDESCRIPTION:`nThe 'Compliance Utility' is a powerful tool that helps troubleshoot and diagnose sensitivity labels, policies, settings and more. Whether you need to fix issues or reset configurations, this tool has you covered.`n`nVERSION:`n$Global:strVersion`n`nAUTHOR:`nClaus Schiroky`nCustomer Service & Support - EMEA Modern Work Team`nMicrosoft Deutschland GmbH`n`nHOMEPAGE:`nhttps://aka.ms/ComplianceUtility`n`nPRIVACY STATEMENT:`nhttps://privacy.microsoft.com/PrivacyStatement`n`nCOPYRIGHT:`nCopyright (c) Microsoft Corporation.`n"

    }

}

Function fncLicense {

    <# Logging #>
    fncLogging -strLogFunction "fncLicense" -strLogDescription "LICENSE" -strLogValue "Called"

    <# Output #>
    Write-Output "MIT License`n`nCopyright (c) Microsoft Corporation.`n`nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the `"Software`"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:`n`nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.`n`nTHE SOFTWARE IS PROVIDED `"AS IS`", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.`n"

}

Function fncHelp {

    <# No internet message #>
    $Private:strNoOnlineHelp = "ATTENTION: The online manual cannot be accessed.`nEither the website (github.com) is unavailable or there is no internet connection.`n`nNote:`n`n- Please use the command line help by entering the command:`nGet-Help ComplianceUtility -Detailed"
    
    <# Open manual on Windows #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# Check internet connection #>
        If ($(fncTestInternetAccess "github.com") -Eq $true) {

            <# Open manual #>
            Start-Process "https://github.com/microsoft/ComplianceUtility/blob/main/Manuals/3.2.0/Manual-Win.md"

            <# Logging #>
            fncLogging -strLogFunction "fncHelp" -strLogDescription "HELP" -strLogValue "Called"

        }
        Else { <# Offline actions #>

            <# Output #>
            Write-ColoredOutput Red $Private:strNoOnlineHelp

            <# Logging #>
            fncLogging -strLogFunction "fncHelp" -strLogDescription "Help" -strLogValue "No internet connection"

        }

    }

    <# Open mnanual on macOS #>
    If ($IsMacOS -eq $true) {

        <# Check internet connection #>
        If ($(fncTestInternetAccess "github.com") -Eq $true) {

            <# Open manual #>
            Open "https://github.com/microsoft/ComplianceUtility/blob/main/Manuals/3.2.0/Manual-Mac.md"

            <# Logging #>
            fncLogging -strLogFunction "fncHelp" -strLogDescription "HELP" -strLogValue "Called"

        }
        Else { <# Offline action #>

            <# Output #>
            Write-ColoredOutput Red $Private:strNoOnlineHelp

            <# Logging #>
            fncLogging -strLogFunction "fncHelp" -strLogDescription "Help" -strLogValue "No internet connection"

        }

    }

}

Function Write-ColoredOutput($Private:ForegroundColor) {
    
    <# Variables #>
    $Private:TextColor = $Global:host.UI.RawUI.ForegroundColor <# Backup current text color #>
    $Global:host.UI.RawUI.ForegroundColor = $Private:ForegroundColor <# Set text color #>

    <# Output #>
    If ($Private:args) {
        Write-Output $Private:args
    }
    Else {
        $Private:input | Write-Output
    }

    <# Set back color #>
    $Global:host.UI.RawUI.ForegroundColor = $Private:TextColor

}

<# Detect and delete a registry setting #>
Function fncDeleteRegistrySetting ($strRegistryKey, $strRegistrySetting) {

    <# Try to remove registry setting #>
    Try {
            
        <# Set registry setting variable #>
        $strItemExists = Get-ItemProperty $strRegistryKey $strRegistrySetting -ErrorAction SilentlyContinue
    
        <# Remove registry setting only if it exists #>
        If (-not ($Null -eq $strItemExists) -or ($strItemExists.Length -eq 0)) {
                
            <# Remove registry setting #>
            Remove-ItemProperty -Path $strRegistryKey -Name $strRegistrySetting -Force -ErrorAction Stop
                
            <# Logging #>
            fncLogging -strLogFunction "fncDeleteRegistrySetting" -strLogDescription "$strRegistrySetting ($strRegistryKey)" -strLogValue "Removed"

        }

    }
    Catch {  
        <# Silently ignore if setting does not exist #>
    }
  
}

Function fncReset ($strResetMethod) {

    <# ShowMenu/Silent actions #>
    If ($strResetMethod -notmatch "Silent") {

        <# Output #>
        Write-Output "RESET:"
        Write-ColoredOutput Red "IMPORTANT: Before you proceed with this option, please close all open applications."
        $Private:ReadHost = Read-Host "Only if the above is true, please press [Y]es to continue, or [N]o to cancel"

        <# Cancel/no actions #>
        If ($Private:ReadHost -eq "N") {

            <# Logging #>
            fncLogging -strLogFunction "fncReset" -strLogDescription "RESET Default" -strLogValue "Canceled"

            <# Command line actions #>
            If ($Global:bolCommingFromMenu -eq $false) {

                <# Set back window title #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                <# Exit #>
                Break

            }

            <# ShowMenu actions #>
            If ($Global:bolCommingFromMenu -eq $true) {

                <# Clear console #>
                Clear-Host

                <# Call ShowMenu #>
                fncShowMenu    

            }

        }

        <# Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "RESET Default" -strLogValue "Initiated"

        <# Output #>
        Write-Output "Resetting..."

    }

    <# Silent actions #>
    If ($strResetMethod -match "Silent") {

        <# Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "RESET Silent" -strLogValue "Initiated"

    }

    <# "Yes"/Silent actions (by reset default) #>
    If ($Private:ReadHost -eq "Y" -or ($strResetMethod -match "Silent")) {

        <# Detect Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

            <# Clean user keys #>
            fncDeleteItem "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\MSIPC"
            fncDeleteItem "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\AIPMigration"
            fncDeleteItem "HKCU:\SOFTWARE\Classes\Microsoft.IPViewerChildMenu"
            fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Cloud\Office"
            fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\DRM"
            fncDeleteItem "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\DRM"
            fncDeleteItem "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\DRM"
            fncDeleteItem "HKCU:\SOFTWARE\Microsoft\XPSViewer\Common\DRM"
            fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Identity"
            fncDeleteItem "HKCU:\SOFTWARE\Microsoft\MSIP"
            fncDeleteItem "HKCU:\SOFTWARE\Microsoft\MSOIdentityCRL"

            <# Clean registry settings #>
            fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Cloud\Office\16.0\Common\Security\Labels" -strRegistrySetting "UseOfficeForLabelling"
            fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security\Labels" -strRegistrySetting "UseOfficeForLabelling"
            fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security\Labels" -strRegistrySetting "UseOfficeForLabelling"
            fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Cloud\Office\16.0\Common\Security\Labels" -strRegistrySetting "AIPException"
            fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security\Labels" -strRegistrySetting "AIPException"
            fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security\Labels" -strRegistrySetting "AIPException"
            fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Cloud\Office\16.0\Common\Security" -strRegistrySetting "OpenXMLEncryptProperty"
            fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security" -strRegistrySetting "OpenXMLEncryptProperty"
            fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security" -strRegistrySetting "OpenXMLEncryptProperty"
            fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Cloud\Office\16.0\Common\Security" -strRegistrySetting "DRMEncryptProperty"
            fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security" -strRegistrySetting "DRMEncryptProperty"
            fncDeleteRegistrySetting -strRegistryKey "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security" -strRegistrySetting "DRMEncryptProperty"
 
            <# Clean client classes keys #>
            fncDeleteItem "HKCR:\AllFilesystemObjects\shell\Microsoft.Azip.Inspect"
            fncDeleteItem "HKCR:\AllFilesystemObjects\shell\Microsoft.Azip.RightClick"

            <# Clean client folders #>
            fncDeleteItem "$env:LOCALAPPDATA\Microsoft\Word\MIPSDK\mip"
            fncDeleteItem "$env:LOCALAPPDATA\Microsoft\Excel\MIPSDK\mip"
            fncDeleteItem "$env:LOCALAPPDATA\Microsoft\PowerPoint\MIPSDK\mip"
            fncDeleteItem "$env:LOCALAPPDATA\Microsoft\Outlook\MIPSDK\mip"
            fncDeleteItem "$env:LOCALAPPDATA\Microsoft\Office\DLP\mip"
            fncDeleteItem "$env:LOCALAPPDATA\Microsoft\Office\CLP"
            fncDeleteItem "$env:TEMP\Diagnostics"
            fncDeleteItem "$env:LOCALAPPDATA\Microsoft\MSIP"
            fncDeleteItem "$env:LOCALAPPDATA\Microsoft\MSIPC"
            fncDeleteItem "$env:LOCALAPPDATA\Microsoft\DRM"

            <# Administrative reset actions #>
            If ($Global:bolRunningPrivileged -eq $true) {

                # Clean machine keys #>
                fncDeleteItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSIPC"
                fncDeleteItem "HKLM:\SOFTWARE\Microsoft\MSIPC"
                fncDeleteItem "HKLM:\SOFTWARE\Microsoft\MSDRM"
                fncDeleteItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSDRM"
                fncDeleteItem "HKLM:\SOFTWARE\WOW6432Node\Microsoft\MSIP"

            }

            <# Actions on PowerShell Core for compatibility mode #>
            If ($PSVersionTable.PSEdition.ToString() -eq "Core") {

                # Remove if an existing installation was found #>
                If (Get-Module -Name AzureInformationProtection -ListAvailable -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

                    <# Remove AzureInformationProtection module #>
                    Remove-Module -Name AzureInformationProtection -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

                    <# Import module in compatiblity mode #>
                    Import-Module -Name AzureInformationProtection -UseWindowsPowerShell -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

                    <# Logging #>
                    fncLogging -strLogFunction "fncReset" -strLogDescription "AzureInformationProtection compatiblity mode" -strLogValue $true

                }

                # Remove if an existing installation was found #>
                If (Get-Module -Name PurviewInformationProtection -ListAvailable -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

                    <# Remove UnifiedLabelingSupportTool module #>
                    Remove-Module -Name PurviewInformationProtection -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

                    <# Import module in compatiblity mode #>
                    Import-Module -Name PurviewInformationProtection -UseWindowsPowerShell -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

                    <# Logging #>
                    fncLogging -strLogFunction "fncReset" -strLogDescription "PurviewInformationProtection compatiblity mode" -strLogValue $true

                }

            }

            <# Clear user settings #>
            If (Get-Module -ListAvailable -Name AzureInformationProtection, PurviewInformationProtection) { <# Check for AIP/PIP client #>
        
                <# Clear user settings #>
                Clear-AIPAuthentication -ErrorAction SilentlyContinue | Out-Null

                <# Logging #>
                fncLogging -strLogFunction "fncReset" -strLogDescription "AIPAuthentication" -strLogValue "Cleared"

            }

        }

        <# Reset for macOS #>
        If ($IsMacOS -eq $true) {

            <# Clean Office folders #>
            fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.Word/Data/Library/Application Support/Microsoft/Office/CLP" <# Word #>
            fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.Excel/Data/Library/Application Support/Microsoft/Office/CLP" <# Excel #>
            fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.PowerPoint/Data/Library/Application Support/Microsoft/Office/CLP" <# PowerPoint #>
            fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.Outlook/Data/Library/Application Support/Microsoft/Office/CLP" <# Outlook #>

            <# Clean Office log folders #>
            fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.Word/Data/Library/Logs" <# Word #>
            fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.Excel/Data/Library/Logs" <# Excel #>
            fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.PowerPoint/Data/Library/Logs" <# PowerPoint #>
            fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.Outlook/Data/Library/Logs" <# Outlook #>

            <# Clean RMS Sharing App log folders #>
            fncDeleteItem "$(printenv HOME)/Library/Containers/com.microsoft.protection.rms-sharing-mac/Data/Library/Logs" <# Outlook #>

            <# Clean Office MIP #>
            fncDeleteItem "$(printenv HOME)/Library/Group Containers/UBF8T346G9.Office/mip_policy/mip/logs" <# MIP #>

        }

        <# Default command line/menu actions #>
        If ($strResetMethod -notmatch "Silent") {

            <# Output #>
            Write-ColoredOutput Green "RESET: Proceeded.`n"

            <# Logging #>
            fncLogging -strLogFunction "fncReset" -strLogDescription "RESET Default" -strLogValue "Proceeded"

        }

        <# Silent command line actions #>
        If ($strResetMethod -match "Silent") {

            <# Logging #>
            fncLogging -strLogFunction "fncReset" -strLogDescription "RESET Silent" -strLogValue "Proceeded"

        }

    }
    Else { <# Any key actions #>

        <# Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "RESET" -strLogValue "Canceled"

        <# Command line actions #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit #>
            Break

        }

        <# Menu actions #>
        If ($Global:bolCommingFromMenu -eq $true) {
 
            <# Clear console #>
            Clear-Host
 
            <# Call ShowMenu #>
            fncShowMenu    
 
        }

    }

}

Function fncDeleteItem ($Private:objItem) {

    <# Detect key, file or folder #>
    If ($(Test-Path -Path $Private:objItem) -Eq $true) {

        <# Try to delete item/folder #>
        Try {
            
            <# Detect Windows #>
            If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

                <# Delete folder/registry key #>
                Get-ChildItem -Path $Private:objItem -Exclude "Telemetry", "powershell.exe", "powershell" -Force | Remove-Item -Recurse -Force -ErrorAction Stop | Out-Null

            }
            
            <# Detect macOS #>
            If ($IsMacOS -eq $true) {

                <# Delete folder/file #>
                Remove-item -Path $Private:objItem -Recurse -Force -ErrorAction Stop | Out-Null

            }

            <# Logging #>
            fncLogging -strLogFunction "fncDeleteItem" -strLogDescription "Item deleted" -strLogValue $Private:objItem

        }
        Catch [System.IO.IOException] { <# Actions if files or folders cannot be accessed, because they are locked/used by another process <#>

            <# Output #>
            Write-ColoredOutput Red "WARNING: Some items or folders are still used by another process.`nIMPORTANT: Please close all applications, restart the PowerShell session (or restart machine) and try again."

            <# Logging #>
            fncLogging -strLogFunction "fncDeleteItem" -strLogDescription "Item locked" -strLogValue $Private:objItem
            fncLogging -strLogFunction "fncDeleteItem" -strLogDescription "RESET" -strLogValue "ERROR: RESET failed"

            <# Release variable #>
            $Private:objItem = $null

            <# ShowMenu actions #>
            If ($Global:bolCommingFromMenu -eq $false) {

                <# Output #>
                Write-ColoredOutput Red "RESET: Failed.`n"

                <# Set back window title #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                <# Exit #>
                Break

            }
            <# ShowMenu actions #>
            If ($Global:bolCommingFromMenu -eq $true) {

                <# Output #>
                Write-ColoredOutput Red "RESET: Failed.`n"

                <# Call Pause #>
                fncPause

                <# Call ShowMenu #>
                fncShowMenu

            }

        }

    }

    <# Release variable #>
    $Private:objItem = $null

}

Function fncCopyItem ($Private:objItem, $Private:strDestination, $Private:strFileName) {

    <# Try to copy item/s #>
    Try {

        <# Detect path and copy item #>
        If ($(Test-Path -Path $Private:objItem) -Eq $true) {

            <# Copy item #>
            Copy-Item -Path $Private:objItem -Destination $Private:strDestination -Recurse -Force -ErrorAction Stop | Out-Null
            
            <# Logging #>
            fncLogging -strLogFunction "fncCopyItem" -strLogDescription "Item copied" -strLogValue $Private:strFileName

        }

    }
    Catch [System.IO.IOException] { <# Action if file cannot be accessed #>

        <# Detect path for individual Logging. Caused by PowerShell Telemetry #>
        If ($Private:objItem -like "*MSIP") {

            <# Logging #>
            fncLogging -strLogFunction "fncCopyItem" -strLogDescription "Item locked" -strLogValue "ERROR: \MSIP"

        }
        Else {

            <# Logging #>
            fncLogging -strLogFunction "fncCopyItem" -strLogDescription "Item locked" -strLogValue "ERROR: "$Private:objItem

        }

        <# Release variables #>
        $Private:objItem = $null
        $Private:strDestination = $null

    }

    <# Release variables #>
    $Private:objItem = $null
    $Private:strDestination = $null

}

Function fncTestInternetAccess ($Private:strURL) {

    <# Test internet access #>
    If ($(Test-Connection $Private:strURL -Count 1 -Quiet) -Eq $true) {

        <# Internet access #>
        Return $true
        
        <# Logging #>
        fncLogging -strLogFunction "fncTestInternetAccess" -strLogDescription "Internet access" -strLogValue $true

    }
    Else {

        <# No internet access #>
        Return $false
       
        <# Logging #>
        fncLogging -strLogFunction "fncTestInternetAccess" -strLogDescription "Internet access" -strLogValue $false

    }

    <# Release variable #>
    $Private:strURL = $null

}

Function fncRecordProblem {

    <# Output #>
    Write-Output "RECORD PROBLEM:"
    Write-ColoredOutput Red "IMPORTANT: Before you proceed with this option, please close all open applications."
    $Private:ReadHost = Read-Host "Only if the above is true, please press [Y]es to continue, or [N]o to cancel"

    <# Logging #>
    fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "RECORD PROBLEM" -strLogValue "Initiated"

    <# "Yes"-actions #>
    If ($Private:ReadHost -Eq "Y") {

        <# Detect Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

            <# Detect admin permissions #>
            If ($Global:bolRunningPrivileged -eq $false) {

                <# Logging #>
                Write-ColoredOutput Red "ATTENTION: Please note that neither CAPI2 or AIP event logs, network trace nor filter drivers are recorded.`nIf you want a complete record, you must run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges."

            }
        
            <# Output #>
            Write-Output "Initializing, please wait..."

            <# Variables for log folder #>    
            $Private:strUniqueFolderName = (Get-Date -Verbose:$false -UFormat "%y%m%d-%H%M%S")
            $Global:strUniqueLogFolder = $Global:strUserLogPath.ToString() + "\" +  $Private:strUniqueFolderName.ToString()

            <# Create log folder #>
            New-Item -ItemType Directory -Force -Path $Global:strUniqueLogFolder | Out-Null
    
            <# Logging #>
            fncLogging "fncRecordProblem" -strLogDescription "New log folder created" -strLogValue $Private:strUniqueFolderName

            <# Call Enablelogging #>
            fncEnableLogging

            <# Output by privileges check #>
            If ($Global:bolRunningPrivileged -eq $false) {

                <# Output with no admin privileges #>
                Write-Output "Recording is now underway for user `"$Env:UserName`"."

            }
            Else {

                <# Output with admin privileges #>
                Write-Output "Recording is now underway for administrator `"$Env:UserName`"."

            }

            <# Output #>
            Write-ColoredOutput Red "IMPORTANT: Now reproduce the problem, but leave this window open."
            Read-Host "After reproducing the problem, close all the applications you were using, return here and press enter to complete the recording"

            <# Output #>
            Write-Output "Collecting logs, please wait...`n"

            <# Call CollectingLogs #>
            fncCollectingLogs
        
            <# Call Disablelogging #>
            fncDisableLogging

        }

        <# Detect macOS #>
        If ($IsMacOS -eq $true) {

            <# Output #>
            Write-Output "Initializing, please wait..."

            <# Variables for log folder #>    
            $Private:strUniqueFolderName = (Get-Date -Verbose:$false -UFormat "%y%m%d-%H%M%S")
            $Global:strUniqueLogFolder = $Global:strUserLogPath.ToString() + "/" +  $Private:strUniqueFolderName.ToString()

            <# Create log folder #>
            New-Item -ItemType Directory -Force -Path $Global:strUniqueLogFolder | Out-Null
    
            <# Logging #>
            fncLogging "fncRecordProblem" -strLogDescription "New log folder created" -strLogValue $Private:strUniqueFolderName

            <# Enable Office ULS logging #>
            Try {
                
                <# Set application preference to enable Office ULS logging #>
                defaults write com.microsoft.office msoridEnableLogging -integer 1
                defaults write com.microsoft.office msoridDefaultMinimumSeverity -integer 200

                <# Logging #>
                fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "Office ULS logging" -strLogValue "Enabled"

            }
            Catch { 
        
                <# Logging #>
                fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "Office ULS logging" -strLogValue "Enable Failed"
        
            }

            <# Output #>
            Write-ColoredOutput Red "IMPORTANT: Now reproduce the problem, but leave this window open."
            Read-Host "After reproducing the problem, close all the applications you were using, return here and press enter to complete the recording."

            <# Output #>
            Write-Output "Collecting logs, please wait...`n"

            <# Call CollectLogging #>
            fncCollectingLogs

            <# Disable Office ULS logging #>
            Try {
                
                <# Set application preference to disable Office ULS logging #>
                defaults delete com.microsoft.office msoridEnableLogging
                defaults delete com.microsoft.office msoridDefaultMinimumSeverity

                <# Logging #>
                fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "Office ULS logging" -strLogValue "Disabled"

            }
            Catch { 
        
                <# Logging #>
                fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "Office ULS logging" -strLogValue "Disable Failed"
        
            }

        }

        <# Logging #>
        fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "RECORD PROBLEM" -strLogValue "Proceeded" 

        <# Output #>
        Write-Output "Log files: $Global:strUniqueLogFolder"
        Write-ColoredOutput Green "RECORD PROBLEM: Proceeded.`n"

        <# Release variable #>
        $Global:strUniqueLogFolder = $null

    }
    ElseIf ($Private:ReadHost -eq "N") { <# "No"/cancel actions #>

        <# Logging #>
        fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "RECORD PROBLEM" -strLogValue "Canceled"

        <# Command line actions #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit #>
            Break

        }

        <# ShowMenu actions #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Clear console #>
            Clear-Host

            <# Call ShowMenu #>
            fncShowMenu    

        }

    }
    Else { <# Any key actions #>

        <# Logging #>
        fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "RECORD PROBLEM" -strLogValue "Canceled"

        <# Command line actions #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit #>
            Break

        }

        <# ShowMenu actions #>
        If ($Global:bolCommingFromMenu -eq $true) {
 
            <# Clear console #>
            Clear-Host
 
            <# Call ShowMenu #>
            fncShowMenu    
 
        }

    }

    <# Release variable #>
    $Private:ReadHost = $null

}

Function fncEnableLogging {

    <# Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Enable logging" -strLogValue "Triggered"

    <# Implement registry key for function fncValidateForActivatedLogging to check whether logging was left enabled (for problem record) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\ComplianceUtility") -Eq $false) { <# Check, if path exist (to check for logging enabled), and create it if not #>

        <# Create registry key #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\ComplianceUtility" -Force | Out-Null

    }

    <# Implement registry key to check for enabled logging on next start, and rollback settings if necessary #>
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\ComplianceUtility" -Name "LoggingActivated" -Value $true -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null

    <# Progress bar #>
    Write-Progress -Activity " Enable logging, please wait..." -PercentComplete 0
    
    <# Check for administrative privileges, and enabling corresponding logs #>
    If ($Global:bolRunningPrivileged -eq $true) {

        <# Progress bar update #>
        Write-Progress -Activity " Enable logging: CAPI2 event logging..." -PercentComplete (100/8 * 1)

        <# Enable CAPI2 event log #>
        Write-Output Y | wevtutil set-log Microsoft-Windows-CAPI2/Operational /enabled:True

        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "CAPI2 event log" -strLogValue "Enabled"

        <# Clear CAPI2 event log #>
        wevtutil.exe clear-log Microsoft-Windows-CAPI2/Operational
    
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "CAPI2 event log" -strLogValue "Cleared"

        <# Progress bar update #>
        Write-Progress -Activity " Enable logging: Starting network trace..." -PercentComplete (100/8 * 2)

        <# Start network trace #>
        netsh.exe trace start capture=yes scenario=NetConnection,InternetClient sessionname="ComplianceUtility-Trace" report=disabled maxsize=1024, tracefile="$Global:strUniqueLogFolder\NetMon.etl" | Out-Null
    
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Network trace" -strLogValue "Started"

    }

    <# Progress bar update #>
    Write-Progress -Activity " Enable logging: Office logging..." -PercentComplete (100/8 * 3)

    <# Enable Office logging for 2016 (16.0) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Logging") -Eq $false) {

        <# Create registry key, if does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Logging" -Force | Out-Null

    }

    <# Check for registry key "Logging" (2016 x64) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\Logging") -Eq $false) {

        <# Create registry key, if does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\Logging" -Force | Out-Null

    }

    <# Implement/enable Office logging #>
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Logging" -Name "EnableLogging" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\Logging" -Name "EnableLogging" -Value 1 -PropertyType DWord -Force | Out-Null

    <# Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office Logging" -strLogValue "Enabled"

    <# Progress bar update #>
    Write-Progress -Activity " Enable logging: Office TCOTrace..." -PercentComplete (100/8 * 4)

    <# <# Check for registry key "Debug" (2016) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Debug") -Eq $false) { 

        <# Create registry key #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Debug" -Force | Out-Null

    }
    <# Enable Office TCOTrace logging for Office 2016 (16.0) #>
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Debug" -Name "TCOTrace" -Value 1 -PropertyType DWord -Force | Out-Null

    <# Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office TCOTrace" -strLogValue "Enabled"

    <# Progress bar update #>
    Write-Progress -Activity " Enable logging: Cleaning MSIP/MSIPC logs..." -PercentComplete (100/8 * 5)

    <# Clean MSIP/MSIPC/AIP v2 logs folder #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\MSIP\Logs) -Eq $true) { <# If foler exist #>

        <# Clean MSIP/AIP v1/2 log folder content #>
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\MSIP\Logs" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "MSIP log folder" -strLogValue "Cleared"

    }

    <# Check for MSIPC folder #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\MSIPC\Logs) -Eq $true) {

        <# Clean MSIPC log folder #>
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\MSIPC\Logs" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "MSIPC log folder" -strLogValue "Cleared"

    }

    <# Check for MSIP folder #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\MSIP\mip) -Eq $true) {

        <# Clean MIP SDK/AIP v2 log folder #>
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\MSIP\mip" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "MIP log folder" -strLogValue "Cleared"

    }

    <# Check for MIP folder #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\Office\DLP\mip) -Eq $true) {

        <# Clean Office DLP/MIP log folder #>
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Office\DLP\mip" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office DLP/MIP log folder" -strLogValue "Cleared"

    }

    <# Check for Word MIPSDK log folder #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\Word\MIPSDK\mip) -Eq $true) {

        <# Clean Word MIPSDK log folder #>
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Word\MIPSDK\mip" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Word MIPSDK log folder" -strLogValue "Cleared"

    }

    <# Check for Excel MIPSDK log folder #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\Excel\MIPSDK\mip) -Eq $true) {

        <# Clean Excel MIPSDK log folder #>
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Excel\MIPSDK\mip" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Excel MIPSDK log folder" -strLogValue "Cleared"
    
    }

    <# Check for PowerPoint MIPSDK log folder #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\PowerPoint\MIPSDK\mip) -Eq $true) {

        <# Clean PowerPoint MIPSDK log folder #>
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\PowerPoint\MIPSDK\mip" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "PowerPoint MIPSDK log folder" -strLogValue "Cleared"
    
    }

    <# Check for Outlook MIPSDK log folder #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\Outlook\MIPSDK\mip) -Eq $true) {

        <# Clean Outlook MIPSDK log folder #>
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Outlook\MIPSDK\mip" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Outlook MIPSDK log folder" -strLogValue "Cleared"
    
    }    

    <# Detect Diagnostic folder #>
    If ($(Test-Path -Path $env:TEMP\Diagnostics) -Eq $true) {

        <# Clean Office Diagnostics folder #>
        Remove-Item -Path "$env:TEMP\Diagnostics" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office Diagnostics log folder" -strLogValue "Cleared"

    }

    <# Progress bar update #>
    Write-Progress -Activity " Enable logging: Flushing DNS..." -PercentComplete (100/8 * 6)

    <# Flush DNS #>
    ipconfig.exe /flushdns | Out-Null
    
    <# Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Flush DNS" -strLogValue "Called"

    <# Progress bar update #>
    Write-Progress -Activity " Enable logging: Starting PSR..." -PercentComplete (100/8 * 7)

    <# Start PSR #>
    psr.exe /gui 0 /start /output "$Global:strUniqueLogFolder\ProblemSteps.zip"
    
    <# Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "PSR" -strLogValue "Started"

    <# Clean temp folder for office.log (TCOTrace) #>
    If ($(Test-Path $Global:strTempFolder"\office.log") -Eq $true) {
    
        <# Remove file office.log #>
        Remove-Item -Path "$Global:strTempFolder\office.log" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office TCOTrace temp file" -strLogValue "Cleared"
    
    }

    <# Clean temp folder for office log (machine name) #>
    If ($(Test-Path "$Global:strTempFolder\$([System.Environment]::MachineName)*.log") -Eq $true) {
    
        <# Remove file office.log #>
        Remove-Item -Path "$Global:strTempFolder\$([System.Environment]::MachineName)*.log" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office log temp file" -strLogValue "Cleared"
    
    }

    <# Progress bar update #>
    Write-Progress -Activity "  Logging enabled" -Completed

    <# Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Enable logging" -strLogValue "Proceeded" 

}

Function fncDisableLogging {

    <# Logging #>
    fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "Disable logging" -strLogValue "Triggered" 

    <# Progress bar #>
    Write-Progress -Activity " Disable logging, please wait..." -PercentComplete 0

    <# Check for administrative privileges, and enabling admininistrative actions #>
    If ($Global:bolRunningPrivileged -eq $true) {

        <# Progress bar update #>
        Write-Progress -Activity " Disable logging: CAPI2 event log..." -PercentComplete (100/6 * 1) 

        <# Disable CAPI2 event log #>
        wevtutil.exe set-log Microsoft-Windows-CAPI2/Operational /enabled:false
    
        <# Logging #>
        fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "CAPI2 event log" -strLogValue "Disabled"

        <# Progress bar update #>
        Write-Progress -Activity " Disable logging: Network trace..." -PercentComplete (100/6 * 2)

        <# Stopping network trace #>
        netsh.exe trace stop sessionname="ComplianceUtility-Trace" | Out-Null
    
        <# Logging #>
        fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "Network trace" -strLogValue "Disabled"

    }

    <# Progress bar update #>
    Write-Progress -Activity " Disable logging: Office logging..." -PercentComplete (100/6 * 3)

    <# Disable Office logging for  2016 (16.0) #>
    fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Logging"
    fncDeleteItem "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\Logging"

    <# Logging #>
    fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "Office Logging" -strLogValue "Disabled"

    <# Progress bar update #>
    Write-Progress -Activity " Disable logging: Office TCOTrace..." -PercentComplete (100/6 * 4)

    <# Disable Office TCOTrace logging for Office 2016 (16.0) #>
    fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Debug"

    <# Logging #>
    fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "Office TCOTrace" -strLogValue "Disabled"

    <# Progress bar update #>
    Write-Progress -Activity " Disable logging: PSR..." -PercentComplete (100/6 * 5)

    <# Stop PSR #>
    psr.exe /stop
    
    <# Logging #>
    fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "PSR" -strLogValue "Disabled"

    <# Implement registry key for fncValidateForActivatedLogging to check whether logging was left enabled (for problem record) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\ComplianceUtility") -Eq $false) { <# Detect/create path to check for logging enabled #>

        <# Create registry key #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\ComplianceUtility" -Force | Out-Null

    }

    <# Implement registry key to check for enabled logging on next start, and rollback settings if necessary #>
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\ComplianceUtility" -Name "LoggingActivated" -Value $false -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null

    <# Progress bar update #>
    Write-Progress -Activity " Logging disabled" -Completed

    <# Logging #>
    fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "Disable logging" -strLogValue "Proceeded" 

}

<# Check whether logging (for problem record) was left enabled #>
Function fncValidateForActivatedLogging {

    <# Detect Windows #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# Read registry key to check for enabled logging. Used in fncEnableLogging, and fncDisableLogging #>
        If ((Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\ComplianceUtility" -Name LoggingActivated -ErrorAction SilentlyContinue).LoggingActivated -eq $true) {

            <# Logging #>
            fncLogging -strLogFunction "fncValidateForActivatedLogging" -strLogDescription "Disable logging" -strLogValue "Initiated" 
            
            <# Call DisableLogging #>
            fncDisableLogging

        }

    }

    <# Detect macOS #>
    If ($IsMacOS -eq $true) {

        <# Disable Office ULS logging #>
        Try {
                
            <# Pro-active disabling Office ULS logging #>
            defaults delete com.microsoft.office msoridEnableLogging
            defaults delete com.microsoft.office msoridDefaultMinimumSeverity

        }
        Catch { 
        
            <# Logging #>
            fncLogging -strLogFunction "fncValidateForActivatedLogging" -strLogDescription "Office ULS logging" -strLogValue "Disable Failed"
        
        }

    }

}

Function fncCollectingLogs {

    <# Logging #>
    fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Collecting logs" -strLogValue "Triggered" 

    <# Progress bar #>
    Write-Progress -Activity " Collecting logs, please wait..." -PercentComplete 0

    <# Detect Windows #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# Collecting system information #>
        Get-ComputerInfo > "$Global:strUniqueLogFolder\SystemInformation.log"

        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export system information" -strLogValue "SystemInformation.log"

        <# Check for administrative permissons, and enabling admininistrative actions #>
        If ($Global:bolRunningPrivileged -eq $true) {

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: CAPI2 event log..." -PercentComplete (100/27 * 1)

            <# Export CAPI2 event log #>
            wevtutil.exe export-log Microsoft-Windows-CAPI2/Operational "$Global:strUniqueLogFolder\CAPI2.evtx" /overwrite:true
        
            <# Logging #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export CAPI2 event log" -strLogValue "CAPI2.evtx"

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: Azure Information Protection event log..." -PercentComplete (100/27 * 2)

            <# Actions when AIP event log exist #>
            If ([System.Diagnostics.EventLog]::Exists("Azure Information Protection") -Eq $true) {

                <# Export AIP event log #>
                wevtutil.exe export-log "Azure Information Protection" "$Global:strUniqueLogFolder\AIP.evtx" /overwrite:true
            
                <# Logging #>
                fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export AIP event log" -strLogValue "AIP.evtx"

            }

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: Purview Information Protection event log..." -PercentComplete (100/27 * 3)

            <# Actions when 'PIP' event log exist #>
            If ([System.Diagnostics.EventLog]::Exists("Microsoft Purview Information Protection") -Eq $true) {

                <# Export AIP event log #>
                wevtutil.exe export-log "Microsoft Purview Information Protection" "$Global:strUniqueLogFolder\PIP.evtx" /overwrite:true
            
                <# Logging #>
                fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export PIP event log" -strLogValue "PIP.evtx"

            }

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: Network trace..." -PercentComplete (100/27 * 4)

            <# Stop network trace #>
            netsh.exe trace stop sessionname="ComplianceUtility-Trace" | Out-Null

            <# Logging #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Network trace" -strLogValue "Stopped"
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export network trace" -strLogValue "NetMon.etl"

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: Filter drivers..." -PercentComplete (100/27 * 5)

            <# Export filter drivers #>
            fltmc.exe filters > "$Global:strUniqueLogFolder\Filters.log"

            <# Logging #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export filter drivers" -strLogValue "Filters.log"

        }

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: PSR recording..." -PercentComplete (100/27 * 6)

        <# Stop PSR #>
        psr.exe /stop

        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "PSR" -strLogValue "Stopped"
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export PSR" -strLogValue "ProblemSteps.zip"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Application event log..." -PercentComplete (100/27 * 7)

        <# Export Application event log #>
        wevtutil.exe export-log Application "$Global:strUniqueLogFolder\Application.evtx" /overwrite:true

        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Application event log" -strLogValue "Application.evtx"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: System event log..." -PercentComplete (100/27 * 8)

        <# Export System event log #>
        wevtutil.exe export-log System "$Global:strUniqueLogFolder\System.evtx" /overwrite:true
        
        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export System event log" -strLogValue "System.evtx"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Office log files..." -PercentComplete (100/27 * 9)

        <# Check for Office log path and create it, if it not exist #>
        If ($(Test-Path -Path "$Global:strUniqueLogFolder\Office") -Eq $false) {

            <# Create Office log folder #>
            New-Item -ItemType Directory -Force -Path "$Global:strUniqueLogFolder\Office" | Out-Null
 
            <# Perform action only, if the CLP folder contain files (Note: Afer a RESET this folder is empty). #>
            If (((Get-ChildItem -LiteralPath $env:LOCALAPPDATA\Microsoft\Office\CLP -File -Force | Select-Object -First 1 | Measure-Object).Count -ne 0)) {

                <# Compress label and policy xml files into zip file (overwrites) #>
                Compress-Archive -Path $env:LOCALAPPDATA\Microsoft\Office\CLP"\*" -DestinationPath "$Global:strUniqueLogFolder\Office\LabelsAndPolicies" -Force -ErrorAction SilentlyContinue

                <# Logging #>
                fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Office CLP" -strLogValue "\Office\LabelsAndPolicies.zip"

            }

            <# Detect/create Office MIP path only if no AIP client is installed; because with AIP client we collect already the mip folder with the AIPLogs.zip #>
            If (-not (Get-Module -ListAvailable -Name AzureInformationProtection, PurviewInformationProtection)) { <# Check for AIP client #>
  
                <# Check for Office MIP path #>
                If ($(Test-Path -Path "$Global:strUniqueLogFolder\Office\DLP\mip") -Eq $true) {

                    <# Actions if the MIP folder contain files  #>
                    If (((Get-ChildItem -LiteralPath $env:LOCALAPPDATA\Microsoft\Office\DLP\mip -File -Force | Select-Object -First 1 | Measure-Object).Count -ne 0)) {

                        <# Create Office MIP log folder #>
                        New-Item -ItemType Directory -Force -Path "$Global:strUniqueLogFolder\Office\mip" | Out-Null

                        <# Export Office MIP content #>
                        fncCopyItem $env:LOCALAPPDATA\Microsoft\Office\DLP\mip "$Global:strUniqueLogFolder\Office" "mip\*"

                        <# Logging #>
                        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Office MIP logs" -strLogValue "\Office\mip"

                    }
                }
   
            }
    
        }

        <# Define array for MIP SDK apps #>
        $Private:arrMIPSDKApps = "Word", "Excel", "PowerPoint", "Outlook"

        <# Loop though array and collect MIPSDK logs #>
        ForEach ($_ in $Private:arrMIPSDKApps) {

            <# Check for each App MIPSDK log path, and collect .json files #>
            If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\$_\MIPSDK\mip) -Eq $true) {

                <# Collect MIPSDK log folder only, if the folder contains files (Note: Afer a RESET this folder is empty). #>
                If (((Get-ChildItem -LiteralPath $env:LOCALAPPDATA\Microsoft\$_\MIPSDK\mip -File -Force | Select-Object -First 1 | Measure-Object).Count -ne 0)) {
    
                    <# Compress MIPSDK\mip content to .zip file (overwrites) #>
                    Compress-Archive -Path $env:LOCALAPPDATA\Microsoft\$_\MIPSDK\mip"\*" -DestinationPath "$Global:strUniqueLogFolder\Office\MIPSDK-$_.zip" -Force -ErrorAction SilentlyContinue
    
                    <# Logging #>
                    fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export $_ MIPSDK logs" -strLogValue "\Office\MIPDSK-$_.zip"
    
                }
    
            }

        }

        <# Releasing MIP SDK apps array #>
        $Private:arrMIPSDKApps = $null

        <# Copy Office Diagnostics folder from temp folder to Office logs folder #>
        fncCopyItem $env:TEMP\Diagnostics "$Global:strUniqueLogFolder\Office" "Diagnostics\*"

        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Office Diagnostics logs" -strLogValue "\Office\Diagnostics"

        <# Copy office log files from temp folder to logs folder #>
        fncCopyItem $Global:strTempFolder"\office.log" "$Global:strUniqueLogFolder\Office\office.log" "office.log"

        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Office log" -strLogValue "office.log"

        <# Copy Office logging files for 2016 (16.0) to logs folder #>
        fncCopyItem "$Global:strTempFolder\$([System.Environment]::MachineName)*.log" "$Global:strUniqueLogFolder\Office" "Office\$([System.Environment]::MachineName)*.log"

        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Office log" -strLogValue "\Office"

        <# Clean Office log files from temp folder #>
        fncDeleteItem "$Global:strTempFolder\$([System.Environment]::MachineName)*.log"
        fncDeleteItem "$Global:strTempFolder\Office.log"

        # Progress bar update #>
        Write-Progress -Activity " Collecting logs: AIP/PIP/Office Diagnostics logs folders..." -PercentComplete (100/27 * 10)

        <# Remember default progress bar status: 'Continue' #>
        $Private:strOriginalPreference = $Global:ProgressPreference 
        $Global:ProgressPreference = "SilentlyContinue" <# Hiding progress bar #>   

        <# Export AIP logs folder #>
        If (Get-Module -ListAvailable -Name AzureInformationProtection, PurviewInformationProtection) {

            <# Check for AIP #>
            If (Get-Module -ListAvailable -Name AzureInformationProtection){
            
                <# Logging AIP client version #>
                fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "AIP client version" -strLogValue $((Get-Module -ListAvailable -Name AzureInformationProtection).Version).ToString()

                <# Actions on PowerShell Core (7.x) for compatibility mode #>
                If ($PSVersionTable.PSEdition.ToString() -eq "Core") {

                    <# Remove AzureInformationProtection module, because it's not compatible with PowerShell Core (7.x) #>
                    Remove-Module -Name AzureInformationProtection -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        
                    <# Import AzureInformationProtection module in compatiblity mode #>
                    Import-Module -Name AzureInformationProtection -UseWindowsPowerShell -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        
                    <# Logging #>
                    fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "AzureInformationProtection compatiblity mode" -strLogValue $true

                }

            }

            <# Check for PIP #>
            If (Get-Module -ListAvailable -Name PurviewInformationProtection){
            
                <# Logging: PIP client version #>
                fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "PIP client version" -strLogValue $((Get-Module -ListAvailable -Name PurviewInformationProtection).Version).ToString()

                <# Actions on PowerShell Core (7.x) for compatibility mode #>
                If ($PSVersionTable.PSEdition.ToString() -eq "Core") {

                    <# Remove AzureInformationProtection module, because it's not compatible with PowerShell Core (7.x) #>
                    Remove-Module -Name PurviewInformationProtection -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        
                    <# Import AzureInformationProtection module in compatiblity mode #>
                    Import-Module -Name PurviewInformationProtection -UseWindowsPowerShell -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        
                    <# Logging #>
                    fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "PurviewInformationProtection compatiblity mode" -strLogValue $true

                }

            }

            <# Try to export log folders with authentication; fails without #>
            Try {

                <# Export AIP log folders #>
                Export-AIPLogs -FileName "$Global:strUniqueLogFolder\AIPLogs.zip" | Out-Null

                <# Logging #>
                fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export AIP Log folders" -strLogValue $true                

            }
            Catch{ <# Actions without authentication #>

                <# Clear authentication #>
                Clear-AIPAuthentication -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

                <# Output #>
                Write-Output "Please authenticate with your user credentials to retrieve your AIP/PIP log folders."

                <# Authenticate for accessing logs #>
                Set-AIPAuthentication

                <# Export AIP log folders #>
                Export-AIPLogs -FileName "$Global:strUniqueLogFolder\AIPLogs.zip" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

                <# Logging #>
                fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export AIP Log folders" -strLogValue $true

            }

        }
        Else {<# Action without any AIP/PIP client #>
            
            <# Logging: If no AIP/PIP client is installed #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "AIP/PIP client installed" -strLogValue $false

            <# Export Office MIP content to logs folder #>
            fncCopyItem $env:LOCALAPPDATA\Microsoft\Office\DLP\mip "$Global:strUniqueLogFolder\Office" "mip\*"

            <# Logging #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Office MIP content" -strLogValue "\Office"

            <# Export Office Diagnostics content to logs folder #>
            fncCopyItem $env:TEMP\Diagnostics "$Global:strUniqueLogFolder\Office" "Diagnostics\*"

            <# Logging #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Office Diagnostics content" -strLogValue "\Office"

            <# Export MSIP/MSIPC content to logs folder #>
            fncCopyItem $env:LOCALAPPDATA\Microsoft\MSIP "$Global:strUniqueLogFolder\MSIP" "MSIP\*"

            <# Logging #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export MSIP content" -strLogValue "\MSIP"

            <# Copy files to logs folder #>
            fncCopyItem $env:LOCALAPPDATA\Microsoft\MSIPC "$Global:strUniqueLogFolder\MSIPC" "MSIPC\*"

            <# Logging #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export MSIPC content" -strLogValue "\MSIPC"

        }

        <# Set back progress bar to previous setting #>
        $Global:ProgressPreference = $Private:strOriginalPreference  

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: WinHTTP..." -PercentComplete (100/27 * 11)

        <# Export WinHTTP #>
        netsh.exe winhttp show proxy > "$Global:strUniqueLogFolder\WinHTTP.log"
        
        <# Logging #>
        fncLOgging -strLogFunction "fncCollectingLogs" -strLogDescription "Export WinHTTP" -strLogValue "WinHTTP.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: WinHTTP (WoW6432)..." -PercentComplete (100/27 * 12)

        <# Export WinHTTP_WoW6432 (only 64-bit OS) #>
        If ((Get-CimInstance Win32_OperatingSystem  -Verbose:$false).OSArchitecture -eq "64-bit") {

            & $env:WINDIR\SysWOW64\netsh.exe winhttp show proxy > "$Global:strUniqueLogFolder\WinHTTP_WoW6432.log"
        
            <# Logging #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export WinHTTP_WoW6432" -strLogValue "WinHTTP_WoW6432.log"

        }

        <# Export AutoConfigURL #>
        If ((Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\" -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL) {

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: AutoConfigURL..." -PercentComplete (100/27 * 13)

            <# Logging #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export IE AutoConfigURL" -strLogValue "AutoConfigURL.log" <# Windows version and release ID #>

            <# Export AutoConfigURL #>
            Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object AutoConfigURL > "$Global:strUniqueLogFolder\AutoConfigURL.log"

        }

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Machine certificates..." -PercentComplete (100/27 * 14)

        <# Export machine certificates #>
        certutil.exe -silent -store my > "$Global:strUniqueLogFolder\CertMachine.log"
        
        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export machine certificates" -strLogValue "CertMachine.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: User certificates..." -PercentComplete (100/27 * 15)

        <# Export user certificates #>
        certutil.exe -silent -user -store my > "$Global:strUniqueLogFolder\CertUser.log"
        
        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export user certificates" -strLogValue "CertUser.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Credentials information..." -PercentComplete (100/27 * 16)

        <# Export Credential Manager data #>
        cmdkey.exe /list > "$Global:strUniqueLogFolder\CredMan.log"
        
        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Credential Manager" -strLogValue "CredMan.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: IP configuration..." -PercentComplete (100/27 * 17)

        <# Export IP configuration #>
        ipconfig.exe /all > "$Global:strUniqueLogFolder\IPConfigAll.log"
        
        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export ipconfig" -strLogValue "IPConfigAll.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: DNS..." -PercentComplete (100/27 * 18)

        <# Export DNS configuration  #>
        ipconfig.exe /displaydns > "$Global:strUniqueLogFolder\WinIPConfig.txt" | Out-Null
        
        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export DNS" -strLogValue "WinIPConfig.txt"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Environment information..." -PercentComplete (100/27 * 19)

        <# Export environment variables #>
        Get-ChildItem Env: | Out-File "$Global:strUniqueLogFolder\EnvVar.log"
        
        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export environment variables" -strLogValue "EnvVar.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Group policy report..." -PercentComplete (100/27 * 20)
        
        <# Export group policy #>
        gpresult /f /h "$Global:strUniqueLogFolder\Gpresult.htm" | Out-Null
        
        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export group policy report" -strLogValue "Gpresult.htm"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Time zone information..." -PercentComplete (100/27 * 21)

        <# Export timezone offse #>
        (Get-Timezone).BaseUTCOffset.Hours | Out-File "$Global:strUniqueLogFolder\BaseUTCOffset.log"
        
        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export timezone offset" -strLogValue "BaseUTCOffset.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Tasklist..." -PercentComplete (100/27 * 22)

        <# Export Tasklist #>
        Tasklist.exe /svc > "$Global:strUniqueLogFolder\Tasklist.log"
        
        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Tasklist" -strLogValue "Tasklist.log"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Programs and Features..." -PercentComplete (100/27 * 23)

        <# Export Programs and Features (32) #>
        If ($(Test-Path -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") -Eq $true) {

            <# Programs32 #>
            Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv -Path "$Global:strUniqueLogFolder\Programs32.csv" -NoTypeInformation -Delimiter ";" -Encoding UTF8 -ErrorAction SilentlyContinue

            <# Logging #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Programs (x86)" -strLogValue "Programs32.csv" 

        }
        
        <# Export Programs and Features (64) #>
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv -Path  "$Global:strUniqueLogFolder\Programs64.csv" -NoTypeInformation -Delimiter ";" -Encoding UTF8 -ErrorAction SilentlyContinue

        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Programs (x64)" -strLogValue "Programs64.csv"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Scheduled Tasks..." -PercentComplete (100/27 * 24)

        <# Array to collect Scheduled Tasks data #>
        [System.Collections.ArrayList]$Private:arrScheduledTasks = @()

        <# Variable for task data #>
        $Private:strAllTasks = Get-ScheduledTask

        <# Looping trouth all Scheduled Tasks #>
        ForEach ($Private:strTask in $Private:strAllTasks) {

            <# Variable to collect task details #>
            $Private:strTaskInfo = $Private:strTask | Get-ScheduledTaskInfo

            <# Collecing data when NextRunTime is not empty #>
            If ( -not ($Null -eq $Private:strTaskInfo.NextRunTime)){
                $Private:arrScheduledTasks.Add([PSCustomObject]@{
                    TaskName    = $Private:strTask.TaskName
                    TaskPath    = $Private:strTask.TaskPath
                    NextRunTime = $Private:strTaskInfo.NextRunTime
                    State       = $Private:strTask.State}) | Out-Null
            }

        }

        <# Export Scheduled Tasks #>
        $Private:arrScheduledTasks | Sort-Object -Property 'NextRunTime' | Export-Csv -Path "$Global:strUniqueLogFolder\ScheduledTasks.csv" -NoTypeInformation -Delimiter ";" -Encoding UTF8

        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Scheduled Tasks" -strLogValue "ScheduledTasks.csv"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: AIP registry keys..." -PercentComplete (100/27 * 25)
        
        <# Export AIP plugin Adobe Acrobat RMS logs #>
        If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\RMSLocalStorage\MIP\logs) -Eq $true) {

            <# Progress bar update #>
            Write-Progress -Activity " Collecting logs: Adobe logs..." -PercentComplete (100/27 * 26)

            <# Export MSIP/MSIPC content to logs folder #>
            fncCopyItem $env:LOCALAPPDATA\Microsoft\RMSLocalStorage\MIP\logs "$Global:strUniqueLogFolder\Adobe\LOCALAPPDATA" "Adobe\LOCALAPPDATA\*"

            <# Logging #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Adobe logs" -strLogValue "\Adobe"

        }

        <# Export AIP plugin Adobe Acrobat RMS logs #>
        If ($(Test-Path -Path $env:USERPROFILE\appdata\locallow\Microsoft\RMSLocalStorage\mip\logs) -Eq $true) {

            <# Export MSIP/MSIPC content to logs folder #>
            fncCopyItem $env:USERPROFILE\appdata\locallow\Microsoft\RMSLocalStorage\mip\logs "$Global:strUniqueLogFolder\Adobe\USERPROFILE" "Adobe\USERPROFILE\*"

            <# Logging #>
            fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export Adobe logs" -strLogValue "\Adobe"

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
                                "HKCU:\Software\Microsoft\Office\16.0\Common\Identity",
                                "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Internet",
                                "HKCU:\SOFTWARE\Microsoft\Office\Word\Addins",
                                "HKCU:\SOFTWARE\Microsoft\Office\Excel\Addins",
                                "HKCU:\SOFTWARE\Microsoft\Office\PowerPoint\Addins",
                                "HKCU:\SOFTWARE\Microsoft\Office\Outlook\Addins",
                                "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Resiliency",
                                "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Resiliency",
                                "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Resiliency",
                                "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Resiliency",
                                "HKCU:\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\MSIPC",
                                "HKCR:\MSIP.ExcelAddin",
                                "HKCR:\MSIP.WordAddin",
                                "HKCR:\MSIP.PowerPointAddin",
                                "HKCR:\MSIP.OutlookAddin",
                                "HKCR:\Local Settings\SOFTWARE\Microsoft\MSIPC",
                                "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\DRM",
                                "HKCU:\SOFTWARE\Policies\Microsoft\Cloud\Office\16.0\Common\Security",
                                "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security",
                                "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security",
                                "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing\CurrentSkuIdAggregationForApp",
                                "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing\LastKnownC2RProductReleaseId"

        <# Loop though array and cache to a temp file #>
        ForEach ($_ in $Private:arrRegistryKeys) {

            If ($(Test-Path -Path $_) -Eq $true) {

                $Private:strTempFile = $Private:strTempFile + 1
                & REG EXPORT $_.Replace(":", $null) "$Global:strTempFolder\$Private:strTempFile.reg" /Y | Out-Null <# Remove the ":" to export (replace) #>

            }

        }

        <# Insert first information; create log file #>
        "Windows Registry Editor Version 5.00" | Set-Content "$Global:strUniqueLogFolder\Registry.log"

        <# Read data from cached temp file, and add it to the logfile #>
        (Get-Content "$Global:strTempFolder\*.reg" | Where-Object {$_ -ne "Windows Registry Editor Version 5.00"} | Add-Content "$Global:strUniqueLogFolder\Registry.log")

        <# Clean temp folder of cached files #>
        Remove-Item "$Global:strTempFolder\*.reg" -Force -ErrorAction SilentlyContinue | Out-Null

        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export AIP registry keys" -strLogValue "Registry.log"

    }

    <# Detect macOS #>
    If ($IsMacOS -eq $true) {

        <# Collecting system information #>
        system_profiler -detaillevel basic *> "$Global:strUniqueLogFolder\SystemInformation.log"

        <# Logging #>
        fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Export system information" -strLogValue "SystemInformation.log"

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

    <# Logging #>
    fncLogging -strLogFunction "fncCollectingLogs" -strLogDescription "Collecting logs" -strLogValue "Proceeded" 

}

<# Check for updates on PowerShellGallery.com #>
Function fncUpdateRequiredModules {

    <# Detect if powershellgallery.com is trusted repository #>
    If (-not(Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {

        <# Logging #>
        fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "PSGallery trust" -strLogValue "Initiated"

        <# Define powershellgallery.com as trusted; To install AIPService module #>
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose:$false | Out-Null

        <# Logging #>
        fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "PSGallery trust" -strLogValue "Proceeded"

    }

    <# Remember default progress bar status: "Continue" #>
    $Private:strOriginalPreference = $Global:ProgressPreference 
    $Global:ProgressPreference = "SilentlyContinue" <# Hiding progress bar #>

    <# Validate connection to PowerShell Gallery by Find-Module on PowerShell Desktop (5.1). Not available on PowerShell Coore 7.x #>
    If ($PSVersionTable.PSEdition.ToString() -eq "Desktop") {        

        <# Actions if PowerShell Gallery can be reached #>
        If (Find-PackageProvider -Name NuGet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "NuGet update" -strLogValue "Initiated"

            <# Install/update nuGet provider #>
            Install-PackageProvider -Name NuGet -MinimumVersion "2.8.5.208" -ForceBootstrap -Scope CurrentUser -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose:$false | Out-Null

            <# Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "NuGet version" -strLogValue (Find-PackageProvider -Verbose:$false -Name NuGet).Version
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "NuGet update" -strLogValue "Proceeded"

        }
        Else { <# Actions if PowerShell Gallery is unavailable #>

            <# Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "NuGet update" -strLogValue "Failed"

        }
    }
    Else {

            <# Logging on PowerShell 7.1 (or higher) #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "NuGet update" -strLogValue "Not Applicable"

    }

    <# Set back progress bar #>
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

                <# Logging #>
                fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService module update" -strLogValue "Initiated"

                <# Output #>
                Write-Output "Updating AIPService module, please wait..."

                <# Update AIPService PowerShell module #>
                Update-Module -Verbose:$false -Name AIPService -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

                <# Logging #>
                fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService module update" -strLogValue "Proceeded"

            }

            <# Release variables #>
            [Version]$Private:strAIPOnlineVersion = $null
            [Version]$Private:strAIPLocalVersion = $null

        }
        Else { <# Actions if PowerShell Gallery is not available #>

            <# Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService module update" -strLogValue "Failed"

        }

    }

    <# Actions if AIPService module isn't installed #>
    If (-Not (Get-Module -ListAvailable -Name "AIPService")) {

        <# Install AIPService if PowerShell Gallery is available #>
        If (Find-Module -Name AIPService -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService module installation" -strLogValue "Initiated"

            <# Output #>
            Write-Output "Installing AIPService module, please wait..."

            <# Install AIPService PowerShell module #>
            Install-Module -Verbose:$false -Name AIPService -Repository PSGallery -Scope CurrentUser -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

            <# Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService module installation" -strLogValue "Proceeded"

            <# Output #>
            Write-Output "AIPService module installed."
            Write-ColoredOutput Red "ATTENTION: To use AIPService module, you must close this window and run a new instance of PowerShell for it to work.`nThe 'Compliance Utility' is now terminated."

            <# Call Pause #>
            fncPause
    
            <# Set back window title #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit #>
            Break

        }
        Else { <# Actions if PowerShell Gallery is not available #>

            <# Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService module installation" -strLogValue "Failed"

        }

    }

    <# Logging #>
    fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService version" -strLogValue (Get-Module -Verbose:$false -ListAvailable -Name AIPService).Version

}

Function fncCollectAIPServiceConfiguration {

    <# Output #>
    Write-Output "COLLECT AIP SERVICE CONFIGURATION:"

    <# Check if not running as administrator #>
    If ($Global:bolRunningPrivileged -eq $false) {

        <# Output #>
        Write-ColoredOutput Red "ATTENTION: You must run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges to continue with this option.`nCOLLECT AIP SERVICE CONFIGURATION: Failed.`n"

        <# Command line actions #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Release variable (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Exit #>
            Break

        }

        <# ShowMenu actions #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call Pause #>
            fncPause

            <# Clear console #>
            Clear-Host

            <# Call ShowMenu #>
            fncShowMenu    

        }

    }

    <# Output #>
    Write-Output "Initializing, please wait..."

    <# Logging #>
    fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "COLLECT AIP SERVICE CONFIGURATION" -strLogValue "Initiated"

    <# Action if SkipUpdates was called from command line #>
    If ($Global:bolSkipRequiredUpdates -eq $false) {

        <# Call function to check and update needed modules #>
        fncUpdateRequiredModules

    }

    <# Output #>
    Write-Output "Connecting to AIPService..."

    <# Actions on PowerShell Core (7.x) for compatibility mode #>
    If ($PSVersionTable.PSEdition.ToString() -eq "Core") {        

        <# Remove AIPService module, because it's not yet compatible with PowerShell Core (7.x) #>
        Remove-Module -Name AIPService -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

        <# Import AIPService module in compatiblity mode #>
        Import-Module -Name AIPService -UseWindowsPowerShell -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

        <# Logging #>
        fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "AIPService compatiblity mode" -strLogValue $true

    }

    <# Connect/logon to AIPService #>
    If (Connect-AIPService -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) { <# Action if AIPService connection was opened #>

        <# Output #> 
        Write-Output "AIPService connected."

        <# Logging #>
        fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "AIPService connected" -strLogValue $true

    }
    Else{ <# Action if AIPService connection failed #>

        <# Logging #>
        fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "AIPService connected" -strLogValue $false 
        fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "COLLECT AIP SERVICE CONFIGURATION" -strLogValue "Login failed"
    
        <# Output #>
        Write-ColoredOutput Red "COLLECT AIP SERVICE CONFIGURATION: Login failed. Please try again.`n"

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Exit #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call Pause #>
            fncPause

            <# Clear console #>
            Clear-Host

            <# Call ShowMenu #>
            fncShowMenu    

        }

    }

    <# Check if COLLECT folder exist and create it, if it not exist #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect" | Out-Null <# Define Collect path #>

    }

    <# Check for existing AIPService log file and create it, if it not exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log") -Eq $false) {

        <# Create AIPService logging file #>
        Out-File -FilePath $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Encoding UTF8 -Append -Force

    }

    <# Output #> 
    Write-Output "Collecting AIP service configuration, please wait..."

    <# Check for existing AIPService logging file, and extend it if it exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log") -Eq $true) { <# Exporting AIP service configuration and output result: #>
            
        <# Timestamp #>
        $Private:Timestamp = (Get-Date -Verbose:$false -UFormat "%y%m%d-%H%M%S") <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("Date/Timestamp                            : " + $Private:Timestamp) <# Extend log file #>
        Write-ColoredOutput Yellow "Date/Timestamp                            : $Private:Timestamp" <# Output #>
        $Private:Timestamp = $null <# Releasing variable #>
            
        <# AIPService Module version #>
        $Private:AIPServiceModule = (Get-Module -Verbose:$false -ListAvailable -Name AIPService).Version <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("Module version                            : $Private:AIPServiceModule") <# Extend log file #>
        Write-ColoredOutput Yellow "Module version                            : $Private:AIPServiceModule" <# Output #>
        $Private:AIPServiceModule = $null <# Releasing variable #>

        <# BPOSId #>
        $Private:BPOSId = (Get-AipServiceConfiguration).BPOSId <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("BPOSId                                    : $Private:BPOSId") <# Extend log file #>
        Write-ColoredOutput Yellow "BPOSId                                    : $Private:BPOSId" <# Output #>
        $Private:BPOSId = $null <# Releasing variable #>

        <# RightsManagementServiceId #>
        $Private:RightsManagementServiceId = (Get-AipServiceConfiguration).RightsManagementServiceId <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("RightsManagementServiceId                 : $Private:RightsManagementServiceId") <# Extend log file #>
        Write-ColoredOutput Yellow "RightsManagementServiceId                 : $Private:RightsManagementServiceId" <# Output #>
        $Private:RightsManagementServiceId = $null <# Releasing variable #>

        <# LicensingIntranetDistributionPointUrl #>
        $Private:LicensingIntranetDistributionPointUrl = ($Private:AIPServiceModule).LicensingIntranetDistributionPointUrl <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("LicensingIntranetDistributionPointUrl     : $Private:LicensingIntranetDistributionPointUrl") <# Extend log file #>
        Write-ColoredOutput Yellow "LicensingIntranetDistributionPointUrl     : $Private:LicensingIntranetDistributionPointUrl" <# Output #>
        $Private:LicensingIntranetDistributionPointUrl = $null <# Releasing variable #>

        <# LicensingExtranetDistributionPointUrl #>
        $Private:LicensingExtranetDistributionPointUrl = (Get-AipServiceConfiguration).LicensingExtranetDistributionPointUrl <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("LicensingExtranetDistributionPointUrl     : $Private:LicensingExtranetDistributionPointUrl") <# Extend log file #>
        Write-ColoredOutput Yellow "LicensingExtranetDistributionPointUrl     : $Private:LicensingExtranetDistributionPointUrl" <# Output #>
        $Private:LicensingExtranetDistributionPointUrl = $null <# Releasing variable #>

        <# CertificationIntranetDistributionPointUrl #>
        $Private:CertificationIntranetDistributionPointUrl = (Get-AipServiceConfiguration).CertificationIntranetDistributionPointUrl <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("CertificationIntranetDistributionPointUrl : $Private:CertificationIntranetDistributionPointUrl") <# Extend log file #>
        Write-ColoredOutput Yellow "CertificationIntranetDistributionPointUrl : $Private:CertificationIntranetDistributionPointUrl" <# Output #>
        $Private:CertificationIntranetDistributionPointUrl = $null <# Releasing variable #>

        <# CertificationExtranetDistributionPointUrl #>
        $Private:CertificationExtranetDistributionPointUrl = (Get-AipServiceConfiguration).CertificationExtranetDistributionPointUrl <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("CertificationExtranetDistributionPointUrl : $Private:CertificationExtranetDistributionPointUrl") <# Extend log file #>
        Write-ColoredOutput Yellow "CertificationExtranetDistributionPointUrl : $Private:CertificationExtranetDistributionPointUrl" <# Output #>
        $Private:CertificationExtranetDistributionPointUrl = $null <# Releasing variable #>

        <# AdminConnectionUrl #>
        $Private:AdminConnectionUrl = (Get-AipServiceConfiguration).AdminConnectionUrl <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AdminConnectionUrl                        : $Private:AdminConnectionUrl") <# Extend log file #>
        Write-ColoredOutput Yellow "AdminConnectionUrl                        : $Private:AdminConnectionUrl" <# Output #>
        $Private:AdminConnectionUrl = $null <# Releasing variable #>

        <# AdminV2ConnectionUrl #>
        $Private:AdminV2ConnectionUrl = (Get-AipServiceConfiguration).AdminV2ConnectionUrl <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AdminV2ConnectionUrl                      : $Private:AdminV2ConnectionUrl") <# Extend log file #>
        Write-ColoredOutput Yellow "AdminV2ConnectionUrl                      : $Private:AdminV2ConnectionUrl" <# Output #> 
        $Private:AdminV2ConnectionUrl = $null <# Releasing variable #>

        <# OnPremiseDomainName #>
        $Private:OnPremiseDomainName = (Get-AipServiceConfiguration).OnPremiseDomainName <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("OnPremiseDomainName                       : $Private:OnPremiseDomainName") <# Extend log file #>
        Write-ColoredOutput Yellow "OnPremiseDomainName                       : $Private:OnPremiseDomainName" <# Output #>
        $Private:OnPremiseDomainName = $null <# Releasing variable #>

        <# Keys #>
        $Private:Keys = (Get-AipServiceConfiguration).Keys <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("Keys                                      : $Private:Keys") <# Extend log file #>
        Write-ColoredOutput Yellow "Keys                                      : $Private:Keys" <# Output #>
        $Private:Keys = $null <# Releasing variable #>

        <# CurrentLicensorCertificateGuid #>
        $Private:CurrentLicensorCertificateGuid = (Get-AipServiceConfiguration).CurrentLicensorCertificateGuid <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("CurrentLicensorCertificateGuid            : $Private:CurrentLicensorCertificateGuid") <# Extend log file #>
        Write-ColoredOutput Yellow "CurrentLicensorCertificateGuid            : $Private:CurrentLicensorCertificateGuid" <# Output #>
        $Private:CurrentLicensorCertificateGuid = $null <# Releasing variable #>

        <# Templates #>
        $Private:Templates = (Get-AipServiceConfiguration).Templates <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("Template IDs                              : $Private:Templates") <# Extend log file #>
        Write-ColoredOutput Yellow "Template IDs                              : $Private:Templates" <# Output #>
        $Private:Templates = $null <# Releasing variable #>

        <# FunctionalState #>
        $Private:FunctionalState = (Get-AipServiceConfiguration).FunctionalState <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("FunctionalState                           : $Private:FunctionalState") <# Extend log file #>
        Write-ColoredOutput Yellow "FunctionalState                           : $Private:FunctionalState" <# Output #>
        $Private:FunctionalState = $null <# Releasing variable #>

        <# SuperUsersEnabled #>
        $Private:SuperUsersEnabled = (Get-AipServiceConfiguration).SuperUsersEnabled <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("SuperUsersEnabled                         : $Private:SuperUsersEnabled") <# Extend log file #>
        Write-ColoredOutput Yellow "SuperUsersEnabled                         : $Private:SuperUsersEnabled" <# Output #>
        $Private:SuperUsersEnabled = $null <# Releasing variable #>

        <# SuperUsers #>
        $Private:SuperUsers = (Get-AipServiceConfiguration).SuperUsers <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("SuperUsers                                : $Private:SuperUsers") <# Extend log file #>
        Write-ColoredOutput Yellow "SuperUsers                                : $Private:SuperUsers" <# Output #>
        $Private:SuperUsers = $null <# Releasing variable #>

        <# AdminRoleMembers #>
        $Private:AdminRoleMembers = (Get-AipServiceConfiguration).AdminRoleMembers <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AdminRoleMembers                          : $Private:AdminRoleMembers") <# Extend log file #>
        Write-ColoredOutput Yellow "AdminRoleMembers                          : $Private:AdminRoleMembers" <# Output #>
        $Private:AdminRoleMembers = $null <# Releasing variable #>

        <# KeyRolloverCount #>
        $Private:KeyRolloverCount = (Get-AipServiceConfiguration).KeyRolloverCount <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("KeyRolloverCount                          : $Private:KeyRolloverCount") <# Extend log file #>
        Write-ColoredOutput Yellow "KeyRolloverCount                          : $Private:KeyRolloverCount" <# Output #>
        $Private:KeyRolloverCount = $null <# Releasing variable #>

        <# ProvisioningDate #>
        $Private:ProvisioningDate = (Get-AipServiceConfiguration).ProvisioningDate <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("ProvisioningDate                          : $Private:ProvisioningDate") <# Extend log file #>
        Write-ColoredOutput Yellow "ProvisioningDate                          : $Private:ProvisioningDate" <# Output #>
        $Private:ProvisioningDate = $null <# Releasing variable #>

        <# IPCv3ServiceFunctionalState #>
        $Private:IPCv3ServiceFunctionalState = (Get-AipServiceConfiguration).IPCv3ServiceFunctionalState <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("IPCv3ServiceFunctionalState               : $Private:IPCv3ServiceFunctionalState") <# Extend log file #>
        Write-ColoredOutput Yellow "IPCv3ServiceFunctionalState               : $Private:IPCv3ServiceFunctionalState" <# Output #>
        $Private:IPCv3ServiceFunctionalState = $null <# Releasing variable #>

        <# DevicePlatformState #>
        $Private:DevicePlatformState = (Get-AipServiceConfiguration).DevicePlatformState <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("DevicePlatformState                       : $Private:DevicePlatformState") <# Extend log file #>
        Write-ColoredOutput Yellow "DevicePlatformState                       : $Private:DevicePlatformState" <# Output #> 
        $Private:DevicePlatformState = $null <# Releasing variable #>

        <# FciEnabledForConnectorAuthorization #>
        $Private:FciEnabledForConnectorAuthorization = (Get-AipServiceConfiguration).FciEnabledForConnectorAuthorization <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("FciEnabledForConnectorAuthorization       : $Private:FciEnabledForConnectorAuthorization") <# Extend log file #>
        Write-ColoredOutput Yellow "FciEnabledForConnectorAuthorization       : $Private:FciEnabledForConnectorAuthorization" <# Output #>
        $Private:FciEnabledForConnectorAuthorization = $null <# Releasing variable #>

        <# AipServiceDocumentTrackingFeature #>
        $Private:AipServiceDocumentTrackingFeature = Get-AipServiceDocumentTrackingFeature <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AipServiceDocumentTrackingFeature         : $Private:AipServiceDocumentTrackingFeature") <# Extend log file #>
        Write-ColoredOutput Yellow "AipServiceDocumentTrackingFeature         : $Private:AipServiceDocumentTrackingFeature" <# Output #>
        $Private:AipServiceDocumentTrackingFeature = $null <# Releasing variable #>

        <# AipServiceOnboardingControlPolicy #>
        $Private:AipServiceOnboardingControlPolicy = ("{[UseRmsUserLicense, " + $(Get-AipServiceOnboardingControlPolicy).UseRmsUserLicense +"], [SecurityGroupObjectId, " + $(Get-AipServiceOnboardingControlPolicy).SecurityGroupObjectId + "], [Scope, " + $(Get-AipServiceOnboardingControlPolicy).Scope + "]}") <# Filling private variable #>
        Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AipServiceOnboardingControlPolicy         : $Private:AipServiceOnboardingControlPolicy") <# Extend log file #>
        Write-ColoredOutput Yellow "AipServiceOnboardingControlPolicy         : $Private:AipServiceOnboardingControlPolicy" <# Output #>
        $Private:AipServiceOnboardingControlPolicy = $null <# Releasing variable #>

        <# AipServiceDoNotTrackUserGroup #>
        $Private:AipServiceDoNotTrackUserGroup = Get-AipServiceDoNotTrackUserGroup <# Filling private variable #>

        <# Actions if AipServiceDoNotTrackUserGroup variable value is not empty #>
        If ($Private:AipServiceDoNotTrackUserGroup) {

            Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AipServiceDoNotTrackUserGroup             : $Private:AipServiceDoNotTrackUserGroup") <# Extend log file #>
            Write-ColoredOutput Yellow "AipServiceDoNotTrackUserGroup             : $Private:AipServiceDoNotTrackUserGroup" <# Output #>

        }
        Else { <# Actions if variable value is empty #>
            
            Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AipServiceDoNotTrackUserGroup             :") <# Extend log file #>
            Write-ColoredOutput Yellow "AipServiceDoNotTrackUserGroup             :" <# Output #>

        }
            
        <# Release AipServiceDoNotTrackUserGroup variable #>
        $Private:AipServiceDoNotTrackUserGroup = $null 

        <# AipServiceRoleBasedAdministrator #>
        $Private:AipServiceRoleBasedAdministrator = Get-AipServiceRoleBasedAdministrator <# Filling private variable #>

        <# Actions if AipServiceRoleBasedAdministrator variable value is not empty #>
        If ($Private:AipServiceRoleBasedAdministrator) {

            Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AipServiceRoleBasedAdministrator          : $Private:AipServiceRoleBasedAdministrator") <# Extend log file #>
            Write-ColoredOutput Yellow "AipServiceRoleBasedAdministrator          : $Private:AipServiceRoleBasedAdministrator" <# Output #>

        }
        Else { <# Actions if variable value is empty #>
            
            Add-Content -Path $Global:strUserLogPath"\Collect\AIPServiceConfiguration.log" -Value ("AipServiceRoleBasedAdministrator          :") <# Extend log file #>
            Write-ColoredOutput Yellow "AipServiceRoleBasedAdministrator          :" <# Output #>

        }
            
        <# Release AipServiceRoleBasedAdministrator variable #>
        $Private:AipServiceRoleBasedAdministrator = $null 

    }

    <# Disconnect from AIPService #>
    Disconnect-AIPService | Out-Null

    <# Output #>
    Write-Output "AIPService disconnected.`n"

    <# Logging #>
    fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "AIPService disconnected" -strLogValue $true
    fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "Export AIP service configuration" -strLogValue "AIPServiceConfiguration.log"
    fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "COLLECT AIP SERVICE CONFIGURATION" -strLogValue "Proceeded"

    <# Output #> 
    Write-Output "Log file: $Global:strUserLogPath\Collect\AIPServiceConfiguration.log"
    Write-ColoredOutput Green "COLLECT AIP SERVICE CONFIGURATION: Proceeded.`n"

    <# Action if function was called from command line #>
    If ($Global:bolCommingFromMenu -eq $false) {

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Release global variable back to default (updates active) #>
        $Global:bolSkipRequiredUpdates = $false

        <# Exit #>
        Break

    }

    <# Action if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {

        <# Call Pause #>
        fncPause

        <# Clear console #>
        Clear-Host

        <# Call ShowMenu #>
        fncShowMenu    

    }

}

Function fncCollectProtectionTemplates {

    <# Output #>
    Write-Output "COLLECT PROTECTION TEMPLATES:"

    <# Check if not running as administrator #>
    If ($Global:bolRunningPrivileged -eq $false) {

        <# Output #>
        Write-ColoredOutput Red "ATTENTION: You must run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges to continue with this option.`nCOLLECT PROTECTION TEMPLATES: Failed.`n"

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Exit #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call Pause #>
            fncPause

            <# Clear console #>
            Clear-Host

            <# Call ShowMenu #>
            fncShowMenu    

        }

    }

    <# Output #>
    Write-Output "Initializing, please wait..."

    <# Logging #>
    fncLogging -strLogFunction "fncCollecProtectionTemplates" -strLogDescription "COLLECT PROTECTION TEMPLATES" -strLogValue "Initiated"

    <# Action if SkipUpdates was called from command line #>
    If ($Global:bolSkipRequiredUpdates -eq $false) {

        <# Call function to check and update needed modules #>
        fncUpdateRequiredModules

    }

    <# Output #>
    Write-Output "Connecting to AIPService..."

    <# Actions on PowerShell Core (7.x) for compatibility mode #>
    If ($PSVersionTable.PSEdition.ToString() -eq "Core") {

        <# Remove AIPService module, because it's not yet compatible with PowerShell Core (7.x) #>
        Remove-Module -Name AIPService -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

        <# Import AIPService module in compatiblity mode #>
        Import-Module -Name AIPService -UseWindowsPowerShell -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

        <# Logging #>
        fncLogging -strLogFunction "fncCollectProtectionTemplates" -strLogDescription "AIPService compatiblity mode" -strLogValue $true

    }

    <# Connect/logon to AIPService #>
    If (Connect-AIPService -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) { <# Action if AIPService connection was opened #>

        <# Output #> 
        Write-Output "AIPService connected."

        <# Logging #>
        fncLogging -strLogFunction "fncCollectProtectionTemplates" -strLogDescription "AIPService connected" -strLogValue $true

    }
    Else{ <# Action if AIPService connection failed #>

        <# Logging #>
        fncLogging -strLogFunction "fncCollectProtectionTemplates" -strLogDescription "AIPService connected" -strLogValue $false 
        fncLogging -strLogFunction "fncCollectProtectionTemplates" -strLogDescription "COLLECT PROTECTION TEMPLATES" -strLogValue "Login failed"
    
        <# Output #>
        Write-ColoredOutput Red "COLLECT PROTECTION TEMPLATES: Login failed. Please try again.`n"

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false    

            <# Exit #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call Pause #>
            fncPause

            <# Clear console #>
            Clear-Host

            <# Call ShowMenu #>
            fncShowMenu    

        }

    }

    <# Check if COLLECT folder exist and create it, if not #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect\ProtectionTemplates") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect\ProtectionTemplates" | Out-Null <# Define Collect path #>

    }

    <# Output #> 
    Write-Output "Collecting protection templates, please wait..."
    
    <# Check for existing folder #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\ProtectionTemplates") -Eq $true) {

        <# Exporting protection templates #>
        Get-AipServiceConfiguration -WarningAction SilentlyContinue | Select-Object -ExpandProperty Templates | Export-Clixml -Path $Global:strUserLogPath"\Collect\ProtectionTemplates\ProtectionTemplates.xml" | Out-Null
        Get-AIPServicetemplate -WarningAction SilentlyContinue | Format-List * | Export-Clixml -Path $Global:strUserLogPath"\Collect\ProtectionTemplates\ProtectionTemplateDetails.xml" | Out-Null

        <# Logging #>
        fncLogging -strLogFunction "fncCollectProtectionTemplates" -strLogDescription "Export protection templates" -strLogValue "ProtectionTemplates.xml"
        fncLogging -strLogFunction "fncCollectProtectionTemplates" -strLogDescription "Export protection templates" -strLogValue "ProtectionTemplateDetails.xml"       

    }
    
    <# Check if COLLECT\ProtectionTemplates folder exist and create it, if not #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect\ProtectionTemplates\ProtectionTemplatesBackup") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect\ProtectionTemplates\ProtectionTemplatesBackup" | Out-Null <# Define Service Templates path #>

    }

    <# Detect Protection Template IDs for backup #>
    ForEach ($Private:ProtectionTemplate in (Get-AIPServicetemplate).TemplateID) {

        <# Backup Service Template to XML #>
        Export-AipServiceTemplate -Path $Global:strUserLogPath"\Collect\ProtectionTemplates\ProtectionTemplatesBackup\$Private:ProtectionTemplate.xml" -TemplateId $Private:ProtectionTemplate -Force

        <# Logging #>
        fncLogging -strLogFunction "fncCollectProtectionTemplates" -strLogDescription "Protection template exported" -strLogValue "$Private:ProtectionTemplate.xml"

    } 

    <# Disconnect from AIPService #>
    Disconnect-AIPService | Out-Null

    <# Output #>
    Write-Output "AIPService disconnected.`n"

    <# Logging #>
    fncLogging -strLogFunction "fncCollectProtectionTemplates" -strLogDescription "AIPService disconnected" -strLogValue $true
    fncLogging -strLogFunction "fncCollectProtectionTemplates" -strLogDescription "COLLECT PROTECTION TEMPLATES" -strLogValue "Proceeded"

    <# Output #> 
    Write-Output "Protection templates: $Global:strUserLogPath\Collect\ProtectionTemplates\ProtectionTemplatesBackup"
    Write-Output "Logs folder: $Global:strUserLogPath\Collect\ProtectionTemplates"
    Write-ColoredOutput Green "COLLECT PROTECTION TEMPLATES: Proceeded.`n"

    <# Action if function was called from command line #>
    If ($Global:bolCommingFromMenu -eq $false) {

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Release global variable back to default (updates active) #>
        $Global:bolSkipRequiredUpdates = $false

        <# Exit #>
        Break

    }

    <# Action if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {

        <# Call Pause #>
        fncPause

        <# Clear console #>
        Clear-Host

        <# Call ShowMenu #>
        fncShowMenu    

    }

}

Function fncCollectLabelsAndPolicies {

     <# Output #>
    Write-Output "COLLECT LABELS AND POLICIES:"

    <# Check if not running as administrator #>
    If ($Global:bolRunningPrivileged -eq $false) {

        <# Output #>
        Write-ColoredOutput Red "ATTENTION: You must run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges to continue with this option.`nCOLLECT LABELS AND POLICIES: Failed.`n"

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Exit #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call Pause #>
            fncPause

            <# Clear console #>
            Clear-Host

            <# Call ShowMenu #>
            fncShowMenu    

        }

    }

    <# Output #>
    Write-Output "Initializing, please wait..."

    <# Logging #>
    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "COLLECT LABELS AND POLICIES" -strLogValue "Initiated"

    <# Action if SkipUpdates was called from command line #>
    If ($Global:bolSkipRequiredUpdates -eq $false) {

        <# Check for updates only on Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") { 

            <# Call UpdateRequiredModules #>
            fncUpdateRequiredModules

        }

        <# Actions if ExchangeOnlineManagement module is installed #>
        If (Get-Module -ListAvailable -Name "ExchangeOnlineManagement") {

            <# Update ExchangeOnlineManagement, if we can connect to PowerShell Gallery #>
            If (Find-Module -Name ExchangeOnlineManagement -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

                <# Fill variables with version information #>
                [Version]$Private:strEOPOnlineVersion = (Find-Module -Name ExchangeOnlineManagement -Repository PSGallery).Version
                [Version]$Private:strEOPLocalVersion = (Get-Module -ListAvailable -Name "AIPService").Version | Select-Object -First 1

                <# Compare local version vs. online version #>
                If ([Version]::new($Private:strEOPPOnlineVersion.Major, $Private:strEOPPOnlineVersion.Minor, $Private:strEOPPOnlineVersion.Build) -gt [Version]::new($Private:strEOPLocalVersion.Major, $Private:strEOPLocalVersion.Minor, $Private:strEOPLocalVersion.Build) -eq $true) {

                    <# Output #>
                    Write-Output "Updating Exchange Online Management module, please wait..."

                    <# Update AIPService PowerShell module #>
                    Update-Module -Verbose:$false -Name ExchangeOnlineManagement -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

                    <# Logging #>
                    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "ExchangeOnlineManagement module" -strLogValue "Updated"

                }

                <# Release private variables #>
                [Version]$Private:strEOPOnlineVersion = $null
                [Version]$Private:strEOPLocalVersion = $null

            }
            Else { <# Actions if we can't connect to PowerShell Gallery (no internet connection) #>

                <# Logging #>
                fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "ExchangeOnlineManagement module update" -strLogValue "Failed"

            }

        }

    }

    <# Actions if ExchangeOnlineManagement module isn't installed #>
    If (-Not (Get-Module -ListAvailable -Name "ExchangeOnlineManagement")) {

        <# Install ExchangeOnlineManagement if we can connect to PowerShell Gallery #>
        If (Find-Module -Name ExchangeOnlineManagement -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Output #>
            Write-Output "Installing Exchange Online Management module, please wait..."

            <# Install ExchangeOnlineManagement PowerShell module #>
            Install-Module -Verbose:$false -Name ExchangeOnlineManagement -Scope CurrentUser -Repository PSGallery -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

            <# Logging #>
            fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "ExchangeOnlineManagement module" -strLogValue "Installed"

            <# Output #>
            Write-Output "Exchange Online Management module installed."
            Write-ColoredOutput Red "ATTENTION: To use the Exchange Online Management module, you must close this window and run a new instance of PowerShell for it to work.`nThe 'Compliance Utility' is now terminated."

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Call Pause #>
            fncPause
    
            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Interrupting, because of module not loaded into PowerShell instance #>
            Break

        }
        Else { <# Actions if we can't connect to PowerShell Gallery (no internet connection) #>

            <# Output #>
            Write-ColoredOutput Red "ATTENTION: Collecting labels and policies could not be performed.`nEither PowerShell Gallery cannot be reached or there is no connection to the Internet.`n`nYou must have the Exchange Online Management module installed to proceed.`n`nPlease check the following website and install the latest version of the Exchange Online Management module:`nhttps://www.powershellgallery.com/packages/ExchangeOnlineManagement`n"

            <# Output #>
            Write-ColoredOutput Red "COLLECT LABELS AND POLICIES: Failed.`n"

            <# Logging #>
            fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "ExchangeOnlineManagement module installation" -strLogValue "Failed"

            <# Action if function was called from the menu #>
            If ($Global:bolCommingFromMenu -eq $true) {

                <# Call Pause #>
                fncPause
    
                <# Clear console #>
                Clear-Host

                <# Call ShowMenu #>
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

    <# Logging #>
    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "ExchangeOnlineManagement module version" -strLogValue (Get-Module -Verbose:$false -ListAvailable -Name ExchangeOnlineManagement).Version

    <# Output #>
    Write-Output "Connecting to Microsoft Purview compliance portal..."

    <# Remember default progress bar status: "Continue" #>
    $Private:strOriginalPreference = $Global:ProgressPreference 
    $Global:ProgressPreference = "SilentlyContinue" <# Hiding progress bar #>

    <# Try to connect/logon #>
    Try {

        <# Connect to Microsoft Purview compliance portal #>
        Connect-IPPSSession -Verbose:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

    }
    Catch { <# Catch for any error #>

        <# Logging #>
        fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Microsoft Purview compliance portal connected" -strLogValue $false 
        fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Microsoft Purview compliance portal" -strLogValue "Login failed"
    
        <# Output #>
        Write-ColoredOutput Red "COLLECT LABELS AND POLICIES: Login failed. Please try again.`n"

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call Pause #>
            fncPause
    
            <# Clear console #>
            Clear-Host

            <# Call ShowMenu #>
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

    <# Output #> 
    Write-Output "Microsoft Purview compliance portal connected."

    <# Logging #>
    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Microsoft Purview compliance portal connected" -strLogValue $true

    <# Output #> 
    Write-Output "Collecting labels and policies, please wait..."

    <# Detect/create COLLECT\LabelsAndPolicies folder #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect\LabelsAndPolicies") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect\LabelsAndPolicies" | Out-Null <# Create folder #>

    }

    <# Check for existing LabelsAndPolicies folder #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\LabelsAndPolicies") -Eq $true) {

        <# Collect labels #>
        Get-Label -WarningAction SilentlyContinue | Export-Clixml -Path $Global:strUserLogPath"\Collect\LabelsAndPolicies\Labels.xml" | Out-Null
        fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Export labels and policies" -strLogValue "Labels.xml" <# Logging #>
    
        <# Collect labels with details #>
        Get-Label -IncludeDetailedLabelActions -WarningAction SilentlyContinue | Export-Clixml -Path $Global:strUserLogPath"\Collect\LabelsAndPolicies\LabelsDetailedActions.xml" | Out-Null
        fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Export labels and policies" -strLogValue "LabelsDetailedActions.xml" <# Logging #>

        <# Collect policies #>
        Get-LabelPolicy -WarningAction SilentlyContinue | ForEach-Object {Get-LabelPolicy -Identity $_.Identity} | Export-Clixml -Path $Global:strUserLogPath"\Collect\LabelsAndPolicies\LabelPolicies.xml" | Out-Null
        fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Export labels and policies" -strLogValue "LabelPolicies.xml" <# Logging #>

        <# Collect rules #>
        Get-LabelPolicy -WarningAction SilentlyContinue | ForEach-Object {Get-LabelPolicyRule -Policy $_.Identity} | Export-Clixml -Path $Global:strUserLogPath"\Collect\LabelsAndPolicies\LabelRules.xml" | Out-Null
        fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Export labels and policies" -strLogValue "LabelRules.xml" <# Logging #>

        <# Collect auto-labeling policies #>
        Get-AutoSensitivityLabelPolicy -WarningAction SilentlyContinue | ForEach-Object {Get-AutoSensitivityLabelPolicy -Identity $_.Identity} | Export-Clixml -Path $Global:strUserLogPath"\Collect\LabelsAndPolicies\AutoLabelPolicies.xml" | Out-Null
        fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Export labels and policies" -strLogValue "AutoLabelPolicies.xml" <# Logging #>

        <# Collect auto-labeling rules #>
        Get-AutoSensitivityLabelRule -WarningAction SilentlyContinue | ForEach-Object {Get-AutoSensitivityLabelRule -Policy $_.Identity} | Export-Clixml -Path $Global:strUserLogPath"\Collect\LabelsAndPolicies\AutoLabelRules.xml" | Out-Null
        fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Export labels and policies" -strLogValue "AutoLabelRules.xml" <# Logging #>

    }

    <# Logging #>
    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Export labels and policies folder" -strLogValue "\Collect\LabelsAndPolicies"

    <# Detect Windows #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") { 

        <# Check if Office CLP folder exist (Windows only) #>
        If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\Office\CLP) -Eq $true) {

            <# Perform action only, if the CLP folder contain files (Note: Afer a RESET this folder is empty). #>
            If (((Get-ChildItem -LiteralPath $env:LOCALAPPDATA\Microsoft\Office\CLP -File -Force | Select-Object -First 1 | Measure-Object).Count -ne 0)) {

                <# Copy CLP Office policy folder content #>
                fncCopyItem $env:LOCALAPPDATA\Microsoft\Office\CLP $Global:strUserLogPath"\Collect\LabelsAndPolicies" "CLP\*"

                <# Private variable for unique logging/output with CLP #>
                $Private:CLPPolicy = $true

                <# Logging #>
                fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Export Office CLP policy folder" -strLogValue "\Collect\LabelsAndPolicies\CLP"

            }

        }
    
    }

    <# Set back progress bar #>
    $Global:ProgressPreference = $Private:strOriginalPreference

    <# logging based on existence of CLP folder #>
    If ($Private:CLPPolicy -Eq $true) {
        
        <# Output #> 
        Write-Output "`nLog folder: $Global:strUserLogPath\Collect\LabelsAndPolicies"
        Write-Output "Office CLP policy folder: $Global:strUserLogPath\Collect\LabelsAndPolicies\CLP" <# Only available on Windows #>

    }
    Else {

        <# Output on macOS #>
        If ($IsMacOS -eq $true) {

            Write-Output "`nLog folder: $Global:strUserLogPath/Collect/LabelsAndPolicies"

        }

        <# Output on Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

            Write-Output "`nLog folder: $Global:strUserLogPath\Collect\LabelsAndPolicies"

        }

    }

    <# Release private variable #>
    $Private:CLPPolicy = $null

    <# Disconnect Exchange Online #>
    Disconnect-ExchangeOnline -Confirm:$false

    <# Logging #>
    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "Microsoft Purview compliance portal disconnected" -strLogValue $true
    fncLogging -strLogFunction "fncCollectLabelsAndPolicies" -strLogDescription "COLLECT LABELS AND POLICIES" -strLogValue "Proceeded"

    <# Output #> 
    Write-Output "Microsoft Purview compliance portal disconnected."
    Write-ColoredOutput Green "COLLECT LABELS AND POLICIES: Proceeded.`n"

    <# Action if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {

        <# Call Pause #>
        fncPause
    
        <# Clear console #>
        Clear-Host

        <# Call ShowMenu #>
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
        
Function fncCollectEndpointURLs {

    <# Logging #>
    fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "COLLECT ENDPOINT URLs" -strLogValue "Initiated"

    <# Output #>
    Write-Output "COLLECT ENDPOINT URLs:"

    <# Define and fill variables with static URLs #>
    $Private:MyUnifiedLabelingDistributionPointUrl = "dataservice.protection.outlook.com"
    $Private:MyTelemetryDistributionPointUrl = "self.events.data.microsoft.com"

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

        <# Output #>
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

                <# Output #> 
                Write-ColoredOutput Magenta "-------------------------------------------------`nTenant Id:  $Private:strTenantId`n-------------------------------------------------`n"

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

                <# Logging #>
                fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "Export endpoint URLs" -strLogValue "EndpointURLs.log"
                fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "COLLECT ENDPOINT URLs" -strLogValue "Proceeded"

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

                    <# Output #> 
                    Write-ColoredOutput Magenta "------------------------------------------------`nTenant Id:  $Private:strTenantId`n------------------------------------------------`n"

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
                    
                }
            
            }
 
        }

    }
    Else { <# Actions for COLLECT Endpoints URLs, if bootstrap has failed/reading URLs from portal/running administrative #>

        <# Actions if running administrative #>
        If ($Global:bolRunningPrivileged -eq $true) {

            <# Output #>
            Write-Output "Initializing, please wait..."

            <# Action if SkipUpdates was called from command line #>
            If ($Global:bolSkipRequiredUpdates -eq $false) {

                <# Call function to check and update needed modules #>
                fncUpdateRequiredModules

            }

            <# Output #>
            Write-Output "Connecting to AIPService..."

            <# Actions on PowerShell Core (7.x) for compatibility mode #>
            If ($PSVersionTable.PSEdition.ToString() -eq "Core") {

                <# Remove AIPService module, because it's not yet compatible with PowerShell Core (7.x) #>
                Remove-Module -Name AIPService -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

                <# Import AIPService module in compatiblity mode #>
                Import-Module -Name AIPService -UseWindowsPowerShell -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

                <# Logging #>
                fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "AIPService compatiblity mode" -strLogValue $true

            }

            <# Connect/logon to AIPService #>
            If (Connect-AIPService -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) { <# Action if AIPService connection was opened #>

                <# Output #> 
                Write-Output "AIPService connected"

                <# Logging #>
                fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "AIPService connected" -strLogValue $true

            }
            Else{ <# Action if AIPService connection failed #>

                <# Logging #>
                fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "AIPService connected" -strLogValue $false 
                fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "COLLECT ENDPOINT URLs" -strLogValue "Login failed"
            
                <# Output #>
                Write-ColoredOutput Red "COLLECT ENDPOINT URLs: Login failed. Please try again.`n"

                <# Action if function was called from command line #>
                If ($Global:bolCommingFromMenu -eq $false) {

                    <# Set back window title to default #>
                    $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                    <# Release global variable back to default (updates active) #>
                    $Global:bolSkipRequiredUpdates = $false

                    <# Exit #>
                    Break

                }

                <# Action if function was called from the menu #>
                If ($Global:bolCommingFromMenu -eq $true) {

                    <# Call Pause #>
                    fncPause

                    <# Clear console #>
                    Clear-Host

                    <# Call ShowMenu #>
                    fncShowMenu    

                }

            }

            <# Output #>
            Write-Output "Verifying endpoint URLs...`n"

            <# Private variabel definition for Tenant Id string #>
            $Private:strTenantId = (Get-AipServiceConfiguration).RightsManagementServiceId

            <# Output #> 
            Write-ColoredOutput Magenta "------------------------------------------------`nTenant Id:  $Private:strTenantId`n------------------------------------------------`n"

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

            <# Disconnect from AIPService #>
            Disconnect-AIPService | Out-Null

            <# Output #>
            Write-Output "AIPService disconnected`n"
    
            <# Logging #>
            fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "AIPService disconnected" -strLogValue $true
            fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "Export endpoint URLs" -strLogValue "EndpointURLs.log"
            fncLogging -strLogFunction "fncCollectEndpointURLs" -strLogDescription "COLLECT ENDPOINT URLs" -strLogValue "Proceeded"

            <# Release private variable #>
            $Private:strTenantId = $null

        }
        Else { <# Actions if running with user privileges #>
    
            <# Logging on PowerShell Desktop (5.1) #>
            If ($PSVersionTable.PSEdition.ToString() -eq "Desktop" -and [Version]::new($PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor) -eq [Version]::new("5.1")) {
                
                <# Output #>
                Write-ColoredOutput Red "ATTENTION: You must run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges to continue with this option. Alternatively, you can start (bootstrap) any Microsoft 365 App and try again."
                
            }
            Else { <# Logging on PowerShell 7.x #>

                <# Output #>
                Write-ColoredOutput Red "ATTENTION: You must run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges to continue with this option."

            }
            
             <# Output #>
             Write-ColoredOutput Red "COLLECT ENDPOINT URLs: Failed.`n"

            <# Action if function was called from command line #>
            If ($Global:bolCommingFromMenu -eq $false) {

                <# Set back window title to default #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                <# Release global variable back to default (updates active) #>
                $Global:bolSkipRequiredUpdates = $false

                <# Exit #>
                Break

            }

            <# Action if function was called from the menu #>
            If ($Global:bolCommingFromMenu -eq $true) {

                <# Call Pause #>
                fncPause

                <# Clear console #>
                Clear-Host

                <# Call ShowMenu #>
                fncShowMenu    

            }

        }

    }

    <# Output #>
    Write-Output "Log file: $Global:strUserLogPath\Collect\EndpointURLs.log"
    Write-ColoredOutput Green "COLLECT ENDPOINT URLs: Proceeded.`n"
    
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

        <# Logging #>
        fncLogging -strLogFunction "fncVerifyIssuer" -strLogDescription "Export certificate" -strLogValue "$strEndpointName.ce_"

        <# Feed variable/certificate data with issuer #>
        $Private:MyWebCert = $Private:MyWebCert.Issuer

        <# Output #> 
        Write-ColoredOutput Yellow "Endpoint: $strEndpointName"
        Write-ColoredOutput Yellow "URL:      https://$strCertURL"
        Write-ColoredOutput Yellow "Issuer:   $Private:MyWebCert`n"

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

Function fncCollectDLPRulesAndPolicies {

    <# Output #>
    Write-Output "COLLECT DLP RULES AND POLICIES:"

    <# Check for admin permissions #>
    If ($Global:bolRunningPrivileged -eq $false) {

        <# Output #>
        Write-ColoredOutput Red "ATTENTION: You must run the 'Compliance Utility' in an administrative PowerShell window as a user with local administrative privileges to continue with this option.`nCOLLECT DLP RULES AND POLICIES: Failed.`n"

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Exit #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call Pause #>
            fncPause

            <# Clear console #>
            Clear-Host

            <# Call ShowMenu #>
            fncShowMenu    

        }

    }

    <# Output #>
    Write-Output "Initializing, please wait..."

    <# Logging #>
    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "COLLECT DLP RULES AND POLICIES" -strLogValue "Initiated"

    <# Action if SkipUpdates was called from command line #>
    If ($Global:bolSkipRequiredUpdates -eq $false) {

        <# Detect Windows #>
        If ([System.Environment]::OSVersion.Platform -eq "Win32NT") { 

            <# Call UpdateRequiredModules only on Windows #>
            fncUpdateRequiredModules

        }
        
        <# Actions if ExchangeOnlineManagement module is installed #>
        If (Get-Module -ListAvailable -Name "ExchangeOnlineManagement") {

            <# Update ExchangeOnlineManagement, if we can connect to PowerShell Gallery #>
            If (Find-Module -Name ExchangeOnlineManagement -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

                <# Fill variables with version information #>
                [Version]$Private:strEOPOnlineVersion = (Find-Module -Name ExchangeOnlineManagement -Repository PSGallery).Version
                [Version]$Private:strEOPLocalVersion = (Get-Module -ListAvailable -Name "AIPService").Version | Select-Object -First 1

                <# Compare local version vs. online version #>
                If ([Version]::new($Private:strEOPPOnlineVersion.Major, $Private:strEOPPOnlineVersion.Minor, $Private:strEOPPOnlineVersion.Build) -gt [Version]::new($Private:strEOPLocalVersion.Major, $Private:strEOPLocalVersion.Minor, $Private:strEOPLocalVersion.Build) -eq $true) {

                    <# Output #>
                    Write-Output "Updating Exchange Online Management module, please wait..."

                    <# Update AIPService PowerShell module #>
                    Update-Module -Verbose:$false -Name ExchangeOnlineManagement -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

                    <# Logging #>
                    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "ExchangeOnlineManagement module" -strLogValue "Updated"

                }

                <# Release private variables #>
                [Version]$Private:strEOPOnlineVersion = $null
                [Version]$Private:strEOPLocalVersion = $null

            }
            Else { <# Actions if we can't connect to PowerShell Gallery (no internet connection) #>

                <# Logging #>
                fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "ExchangeOnlineManagement module update" -strLogValue "Failed"

            }

        }

    }

    <# Actions if ExchangeOnlineManagement module isn't installed #>
    If (-Not (Get-Module -ListAvailable -Name "ExchangeOnlineManagement")) {

        <# Install ExchangeOnlineManagement if we can connect to PowerShell Gallery #>
        If (Find-Module -Name ExchangeOnlineManagement -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Output #>
            Write-Output "Installing Exchange Online Management module, please wait..."

            <# Install ExchangeOnlineManagement PowerShell module #>
            Install-Module -Verbose:$false -Name ExchangeOnlineManagement -Scope CurrentUser -Repository PSGallery -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

            <# Logging #>
            fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "ExchangeOnlineManagement module" -strLogValue "Installed"

            <# Output #>
            Write-Output "Exchange Online Management module installed."
            Write-ColoredOutput Red "ATTENTION: To use the Exchange Online Management module, you must close this window and run a new instance of PowerShell for it to work.`nThe 'Compliance Utility' is now terminated."

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Call Pause #>
            fncPause
    
            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Interrupting, because of module not loaded into PowerShell instance #>
            Break

        }
        Else { <# Actions if we can't connect to PowerShell Gallery (no internet connection) #>

            <# Output #>
            Write-ColoredOutput Red "ATTENTION: Collecting DLP rules and policies could not be performed.`nEither PowerShell Gallery cannot be reached or there is no connection to the Internet.`n`nYou must have the Exchange Online Management module installed to proceed.`n`nPlease check the following website and install the latest version of the Exchange Online Management module:`nhttps://www.powershellgallery.com/packages/ExchangeOnlineManagement`n"

            <# Output #>
            Write-ColoredOutput Red "COLLECT DLP RULES AND POLICIES: Failed.`n"

            <# Logging #>
            fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "ExchangeOnlineManagement module installation" -strLogValue "Failed"

            <# Action if function was called from command line #>
            If ($Global:bolCommingFromMenu -eq $false) {
   
                <# Release global variable back to default (updates active) #>
                $Global:bolSkipRequiredUpdates = $false

                <# Set back window title to default #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                <# Interrupt, because of missing internet connection #>
                Break

            }

            <# Action if function was called from the menu #>
            If ($Global:bolCommingFromMenu -eq $true) {

                <# Call Pause #>
                fncPause
    
                <# Clear console #>
                Clear-Host

                <# Call ShowMenu #>
                fncShowMenu

            }

        }

    }

    <# Logging #>
    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "ExchangeOnlineManagement module version" -strLogValue (Get-Module -Verbose:$false -ListAvailable -Name ExchangeOnlineManagement).Version

    <# Output #>
    Write-Output "Connecting to Microsoft Purview compliance portal..."

    <# Remember default progress bar status: "Continue" #>
    $Private:strOriginalPreference = $Global:ProgressPreference 
    $Global:ProgressPreference = "SilentlyContinue" <# Hiding progress bar #>

    <# Try to connect/logon #>
    Try {

        <# Connect to Microsoft Purview compliance portal #>
        Connect-IPPSSession -Verbose:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

    }
    Catch { <# Catch for any error #>

        <# Logging #>
        fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "Microsoft Purview compliance portal connected" -strLogValue $false 
        fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "Microsoft Purview compliance portal" -strLogValue "Login failed"
    
        <# Output #>
        Write-ColoredOutput Red "COLLECT DLP RULES AND POLICIES: Login failed. Please try again.`n"

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false           

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Interrupt, because of missing internet connection #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call Pause #>
            fncPause
    
            <# Clear console #>
            Clear-Host

            <# Call ShowMenu #>
            fncShowMenu

        }

    }

    <# Output #> 
    Write-Output "Microsoft Purview compliance portal connected."

    <# Logging #>
    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "Microsoft Purview compliance portal connected" -strLogValue $true

    <# Output #> 
    Write-Output "Collecting DLP rules and policies, please wait..."

    <# Check if COLLECT\DLPRulesAndPolicies folder exist #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect\DLPRulesAndPolicies") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect\DLPRulesAndPolicies" | Out-Null <# Create folder #>

    }

    <# Collecting DLP policies #>
    Get-DlpCompliancePolicy -WarningAction SilentlyContinue | Export-Clixml -Path $Global:strUserLogPath"\Collect\DLPRulesAndPolicies\DlpPolicy.xml" | Out-Null
    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "Export DLP rules and policy" -strLogValue "DlpPolicy.xml" <# Logging #>
    
    <# Collecting DLP rules #>
    Get-DlpComplianceRule -WarningAction SilentlyContinue | Select-Object -Property * -ExcludeProperty SerializationData | Format-List | Export-Clixml -Path $Global:strUserLogPath"\Collect\DLPRulesAndPolicies\DlpRule.xml" | Out-Null
    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "Export DLP rules and policy" -strLogValue "DlpRule.xml" <# Logging #>

    <# Collecting DLP distribution status #>
    Get-DlpCompliancePolicy | ForEach-Object {Get-DLPcompliancePolicy -Identity $_.Identity -DistributionDetail} | Format-List Name,GUID,Distr* | Export-Clixml -Path $Global:strUserLogPath"\Collect\DLPRulesAndPolicies\DlpPolicyDistributionStatus.xml" | Out-Null
    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "Export DLP rules and policy" -strLogValue "DlpPolicyDistributionStatus.xml" <# Logging #>
 
    <# Collecting DLP sensitive information types #>
    Get-DlpSensitiveInformationType | Select-Object -Property * | Export-Clixml -Path $Global:strUserLogPath"\Collect\DLPRulesAndPolicies\DlpSensitiveInformationType.xml" | Out-Null
    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "Export DLP rules and policy" -strLogValue "DlpSensitiveInformationType.xml" <# Logging #>

    <# Collecting DLP sensitive information type rules #>
    Get-DlpSensitiveInformationTypeRulePackage | Select-Object -Property * | Export-Clixml -Path $Global:strUserLogPath"\Collect\DLPRulesAndPolicies\DlpSensitiveInformationTypeRulePackage.xml" | Out-Null
    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "Export DLP rules and policy" -strLogValue "DlpSensitiveInformationTypeRulePackage.xml" <# Logging #>

    <# Collecting DLP keyword dictionary #>
    Get-DlpKeywordDictionary | Select-Object -Property * | Format-List | Export-Clixml -Path $Global:strUserLogPath"\Collect\DLPRulesAndPolicies\DlpKeywordDictionary.xml" | Out-Null
    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "Export DLP rules and policy" -strLogValue "DlpKeywordDictionary.xml" <# Logging #>

    <# Collecting DLP Exact Data Match (EDM) schemas #>
    Get-DlpEdmSchema | Select-Object -Property * | Format-List | Export-Clixml -Path $Global:strUserLogPath"\Collect\DLPRulesAndPolicies\DlpEdmSchema.xml" | Out-Null
    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "Export DLP rules and policy" -strLogValue "DlpEdmSchema.xml" <# Logging #>

    <# Disconnect Exchange Online #>
    Disconnect-ExchangeOnline -Confirm:$false

    <# Set back progress bar to previous default #>
    $Global:ProgressPreference = $Private:strOriginalPreference

    <# Output #>
    Write-Output "Microsoft Purview compliance portal disconnected."

    <# Logging #>
    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "Microsoft Purview compliance portal disconnected" -strLogValue $true
    fncLogging -strLogFunction "fncCollectDLPRulesAndPolicies" -strLogDescription "COLLECT DLP RULES AND POLICIES" -strLogValue "Proceeded"

    <# Output on macOS #>
    If ($IsMacOS -eq $true) {

        Write-Output "`nLog folder: $Global:strUserLogPath/Collect/DLPRulesAndPolicies"

    }

    <# Output on Windows #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        Write-Output "`nLog folder: $Global:strUserLogPath\Collect\DLPRulesAndPolicies"

    }

    <# Output #>
    Write-ColoredOutput Green "COLLECT DLP RULES AND POLICIES: Proceeded.`n"

    <# Action if function was called from command line #>
    If ($Global:bolCommingFromMenu -eq $false) {

        <# Release global variable back to default (updates active) #>
        $Global:bolSkipRequiredUpdates = $false        

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Interrupt, because of missing internet connection #>
        Break

    }

    <# Action if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {

        <# Call Pause #>
        fncPause
    
        <# Clear console #>
        Clear-Host

        <# Call ShowMenu #>
        fncShowMenu

    }    

}

Function fncCollectUserLiceneseDetails {

    <# Output #>
    Write-Output "COLLECT USER LICENSE DETAILS:"

    <# Output #>
    Write-Output "Initializing, please wait..."

    <# Logging #>
    fncLogging -strLogFunction "fncCollectUserLiceneseDetails" -strLogDescription "COLLECT USER LICENSE DETAILS" -strLogValue "Initiated"

    <# Action if SkipUpdates was called from command line #>
    If ($Global:bolSkipRequiredUpdates -eq $false) {

        <# Actions if Microsoft Graph module is installed #>
        If (Get-Module -ListAvailable -Name "Microsoft.Graph") {

            <# Update Microsoft Graph, if we can connect to PowerShell Gallery #>
            If (Find-Module -Name Microsoft.Graph -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

                <# Fill variables with version information #>
                [Version]$Private:strGraphOnlineVersion = (Find-Module -Name Microsoft.Graph -Repository PSGallery).Version
                [Version]$Private:strGraphLocalVersion = (Get-Module -ListAvailable -Name "Microsoft.Graph").Version | Select-Object -First 1

                <# Compare local version vs. online version #>
                If ([Version]::new($Private:strGraphOnlineVersion.Major, $Private:strGraphOnlineVersion.Minor, $Private:strGraphOnlineVersion.Build) -gt [Version]::new($Private:strGraphLocalVersion.Major, $Private:strGraphLocalVersion.Minor, $Private:strGraphLocalVersion.Build) -eq $true) {

                    <# Output #>
                    Write-Output "Updating Microsoft Graph PowerShell module, please wait..."

                    <# Update Microsoft Graph PowerShell module #>
                    Update-Module -Verbose:$false -Name Microsoft.Graph -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

                    <# Logging #>
                    fncLogging -strLogFunction "fncCollectUserLiceneseDetails" -strLogDescription "Microsoft Graph PowerShell module" -strLogValue "Updated"

                }

                <# Release private variables #>
                [Version]$Private:strGraphOnlineVersion = $null
                [Version]$Private:strGraphLocalVersion = $null

            }
            Else { <# Actions if we can't connect to PowerShell Gallery (no internet connection) #>

                <# Logging #>
                fncLogging -strLogFunction "fncCollectUserLiceneseDetails" -strLogDescription "Microsoft Graph PowerShell modules update" -strLogValue "Failed"

            }

        }

    }

    <# Actions if Microsof Graph module isn't installed #>
    If (-Not (Get-Module -ListAvailable -Name "Microsoft.Graph")) {

        <# Install Microsoft Graph if we can connect to PowerShell Gallery #>
        If (Find-Module -Name Microsoft.Graph -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Output #>
            Write-Output "Installing Microsoft Graph PowerShell module, please wait..."

            <# Install Microsoft Graph PowerShell module #>
            Install-Module -Verbose:$false -Name Microsoft.Graph -Scope CurrentUser -Repository PSGallery -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

            <# Logging #>
            fncLogging -strLogFunction "fncCollectUserLiceneseDetails" -strLogDescription "Microsoft Graph PowerShell module" -strLogValue "Installed"

            <# Output #>
            Write-Output "Microsoft Graph PowerShell modules installed."
            Write-ColoredOutput Red "ATTENTION: To use the Graph PowerShell module, you must close this window and run a new instance of PowerShell for it to work.`nThe 'Compliance Utility' is now terminated."

            <# Release global variable back to default (updates active) #>
            $Global:bolSkipRequiredUpdates = $false

            <# Call Pause #>
            fncPause
    
            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Interrupting, because of module not loaded into PowerShell instance #>
            Break

        }
        Else { <# Actions if we can't connect to PowerShell Gallery (no internet connection) #>

            <# Output #>
            Write-ColoredOutput Red "ATTENTION: Collecting user license details could not be performed.`nEither PowerShell Gallery cannot be reached or there is no connection to the Internet.`n`nYou must have Microsoft Graph PowerShell modules installed to proceed.`n`nPlease check the following website and install the latest version of the Microsoft Graph modul:`nhttps://www.powershellgallery.com/packages/Microsoft.Graph`n"

            <# Output #>
            Write-ColoredOutput Red "COLLECT USER LICENSE DETAILS: Failed.`n"

            <# Logging #>
            fncLogging -strLogFunction "fncCollectUserLiceneseDetails" -strLogDescription "Microsoft Graph PowerShell module installation" -strLogValue "Failed"

            <# Action if function was called from the menu #>
            If ($Global:bolCommingFromMenu -eq $true) {

                <# Call Pause #>
                fncPause
    
                <# Clear console #>
                Clear-Host

                <# Call ShowMenu #>
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

    <# Logging #>
    fncLogging -strLogFunction "fncCollectUserLiceneseDetails" -strLogDescription "Microsoft Graph PowerShell module version" -strLogValue (Get-Module -Verbose:$false -ListAvailable -Name Microsoft.Graph).Version

    <# Output #>
    Write-Output "Connecting to Microsoft Graph..."
    
    <# Remember default progress bar status: "Continue" #>
    $Private:strOriginalPreference = $Global:ProgressPreference 
    $Global:ProgressPreference = "SilentlyContinue" <# Hiding progress bar #>

    <# Try to connect/logon to compliance center #>
    Try {

        <# Connect/logon to Microsoft Graph #>
        Connect-Graph -Verbose:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

    }
    Catch { <# Catch action for any error that occur on connect/logon #>

        <# Logging #>
        fncLogging -strLogFunction "fncCollectUserLiceneseDetails" -strLogDescription "Microsoft Graph connected" -strLogValue $false 
        fncLogging -strLogFunction "fncCollectUserLiceneseDetails" -strLogDescription "Microsoft Graph" -strLogValue "Login failed"
    
        <# Output #>
        Write-ColoredOutput Red "COLLECT USER LICENSE DETAILS: Login failed. Please try again.`n"

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Call Pause #>
            fncPause
    
            <# Clear console #>
            Clear-Host

            <# Call ShowMenu #>
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

    <# Output #> 
    Write-Output "Microsoft Graph connected."

    <# Logging #>
    fncLogging -strLogFunction "fncCollectUserLiceneseDetails" -strLogDescription "Microsoft Graph connected" -strLogValue $true

    <# Output #> 
    Write-Output "Collecting user license details, please wait..."

    <# Check if COLLECT folder exist and create it, if not #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect" | Out-Null <# Define Collect path #>

    }

    <# Check for existing UserLicenseDetails.log file and create it, if it not exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\UserLicenseDetails.log") -Eq $false) {

        <# Create DLPRulesAndPolicies.log logging file #>
        Out-File -FilePath $Global:strUserLogPath"\Collect\UserLicenseDetails.log" -Encoding UTF8 -Append -Force

    }

    <# Check for existing UserLicenseDetails.log file and extend it #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\UserLicenseDetails.log") -Eq $true) {

        <# Defining private variable; getting UPN from connected session #>
        $Private:strGraphAccountUPN = Get-MgContext | Select-Object -ExpandProperty Account

        <# Log UPN into log file as seperator #>
        Add-Content -Path $Global:strUserLogPath"\Collect\UserLicenseDetails.log" -Value "ACCOUNT: $Private:strGraphAccountUPN`n"
        
        <# Collecting user license details #>
        Get-MgUserLicenseDetail -UserId $Private:strGraphAccountUPN -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Format-Table -AutoSize | Out-File $Global:strUserLogPath"\Collect\UserLicenseDetails.log" -Encoding UTF8 -Append -Force

        <# Collecting user service plan details #>
        (Get-MgUserLicenseDetail -UserId $Private:strGraphAccountUPN -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).ServicePlans | Out-File $Global:strUserLogPath"\Collect\UserLicenseDetails.log" -Encoding UTF8 -Append -Force

        <# Collecting subscribed Skus - if required authorization/rule exist #>
        Get-MgSubscribedSku -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Format-List | Out-File $Global:strUserLogPath"\Collect\UserLicenseDetails.log" -Encoding UTF8 -Append -Force

        <# Releasing private variable #>
        $Private:strGraphAccountUPN = $null

    }

    <# Disconnect Microsoft Graph #>
    Disconnect-Graph -Verbose:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

    <# Set back progress bar to previous default #>
    $Global:ProgressPreference = $Private:strOriginalPreference

    <# Output #>
    Write-Output "Microsoft Graph disconnected."

    <# Logging #>
    fncLogging -strLogFunction "fncCollectUserLiceneseDetails" -strLogDescription "Microsoft Graph disconnected" -strLogValue $true
    fncLogging -strLogFunction "fncCollectUserLiceneseDetails" -strLogDescription "Export user license details" -strLogValue "UserLicenseDetails.log"
    fncLogging -strLogFunction "fncCollectUserLiceneseDetails" -strLogDescription "COLLECT USER LICENSE DETAILS" -strLogValue "Proceeded"

    <# Output on macOS #>
    If ($IsMacOS -eq $true) {

        Write-Output "`nLog file: $Global:strUserLogPath/Collect/UserLicenseDetails.log"

    }

    <# Output on Windows #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        Write-Output "`nLog file: $Global:strUserLogPath\Collect\UserLicenseDetails.log"

    }
    
    <# Output #>
    Write-ColoredOutput Green "COLLECT USER LICENSE DETAILS: Proceeded.`n"

    <# Action if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {

        <# Call Pause #>
        fncPause
    
        <# Clear console #>
        Clear-Host

        <# Call ShowMenu #>
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

Function fncRemovePreviousVersions {

    <# Detect and try to remove previous versions #>
    Try {

        <# Remove UnifiedLabelingSupportTool only if an existing folder was found #>
        If (Get-Module -Name UnifiedLabelingSupportTool -ListAvailable -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Detect Windows for manual removal #>
            If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

                <# Actions on PowerShell Desktop (5.1) #>
                If ($PSVersionTable.PSEdition.ToString() -eq "Desktop") {
                        
                    <# Variable for Desktop #>
                    $Private:strToolDesktopPath | Out-Null
                    $Private:strToolDesktopPath = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules\UnifiedLabelingSupportTool"

                    <# Detect path #>
                    If ($(Test-Path -Path $Private:strToolDesktopPath) -Eq $true) {
                    
                        <# Output #>
                        Write-Host "Removing previous version, please wait..."

                        <# Remove folder/content #>
                        Remove-Item -LiteralPath $Private:strToolDesktopPath -Force -Recurse -ErrorAction Stop | Out-Null
                    
                    }

                }

                <# Actions on PowerShell Core (7.x) #>
                If ($PSVersionTable.PSEdition.ToString() -eq "Core") {
            
                    <# Variable for Core #>
                    $Private:strToolCorePath | Out-Null
                    $Private:strToolCorePath = [Environment]::GetFolderPath("MyDocuments") + "\PowerShell\Modules\UnifiedLabelingSupportTool"

                    <# Detect path #>
                    If ($(Test-Path -Path $Private:strToolCorePath) -Eq $true) {

                        <# Output #>
                        Write-Host "Removing previous version, please wait..."

                        <# Remove folder/content #>
                        Remove-Item -LiteralPath $Private:strToolCorePath -Force -Recurse -ErrorAction Stop | Out-Null
                    
                    }

                }

            }

            <# Logging #>
            fncLogging -strLogFunction "fncRemovePreviousVersions" -strLogDescription "UnifiedLabelingSupportTool" -strLogValue "Removed"

        }            

    }
    Catch {

        <# Logging #>
        fncLogging -strLogFunction "fncRemovePreviousVersions" -strLogDescription "UnifiedLabelingSupportTool" -strLogValue "Removal failed"

    }

}

Function fncCompressLogs {

    <# Output #> 
    Write-Output "COMPRESS LOGS:`nCompressing logs, please wait...`n"

    <# Define default zip folder path #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# Define default zip folder path for Windows #>
        $Global:strZipSourcePath = $Global:strTempFolder + "\ComplianceUtility"

    }

    <# Define default zip folder path for macOS #>
    If ($IsMacOS -eq $true) {

        <# Define default zip folder path for macOS #>
        $Global:strZipSourcePath = $Global:strUserLogPath

    }

    <# Logging #>
    fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "COMPRESS LOGS" -strLogValue "Initiated"
    fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Zip source path" -strLogValue $Global:strZipSourcePath

    <# Compress all files into a .zip file #>
    If ($(Test-Path -Path $Global:strZipSourcePath) -Eq $true) { <# Actions, if path exist #>

        <# Define .zip file name #>
        $Private:strZipFile = "ComplianceUtility (" + $([System.Environment]::USERNAME) + (Get-Date -UFormat "-%H%M%S") + ").zip".ToString()

        <# Define user desktop path #>
        $Private:DesktopPath = [Environment]::GetFolderPath("Desktop")

        <# Logging #>
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Zip destination path" -strLogValue $Private:DesktopPath
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Zip file name" -strLogValue $Private:strZipFile
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "COMPRESS LOGS" -strLogValue "Proceeded"

        <# Compress all files and logs into zip file (overwrites) #>
        Compress-Archive -Path $Global:strZipSourcePath"\*" -DestinationPath "$Private:DesktopPath\$Private:strZipFile" -Force -ErrorAction SilentlyContinue

    }

    <# Output on macOS #>
    If ($IsMacOS -eq $true) {

        Write-Output "Zip file: $Private:DesktopPath/$Private:strZipFile"

    }

    <# Output on Windows #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        Write-Output "Zip file: $Private:DesktopPath\$Private:strZipFile"

    }

    <# Output #> 
    Write-ColoredOutput Green "COMPRESS LOGS: Proceeded.`n"

    <# Clean Logs folders if .zip archive is on the desktop #>
    If ($(Test-Path -Path $Private:DesktopPath\$Private:strZipFile) -Eq $true) { <# Actions, if file exist on desktop #>

        <# Clean Logs folders #>
        Remove-Item "$Global:strZipSourcePath" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

        <# Logging #>
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Log folders cleaned" -strLogValue $true

    }
    Else{

        <# Logging #>
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

        <# Output #> 
        Write-ColoredOutput Yellow $Private:strPauseMessage
        $Private:strValue = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    }

    <# Logging #>
    fncLogging -strLogFunction "fncPause" -strLogDescription "PAUSE" -strLogValue "Selected"

}

Function fncShowMenu {

    <# Clear console #>
    Clear-Host

    <# Define variables #>
    $Global:bolCommingFromMenu | Out-Null
    $Global:bolSkipRequiredUpdates | Out-Null

    <# Helper variable to control menu handling inside function calls #>
    $Global:bolCommingFromMenu = $true

    <# Logging #>
    fncLogging -strLogFunction "fncShowMenu" -strLogDescription "MENU" -strLogValue "Selected"

    <# Menu output #>
    Write-Output "ComplianceUtility:`n"
    Write-ColoredOutput Green "  [I] INFORMATION"
    Write-ColoredOutput Green "  [M] MIT LICENSE"
    Write-ColoredOutput Green "  [H] HELP"
    Write-ColoredOutput Yellow "  [R] RESET"
    Write-ColoredOutput Yellow "  [P] RECORD PROBLEM"
    Write-ColoredOutput Yellow "  [C] COLLECT"
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") { <# Detect Windows and show Windows supported features #>
        If (@($Global:bolMenuCollectExtended) -Match $true) {
            Write-ColoredOutput Yellow "   ├──[A] AIP service configuration"
            Write-ColoredOutput Yellow "   ├──[T] Protection templates"
            Write-ColoredOutput Yellow "   ├──[E] Endpoint URLs"
            Write-ColoredOutput Yellow "   ├──[L] Labels and policies"
            Write-ColoredOutput Yellow "   ├──[D] DLP rules and policies"
            Write-ColoredOutput Yellow "   └──[U] User license details"
        }
    }
    If ($IsMacOS -eq $true) { <# Detect macOS and show macOS supported features #>
        If (@($Global:bolMenuCollectExtended) -Match $true) {
            Write-ColoredOutput Yellow "   ├──[L] Labels and policies"
            Write-ColoredOutput Yellow "   ├──[D] DLP rules and policies"
            Write-ColoredOutput Yellow "   └──[U] User license details"
        }
    }
    Write-ColoredOutput Yellow "  [Z] COMPRESS LOGS"
    Write-ColoredOutput Green "  [X] EXIT`n"

    <# Define menu selection variable #>
    $Private:intMenuSelection = Read-Host "Please select an option and press enter"

    <# Actions for information menu selected #>
    If ($Private:intMenuSelection -Eq "I") {
        
        <# Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "INFORMATION" -strLogValue "Selected"
        
        <# Clear console #>
        Clear-Host
        
        <# Call information function #>
        fncInformation
        
        <# Call Pause #>
        fncPause

    }

    <# Actions for License menu selected #>
    If ($Private:intMenuSelection -Eq "M") {
        
        <# Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "MIT LICENSE" -strLogValue "Selected"
        
        <# Clear console #>
        Clear-Host

        <# Call License #>
        fncLicense

        <# Call Pause #>
        fncPause
    }
   
    <# Actions for help menu selected #>
    If ($Private:intMenuSelection -Eq "H") {
        
        <# Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "HELP" -strLogValue "Selected"
        
        <# Clear console #>
        Clear-Host

        <# Call Help #>
        fncHelp

    }
    
    <# Actions for reset menu selected #>
    If ($Private:intMenuSelection -Eq "R") {

        <# Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "RESET" -strLogValue "Selected"
        
        <# Clear console #>
        Clear-Host

        <# Call Reset #>
        fncReset

        <# Call Pause #>
        fncPause

    }

    <# Actions for record problem menu selected #>
    If ($Private:intMenuSelection -Eq "P") {
        
        <# Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "RECORD PROBLEM" -strLogValue "Selected"
        
        <# Clear console #>
        Clear-Host
        
        <# Call user logging function #>
        fncRecordProblem
        
        <# Call Pause #>
        fncPause

    }

    <# COLLECT actions #>
    If ($Private:intMenuSelection -Eq "C") {
        
        <# Menu extenstion  #>
        If (@($Global:bolMenuCollectExtended) -Match $true) {$Global:bolMenuCollectExtended = $false}
        Else {$Global:bolMenuCollectExtended = $true}

    }

    <# Detect Windows #>
    If ([System.Environment]::OSVersion.Platform -eq "Win32NT") {

        <# Service configuration actions #>
        If ($Private:intMenuSelection -Eq "A") {
        
            <# Logging #>
            fncLogging -strLogFunction "fncShowMenu" -strLogDescription "COLLECT AIP SERVICE CONFIGURATION" -strLogValue "Selected"
            
            <# Clear console #>
            Clear-Host
            
            <# Call CollectAIPServiceConfigurationn #>
            fncCollectAIPServiceConfiguration
            
            <# Call Pause #>
            fncPause

        }

        <# Protection templates actions #>
        If ($Private:intMenuSelection -Eq "T") {
        
            <# Logging #>
            fncLogging -strLogFunction "fncShowMenu" -strLogDescription "COLLECT PROTECTION TEMPLATES" -strLogValue "Selected"
            
            <# Clear console #>
            Clear-Host
            
            <# Call CollectProtectionTemplates #>
            fncCollectProtectionTemplates
            
            <# Call Pause #>
            fncPause

        }

        <# CollectEndpointURLs actions #>
        If ($Private:intMenuSelection -Eq "E") {
        
            <# Logging #>
            fncLogging -strLogFunction "fncShowMenu" -strLogDescription "COLLECT ENDPOINT URLs" -strLogValue "Selected"
            
            <# Clear console #>
            Clear-Host
            
            <# Call CollectEndpointURLs #>
            fncCollectEndpointURLs
            
            <# Call Pause #>
            fncPause
            
        }

    }

    <# labels and policies actions #>
    If ($Private:intMenuSelection -Eq "L") {
        
        <# Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "COLLECT LABELS AND POLICIES" -strLogValue "Selected"
            
        <# Clear console #>
        Clear-Host
            
        <# Call CollectLabelsAndPolicies #>
        fncCollectLabelsAndPolicies
            
        <# Call Pause #>
        fncPause

    }

    <# DLP rules and policies actions #>
    If ($Private:intMenuSelection -Eq "D") {
        
        <# Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "COLLECT DLP RULES AND POLICIES" -strLogValue "Selected"
            
        <# Clear console #>
        Clear-Host
            
        <# Call CollectDLPRulesAndPolicies #>
        fncCollectDLPRulesAndPolicies
            
        <# Call Pause #>
        fncPause
            
    }

    <# User license details actions #>
    If ($Private:intMenuSelection -Eq "U") {
        
        <# Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "COLLECT USER LICENSE DETAILS" -strLogValue "Selected"
            
        <# Clear console #>
        Clear-Host

        <# Call CollectUserLiceneseDetails #>
        fncCollectUserLiceneseDetails
            
        <# Call Pause #>
        fncPause
            
    }

    <# Compress logs actions #>
    If ($Private:intMenuSelection -Eq "Z") {
    
        <# Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "COMPRESS LOGS" -strLogValue "Selected"
        
        <# Clear console #>
        Clear-Host
        
        <# Call CompressLogs #>
        fncCompressLogs
        
        <# Call Pause #>
        fncPause
        
    }

    <# Exit menu actions #>
    If ($Private:intMenuSelection -Eq "X") {

        <# Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "EXIT" -strLogValue "Selected"

        <# Clear variable #>
        $Global:bolCommingFromMenu = $false

        <# Release variable (updates active) #>
        $Global:bolSkipRequiredUpdates = $false

        <# Set back window title #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle
        
        <# Exit #>
        Break
        
    }
    Else {

        <# Clear console #>
        Clear-Host

        <# Call ShowMenu #>
        fncShowMenu

    }

}

<# Initialize module #>
fncInitialize

<# Remove previous versions #>
fncRemovePreviousVersions

<# Detect enabled logging #>
fncValidateForActivatedLogging

<# Export functions #>
Export-ModuleMember -Function ComplianceUtility -Alias "CompUtil", "UnifiedLabelingSupportTool"
