#Requires -Version 5.1

<# ╔═══════════════════════════════════════════════════════════════════════════╗
   ║ WARNING: DO NOT MODIFY OR DELETE ANY COMPONENT OF THE RMS_Support_Tool OR ║
   ║ THE RESULTING TRACE FILES, AS THIS WILL RESULT IN INCORRECT INFORMATION   ║
   ║ WHEN ANALYZING YOUR ENVIRONMENT.                                          ║
   ╚═══════════════════════════════════════════════════════════════════════════╝ #>

<# Defining global variables #>
[Version]$Global:strVersion = "2.0.1" <# Defining version #>
$Global:strWindowsEdition = (Get-CimInstance Win32_OperatingSystem).Caption <# Defining variable to evaluate Windows version #>
$Global:strTempFolder = (Get-Item Env:"Temp").Value <# Defining variable for user temp folder #>
$Global:strUserLogPath = New-Item -ItemType Directory -Force -Path $Global:strTempFolder"\RMS_Support_Tool\Logs" <# Defining default user log path #>
$Global:bolRunningAsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups -match "S-1-5-32-544") <# Defining control variable for permission checks #>
$Global:strDefaultWindowTitle = $Host.UI.RawUI.WindowTitle <# Caching window title #>
$Global:host.UI.RawUI.WindowTitle = "RMS_Support_Tool ($Global:strVersion)" <# Set window title #>
$Global:strUniqueLogFolder = $null <# Defining variable for unique user log folder #>
$Global:MenuAnalyzeExtended = $false <# Defining variable for ANALYZE menu handling #>
$Global:MenuCollectExtended = $false <# Defining variable for COLLECT menu handling #>
$Global:bolCommingFromMenu = $false <# Defining control variable for menu handling inside function calls #>
$Global:FormatEnumerationLimit = -1 <# Defining variable to show full Format-List for arrays #>

<# Predefine connection settings #>
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

<# Core function definitions for script module #>
Function RMS_Support_Tool {

    <#
    .SYNOPSIS
        The 'RMS Support Tool' provides the functionality to reset all Microsoft® AIP/MIP/AD RMS client services and collect and analyze data for troubleshooting.

    .DESCRIPTION
        The 'RMS Support Tool' provides the functionality to reset all Microsoft® AIP/MIP/AD RMS client services. Its main purpose is to delete the currently downloaded policies, reset all settings for AIP/MIP/AD RMS services, and it can also be used to collect and analyze troubleshooting data.

    .NOTES
        Please find more information on this website about how to use the RMS_Support_Tool:

        https://aka.ms/RMS_Support_Tool

        Note:

        - Please only run RMS_Support_Tool if you have been prompted to do so by a Microsoft® support engineer.
        - It is recommended to test the RMS_Support_Tool with a test environment before executing it in a live environment.
        - Do not modify any component of the RMS_Support_Tool in any kind, as this will result in incorrect information in the analysis of your environment.
        - There is no support for the RMS_Support_Tool. Please see the disclaimer below.
        - Nomenclature: 
            AIP = Azure Information Protection.
            MSIP/MIP = Microsoft® Information Protection.
            MSIPC = Microsoft® Information Protection Client.
            RMS = Rights Management Service.
            AD RMS = Active Directory Rights Management Service.

        MIT LICENSE
        Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

        DISCLAIMER OF WARRANTY: THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. PLEASE DO UNDERSTAND THAT THERE IS NO GUARANTEE THAT THIS SOFTWARE WILL RUN WITH ANY GIVEN ENVIRONMENT OR CONFIGURATION. BY INSTALLING AND USING THE SOFTWARE YOU ACCEPT THIS DISCLAIMER OF WARRANTY. IF YOU DO NOT ACCEPT THE TERMS, DO NOT INSTALL OR USE THIS SOFTWARE.
        
        VERSION
        2.0.1
        
        CREATE DATE
        02/09/2021

        AUTHOR
        Claus Schiroky
        Customer Service & Support - EMEA Modern Work Team
        Microsoft Deutschland GmbH

        HOMEPAGE
        https://aka.ms/RMS_Support_Tool

        SPECIAL THANKS TO
        Matthias Meiling
        Information Protection - EMEA Security Team
        Microsoft Romania SRL 

        Steve Light
        Information Protection - ATC Security Team
        Microsoft Corp.

        PRIVACY STATEMENT
        https://privacy.microsoft.com/PrivacyStatement

        COPYRIGHT
        Copyright® 2021 Microsoft®. All rights reserved.

    .PARAMETER Information
        This parameter shows syntax and a description.

    .PARAMETER Disclaimer
        This paramter displays the disclaimer of warranty.
        Please read it carefully, and act accordingly.

    .PARAMETER Help
        This parameter opens the help file.

    .PARAMETER Reset
        IMPORTANT: Before you proceed with this option, please close all open applications.
        This option removes AIP/MIP/AD RMS certificates, policy templates, labels and corresponding settings.

        Before, the RMS_Support_Tool creates a backup copy of existing custom configurations from the following registry key:
        
        [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSIPC\ServiceLocation]
        
        The name of the backup file is ServiceLocationBackup.reg.

        Note:

        - Reset with the default argument will not reset all settings, but only user-specific settings if you run PowerShell with user permissions. This is sufficient in most cases to reset Microsoft® 365 desktop applications, while a complete reset is useful for all other applications.
        - f you want a complete reset, you must run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions.When an Office 2013 installation is detected, modern authentication (ADAL) is automatically enabled as a precaution.
        
        Valid <String> arguments are: "Default", or "Silent":

        Default:

        When you run PowerShell with user permissions, this argument removes only user-specific AIP/MIP/AD RMS certificates, policy templates and settings:

        PS C:\> RMS_Support_Tool -Reset Default

        All group policy settings are reapplied by "gpupdate /force", and the following registry keys are cleaned up:

        [HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\MSIPC]
        [HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\AIPMigration]
        [HKCU:\SOFTWARE\Classes\Microsoft.IPViewerChildMenu]
        [HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\DRM]
        [HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\DRM]
        [HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Common\DRM]
        [HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\DRM]
        [HKCU:\SOFTWARE\Microsoft\XPSViewer\Common\DRM]
        [HKCU:\SOFTWARE\Microsoft\MSIP]
        [HKCU:\SOFTWARE\Microsoft\MSOIdentityCRL]
        [HKCR:\AllFilesystemObjects\shell\Microsoft.Azip.Inspect]
        [HKCR:\AllFilesystemObjects\shell\Microsoft.Azip.RightClick]

        The DRMEncryptProperty and OpenXMLEncryptProperty registry setting are purged of the following keys:

        [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\15.0\Common\Security]
        [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Common\Security]

        The following file system folders are cleaned up as well:

        %LOCALAPPDATA%\Microsoft\Office\DLP\mip
        %TEMP%\Diagnostics
        %LOCALAPPDATA%\Microsoft\MSIP
        %LOCALAPPDATA%\Microsoft\MSIPC
        %LOCALAPPDATA%\Microsoft\DRM

        When you run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions, the following registry keys are cleaned up in addition:

        [HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSIPC]
        [HKLM:\SOFTWARE\Microsoft\MSIPC]
        [HKLM:\SOFTWARE\Microsoft\MSDRM]
        [HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSDRM]
        [HKLM:\SOFTWARE\WOW6432Node\Microsoft\MSIP]

        Silent:

        This command line-parameter argument does the same as "-Reset Default", but does not print any output - unless an error occurs when attempting to reset:

        PS C:\> RMS_Support_Tool -Reset Silent

        If a silent reset triggers an error, you can use the additional parameter "-Verbose" to find out more about the cause of the error:

        PS C:\> RMS_Support_Tool -Reset Silent -Verbose

        You can also review the Script.log file for errors of silent reset.  

    .PARAMETER RecordProblem
        IMPORTANT: Before you proceed with this option, please close all open applications.

        Note:

        - When you run PowerShell with user permissions, neither CAPI2 or AIP event logs, network trace, nor filter drivers are recorded.
        - If you want a complete record, you must run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions.
        
        As a first step, this parameter cleans up existing MSIP/MSIPC log folders, then it activates the required logging, tracing or debugging mechanisms by implementing registry settings, and enabling some Windows event logs. This process will be reflected by a progress bar “Enable logging...".
        In the event that you accidentally close the PowerShell window while logging is enabled, the RMS_Support_Tool disables logging the next time you start it.

        In a second step asks you to reproduce the problem. While you’re doing so, the RMS_Support_Tool collects and records data. Once you have reproduced the problem, all collected files will be stored into the default logs folder (%temp%\RMS_Support_Tool\Logs). Every time you call this option, a new unique subfolder will be created in the logs-folder that reflects the date and time when it was created, e.g. “210209-133005”. While the files are being cached, you will see a progress bar “Collecting logs...".

        In the last step, the RMS_Support_Tool resets all activated log, trace, and debug settings to their defaults. This process will be reflected by a progress bar “Disable logging...".

        You can then review the log files in the logs folder.

    .PARAMETER CollectAIPServiceConfiguration
        This parameter collects AIP service configuration information of your tenant.

        Results are written into the log file AIPServiceConfiguration.log in the subfolder "Collect" of the Logs folder. 

        Note:

        - You must run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions to continue with this option. Please contact your administrator if necessary.
        - You need to know your Microsoft® 365 global administrator account information to proceed with this option, as you will be asked for your credentials.

    .PARAMETER CollectAIPProtectionTemplates
        This parameter collects AIP protection templates of your tenant.

        Results are written into the log file AIPProtectionTemplates.log in the subfolder "Collect" of the Logs folder. 

        Note:

        - You must run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions to continue with this option. Please contact your administrator if necessary.
        - You need to know your Microsoft® 365 global administrator account information to proceed with this option, as you will be asked for your credentials.

    .PARAMETER CollectMSCLabelsAndPolicies
        This parameter collects the labels and policy definitions from your Microsoft® 365 Security Center (MSC). Those with protection and those with classification only.

        Results are written into log file MSCLabelsAndPolicies.log in the subfolder "Collect" of the Logs folder.

        Note:

        - You must run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions to continue with this option. Please contact your administrator if necessary.
        - You need to know your Microsoft® 365 global administrator account information to proceed with this option, as you will be asked for your credentials.
        - The Microsoft® Exchange Online PowerShell V2 cmdlets are required to proceed this option. If you do not have this module installed, RMS_Support_Tool will try to install it from PowerShell Gallery.

    .PARAMETER AnalyzeEndpointURLs
        This parameter analyzes important enpoint URLs.
        The URLs are taken from your local registry or your tenant's AIP service configuration information, and extended by additional relevant URLs.

        In a first step, this parameter is used to check whether you can access the URL.

        In a second step, the issuer of the corresponding certificate of the URL is validated. 
        This process is represented by an output with the Tenant Id, Endpoint name, URL, Issuer, and the Status of the validation of the certificate issuer. For example:

        -----------------------------------------------
        Tenant Id: 48fc04bd-c84b-44ac-91b7-a4c5eefd5ac1
        -----------------------------------------------

        Endpoint: CertificationDistributionPointUrl
        URL:      https://48fc04bd-c84b-44ac-91b7-a4c5eefd5ac1.rms.na.aadrm.com/_wmcs/certification
        Issuer:   C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Secure Server CA 2011
        Status:   Ok (200)

        In addition, analyze results are written into log file EndpointURLs.log in the subfolder "Analyze" of the Logs folder.

        Note:

        - You must run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions to continue with this option, if the corresponding Microsoft® 365 desktop application is not bootstraped. Please contact your administrator if necessary.
        - You need to know your Microsoft® 365 global administrator account information to proceed with this option, as you will be asked for your credentials.

    .PARAMETER AnalyzeProtection
        This option analyzes whether the current user is able to use protection.

        Therefore an ad-hoc protection policy for custom permissions is created, and used to validate the protection with a sample file (Protection.txt). The result is represented by an output with the status of that process. For example:

        License      : {[Users, RMSSupToolEncrTest@microsoft.com], [Permissons, VIEWER]}
        File         : C:\Users\<UserName>\AppData\Local\Temp\RMS_Support_Tool\Logs\Analyze\Protection.ptxt
        Verification : Successfull

        In addition, analyze results are written to the Protection.log file, and the resulting protected file (Protection.ptxt) is stored in the subfolder "Analyze" of the Logs folder.

        Note:

        - Please pay attention to point 1. Microsoft® Azure Information Protection cmdlets of the requirements section of this help file.

    .PARAMETER CheckForUpdate
        This parameter checks if a new version is available for the RMS_Support_Tool.

        If you run the RMS_Support_Tool with administrative permissions, it automatically performs each new update.

        Note:

        - Under certain circumstances, you may need to run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions to perform an update.
        - If the RMS_Support_Tool was not installed via PowerShell Gallery, any older version must first be removed before an update or installation can be performed.

    .PARAMETER CompressLogs
        This command line parameter should always be used at the very end of a scenario.

        IMPORTANT: Do not modify or delete any of the resulting trace files, as this will result in incorrect information when analyzing your environment.

        This parameter compresses all collected log files and folders into a .zip archive, and the corresponding file is saved to your desktop. In addition, the default logs folder (%temp%\RMS_Support_Tool\Logs) is cleaned.

        After this step you can send/upload the .zip file for the Microsoft® support engineer. 

    .PARAMETER Menu
        This will start the RMS_Support_Tool with the default menu.

    .PARAMETER Version
        This parameter displays the version of the RMS_Support_Tool.

    .EXAMPLE
        RMS_Support_Tool -Information
        This shows syntax and description.

    .EXAMPLE
        RMS_Support_Tool -Disclaimer
        This displays the disclaimer of warranty.
        Please read it carefully, and act accordingly.

    .EXAMPLE
        RMS_Support_Tool -Help
        This parameter opens the help file.

    .EXAMPLE
        RMS_Support_Tool -Reset Default
        This parameter removes AIP/MIP/AD RMS certificates, policy templates and corresponding settings.

    .EXAMPLE
        RMS_Support_Tool -Reset Silent
        This parameter removes all AIP/MIP/AD RMS certificates, policy templates and all corresponding user settings without any output.

    .EXAMPLE
        RMS_Support_Tool -RecordProblem
        This parameter removes all AIP/MIP/AD RMS certificates, policy templates and all corresponding machine settings, and starts recording data.

    .EXAMPLE
        RMS_Support_Tool -CollectAIPServiceConfiguration
        This parameter collects AIP service configuration information of your tenant.

    .EXAMPLE
        RMS_Support_Tool -CollectAIPProtectionTemplates
        This parameter collects AIP protection templates of your tenant.

    .EXAMPLE
        RMS_Support_Tool -CollectMSCLabelsAndPolicies
        This parameter collects the labels and policy definitions from your Microsoft® 365 Security Center (MSC)

    .EXAMPLE
        RMS_Support_Tool -AnalyzeEndpointURLs
        This parameter analyzes important enpoint URLs, and the results are written into a log file.
        
    .EXAMPLE
        RMS_Support_Tool -AnalyzeProtection
        This option analyzes whether the current user is able to use protection.

    .EXAMPLE
        RMS_Support_Tool -CompressLogs
        This parameter compress all collected logs files into a .zip archive, and the corresponding path and file name is displayed.

    .EXAMPLE
        RMS_Support_Tool -CheckForUpdate
        This parameter checks if a new version is available for the RMS_Support_Tool.

    .EXAMPLE
        RMS_Support_Tool -RecordProblem -CompressLogs
        This parameter removes AIP/MIP/AD RMS certificates, policy templates and corresponding settings, starts recording data, and compress all collected logs files to a .zip archive in the users desktop folder.

    .EXAMPLE
        RMS_Support_Tool -Menu
        This will start the RMS_Support_Tool with the default menu.

    .EXAMPLE
        RMS_Support_Tool -Version
        This parameter displays the version of the RMS_Support_Tool.

    .LINK
        https://aka.ms/RMS_Support_Tool

    #>

    <# Defining CmdletBinding attribut to define parameter settings #>
    [CmdletBinding (
        HelpURI = "https://aka.ms/RMS_Support_Tool", <# URL for help file; used with parameter Help #>
        PositionalBinding = $false, <# Parameters in the function are not positional #>
        DefaultParameterSetName = "Menu" <# If no parameter has been selected, this will be the default #>
    )]

    <# Parameter definitions #>
    Param (
        
        <# Parameter definition for Information #>
        [Alias("i")]
        [Parameter(ParameterSetName = "Information")]
        [switch]$Information,

        <# Parameter definition for Disclaimer #>
        [Alias("d")]
        [Parameter(ParameterSetName = "Disclaimer")]
        [switch]$Disclaimer,

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

        <# Parameter definition for CollectAIPProtectionTemplates #>
        [Alias("o")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CollectAIPProtectionTemplates,

        <# Parameter definition for CollectMSCLabelsAndPolicies #>
        [Alias("l")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CollectMSCLabelsAndPolicies,

        <# Parameter definition for AnalyzeEndpointURLs #>
        [Alias("u")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$AnalyzeEndpointURLs,

        <# Parameter definition for AnalyzeProtection #>
        [Alias("t")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$AnalyzeProtection,

        <# Parameter definition for CheckForUpdate #>
        [Parameter(ParameterSetName = "Update")]
        [switch]$CheckForUpdate,

        <# Parameter definition for CompressLogs, with preset. #>
        [Alias("z")]
        [Parameter(ParameterSetName = "Reset and logging")]
        [switch]$CompressLogs,

        <# Parameter definition for Menu #>
        [Parameter(ParameterSetName = "Menu")]
        [switch]$Menu,

        <# Parameter definition for Version #>
        [Alias("v")]
        [Parameter(ParameterSetName = "Version")]
        [switch]$Version

    )

    <# Action if the parameter '-Information' has been selected #>
    If ($PsCmdlet.ParameterSetName -eq "Information") {

        <# Calling information function #>
        fncInformation

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Information" -strLogValue "Proceeded"

    } 

    <# Action if the parameter '-Disclaimer' has been selected #>
    If ($PSBoundParameters.ContainsKey("Disclaimer")) {

        <# Calling disclaimer function #>
        fncDisclaimer
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Disclaimer" -strLogValue "Proceeded"

    }
    
    <# Action if the parameter '-Help' has been selected #>
    If ($PSBoundParameters.ContainsKey("Help")) {

        <# Calling help function #>
        fncHelp

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Help" -strLogValue "Proceeded"

    }

    <# Action if the parameter '-Reset' has been selected #>
    If ($PSBoundParameters.ContainsKey("Reset")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Parameter Reset" -strLogValue "Triggered"                

        <# Calling reset function #>
        fncReset -strResetMethod $Reset

    }

    <# Action if the parameter '-RecordProblem' has been selected #>
    If ($PSBoundParameters.ContainsKey("RecordProblem")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Parameter RecordProblem" -strLogValue "Triggered"       

        <# Calling record problem function #>
        fncRecordProblem

    }

    <# Action if the parameter '-CollectAIPServiceConfiguration' has been selected #>
    If ($PSBoundParameters.ContainsKey("CollectAIPServiceConfiguration")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Parameter CollectAIPServiceConfiguration" -strLogValue "Triggered"

        <# Calling function to collect AIP configuration #>
        fncCollectAIPServiceConfiguration

    }

    <# Action if the parameter '-CollectAIPProtectionTemplates' has been selected #>
    If ($PSBoundParameters.ContainsKey("CollectAIPProtectionTemplates")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Parameter CollectAIPProtectionTemplates" -strLogValue "Triggered"

        <# Calling function to collect AIP protection templates #>
        fncCollectAIPProtectionTemplates

    }

    <# Action if the parameter '-CollectMSCLabelsAndPolicies' has been selected #>
    If ($PSBoundParameters.ContainsKey("CollectMSCLabelsAndPolicies")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Parameter CollectMSCLabelsAndPolicies" -strLogValue "Triggered"

        <# Calling function to collect MSC labels and policies #>
        fncCollectMSCLabelsAndPolicies

    }

    <# Action if the parameter '-AnalyzeEndpointURLs' has been selected #>
    If ($PSBoundParameters.ContainsKey("AnalyzeEndpointURLs")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Parameter AnalyzeEndpointsURLs" -strLogValue "Triggered"

        <# Calling AnalyzeEndpoints function #>
        fncAnalyzeEndpointURLs

    }

    <# Action if the parameter '-AnalyzeProtection' has been selected #>
    If ($PSBoundParameters.ContainsKey("AnalyzeProtection")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Parameter AnalyzeProtection" -strLogValue "Triggered"

        <# Calling AnalyzeProtection function #>
        fncAnalyzeProtection

    }

    <# Action if the parameter '-CheckForUpdate' has been selected #>
    If ($PSBoundParameters.ContainsKey("CheckForUpdate")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Parameter CheckForUpdate" -strLogValue "Triggered"

        <# Calling CheckForUpdate function #>
        fncCheckForUpdate

    }

    <# Action if the parameter '-CompressLogs' has been selected #>
    If ($PSBoundParameters.ContainsKey("CompressLogs")) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Parameter CompressLogs" -strLogValue "Triggered"

        <# Calling function to compress all logs into a zip archive #>
        fncCompressLogs

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Exit function #>
        Break

    }

    <# Action if the parameter '-Menu' has been selected; default without any parameter #>
    If ($PsCmdlet.ParameterSetName -eq "Menu") {

        <# Calling function to show menu #>
        fncShowMenu

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Menu" -strLogValue "Proceeded"

    }

    <# Action if the parameter '-Version' has been selected #>
    If ($PSBoundParameters.ContainsKey("Version")) {

        <# Calling function to display version information #>
        fncShowVersion

        <# Verbose/Logging #>
        fncLogging -strLogFunction "RMS_Support_Tool" -strLogDescription "Version" -strLogValue "Proceeded"

    }

}

<# Function that creates some default log enties #>
Function fncCreateDefaultLogEntries {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "Script module version" -strLogValue $Global:strVersion <# Script module version #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "Windows edition" -strLogValue $Global:strWindowsEdition <# Windows edition #>
    
    <# Verbose/Logging: Windows version #>
    If ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name ReleaseID -ErrorAction SilentlyContinue).ReleaseId) {

        <# Windows version and release ID #>
        fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "Windows version" -strLogValue $([System.Environment]::OSVersion.Version) ($((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name ReleaseID).ReleaseId))

    }
    Else {

        <# Windows version #>
        fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "Windows version" -strLogValue $([System.Environment]::OSVersion.Version)

    }

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "Windows architecture" -strLogValue $((Get-CimInstance Win32_OperatingSystem -Verbose:$false).OSArchitecture) <# Windows architecture #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "Username" -strLogValue $([System.Environment]::UserName) <# Username #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "Machine name" -strLogValue $([System.Environment]::MachineName) <# Machine name #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "PowerShell Host" -strLogValue $($Host.Name.ToString()) <# PowerShell host #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "PowerShell Version" -strLogValue $($Host.Version.ToString()) <# PowerShell version #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "PowerShell Edition" -strLogValue $($PSVersionTable.PSEdition.ToString()) <# PowerShell edition #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "PowerShell Build version" -strLogValue $($PSVersionTable.BuildVersion) <# PowerShell build version #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "PowerShell Current culture" -strLogValue $($Host.CurrentCulture.ToString()) <# PowerShell current culture #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "PowerShell Current UI culture" -strLogValue $($Host.CurrentUICulture.ToString()) <# PowerShell current UI culture #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "PowerShell CLR version" -strLogValue $($PSVersionTable.CLRVersion.ToString()) <# PowerShell CRL version #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "PowerShell WSManStack version" -strLogValue $($PSVersionTable.WSManStackVersion.ToString()) <# PowerShell WSManStack version #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "PowerShell PSRemotingProtocol version" -strLogValue $($PSVersionTable.PSRemotingProtocolVersion.ToString()) <# PowerShell PSRemotingProtocol version #>
    fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "PowerShell Serialization version" -strLogValue $($PSVersionTable.SerializationVersion.ToString()) <# PowerShell Serialization version #>

    <# Log, if running with local administrative permissions #>
    If ($Global:bolRunningAsAdmin -eq $true) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "PowerShell Mode" -strLogValue "Administrator"

    }
    Else{

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "PowerShell mode" -strLogValue "User"

    }

    <# Verbose/Logging: AIP client version #>
    If (Get-Module -ListAvailable -Name AzureInformationProtection -Verbose:$false) {

        <# Logging: If AIP client is installed #>
        fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "AIP client version" -strLogValue $((Get-Module -ListAvailable -Name AzureInformationProtection -Verbose:$false).Version)

    }
    Else {

        <# Logging: If AIP client is not installed #>
        fncLogging -strLogFunction "fncCreateDefaultLogEntries" -strLogDescription "AIP client installed" -strLogValue $false

    }

}

<# Function for evaluating Windows and PowerShell version (Exit, if an unsupported version/environment is found) #>
Function fncCheckWindowsAndPSVersion {

    <# Checking for supported OS versions #>
    If (-Not $Global:strWindowsEdition -Match "Windows 8.1" -Or
        -Not $Global:strWindowsEdition -Match "Windows 10" -Or
        -Not $Global:strWindowsEdition -Match "2012" -Or
        -Not $Global:strWindowsEdition -Match "Server 2016" -Or
        -Not $Global:strWindowsEdition -Match "Server 2019") {

        <# Clear global variables #>
        $Global:strWindowsEdition = $null

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCheckWindowsAndPSVersion" -strLogDescription "Unsupported operating system" -strLogValue $true

        <# Console output #>
        Write-Output (Write-Host "ATTENTION: The RMS_Support_Tool does not support the operating system you're using.`nPlease ensure to use one of the following supported operating systems:`nMicrosoft® Windows 8.1, Windows 10, Windows Server 2012, Windows Server 2012 R2, Windows Server 2016 and Windows Server 2019.`n" -ForegroundColor Red)

        <# Signal sound #>
        [console]::beep(500,200)

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Exit function #>
        Break

    }

    <# Checking for supported PowerShell version #>
    If ($PSVersionTable.PSVersion.Major -cnotmatch "5") {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCheckWindowsAndPSVersion" -strLogDescription "Unsupported PowerShell version" -strLogValue $true

        <# Console output #>
        Write-Output (Write-Host "ATTENTION: The 'RMS_Support_Tool.psm1' cannot be run because it contained a '#requires' statement for Windows PowerShell 5.1.`nThe version of Windows PowerShell that is required by the script does not match the currently running version of Windows PowerShell $($PSVersionTable.PSVersion).`n" -ForegroundColor Red)

        <# Signal sound #>
        [console]::beep(500,200)

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Exit function #>
        Break

    }

}

<# Function responsable to check for new version #>
Function fncCheckForUpdate { <# Check for latest version of the script module #>

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Update" -strLogValue "Initiated"

    <# Console output #>
    Write-Output "CHECK FOR UPDATE:`n"
    Write-Output "Searching for new version..."

    <# Defining default message for outdated version #>
    $Private:strOutdatedVersionMessage = "ATTENTION: You're using an outdated version of the RMS_Support_Tool.`nPlease update to the latest version by running the following command:`n`nPS C:\> Update-Module -Name RMS_Support_Tool -Force`n`nNote:`n`n- Under certain circumstances, you may need to run the RMS_Support_Tool as user with local administrative permissions to perform an update.`n- If the RMS_Support_Tool was not installed via PowerShell Gallery, any older version must first be removed before an update or installation can be performed."

    <# Validating connection to PowerShell Gallery by Find-Module #>
    If (Find-Module -Name RMS_Support_Tool -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) { <# Actions, if PowerShell Gallery can be reached #>

        <# Filling variable with online version information #>
        [Version]$Private:strOnlineVersion = (Find-Module -Name RMS_Support_Tool -Repository PSGallery).Version

        # Comparing local version vs. latest (online) version #>
        If ([Version]::new($Private:strOnlineVersion.Major, $Private:strOnlineVersion.Minor, $Private:strOnlineVersion.Build) -gt [Version]::new($Global:strVersion.Major, $Global:strVersion.Minor, $Global:strVersion.Build) -eq $true) {

            <# Action, if running as administrator #>
            If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $true) {

                <# Update module only if the existing version was installed by PowerShell Gallery #>
                If ((Get-InstalledModule -Name RMS_Support_Tool -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) -eq $true) {

                    <# Console output #>
                    Write-Output "A new version of the RMS_Support_Tool is available."
                    Write-Output "Updating RMS_Support_Tool, please wait..."

                    <# Updating RMS_Support_Tool #>
                    Update-Module -Name RMS_Support_Tool -Force

                    <# Internet availalbe: Console output #>
                    Write-Output (Write-Host "ATTENTION: A new version of the RMS_Support_Tool has been installed.`nThe RMS_Support_Tool is now terminated.`nPlease restart with a new PowerShell session/window." -ForegroundColor Red)

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
            Else { <# Actions, if running without administrative permissions #>

                <# Console output #>
                Write-Output (Write-Host $Private:strOutdatedVersionMessage -ForegroundColor Red)

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Script module version" -strLogValue "Outdated"

            }

            <# Signal sound #>
            [console]::beep(500,200)

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Update" -strLogValue "Proceeded"
            fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Exit script module" -strLogValue $true

            <# Releasing private/global variables #>
            [Version]$Private:strOnlineVersion = $null
            $Global:strWindowsEdition = $null

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Console output #>
            Write-Output (Write-Host "CHECK FOR UPDATE: Proceeded.`n" -ForegroundColor Green)

            <# Exit function #>
            Break

        }
        Else {

            <# Console output #>
            Write-Output "You're using the latest version of the RMS_Support_Tool."

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Script module version" -strLogValue "Latest"

            <# Console output #>
            Write-Output (Write-Host "CHECK FOR UPDATE: Proceeded.`n" -ForegroundColor Green)

        }

    }
    Else { <# Actions, if PowerShell Gallery can not be reached (no internet connection) #>

        <# Console output #>
        Write-Output (Write-Host "ATTENTION: Checking for update could not be performed.`nEither the website cannot be reached or there is no connection to the Internet.`n`nYou are using version: $Global:strVersion.`n`nPlease check on the following website if you are using the latest version of the RMS_Support_Tool, and update if necessary:`nhttps://aka.ms/RMS_Support_Tool/Latest" -ForegroundColor Red)

        <# Signal sound #>
        [console]::beep(500,200)

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Update" -strLogValue "No internet connection"

        <# Console output #>
        Write-Output (Write-Host "CHECK FOR UPDATE: Proceeded.`n" -ForegroundColor Green)

        <# Console output with pause #>
        fncPause

    }

    <# Signal sound #>
    [console]::beep(1000,200)

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCheckForUpdate" -strLogDescription "Update" -strLogValue "Proceeded"

    <# Releasing private variables #>
    [Version]$Private:strOnlineVersion = $null

}

<# Function that creates single log entries for log file and verbose output #>
Function fncLogging ($strLogFunction, $strLogDescription, $strLogValue) {

    <# Checking if path exist and create it, if not #>
    If ($(Test-Path -Path $Global:strUserLogPath) -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath | Out-Null <# Defining default user log path #>

    }

    <# Verbose output #>
    Write-Verbose "$(Get-Date -UFormat "%Y-%m-%d"), $(Get-Date -UFormat "%H:%M"), $strLogFunction, $strLogDescription, $strLogValue"

    <# Write (append) verbose output to log file #>
    Write-Verbose "$(Get-Date -UFormat "%Y-%m-%d"), $(Get-Date -UFormat "%H:%M"), $strLogFunction, $strLogDescription, $strLogValue" -ErrorAction SilentlyContinue -Verbose 4>> $Global:strUserLogPath"\Script.log" 

}

<# Function to show information #>
Function fncInformation {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncInformation" -strLogDescription "Information" -strLogValue "Called"

    <# Action, if function was called from command line #>
    If ($Global:bolCommingFromMenu -eq $false) {

        <# Call Information #>
        Get-Help -Verbose:$false RMS_Support_Tool

    }

    <# Action, if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {
    
        <# Console output #>
        Write-Output "NAME:`nRMS_Support_Tool`n`nDESCRIPTION:`nThe RMS_Support_Tool provides the functionality to reset all Microsoft® AIP/MIP/AD RMS client services. Its main purpose is to delete the currently downloaded policies, reset all settings for AIP/MIP/AD RMS services, and it can also be used to collect and analyze troubleshooting data.`n`nVERSION:`n$Global:strVersion`n`nAUTHOR:`nClaus Schiroky`nCustomer Service & Support - EMEA Modern Work Team`nMicrosoft Deutschland GmbH`n`nHOMEPAGE:`nhttps://aka.ms/RMS_Support_Tool`n`nSPECIAL THANKS TO:`nMatthias Meiling`nInformation Protection - EMEA Security Team`nMicrosoft Romania SRL`n`nSteve Light`nInformation Protection - ATC Security Team`nMicrosoft Corp.`n`nPRIVACY STATEMENT:`nhttps://privacy.microsoft.com/PrivacyStatement`n`nCOPYRIGHT:`nCopyright® 2021 Microsoft®. All rights reserved.`n"

    }

}

<# Function to show disclaimer #>
Function fncDisclaimer {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncDisclaimer" -strLogDescription "Disclaimer" -strLogValue "Called"

    <# Console output #>
    Write-Output (Write-Host "DISCLAIMER OF WARRANTY: THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. PLEASE DO UNDERSTAND THAT THERE IS NO GUARANTEE THAT THIS SOFTWARE WILL RUN WITH ANY GIVEN ENVIRONMENT OR CONFIGURATION. BY INSTALLING AND USING THE SOFTWARE YOU ACCEPT THIS DISCLAIMER OF WARRANTY. IF YOU DO NOT ACCEPT THE TERMS, DO NOT INSTALL OR USE THIS SOFTWARE.`n`nNote:`n`n- Please only run RMS_Support_Tool if you have been prompted to do so by a Microsoft® support engineer.`n- It is recommended to test the RMS_Support_Tool with a test environment before executing it in a live environment.`n- Do not modify any component of the RMS_Support_Tool in any kind, as this will result in incorrect information in the analysis of your environment.`n- There is no support for the RMS_Support_Tool.`n- Before using the RMS_Support_Tool, please ensure to read its manual:`n  https://aka.ms/RMS_Support_Tool`n" -ForegroundColor Red)

}

<# Function to show help file #>
Function fncHelp {

    <# Action if help file can be found in script module folder #>
    If ($(Test-Path $Private:PSScriptRoot"\RMS_Support_Tool.htm") -Eq $true) {

        <# Open help file #>
        Invoke-Item $Private:PSScriptRoot"\RMS_Support_Tool.htm"

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncHelp" -strLogDescription "Help" -strLogValue "Called"

    }

    <# Action if help file can't be found in script module folder #>
    If ($(Test-Path $Private:PSScriptRoot"\RMS_Support_Tool.htm") -Eq $false) {

        <# Checking if internet connection is available #>
        If ($(fncTestInternetAccess "github.com") -Eq $true) {

            <# Call online help; Set by HelpURI in CmdletBinding #>
            Get-Help -Verbose:$false RMS_Support_Tool -Online        

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncHelp" -strLogDescription "Help" -strLogValue "Called"

        }
        Else { <# Action if web site is unavailable or if there's no internet connection #>

            <# Console output #>
            Write-Output (Write-Host "ATTENTION: The help file (RMS_Support_Tool.htm) could not be found.`nEither the website cannot be reached or there is no internet connection.`n`nNote:`n`n- If you’re working in an environment that does not have internet access, you must download the file manually, before proceeding the RMS_Support_Tool.`n- You must place the file to the location where you have stored the RMS_Support_Tool files.`n- Please download the file from the following hyperlink (from a machine where you have internet access):`n  https://aka.ms/RMS_Support_Tool/Latest`n" -ForegroundColor Red)

            <# Signal sound #>
            [console]::beep(500,200)

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncHelp" -strLogDescription "Help" -strLogValue "No internet connection"

        }

    }

}

<# Function to reset Microsoft® AIP/MIP/AD RMS services for the current user #>
Function fncReset ($strResetMethod) {

    <# Action if function was not called with default #>
    If ($strResetMethod -notmatch "Silent") {

        <# Console output #>
        Write-Output "RESET:"

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "Reset Default" -strLogValue "Initiated"

        <# Checking if not running as administrator #>
        If ($Global:bolRunningAsAdmin -eq $false) {

            <# Console output #>
            Write-Output (Write-Host "ATTENTION: Please note that this will not reset all settings, but only user-specific settings.`nIf you want a complete reset, you must run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions." -ForegroundColor Red)

            <# Console output #>
            Write-Output "Resetting user-specific AIP/MIP/AD RMS settings, please wait..."

        }
        Else{ <# Action if running as administrator #>

            <# Console output #>
            Write-Output "Resetting all AIP/MIP/AD RMS settings, please wait..."

        }

    }
    Else { <# Action if function was called with silent argument #>

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "Reset Silent" -strLogValue "Initiated"

    }

    <# If "registry overrides" exist, create a backup copy #>
    If ($(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\MSIPC\ServiceLocation") -Eq $true) {

        <# Backup registry settings to a reg file #>
        REG EXPORT "HKLM\SOFTWARE\Microsoft\MSIPC\ServiceLocation" $Private:PSScriptRoot\Logs\ServiceLocationBackup.reg /Y | Out-Null

        <# Console output #>
        Write-Output "Your ServiceLocation registry settings were stored to"$Private:PSScriptRoot\Logs\ServiceLocationBackup.reg

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "Export ServiceLocation backup" -strLogValue "ServiceLocationBackup.reg"

    }

    <# Force update group policy settings #>
    Echo Y | gpupdate /force | Out-Null

    <# Cleaning user registry keys #>
    fncDeleteItem "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\MSIPC"
    fncDeleteItem "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\AIPMigration"
    fncDeleteItem "HKCU:\SOFTWARE\Classes\Microsoft.IPViewerChildMenu"
    fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Cloud\Office"
    fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\DRM"
    fncDeleteItem "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\DRM"
    fncDeleteItem "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Common\DRM"
    fncDeleteItem "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\DRM"
    fncDeleteItem "HKCU:\SOFTWARE\Microsoft\XPSViewer\Common\DRM"
    fncDeleteItem "HKCU:\SOFTWARE\Microsoft\MSIP"
    fncDeleteItem "HKCU:\SOFTWARE\Microsoft\MSOIdentityCRL"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security\Lables" -Name "UseOfficeForLabelling" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Security" -Name "DRMEncryptProperty" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security" -Name "DRMEncryptProperty" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Security" -Name "OpenXMLEncryptProperty" -Force -ErrorAction SilentlyContinue | Out-Null

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncReset" -strLogDescription "UseOfficeForLabelling" -strLogValue "Removed"
    fncLogging -strLogFunction "fncReset" -strLogDescription "DRMEncryptProperty" -strLogValue "Removed"
    fncLogging -strLogFunction "fncReset" -strLogDescription "OpenXMLEncryptProperty" -strLogValue "Removed"

    <# Cleaning client classes registry keys #>
    fncDeleteItem "HKCR:\AllFilesystemObjects\shell\Microsoft.Azip.Inspect"
    fncDeleteItem "HKCR:\AllFilesystemObjects\shell\Microsoft.Azip.RightClick"

    <# Cleaning client folders in file system #>
    fncDeleteItem "\\?\$env:LOCALAPPDATA\Microsoft\Office\DLP\mip"
    fncDeleteItem "\\?\$env:TEMP\Diagnostics"
    fncDeleteItem "\\?\$env:LOCALAPPDATA\Microsoft\MSIP"
    fncDeleteItem "\\?\$env:LOCALAPPDATA\Microsoft\MSIPC"
    fncDeleteItem "\\?\$env:LOCALAPPDATA\Microsoft\DRM"

    <# Clearing user settings and RMS templates for the current user #>
    If (Get-Module -ListAvailable -Name AzureInformationProtection) { <# Checking for installed AIP client #>

        <# Clearing user settings and RMS templates #>
        Clear-AIPAuthentication -ErrorAction SilentlyContinue | Out-Null

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "AIPAuthentication" -strLogValue "Cleared"

    }

    <# Checking for Office 2013, and enable modern authentication if installed #>
    If ($(fncCheckForOffice2013) -Eq $true) { 

        <# Checking for Office 2013 registry key #>
        If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0") -Eq $true) {
    
            <# Creating registry key (overwrite) #>
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Identity" -ErrorAction SilentlyContinue | Out-Null
    
            <# Implementing registry settings to enable modern authentication for Office 2013 #>
            New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Identity" -Name "EnableADAL" -Value 1 -PropertyType DWord -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Identity" -Name "Version" -Value 1 -PropertyType DWord -ErrorAction SilentlyContinue | Out-Null
    
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncReset" -strLogDescription "ADAL for Office 2013" -strLogValue "Enabled"

        }

    }

    <# Additional actions to proceed administrative reset #>
    If ($Global:bolRunningAsAdmin -eq $true) {

        # Cleaning machine registry keys #>
        fncDeleteItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSIPC"
        fncDeleteItem "HKLM:\SOFTWARE\Microsoft\MSIPC"
        fncDeleteItem "HKLM:\SOFTWARE\Microsoft\MSDRM"
        fncDeleteItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSDRM"
        fncDeleteItem "HKLM:\SOFTWARE\WOW6432Node\Microsoft\MSIP"

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "Reset complete" -strLogValue $true

    }
    Else{

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncReset" -strLogDescription "Reset complete" -strLogValue $false

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

    <# Signal sound #>
    [console]::beep(1000,200)

}

<# Function to check, if Office 2013 is installed; used to enable ADAL at reset #>
Function fncCheckForOffice2013 {

    <# Looping through uninstall registry key to find any Office application #>
    Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -Name | ForEach-Object {

        <# Checking for Office applications/GUIDs #>
        If ($_.ToString() -like "*0000000FF1CE}") {

            <# Checking for major version '15' = Office 2013 #>
            If (Get-ItemProperty $_.PSPath | Where-Object {$_.VersionMajor -eq "15"}) {

                <# Returning 'true', if an Office 2013 applictation was found #>
                Return $true

                <# Set back window title to default #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle                

                <# Leaving ForEach loop #>
                Break

            }
            Else {

                <# Returning 'false', if no Office 2013 applictation was found #>
                Return $false

                <# Set back window title to default #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle
                
                <# Leaving loop #>
                Break

            }

        }

    }

}

<# Function to delete item/s or folders (with IO error handling); used in fncReset, and fncDisableLogging #>
Function fncDeleteItem ($Private:objItem) {

    Try {

        <# Checking if key, file or folder exist and proceed with related actions #>
        If ($(Test-Path -Path $Private:objItem) -Eq $true) {

            <# Deleting folder or registry key #>
            Remove-Item -Path $Private:objItem -Recurse -Force -ErrorAction Stop | Out-Null
           
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncDeleteItem" -strLogDescription "Item deleted" -strLogValue $Private:objItem.TrimStart("\\?\")

        }

    }
    Catch [System.IO.IOException] { <# Actions if files or folders cannot be accessed, because they are locked/used by another process <#>

        <# Console output #>
        Write-Output (Write-Host "WARNING: Some items or folders are still used by another process.`nIMPORTANT: Please close all applications (or restart machine) and try again." -ForegroundColor Red)

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncDeleteItem" -strLogDescription "Item locked" -strLogValue $Private:objItem.TrimStart("\\?\")
        fncLogging -strLogFunction "fncDeleteItem" -strLogDescription "Reset" -strLogValue "ERROR: Reset failed"

        <# Releasing private variable #>
        $Private:objItem = $null

        <# Action if function was not called from the menu #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Console output #>
            Write-Output (Write-Host "RESET: Failed.`n" -ForegroundColor Red)

            <# Signal sound #>
            [console]::beep(500,200)

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Interrupting Reset #>
            Break

        }
        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Console output #>
            Write-Output (Write-Host "RESET: Failed.`n" -ForegroundColor Red)

            <# Signal sound #>
            [console]::beep(500,200)

            <# Console output with pause #>
            fncPause

            <# Calling menu #>
            fncShowMenu

        }

    }

    <# Releasing private variable #>
    $Private:objItem = $null

}

<# Function to copy item/s (with error handler); used in fncCollectLogging #>
Function fncCopyItem ($Private:objItem, $Private:strDestination, $Private:strFileName) {

    Try {

        <# Checking if path exist and proceed with file copy #>
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

        <# Releasing private variable #>
        $Private:objItem = $null
        $Private:strDestination = $null

    }

    <# Releasing private variables #>
    $Private:objItem = $null
    $Private:strDestination = $null

}

<# Function to check for internet access #>
Function fncTestInternetAccess ($Private:strURL) {

    <# Checking if internet access is available #>
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

    <# Releasing private variable #>
    $Private:strURL = $null

}

<# Function to record data/problem #>
Function fncRecordProblem {

    <# Console output #>
    Write-Output "RECORD PROBLEM:"
    Write-Output (Write-Host "ATTENTION: Before you proceed with this option, please close all open applications." -ForegroundColor Red)
    $Private:ReadHost = Read-Host "Only if the above is true, please press [Y]es to continue, or [N]o to cancel"

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "Record Problem" -strLogValue "Initiated"

    <# Actions if yes was selected #>
    If ($Private:ReadHost -Eq "Y") {

        <# Checking if not running as administrator #>
        If ($Global:bolRunningAsAdmin -eq $false) {

            <# Verbose/Logging #>
            Write-Output (Write-Host "ATTENTION: Please note that neither CAPI2 or AIP event logs, network trace nor filter drivers are recorded.`nIf you want a complete record, you must run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions." -ForegroundColor Red)

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

        <# Cleaning MSIP/MSIPC client folders in file system #>
        fncDeleteItem "\\?\$env:LOCALAPPDATA\Microsoft\MSIP"
        fncDeleteItem "\\?\$env:LOCALAPPDATA\Microsoft\MSIPC"

        <# Calling function to enable logging #>
        fncEnableLogging

        <# Console output, after permission check #>
        If ($Global:bolRunningAsAdmin -eq $false) {

            <# Console output, if not running with administrative permissions #>
            Write-Output "Record problem is now activated for user '$Env:UserName'."

        }
        Else {

            <# Console output if running with administrative permissions #>
            Write-Output "Record problem is now activated for administrator '$Env:UserName'."

        }

        <# Console output #>
        Write-Output (Write-Host "IMPORTANT: Now start to reproduce your problem, but leave this window open." -ForegroundColor Red)
        Read-Host "After reproducing the problem, close all applications you have used for, then come back here and press enter to continue"

        <# Console output #>
        Write-Output "Collecting logs, please wait...`n"

        <# Calling function to collect log files #>
        fncCollectLogging
    
        <# Function to disable/rool back logging settings #>
        fncDisableLogging

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncRecordProblem" -strLogDescription "Record Problem" -strLogValue "Proceeded" 

        <# Console output #>
        Write-Output "Log files: $Global:strUniqueLogFolder"
        Write-Output (Write-Host "RECORD PROBLEM: Proceeded.`n" -ForegroundColor Green)

        <# Releasing variable #>
        $Global:strUniqueLogFolder = $null

        <# Signal sound #>
        [console]::beep(1000,200)

    }
    <# Actions if 'No' (cancel) was selected #>
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

            <# Clearing console #>
            Clear-Host

            <# Calling show menu function #>
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
 
            <# Clearing console #>
            Clear-Host
 
            <# Calling show menu function #>
            fncShowMenu    
 
        }

    }

    <# Releasing private variable #>
    $Private:ReadHost = $null

}

<# Function to initialize/enable logging #>
Function fncEnableLogging {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Enable logging" -strLogValue "Triggered"

    <# Implement registry key for function fncValidateForActivatedLogging to check whether logging was left enabled (for problem record) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\RMS_Support_Tool") -Eq $false) { <# Checking, if path exist (to check for logging enabled), and create it if not #>

        <# Create registry key, if does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\RMS_Support_Tool" -Force | Out-Null

    }

    <# Implement registry key to check for enabled logging on next start, and rollback settings if necessary #>
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\RMS_Support_Tool" -Name "LoggingActivated" -Value $true -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null

    <# Progress bar #>
    Write-Progress -Activity " Enable logging..." -PercentComplete 0
    
    <# Checking if running with administrative permissions, and enabling corresponding logs #>
    If ($Global:bolRunningAsAdmin -eq $true) {

        <# Progress bar update #>
        Write-Progress -Activity " Enable logging: CAPI2 event logging..." -PercentComplete (100/8 * 1)

        <# Enable CAPI2 event log #>
        Echo Y | wevtutil set-log Microsoft-Windows-CAPI2/Operational /enabled:True

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "CAPI2 event log" -strLogValue "Enabled"

        <# Clear CAPI2 event log #>
        wevtutil.exe clear-log Microsoft-Windows-CAPI2/Operational
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "CAPI2 event log" -strLogValue "Cleared"


        <# Progress bar update #>
        Write-Progress -Activity " Enable logging: Starting network trace..." -PercentComplete (100/8 * 2)

        <# Start network trace #>
        netsh.exe trace start capture=yes scenario=NetConnection,InternetClient sessionname="RMS_Support_Tool-Trace" report=disabled maxsize=1024, tracefile=$Global:strUniqueLogFolder"\NetMon.etl" | Out-Null
    
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

    <# Check for registry key 'Logging' (2013) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Logging") -Eq $false) {

        <# Create registry key, if does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Logging" -Force | Out-Null

    }

    <# Check for registry key 'Logging' (2016 x64) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\Logging") -Eq $false) {

        <# Create registry key, if does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\Logging" -Force | Out-Null

    }

    <# Check for registry key 'Logging' (2013 x64) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Common\Logging") -Eq $false) {

        <# Create logging registry key, if it does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Common\Logging" -Force | Out-Null

    }

    <# Implementing registry settings to enable logging for the different Office versions #>
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Logging" -Name "EnableLogging" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Logging" -Name "EnableLogging" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Common\Logging" -Name "EnableLogging" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\Logging" -Name "EnableLogging" -Value 1 -PropertyType DWord -Force | Out-Null

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office Logging" -strLogValue "Enabled"

    <# Progress bar update #>
    Write-Progress -Activity " Enable logging: Office TCOTrace..." -PercentComplete (100/8 * 4)

    <# Enable Office TCOTrace logging for Office 2013 (15.0), 2016 (16.0) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Debug") -Eq $false) { <# Check for registry key 'Debug' (2016) #>

        <# Create registry key if it does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Debug" -Force | Out-Null

    }
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Debug" -Name "TCOTrace" -Value 1 -PropertyType DWord -Force | Out-Null

    <# Check for registry key 'Debug'  (2013) #>
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Debug") -Eq $false) { <# Check for registry key 'Debug' (2013) #>

        <# Create registry key if it does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Debug" -Force | Out-Null

    }
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Debug" -Name "TCOTrace" -Value 1 -PropertyType DWord -Force | Out-Null

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office TCOTrace" -strLogValue "Enabled"

    <# Progress bar update #>
    Write-Progress -Activity " Enable logging: Cleaning MSIP/MSIPC logs..." -PercentComplete (100/8 * 5)

    <# Cleaning MSIP/MSIPC/AIP v2 logs folder content #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\MSIP\Logs) -Eq $true) { <# If foler exist #>

        <# Cleaning MSIP/AIP v1/2 log folder content #>
        Remove-Item -Path "\\?\$env:LOCALAPPDATA\Microsoft\MSIP\Logs" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "MSIP log folder" -strLogValue "Cleared"

    }

    <# Checking if MSIPC folder exist #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\MSIPC\Logs) -Eq $true) {

        <# Cleaning MSIPC log folder content #>
        Remove-Item -Path "\\?\$env:LOCALAPPDATA\Microsoft\MSIPC\Logs" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "MSIPC log folder" -strLogValue "Cleared"

    }

    <# Checking if MSIP folder exist #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\MSIP\mip) -Eq $true) {

        <# Cleaning MIP SDK/AIP v2 log folder content #>
        Remove-Item -Path "\\?\$env:LOCALAPPDATA\Microsoft\MSIP\mip" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "MIP log folder" -strLogValue "Cleared"

    }

    <# Checking if MIP folder exist #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\Office\DLP\mip) -Eq $true) {

        <# Cleaning Office DLP/MIP log folder content #>
        Remove-Item -Path "\\?\$env:LOCALAPPDATA\Microsoft\Office\DLP\mip" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office DLP/MIP log folder" -strLogValue "Cleared"

    }

    <# If foler exist #>
    If ($(Test-Path -Path $env:TEMP\Diagnostics) -Eq $true) {

        <# Cleaning Office Diagnostics folder content #>
        Remove-Item -Path "\\?\$env:TEMP\Diagnostics" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
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
    psr.exe /gui 0 /start /output $Global:strUniqueLogFolder"\ProblemSteps.zip"
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "PSR" -strLogValue "Started"

    <# Cleaning temp folder for office.log (TCOTrace) #>
    If ($(Test-Path $Global:strTempFolder"\office.log") -Eq $true) {
    
        <# Removing file office.log #>
        Remove-Item -Path "\\?\$Global:strTempFolder\office.log" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office TCOTrace temp file" -strLogValue "Cleared"
    
    }

    <# Cleaning temp folder for office log (machine name) #>
    If ($(Test-Path "$Global:strTempFolder\$([System.Environment]::MachineName)*.log") -Eq $true) {
    
        <# Removing file office.log #>
        Remove-Item -Path "\\?\$Global:strTempFolder\$([System.Environment]::MachineName)*.log" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Office log temp file" -strLogValue "Cleared"
    
    }

    <# Progress bar update #>
    Write-Progress -Activity "  Logging enabled" -Completed

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncEnableLogging" -strLogDescription "Enable logging" -strLogValue "Proceeded" 

}

<# Function to disable/rool back all logging settings #>
Function fncDisableLogging {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "Disable logging" -strLogValue "Triggered" 

    <# Progress bar #>
    Write-Progress -Activity " Disable logging..." -PercentComplete 0

    <# Checking if running with administrative permissions, and enabling admininistrative actions #>
    If ($Global:bolRunningAsAdmin -eq $true) {

        <# Progress bar update #>
        Write-Progress -Activity " Disable logging: CAPI2 event log..." -PercentComplete (100/6 * 1) 

        <# Disable CAPI2 event log #>
        wevtutil.exe set-log Microsoft-Windows-CAPI2/Operational /enabled:false
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "CAPI2 event log" -strLogValue "Disabled"

        <# Progress bar update #>
        Write-Progress -Activity " Disable logging: Network trace..." -PercentComplete (100/6 * 2)

        <# Stopping network trace #>
        netsh.exe trace stop sessionname="RMS_Support_Tool-Trace" | Out-Null
    
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
    If ($(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\RMS_Support_Tool") -Eq $false) { <# Checking, if path exist (to check for logging enabled), and create it if not #>

        <# Create registry key if it does not exist #>
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\RMS_Support_Tool" -Force | Out-Null

    }

    <# Implement registry key to check for enabled logging on next start, and rollback settings if necessary #>
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\RMS_Support_Tool" -Name "LoggingActivated" -Value $false -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null

    <# Progress bar update #>
    Write-Progress -Activity " Logging disabled" -Completed

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncDisableLogging" -strLogDescription "Disable logging" -strLogValue "Proceeded" 

}

<# Function to check whether logging (for problem record) was left enabled #>
Function fncValidateForActivatedLogging {

    <# Reading registry key to check for enabled logging. Used in fncEnableLogging, and fncDisableLogging #>
    If ((Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\RMS_Support_Tool" -Name LoggingActivated -ErrorAction SilentlyContinue).LoggingActivated -eq $true) {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncValidateForActivatedLogging" -strLogDescription "Disable logging" -strLogValue "Initiated" 
        
        <# Function call to disable/rool back all logging settings #>
        fncDisableLogging

    }

}

<# Function to finalize logging (collecting/exporting data) #>
Function fncCollectLogging {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Collecting logs" -strLogValue "Triggered" 

    <# Progress bar #>
    Write-Progress -Activity " Collecting logs..." -PercentComplete 0

    <# Checking if running with administrative permissons, and enabling admininistrative actions #>
    If ($Global:bolRunningAsAdmin -eq $true) {

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: CAPI2 event log..." -PercentComplete (100/25 * 1)

        <# Export CAPI2 event log #>
        wevtutil.exe export-log Microsoft-Windows-CAPI2/Operational $Global:strUniqueLogFolder"\CAPI2.evtx" /overwrite:true
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export CAPI2 event log" -strLogValue "CAPI2.evtx"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: AIP event log..." -PercentComplete (100/25 * 2)

        <# Actions when AIP event log exist #>
        If ([System.Diagnostics.EventLog]::Exists('Azure Information Protection') -Eq $true) {

            <# Export AIP event log #>
            wevtutil.exe export-log "Azure Information Protection" $Global:strUniqueLogFolder"\AIP.evtx" /overwrite:true
        
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export AIP event log" -strLogValue "AIP.evtx"

        }

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Network trace..." -PercentComplete (100/25 * 3)

        <# Stopping network trace #>
        netsh.exe trace stop sessionname="RMS_Support_Tool-Trace" | Out-Null

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Network trace" -strLogValue "Stopped"
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export network trace" -strLogValue "NetMon.etl"

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Filter drivers..." -PercentComplete (100/25 * 4)

        <# Export filter drivers #>
        fltmc.exe filters > $Global:strUniqueLogFolder"\Filters.log"

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
    wevtutil.exe export-log Application $Global:strUniqueLogFolder"\Application.evtx" /overwrite:true

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Application event log" -strLogValue "Application.evtx"

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: System event log..." -PercentComplete (100/25 * 7)

    <# Export System event log #>
    wevtutil.exe export-log System $Global:strUniqueLogFolder"\System.evtx" /overwrite:true
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export System event log" -strLogValue "System.evtx"

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: Office log files..." -PercentComplete (100/25 * 8)

    <# Checking for Office log path and create it, if it not exist #>
    If ($(Test-Path -Path $Global:strUniqueLogFolder"\Office") -Eq $false) {

        <# Creating Office log folder #>
        New-Item -ItemType Directory -Force -Path $Global:strUniqueLogFolder"\Office" | Out-Null
        
        <# Checking for Office MIP path, and create it only if no AIP client is installed; because with AIP client we collect already the mip folder with the AIPLogs.zip #>
        If (-not (Get-Module -ListAvailable -Name AzureInformationProtection)) { <# Checking for AIP client #>

            <# Creating Office MIP log folder #>
            New-Item -ItemType Directory -Force -Path $Global:strUniqueLogFolder"\Office\mip" | Out-Null

            <# Export Office MIP content to logs folder #>
            fncCopyItem $env:LOCALAPPDATA\Microsoft\Office\DLP\mip $Global:strUniqueLogFolder"\Office" "mip\*"

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Office MIP logs" -strLogValue "\Office\mip"

        }

    }

    <# Copy Office Diagnostics folder from temp folder to Office logs folder #>
    fncCopyItem $env:TEMP\Diagnostics $Global:strUniqueLogFolder"\Office" "Diagnostics\*"

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Office Diagnostics logs" -strLogValue "\Office\Diagnostics"

    <# Copy office log files from temp folder to logs folder #>
    fncCopyItem $Global:strTempFolder"\office.log" $Global:strUniqueLogFolder"\Office\office.log" "office.log"

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Office log" -strLogValue "office.log"

    <# Copy Office logging files for 2013 (15.0), 2016 (16.0) to logs folder #>
    fncCopyItem "\\?\$Global:strTempFolder\$([System.Environment]::MachineName)*.log" $Global:strUniqueLogFolder"\Office" "Office\$([System.Environment]::MachineName)*.log"

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Office log" -strLogValue "\Office"

    <# Cleaning Office log files from temp folder #>
    fncDeleteItem "\\?\$Global:strTempFolder\$([System.Environment]::MachineName)*.log"
    fncDeleteItem "\\?\$Global:strTempFolder\Office.log"

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: AIP/MSIP/MSIPC/MIP logs..." -PercentComplete (100/25 * 9)

    <# Export MIP/MSIP/MSIPC folders (and more) to logs folder #>
    If (Get-Module -ListAvailable -Name AzureInformationProtection) { <# Checking for AIP client and collecting folder content #>

        <# Feeding variable with AIP client version information #>
        $strAIPClientVersion = $((Get-Module -ListAvailable -Name AzureInformationProtection).Version).ToString()

        <# Action with AIPv1 client #>
        If ($strAIPClientVersion.StartsWith("1") -eq $true) {
            
            <# Copy MSIP content to logs folder #>
            fncCopyItem $env:LOCALAPPDATA\Microsoft\MSIP $Global:strUniqueLogFolder"\MSIP" "MSIP\*"

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export MSIP content" -strLogValue "\MSIP"

            <# Copy MSIPC content to logs folder #>
            fncCopyItem $env:LOCALAPPDATA\Microsoft\MSIPC $Global:strUniqueLogFolder"\MSIPC" "MSIPC\*"

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export MSIPC content" -strLogValue "\MSIPC"

        }
        <# Action with AIPv2 client #>
        ElseIf ($strAIPClientVersion.StartsWith("2") -eq $true) {

            <# Remember default progress bar status: 'Continue' #>
            $Private:strOriginalPreference = $Global:ProgressPreference 
            $Global:ProgressPreference = "SilentlyContinue" <# Hiding progress bar #>
            
            <# Exporting AIP log folders #>
            Export-AIPLogs -FileName "$Global:strUniqueLogFolder\AIPLogs.zip" | Out-Null
            
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export AIP Log folders" -strLogValue $true

            <# Set back progress bar to previous setting #>
            $Global:ProgressPreference = $Private:strOriginalPreference

        }

    }
    Else {<# Action without any AIP client #>

        <# Export Office MIP content to logs folder #>
        fncCopyItem $env:LOCALAPPDATA\Microsoft\Office\DLP\mip $Global:strUniqueLogFolder"\Office" "mip\*"

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Office MIP content" -strLogValue "\Office"

        <# Export Office Diagnostics content to logs folder #>
        fncCopyItem $env:TEMP\Diagnostics $Global:strUniqueLogFolder"\Office" "Diagnostics\*"

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Office Diagnostics content" -strLogValue "\Office"

        <# Export MSIP/MSIPC content to logs folder #>
        fncCopyItem $env:LOCALAPPDATA\Microsoft\MSIP $Global:strUniqueLogFolder"\MSIP" "MSIP\*"

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export MSIP content" -strLogValue "\MSIP"

        <# Copy files to logs folder #>
        fncCopyItem $env:LOCALAPPDATA\Microsoft\MSIPC $Global:strUniqueLogFolder"\MSIPC" "MSIPC\*"

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export MSIPC content" -strLogValue "\MSIPC"

    }

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: WinHTTP..." -PercentComplete (100/25 * 10)

    <# Export WinHTTP #>
    netsh.exe winhttp show proxy > $Global:strUniqueLogFolder"\WinHTTP.log"
    
    <# Verbose/Logging #>
    fncLOgging -strLogFunction "fncCollectLogging" -strLogDescription "Export WinHTTP" -strLogValue "WinHTTP.log"

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: WinHTTP (WoW6432)..." -PercentComplete (100/25 * 11)

    <# Export WinHTTP_WoW6432 (only 64-bit OS) #>
    If ((Get-CimInstance Win32_OperatingSystem  -Verbose:$false).OSArchitecture -eq "64-bit") {

        & $env:WINDIR\SysWOW64\netsh.exe winhttp show proxy > $Global:strUniqueLogFolder"\WinHTTP_WoW6432.log"
       
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
        Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object AutoConfigURL > $Global:strUniqueLogFolder"\AutoConfigURL.log"

    }

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: Machine certificates..." -PercentComplete (100/25 * 13)

    <# Export machine certificates #>
    certutil.exe -silent -store my > $Global:strUniqueLogFolder"\CertMachine.log"
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export machine certificates" -strLogValue "CertMachine.log"

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: User certificates..." -PercentComplete (100/25 * 14)

    <# Export user certificates #>
    certutil.exe -silent -user -store my > $Global:strUniqueLogFolder"\CertUser.log"
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export user certificates" -strLogValue "CertUser.log"

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: Credentials information..." -PercentComplete (100/25 * 15)

    <# Export Credential Manager data #>
    cmdkey.exe /list > $Global:strUniqueLogFolder"\CredMan.log"
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Credential Manager" -strLogValue "CredMan.log"

   <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: IP configuration..." -PercentComplete (100/25 * 16)

    <# Export IP configuration #>
    ipconfig.exe /all > $Global:strUniqueLogFolder"\IPConfigAll.log"
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export ipconfig" -strLogValue "IPConfigAll.log"

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: DNS..." -PercentComplete (100/25 * 17)

    <# Export DNS configuration  #>
    ipconfig.exe /displaydns > $Global:strUniqueLogFolder"\WinIPConfig.txt" | Out-Null
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export DNS" -strLogValue "WinIPConfig.txt"

   <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: Environment information..." -PercentComplete (100/25 * 18)

    <# Export environment variables #>
    Get-ChildItem Env: | Out-File $Global:strUniqueLogFolder"\EnvVar.log"
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export environment variables" -strLogValue "EnvVar.log"

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: Group policy report..." -PercentComplete (100/25 * 19)
    
    <# Export group policy results #>
    gpresult /f /h $Global:strUniqueLogFolder"\Gpresult.htm" | Out-Null
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export group policy report" -strLogValue "Gpresult.htm"

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: Time zone information..." -PercentComplete (100/25 * 20)

    <# Export timezone offse (UTC) #>
    (Get-Timezone).BaseUTCOffset.Hours | Out-File $Global:strUniqueLogFolder"\BaseUTCOffset.log"
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export timezone offset" -strLogValue "BaseUTCOffset.log"

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: Tasklist..." -PercentComplete (100/25 * 21)

    <# Export Tasklist #>
    Tasklist.exe /svc > $Global:strUniqueLogFolder"\Tasklist.log"
    
    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Tasklist" -strLogValue "Tasklist.log"

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: Programs and Features..." -PercentComplete (100/25 * 22)

    <# Export Programs and Features (32) #>
    If ($(Test-Path -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") -Eq $true) {

        <# Programs32 #>
        Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-CSV $Global:strUniqueLogFolder"\Programs32.log" -ErrorAction SilentlyContinue

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Programs (x86)" -strLogValue "Programs32.log" 

    }
    
    <# Export Programs and Features (64) #>
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-CSV $Global:strUniqueLogFolder"\Programs64.log" -ErrorAction SilentlyContinue

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Programs (x64)" -strLogValue "Programs64.log"

    <# Progress bar update #>
    Write-Progress -Activity " Collecting logs: AIP registry keys..." -PercentComplete (100/25 * 24)
    
    <# Export AIP plugin Adobe Acrobat RMS logs #>
    If ($(Test-Path -Path $env:LOCALAPPDATA\Microsoft\RMSLocalStorage\MIP\logs) -Eq $true) {

        <# Progress bar update #>
        Write-Progress -Activity " Collecting logs: Adobe logs..." -PercentComplete (100/25 * 24)

        <# Export MSIP/MSIPC content to logs folder #>
        fncCopyItem $env:LOCALAPPDATA\Microsoft\RMSLocalStorage\MIP\logs $Global:strUniqueLogFolder"\Adobe\LOCALAPPDATA" "Adobe\LOCALAPPDATA\*"

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Adobe logs" -strLogValue "\Adobe"

    }

    <# Export AIP plugin Adobe Acrobat RMS logs #>
    If ($(Test-Path -Path $env:USERPROFILE\appdata\locallow\Microsoft\RMSLocalStorage\mip\logs) -Eq $true) {

        <# Export MSIP/MSIPC content to logs folder #>
        fncCopyItem $env:USERPROFILE\appdata\locallow\Microsoft\RMSLocalStorage\mip\logs $Global:strUniqueLogFolder"\Adobe\USERPROFILE" "Adobe\USERPROFILE\*"

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export Adobe logs" -strLogValue "\Adobe"

    }

    <# Export several registry keys: Defining an array and feeding it with related registry keys #>
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

    <# Inserting first information; create log file #>
    "Windows Registry Editor Version 5.00" | Set-Content "$Global:strUniqueLogFolder\Registry.log"

    <# Reading data from cached temp file, and add it to the logfile #>
    (Get-Content "$Global:strTempFolder\*.reg" | ? {$_ -ne "Windows Registry Editor Version 5.00"} | Add-Content "$Global:strUniqueLogFolder\Registry.log")

    <# Cleaning temp folder of cached files #>
    Remove-Item "\\?\$Global:strTempFolder\*.reg" -Force -ErrorAction SilentlyContinue | Out-Null

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Export AIP registry keys" -strLogValue "Registry.log"

    <# Progress bar update #>
    Write-Progress -Activity " Logs collected" -Completed

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectLogging" -strLogDescription "Collecting logs" -strLogValue "Proceeded" 

}

<# Function to check and update needed modules for PowerShellGallery.com #>
Function fncUpdateRequiredModules {

    <# Checking for AADRM module and uninstalling it (AADRM retired, and replaced by AIPservice: https://docs.microsoft.com/en-us/powershell/azure/aip/overview?view=azureipps) #>
    If (Get-Module -ListAvailable -Name AADRM) {

        <# Unstalling AADRM PowerShell module #>
        Uninstall-Module -Verbose:$false -Name AADRM | Out-Null 

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AADRM module" -strLogValue "Removed"

    }

    <# Define powershellgallery.com as trusted location, to be able to install AIPService module #>
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose:$false | Out-Null

    <# Remember default progress bar status: 'Continue' #>
    $Private:strOriginalPreference = $Global:ProgressPreference 
    $Global:ProgressPreference = "SilentlyContinue" <# Hiding progress bar #>

    <# Validating connection to PowerShell Gallery by Find-Module #>
    If (Find-PackageProvider -Name NuGet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) { <# Actions if PowerShell Gallery can be reached #>

        <# Install/update nuGet provider to be able to install the latest modules #>
        Install-PackageProvider -Name NuGet -MinimumVersion "2.8.5.208" -ForceBootstrap -Scope CurrentUser -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose:$false | Out-Null

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "NuGet version" -strLogValue (Find-PackageProvider -Verbose:$false -Name NuGet).Version

    }
    Else { <# Actions if PowerShell Gallery can not be reached (no internet connection) #>

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "NuGet update" -strLogValue "Failed"

    }

    <# Set back progress bar to previous setting #>
    $Global:ProgressPreference = $Private:strOriginalPreference

    <# Validating connection to PowerShell Gallery #>
    If (Get-Module -ListAvailable -Name "AIPService") {

        <# Updating AIPService if we can connect to PowerShell Gallery #>
        If (Find-Module -Name AIPService -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Filling variables with version information #>
            [Version]$Private:strAIPOnlineVersion = (Find-Module -Name AIPService -Repository PSGallery).Version
            [Version]$Private:strAIPLocalVersion = (Get-Module -ListAvailable -Name "AIPService").Version | Select-Object -First 1

            <# Comparing local version vs. online version #>
            If ([Version]::new($Private:strAIPOnlineVersion.Major, $Private:strAIPOnlineVersion.Minor, $Private:strAIPOnlineVersion.Build, $Private:strAIPOnlineVersion.Revision) -gt [Version]::new($Private:strAIPLocalVersion.Major, $Private:strAIPLocalVersion.Minor, $Private:strAIPLocalVersion.Build, $Private:strAIPLocalVersion.Revision) -eq $true) {

                <# Console output #>
                Write-Output "Updating AIPService module..."

                <# Updating AIPService PowerShell module #>
                Update-Module -Verbose:$false -Name AIPService -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService module" -strLogValue "Updated"

            }

            <# Releasing private variables #>
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

        <# Installing AIPService if we can connect to PowerShell Gallery #>
        If (Find-Module -Name AIPService -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Console output #>
            Write-Output "Intalling AIPService module..."

            <# Installing AIPService PowerShell module #>
            Install-Module -Verbose:$false -Name AIPService -Repository PSGallery -Scope CurrentUser -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncUpdateRequiredModules" -strLogDescription "AIPService module" -strLogValue "Installed"

            <# Console output #>
            Write-Output "AIPService module installed."

            <# Console output #>
            Write-Output (Write-Host "ATTENTION: To use AIPService cmdlets, you must close this window and run a new instance of PowerShell for it to work.`nThe RMS_Support_Tool is now terminated." -ForegroundColor Red)

            <# Signal sound #>
            [console]::beep(500,200)

            <# Calling pause function #>
            fncPause
    
            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Interrupting, because of module not loaded into PowerShell instance #>
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

<# Function to collect AIP service configuration #>
Function fncCollectAIPServiceConfiguration {

    <# Console output #>
    Write-Output "COLLECT AIP SERVICE CONFIGURATION:"

    <# Checking if not running as administrator #>
    If ($Global:bolRunningAsAdmin -eq $false) {

        <# Console output #>
        Write-Output (Write-Host "ATTENTION: You must run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions to continue with this option.`nCOLLECT AIP SERVICE CONFIGURATION: Failed.`n" -ForegroundColor Red)

        <# Signal sound #>
        [console]::beep(500,200)

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Calling pause function #>
            fncPause

            <# Clearing console #>
            Clear-Host

            <# Calling show menu function #>
            fncShowMenu    

        }

    }

    <# Console output #>
    Write-Output "Initializing, please wait..."

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectAIPServiceConfiguration" -strLogDescription "Collect AIP service configuration" -strLogValue "Initiated"

    <# Check and update needed modules for PowerShellGallery.com #>
    fncUpdateRequiredModules

    <# Console output #>
    Write-Output "Connecting to AIPService..."

    <# Connecting/logon to AIPService #>
    If (Connect-AIPService -Verbose:$false) { <# Action if AIPService connection was opened #>

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
    
        <# Signal sound #>
        [console]::beep(500,200)

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Calling pause function #>
            fncPause

            <# Clearing console #>
            Clear-Host

            <# Calling show menu function #>
            fncShowMenu    

        }

    }

    <# Checking if 'Collect'-folder exist and create it, if it not exist #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect" | Out-Null <# Defining Collect path #>

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
        $Private:LicensingIntranetDistributionPointUrl = (Get-AipServiceConfiguration).LicensingIntranetDistributionPointUrl <# Filling private variable #>
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
            
        <# Releasing AipServiceDoNotTrackUserGroup variable #>
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
            
        <# Releasing AipServiceRoleBasedAdministrator variable #>
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

        <# Exit function #>
        Break

    }

    <# Action if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {

        <# Calling pause function #>
        fncPause

        <# Clearing console #>
        Clear-Host

        <# Calling show menu function #>
        fncShowMenu    

    }

}

<# Function to collect AIP protection templates #>
Function fncCollectAIPProtectionTemplates {

    <# Console output #>
    Write-Output "COLLECT AIP PROTECTION TEMPLATES:"

    <# Checking if not running as administrator #>
    If ($Global:bolRunningAsAdmin -eq $false) {

        <# Console output #>
        Write-Output (Write-Host "ATTENTION: You must run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions to continue with this option.`nCOLLECT AIP PROTECTION TEMPLATES: Failed.`n" -ForegroundColor Red)

        <# Signal sound #>
        [console]::beep(500,200)

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Calling pause function #>
            fncPause

            <# Clearing console #>
            Clear-Host

            <# Calling show menu function #>
            fncShowMenu    

        }

    }

    <# Console output #>
    Write-Output "Initializing, please wait..."

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectAIPProtectionTemplates" -strLogDescription "Collect AIP protection templates" -strLogValue "Initiated"

    <# Check and update needed modules for PowerShell Gallery #>
    fncUpdateRequiredModules

    <# Console output #>
    Write-Output "Connecting to AIPService..."

    <# Connecting/logon to AIPService #>
    If (Connect-AIPService -Verbose:$false) { <# Action if AIPService connection was opened #>

        <# Console output #> 
        Write-Output "AIPService connected."

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectAIPProtectionTemplates" -strLogDescription "AIPService connected" -strLogValue $true

    }
    Else{ <# Action if AIPService connection failed #>

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectAIPProtectionTemplates" -strLogDescription "AIPService connected" -strLogValue $false 
        fncLogging -strLogFunction "fncCollectAIPProtectionTemplates" -strLogDescription "Collect AIP protection templates" -strLogValue "Login failed"
    
        <# Console output #>
        Write-Output (Write-Host "COLLECT AIP PROTECTION TEMPLATES: Login failed. Please try again.`n" -ForegroundColor Red)
    
        <# Signal sound #>
        [console]::beep(500,200)

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Calling pause function #>
            fncPause

            <# Clearing console #>
            Clear-Host

            <# Calling show menu function #>
            fncShowMenu    

        }

    }

    <# Checking if 'Collect'-folder exist and create it, if not #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect" | Out-Null <# Defining Collect path #>

    }

    <# Check for existing log file and create it, if it not exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\AIPProtectionTemplates.log") -Eq $false) {

        <# Create AIPService logging file #>
        Out-File -FilePath $Global:strUserLogPath"\Collect\AIPProtectionTemplates.log" -Encoding UTF8 -Append -Force

    }

    <# Console output #> 
    Write-Output "Collecting AIP protection templates..."
    
    <# Check for existing log file and extend it, if it exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\AIPProtectionTemplates.log") -Eq $true) { <# Exporting AIP protection templates and output result: #>

        <# Collect AIP protection templates #>
        $Private:Timestamp = (Get-Date -Verbose:$false -UFormat "%y%m%d-%H%M%S") <# Filling private variable with date/time #>
        ("Date/Timestamp               : " + $Private:Timestamp) | Out-File $Global:strUserLogPath"\Collect\AIPProtectionTemplates.log" -Encoding UTF8 -Append <# Extend log file with date/time #>
            
        <# Releasing date/time variable #>
        $Private:Timestamp = $null 

        <# Add template details #>
        Get-AipServiceConfiguration | Select-Object -ExpandProperty Templates | Out-File $Global:strUserLogPath"\Collect\AIPProtectionTemplates.log" -Encoding UTF8 -Append <# Extending log file with template summary #>
        Get-AIPServicetemplate | fl * | Out-File $Global:strUserLogPath"\Collect\AIPProtectionTemplates.log" -Encoding UTF8 -Append <# Extending log file with template details #>

    }

    <# Disconnect from AIPService #>
    Disconnect-AIPService | Out-Null

    <# Console output #>
    Write-Output "AIPService disconnected.`n"

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectAIPProtectionTemplates" -strLogDescription "AIPService disconnected" -strLogValue $true
    fncLogging -strLogFunction "fncCollectAIPProtectionTemplates" -strLogDescription "Export AIP Templates" -strLogValue "AIPProtectionTemplates.log"
    fncLogging -strLogFunction "fncCollectAIPProtectionTemplates" -strLogDescription "Collect AIP protection templates" -strLogValue "Proceeded"

    <# Console output #> 
    Write-Output "Log file: $Global:strUserLogPath\Collect\AIPProtectionTemplates.log"
    Write-Output (Write-Host "COLLECT AIP PROTECTION TEMPLATES: Proceeded.`n" -ForegroundColor Green)

    <# Action if function was called from command line #>
    If ($Global:bolCommingFromMenu -eq $false) {

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Exit function #>
        Break

    }

    <# Action if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {

        <# Calling pause function #>
        fncPause

        <# Clearing console #>
        Clear-Host

        <# Calling show menu function #>
        fncShowMenu    

    }

}

<# Function to collect labels and policies from Security Center #>
Function fncCollectMSCLabelsAndPolicies {

    <# Console output #>
    Write-Output "COLLECT MSC LABELS AND POLICIES:"

    <# Checking if not running as administrator #>
    If ($Global:bolRunningAsAdmin -eq $false) {

        <# Console output #>
        Write-Output (Write-Host "ATTENTION: You must run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions to continue with this option.`nCOLLECT MSC LABELS AND POLICIES: Failed.`n" -ForegroundColor Red)

        <# Signal sound #>
        [console]::beep(500,200)

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Calling pause function #>
            fncPause

            <# Clearing console #>
            Clear-Host

            <# Calling show menu function #>
            fncShowMenu    

        }

    }

    <# Console output #>
    Write-Output "Initializing, please wait..."

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectMSCLabelsAndPolicies" -strLogDescription "Collect MSC labels and policies" -strLogValue "Initiated"

    <# Check and update needed modules for PowerShell Gallery #>
    fncUpdateRequiredModules

    <# Actions if ExchangeOnlineManagement module is installed #>
    If (Get-Module -ListAvailable -Name "ExchangeOnlineManagement") {

        <# Updating ExchangeOnlineManagement, if we can connect to PowerShell Gallery #>
        If (Find-Module -Name ExchangeOnlineManagement -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Filling variables with version information #>
            [Version]$Private:strEOPOnlineVersion = (Find-Module -Name ExchangeOnlineManagement -Repository PSGallery).Version
            [Version]$Private:strAIPLocalVersion = (Get-Module -ListAvailable -Name "AIPService").Version | Select-Object -First 1

            <# Comparing local version vs. online version #>
            If ([Version]::new($Private:strEOPPOnlineVersion.Major, $Private:strEOPPOnlineVersion.Minor, $Private:strEOPPOnlineVersion.Build) -gt [Version]::new($Private:strEOPLocalVersion.Major, $Private:strEOPLocalVersion.Minor, $Private:strEOPLocalVersion.Build) -eq $true) {

                <# Console output #>
                Write-Output "Updating Exchange Online PowerShell V2 module..."

                <# Updating AIPService PowerShell module #>
                Update-Module -Verbose:$false -Name ExchangeOnlineManagement -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncCollectMSCLabelsAndPolicies" -strLogDescription "Exchange Online PowerShell V2 module" -strLogValue "Updated"

            }

            <# Releasing private variables #>
            [Version]$Private:strEOPOnlineVersion = $null
            [Version]$Private:strEOPLocalVersion = $null

        }
        Else { <# Actions if we can't connect to PowerShell Gallery (no internet connection) #>

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectMSCLabelsAndPolicies" -strLogDescription "Exchange Online PowerShell V2 module update" -strLogValue "Failed"

        }

    }

    <# Actions if ExchangeOnlineManagement module isn't installed #>
    If (-Not (Get-Module -ListAvailable -Name "ExchangeOnlineManagement")) {

        <# Installing ExchangeOnlineManagement if we can connect to PowerShell Gallery #>
        If (Find-Module -Name ExchangeOnlineManagement -Repository PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) {

            <# Console output #>
            Write-Output "Installing Exchange Online PowerShell V2 module..."

            <# Installing ExchangeOnlineManagement PowerShell module #>
            Install-Module -Verbose:$false -Name ExchangeOnlineManagement -Scope CurrentUser -Repository PSGallery -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectMSCLabelsAndPolicies" -strLogDescription "Exchange Online PowerShell V2 module" -strLogValue "Installed"

            <# Console output #>
            Write-Output "Exchange Online PowerShell V2 module installed."
            Write-Output (Write-Host "ATTENTION: To use Exchange Online PowerShell V2 cmdlets, you must close this window and run a new instance of PowerShell for it to work.`n           The RMS_Support_Tool is now terminated." -ForegroundColor Red)

            <# Calling pause function #>
            fncPause
    
            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Releasing private variables #>
            $Private:ReadHost = $null

            <# Interrupting, because of module not loaded into PowerShell instance #>
            Break

        }
        Else { <# Actions if we can't connect to PowerShell Gallery (no internet connection) #>

            <# Console output #>
            Write-Output (Write-Host "ATTENTION: Collecting MSC labels and policies could not be performed.`nEither PowerShell Gallery cannot be reached or there is no connection to the Internet.`n`nYou must have Exchange Online PowerShell V2 module installed to proceed.`n`nPlease check the following website and install the latest version of the ExchangeOnlineManagement modul:`nhttps://www.powershellgallery.com/packages/ExchangeOnlineManagement`n" -ForegroundColor Red)

            <# Signal sound #>
            [console]::beep(500,200)

            <# Console output #>
            Write-Output (Write-Host "COLLECT MSC LABELS AND POLICIES: Failed.`n" -ForegroundColor Red)

            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncCollectMSCLabelsAndPolicies" -strLogDescription "Exchange Online PowerShell V2 module installation" -strLogValue "Failed"

            <# Action if function was called from the menu #>
            If ($Global:bolCommingFromMenu -eq $true) {

                <# Calling pause function #>
                fncPause
    
                <# Clearing console #>
                Clear-Host

                <# Calling show menu function #>
                fncShowMenu

            }

            <# Action if function was called from command line #>
            If ($Global:bolCommingFromMenu -eq $false) {
   
                <# Set back window title to default #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                <# Interrupting, because of missing internet connection #>
                Break

            }

        }

    }

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectMSCLabelsAndPolicies" -strLogDescription "Exchange Online PowerShell V2 module version" -strLogValue (Get-Module -Verbose:$false -ListAvailable -Name ExchangeOnlineManagement).Version

    <# Console output #>
    Write-Output "Connecting to Microsoft 365 Security Center (MSC)..."

    <# Remember default progress bar status: 'Continue' #>
    $Private:strOriginalPreference = $Global:ProgressPreference 
    $Global:ProgressPreference = "SilentlyContinue" <# Hiding progress bar #>

    <# Try to connect/logon to Security Center (MSC) #>
    Try {

        <# Connect/logon to MSC #>
        Connect-IPPSSession -Verbose:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

    }
    Catch { <# Catch action for any error that occur on connect/logon #>

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCollectMSCLabelsAndPolicies" -strLogDescription "Microsoft 365 Security Center (MSC) connected" -strLogValue $false 
        fncLogging -strLogFunction "fncCollectMSCLabelsAndPolicies" -strLogDescription "Microsoft 365 Security Center (MSC)" -strLogValue "Login failed"
    
        <# Console output #>
        Write-Output (Write-Host "COLLECT MSC LABELS AND POLICIES: Login failed. Please try again.`n" -ForegroundColor Red)

        <# Signal sound #>
        [console]::beep(500,200)

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {

            <# Calling pause function #>
            fncPause
    
            <# Clearing console #>
            Clear-Host

            <# Calling show menu function #>
            fncShowMenu

        }

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {
    
            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Interrupting, because of missing internet connection #>
            Break

        }

    }

    <# Console output #> 
    Write-Output "Microsoft 365 Security Center (MSC) connected."

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectMSCLabelsAndPolicies" -strLogDescription "Microsoft 365 Security Center (MSC) connected" -strLogValue $true
    
    <# Console output #> 
    Write-Output "Collecting MSC labels and policies..."

    <# Checking if 'Collect'-folder exist and create it, if not #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Collect") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Collect" | Out-Null <# Defining Collect path #>

    }

    <# Check for existing MSCLabelsAndPolicies.log file and create it, if it not exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\MSCLabelsAndPolicies.log") -Eq $false) {

        <# Create CollectLabels.log logging file #>
        Out-File -FilePath $Global:strUserLogPath"\Collect\MSCLabelsAndPolicies.log" -Encoding UTF8 -Append -Force

    }

    <# Check for existing CollectLabels.log file and extend it, if it exist #>
    If ($(Test-Path $Global:strUserLogPath"\Collect\MSCLabelsAndPolicies.log") -Eq $true) {

        <# Collecting data #>
        Add-Content -Path $Global:strUserLogPath"\Collect\MSCLabelsAndPolicies.log" -Value "CURRENT POLICY:`n"
        (Get-LabelPolicy).Name | ft -AutoSize | Out-File $Global:strUserLogPath"\Collect\MSCLabelsAndPolicies.log" -Encoding UTF8 -Append -Force | Format-List 
        Add-Content -Path $Global:strUserLogPath"\Collect\MSCLabelsAndPolicies.log" -Value "`nALL LABELS:"
        Get-Label | ft -AutoSize | Out-File $Global:strUserLogPath"\Collect\MSCLabelsAndPolicies.log" -Encoding UTF8 -Append -Force
        Add-Content -Path $Global:strUserLogPath"\Collect\MSCLabelsAndPolicies.log" -Value "ALL LABELS WITH DETAILS:"
        Get-Label | fl * | Out-File $Global:strUserLogPath"\Collect\MSCLabelsAndPolicies.log" -Encoding UTF8 -Append -Force
        Add-Content -Path $Global:strUserLogPath"\Collect\MSCLabelsAndPolicies.log" -Value "LABEL POLICIES:"
        Get-LabelPolicy | Out-File $Global:strUserLogPath"\Collect\MSCLabelsAndPolicies.log" -Encoding UTF8 -Append -Force

    }

    <# Disconnect from MSC/Exchange Online Protection (EOP) #>
    Remove-PSSession -ComputerName (Get-PSSession).ComputerName

    <# Set back progress bar to previous default #>
    $Global:ProgressPreference = $Private:strOriginalPreference

    <# Console output #>
    Write-Output "Microsoft 365 Security Center (MSC) disconnected."

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCollectMSCLabelsAndPolicies" -strLogDescription "Microsoft 365 Security Center (MSC) disconnected" -strLogValue $true
    fncLogging -strLogFunction "fncCollectMSCLabelsAndPolicies" -strLogDescription "Export labels and policy" -strLogValue "MSCLabelsAndPolicies.log"
    fncLogging -strLogFunction "fncCollectMSCLabelsAndPolicies" -strLogDescription "Collect MSC labels and policies" -strLogValue "Proceeded"

    <# Console output #> 
    Write-Output "`nLog file: $Global:strUserLogPath\Collect\MSCLabelsAndPolicies.log"
    Write-Output (Write-Host "COLLECT MSC LABELS AND POLICIES: Proceeded.`n" -ForegroundColor Green)

    <# Signal sound #>
    [console]::beep(1000,200)

    <# Action if function was called from the menu #>
    If ($Global:bolCommingFromMenu -eq $true) {

        <# Calling pause function #>
        fncPause
    
        <# Clearing console #>
        Clear-Host

        <# Calling show menu function #>
        fncShowMenu

    }

    <# Action if function was called from command line #>
    If ($Global:bolCommingFromMenu -eq $false) {
   
        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

        <# Interrupting, because of missing internet connection #>
        Break

    }

}
        
<# Function to verify Endpoint URL http status code/used in function fncVerifyIssuer #>
Function fncVerifyEndpoint ($strURL, $strEndpointName) {

    <# Checking for endpoints to extend #>
    If ($strEndpointName -Eq "LicensingIntranetDistributionPointUrl" -or $strEndpointName -eq "LicensingExtranetDistributionPointUrl" -or $strEndpointName -eq "CertificationDistributionPointUrl") {

        <# Extending URL with .asmx #>
        $strURL = $strURL + "/ServiceLocator.asmx"

    }

    Try { <# Action with http return code 200 #>

        <# Initialize web connection to check for URL #>
        $Private:CheckConnection = (Invoke-WebRequest -Uri $strURL -UseBasicParsing -DisableKeepAlive).StatusCode

        <# Check for successfully web connection and output result #>
        If ($Private:CheckConnection -eq 200) {

            <# Function return value (http status) #>
            Return, $Private:CheckConnection
            
            <# Verbose/Logging #>
            fncLogging -strLogFunction "fncVerifyEndpoint" -strLogDescription $strEndpointName -strLogValue $Private:CheckConnection

        }

    }
    Catch [Net.WebException] { <# Action with http errors #>

        <# Catching http error into variable #>
        $Private:HttpStatusCode = [int]$_.Exception.Response.StatusCode

        <# Function return value (http status) #>
        Return, $Private:HttpStatusCode

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncVerifyEndpoint" -strLogDescription $strEndpointName -strLogValue $Private:HttpStatusCode

    }

}

<# Function to analyze AIP endpoint URLs #>
Function fncAnalyzeEndpointURLs {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncAnalyzeEndpointURLs" -strLogDescription "Analyze endpoint URLs" -strLogValue "Initiated"

    <# Console output #>
    Write-Output "ANALYZE ENDPOINT URLs:"

    <# Defining and filling variables with static URLs #>
    $Private:MyUnifiedLabelingDistributionPointUrl = "https://dataservice.protection.outlook.com"
    $Private:MyTelemetryDistributionPointUrl = "https://self.events.data.microsoft.com"
    $Private:MyAIPv1PolicyDistributionPointUrl = "https://api.informationprotection.azure.com"

    <# Defining and filling variable with date/time for unique log folder #>
    $Private:MyTimestamp = (Get-Date -Verbose:$false -UFormat "%y%m%d-%H%M%S")
    $Private:strCertLogPath = "$Global:strUserLogPath\Analyze\$Private:MyTimestamp"

    <# Checking if 'Analyze'-folder exist and create it, if not #>
    If ($(Test-Path -Path $Private:strCertLogPath) -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Private:strCertLogPath | Out-Null <# Defining Analyze path #>

    }

    <# Check for existing EndpointURLs.log file and create it, if it not exist #>
    If ($(Test-Path $Global:strUserLogPath"\Analyze\EndpointURLs.log") -Eq $false) {

        Out-File -FilePath $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Encoding UTF8 -Append -Force

    }

    <# Checking for analyze AIP endpoints URLs [MSIPC] if bootstrap was done/running with user permissions/reading URLs from registry #>
    If ($(Test-Path -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC") -Eq $true) {

        <# Console output #>
        Write-Output "Initializing, please wait..."
        Write-Output "Verifying endpoint URLs...`n"

        <# Reading URLs from registry #>
        Get-ChildItem -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC" | ForEach-Object {

            <# Reading Tenant Id #>
            $Private:strMainKey = $_.Name.Substring(75).ToString()
         
            <# Actions if it's about '.aadrm.com', but not about 'discover.aadrm.com' #>
            If ($Private:strMainKey -like "*.aadrm.com" -and $Private:strMainKey -notmatch "discover.aadrm.com") {

                <# Private variabel definition for Tenant Id string #>
                $Private:strTenantId = $Private:strMainKey.Remove(36)

                <# Console output #> 
                Write-Output (Write-Host "-------------------------------------------------`nTenant Id:  $Private:strTenantId`n-------------------------------------------------`n" -ForegroundColor Magenta)

                <# Create Tenant Id as first log entry #>
                Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value "-----------------------------------------------`nTenant Id: $Private:strTenantId`n-----------------------------------------------"

                <# Defining and filling variables with URLs #>
                $Private:MyLicensingIntranetDistributionPointUrl = (Get-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC\$Private:strMainKey\Identities" -ErrorAction SilentlyContinue).InternalUrl
                $Private:MyLicensingExtranetDistributionPointUrl = (Get-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC\$Private:strMainKey\Identities" -ErrorAction SilentlyContinue).ExternalUrl

                <# Defining and filling variables: Extending colledted registry key with https and subkey #>
                $Private:strMainKey = "https://$Private:strMainKey".ToString()
                $Private:MyCertificationDistributionPointUrl = "$Private:strMainKey/_wmcs/certification"

                <# Create Timestamp #>
                Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value ("Date/Timestamp: " + (Get-Date -Verbose:$false -UFormat "$Private:MyTimestamp"))
                
                <# Add read mode #>
                Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value ("Read from registry [MSIPC]:`n")

                <# Calling function to verify endpoint and certificate issuer #>
                fncVerifyIssuer -strCertURL $Private:MyLicensingIntranetDistributionPointUrl -strEndpointName "LicensingIntranetDistributionPointUrl" -strLogPath $Private:strCertLogPath
                fncVerifyIssuer -strCertURL $Private:MyLicensingExtranetDistributionPointUrl -strEndpointName "LicensingExtranetDistributionPointUrl" -strLogPath $Private:strCertLogPath
                fncVerifyIssuer -strCertURL $Private:MyCertificationDistributionPointUrl -strEndpointName "CertificationDistributionPointUrl" -strLogPath $Private:strCertLogPath
                fncVerifyIssuer -strCertURL $Private:MyUnifiedLabelingDistributionPointUrl -strEndpointName "UnifiedLabelingDistributionPointUrl" -strLogPath $Private:strCertLogPath
                fncVerifyIssuer -strCertURL $Private:MyTelemetryDistributionPointUrl -strEndpointName "TelemetryDistributionPointUrl" -strLogPath $Private:strCertLogPath
                fncVerifyIssuer -strCertURL $Private:MyAIPv1PolicyDistributionPointUrl -strEndpointName "AIPv1PolicyDistributionPointUrl" -strLogPath $Private:strCertLogPath

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncAnalyzeEndpointURLs" -strLogDescription "Export endpoint URLs" -strLogValue "EndpointURLs.log"
                fncLogging -strLogFunction "fncAnalyzeEndpointURLs" -strLogDescription "Analyze endpoint URLs" -strLogValue "Proceeded"

            }
            
        }

        <# Checking for analyze AIP endpoints URLs [MSIP] if bootstrap was done/running in 'non-admin mode'/reading URLs from registry #>
        If ($(Test-Path -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC\MSIP") -Eq $true) {

            <# Reading URLs from registry #>
            Get-ChildItem -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC\MSIP" | ForEach-Object {

                <# Reading Tenant Id #>
                $Private:strMainKey = $_.Name.Substring(80).ToString()
         
                <# Actions if it's about '.aadrm.com', but not about 'discover.aadrm.com' #>
                If ($Private:strMainKey -like "*.aadrm.com" -and $Private:strMainKey -notmatch "discover.aadrm.com") {

                    <# Private variabel definition for Tenant Id string #>
                    $Private:strTenantId = $Private:strMainKey.Remove(36)

                    <# Console output #> 
                    Write-Output (Write-Host "------------------------------------------------`nTenant Id:  $Private:strTenantId`n------------------------------------------------`n" -ForegroundColor Magenta)

                    <# Create Tenant Id as first log entry #>
                    Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value "------------------------------------------------`nTenant Id: $Private:strTenantId`n------------------------------------------------"

                    <# Defining and filling variables with URLs #>
                    $Private:MyLicensingIntranetDistributionPointUrl = (Get-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC\MSIP\$Private:strMainKey\Identities" -ErrorAction SilentlyContinue).InternalUrl
                    $Private:MyLicensingExtranetDistributionPointUrl = (Get-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\MSIPC\MSIP\$Private:strMainKey\Identities" -ErrorAction SilentlyContinue).ExternalUrl

                    <# Defining and filling variables: Extending colledted registry key with https and subkey #>
                    $Private:strMainKey = "https://$Private:strMainKey".ToString()
                    $Private:MyCertificationDistributionPointUrl = "$Private:strMainKey/_wmcs/certification"

                    <# Create Timestamp #>
                    Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value ("Date/Timestamp: " + (Get-Date -Verbose:$false -UFormat "$Private:MyTimestamp"))
                
                    <# Add read mode #>
                    Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value ("Read from registry [MSIP]:`n")

                    <# Calling function to verify endpoint and certificate issuer #>
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
    Else { <# Actions for analyze AIP endpoints URLs, if bootstrap has failed/reading URLs from portal/running administrative #>

        <# Actions if running administrative #>
        If ($Global:bolRunningAsAdmin -eq $true) {

            <# Console output #>
            Write-Output "Initializing, please wait..."

            <# Check and update needed modules for PowerShellGallery.com #>
            fncUpdateRequiredModules

            <# Console output #>
            Write-Output "Verifying endpoint URLs..."
            Write-Output "Connecting to AIPService..."

            <# Connect to AIPService #>
            If (Connect-AIPService -Verbose:$false) { <# Action when an AIPService connection is opened #>

                <# Private variabel definition for Tenant Id string #>
                $Private:strTenantId = (Get-AipServiceConfiguration).RightsManagementServiceId

                <# Console output #> 
                Write-Output "AIPService connected`n"
                Write-Output (Write-Host "------------------------------------------------`nTenant Id:  $Private:strTenantId`n------------------------------------------------`n" -ForegroundColor Magenta)

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncAnalyzeEndpointURLs" -strLogDescription "AIPService connected" -strLogValue $true

            }
            Else{ <# Action if AIPService connection failed #>

                <# Verbose/Logging #>
                fncLogging -strLogFunction "fncAnalyzeEndpointURLs" -strLogDescription "AIPService connected" -strLogValue $false 
                fncLogging -strLogFunction "fncAnalyzeEndpointURLs" -strLogDescription "Admin login" -strLogValue "Login failed"
                    
                <# Console output #>
                Write-Output (Write-Host "ANALYZE ENDPOINT URLs: Login failed. Please try again.`n" -ForegroundColor Red)
    
                <# Signal sound #>
                [console]::beep(500,200)

                <# Action if function was called from command line #>
                If ($Global:bolCommingFromMenu -eq $false) {

                    <# Set back window title to default #>
                    $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                    <# Exit function #>
                    Break

                }

                <# Action if function was called from the menu #>
                If ($Global:bolCommingFromMenu -eq $true) {

                    <# Calling pause function #>
                    fncPause

                    <# Clearing console #>
                    Clear-Host

                    <# Calling show menu function #>
                    fncShowMenu    

                }

            }

            <# Defining and filling variables with URLs #>
            $Private:MyLicensingIntranetDistributionPointUrl = (Get-AipServiceConfiguration).LicensingIntranetDistributionPointUrl.ToString()
            $Private:MyLicensingExtranetDistributionPointUrl = (Get-AipServiceConfiguration).LicensingExtranetDistributionPointUrl.ToString()
            $Private:MyCertificationDistributionPointUrl = (Get-AipServiceConfiguration).CertificationExtranetDistributionPointUrl.ToString()

            <# Create Tenant Id as first log entry #>
            Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value "------------------------------------------------`nTenant Id: $Private:strTenantId`n------------------------------------------------"

            <# Create Timestamp #>
            Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value ("Date/Timestamp: " + (Get-Date -Verbose:$false -UFormat "$Private:MyTimestamp"))

            <# Add read mode #>
            Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value ("Read from portal:`n")

            <# Calling function to verify endpoint and certificate issuer #>
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
            fncLogging -strLogFunction "fncAnalyzeEndpointURLs" -strLogDescription "AIPService disconnected" -strLogValue $true
            fncLogging -strLogFunction "fncAnalyzeEndpointURLs" -strLogDescription "Export endpoint URLs" -strLogValue "EndpointURLs.log"
            fncLogging -strLogFunction "fncAnalyzeEndpointURLs" -strLogDescription "Analyze endpoint URLs" -strLogValue "Proceeded"

            <# Releasing private variable #>
            $Private:strTenantId = $null

        }
        Else { <# Actions if running with user permissions #>

            <# Console output #>
            Write-Output (Write-Host "ATTENTION: You must run the RMS_Support_Tool in an administrative PowerShell window as a user with local administrative permissions to continue with this option." -ForegroundColor Red)
            Write-Output (Write-Host "Alternatively, you can start (bootstrap) any Microsoft© 365 desktop application and try again.`nANALYZE ENDPOINT URLs: Failed.`n" -ForegroundColor Red)

            <# Signal sound #>
            [console]::beep(500,200)

            <# Action if function was called from command line #>
            If ($Global:bolCommingFromMenu -eq $false) {

                <# Set back window title to default #>
                $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

                <# Exit function #>
                Break

            }

            <# Action if function was called from the menu #>
            If ($Global:bolCommingFromMenu -eq $true) {

                <# Calling pause function #>
                fncPause

                <# Clearing console #>
                Clear-Host

                <# Calling show menu function #>
                fncShowMenu    

            }

        }

    }

    <# Signal sound #>
    [console]::beep(1000,200)

    <# Console output #>
    Write-Output "Log file: $Global:strUserLogPath\Analyze\EndpointURLs.log"
    Write-Output (Write-Host "ANALYZE ENDPOINT URLs: Proceeded.`n" -ForegroundColor Green)
    
    <# Releasing private variables #>
    $Private:MyLicensingIntranetDistributionPointUrl = $null
    $Private:MyLicensingExtranetDistributionPointUrl = $null
    $Private:MyCertificationDistributionPointUrl = $null
    $Private:MyTimestamp = $null
    $Private:strTenantId = $null
    $Private:strMainKey = $null
    $Private:strCertLogPath = $null
        
}

<# Function to verify certificates issuer #>
Function fncVerifyIssuer ($strCertURL, $strEndpointName, $strLogPath) {

    <# Actions if $strCertURL variable value is not empty #>
    If ($strCertURL) {

        <# Defining web request with URL #>
        $Private:strWebRequest = [System.Net.HttpWebRequest]::Create($strCertURL)

        <# Get web response for URL #>
        Try {

            <# Getting web response for analyzing certificates issuer #>
            $Private:strWebRequest.GetResponse() | Out-Null

        }
        Catch  { <# Action if analyze/web request failed #>

            <# Ignoring 'Catch' (happen when Web Request fail/end) #>

        }

        <# Defining certificate file conditions #>
        $Private:MyWebCert = $Private:strWebRequest.ServicePoint.Certificate

        <# Exporting web certificate #>
        $Private:MyCertBinaries = $Private:MyWebCert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)

        <# Creating temporarily certificate file #>
        Set-Content -Value $Private:MyCertBinaries -Encoding Byte -Path "$strLogPath\$strEndpointName.ce_"
        $Private:MyCertFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate
    
        <# Import certificate file for analyzing #>
        $Private:MyCertFile.Import("$strLogPath\$strEndpointName.ce_")

        <# Feed variable/certificate data with issuer #>
        $Private:MyCertFile = $Private:MyCertFile.GetIssuerName()

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncVerifyIssuer" -strLogDescription "Export certificate" -strLogValue "$strEndpointName.ce_"

        <# Calling function to verify endpoint https status code #>
        $Private:strHttpCode = fncVerifyEndpoint $strCertURL -strEndpointName $strEndpointName

        <# Console output #> 
        Write-Output (Write-Host "Endpoint: $strEndpointName" -ForegroundColor Yellow)
        Write-Output (Write-Host "URL:      $strCertURL" -ForegroundColor Yellow)
        Write-Output (Write-Host "Issuer:   $Private:MyCertFile" -ForegroundColor Yellow)
        Write-Output (Write-Host "Http:     $Private:strHttpCode`n" -ForegroundColor Yellow)

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncVerifyIssuer" -strLogDescription $strEndpointName -strLogValue "Http: $Private:strHttpCode"

        <# Check for existing EndpointURLs.log file and extend it, if it exist #>
        If ($(Test-Path $Global:strUserLogPath"\Analyze\EndpointURLs.log") -Eq $true) {

            <# Exporting analyze result #>
            Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value "Endpoint: $strEndpointName"
            Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value "URL:      $strCertURL"
            Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value "Issuer:   $Private:MyCertFile"
            Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value "Http:     $Private:strHttpCode`n"

        }

    }
    Else { <# Actions if $strCertURL variable value is empty #>

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncVerifyIssuer" -strLogDescription "Export certificate" -strLogValue "-"

        <# Console output #> 
        Write-Output (Write-Host "Endpoint: $strEndpointName" -ForegroundColor Yellow)
        Write-Output (Write-Host "URL:      -" -ForegroundColor Yellow)
        Write-Output (Write-Host "Issuer:   -" -ForegroundColor Yellow)
        Write-Output (Write-Host "Http:     -`n" -ForegroundColor Yellow)

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncVerifyIssuer" -strLogDescription $strEndpointName -strLogValue "Http: -"

        <# Check for existing EndpointURLs.log file and extend it, if it exist #>
        If ($(Test-Path $Global:strUserLogPath"\Analyze\EndpointURLs.log") -Eq $true) {

            <# Exporting analyze result #>
            Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value "Endpoint: $strEndpointName"
            Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value "URL:      -"
            Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value "Issuer:   -"
            Add-Content -Path $Global:strUserLogPath"\Analyze\EndpointURLs.log" -Value "Http:     -`n"

        }

    }

    <# Releasing private variables #>
    $Private:MyWebCert = $null
    $Private:MyCertFile = $null
    $Private:strHttpCode = $null
    $Private:strWebRequest = $null

}

<# Function to request license to check protection/encryption #>
Function fncAnalyzeProtection {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncAnalyzeProtection" -strLogDescription "Analyze protection" -strLogValue "Initiated"

    <# Console output #>
    Write-Output "ANALYZE PROTECTION:"

    <# Console output #>
    Write-Output "Initializing, please wait..."

    <# Checking if 'Analyze'-folder exist and create it, if not #>
    If ($(Test-Path -Path $Global:strUserLogPath"\Analyze") -Eq $false) {

        New-Item -ItemType Directory -Force -Path $Global:strUserLogPath"\Analyze" | Out-Null <# Defining Analyze path #>

    }

    <# Check for existing Protection.log file and create it, if it not exist #>
    If ($(Test-Path $Global:strUserLogPath"\Analyze\Protection.log") -Eq $false) {

        <# Create Protection.log file #>
        Out-File -FilePath $Global:strUserLogPath"\Analyze\Protection.log" -Encoding UTF8 -Append -Force

    }

    <# Create Timestamp as first log entry #>
    Add-Content -Path $Global:strUserLogPath"\Analyze\Protection.log" -Value ("Date/Timestamp : " + (Get-Date -Verbose:$false -UFormat "%y%m%d-%H%M%S"))

    <# Check for existing/previous (protected) Protection.ptxt file #>
    If ($(Test-Path $Global:strUserLogPath"\Analyze\Protection.ptxt") -Eq $true) {

        <# Delete existing/previous Protection.ptxt file to be able to create new without error #>
        fncDeleteItem "\\?\$Global:strUserLogPath\Analyze\Protection.ptxt"

    }

    <# Console output #>
    Write-Output (Write-Host "Verifying protection...`n")

    <# Checking for AIP client 1/2 and trying to protect a sample file #>
    If (Get-Module -ListAvailable -Name AzureInformationProtection) {

        <# Feeding variable with AIP client version information #>
        $strAIPClientVersion = $((Get-Module -ListAvailable -Name AzureInformationProtection).Version).ToString()

        <# Check for existing Protection.txt sample file and create it, if it not exist #>
        If ($(Test-Path $Global:strUserLogPath"\Analyze\Protection.txt") -Eq $false) {

            <# Creating sample text file #>
            Out-File -FilePath $Global:strUserLogPath"\Analyze\Protection.txt" -Encoding UTF8 -Append -Force

            <# Add content to file #>
            Add-Content -Path $Global:strUserLogPath"\Analyze\Protection.txt" -Value "This file has been created by the RMS_Support_Tool."

        }

        <# Console output #>
        Write-Output (Write-Host "License        : {[OwnerMail, RMSSupToolEncrTest@microsoft.com], [UserMail, RMSSupToolEncrTest@microsoft.com], [Permissions, EDIT]}" -ForegroundColor Yellow)

        <# Logging #>
        fncLogging -strLogFunction "fncAnalyzeProtection" -strLogDescription "License created" -strLogValue $true

        <# Trying protection with AIPv1 client #>
        If ($strAIPClientVersion.StartsWith("1") -eq $true) {
            
            <# Feeding variable with temporary license #>
            $Private:TempLicense = New-RMSProtectionLicense -OwnerEmail "RMSSupToolEncrTest@microsoft.com" -UserEmail "RMSSupToolEncrTest@microsoft.com" -Permission EDIT
            
            <# Add content to log file #>
            Add-Content -Path $Global:strUserLogPath"\Analyze\Protection.log" -Value "License        : {[OwnerMail, RMSSupToolEncrTest@microsoft.com], [UserMail, RMSSupToolEncrTest@microsoft.com], [Permission, EDIT]}"

            <# Protect test file with temporary license #>
            $Private:TempTestFile = (Protect-RMSFile -License $Private:TempLicense -InPlace -File $Global:strUserLogPath"\Analyze\Protection.txt" -ErrorAction SilentlyContinue).EncryptedFile

            <# Checking if protection was successfull #>
            If ($Private:TempTestFile.EndsWith(".ptxt") -eq $true) {

                <# Checking for protection status #>
                If ((Get-RMSFileStatus -file $Private:TempTestFile -ErrorAction SilentlyContinue).Status -match "Protected") {

                    <# Console output #>
                    Write-Output (Write-Host "File           : $Global:strUserLogPath\Analyze\Protection.ptxt" -ForegroundColor Yellow)
                    Write-Output (Write-Host "Verification   : Successfull`n" -ForegroundColor Green)

                    <# Logging #>
                    fncLogging -strLogFunction "fncAnalyzeProtection" -strLogDescription "Verification" -strLogValue "Successfull"

                    <# Add content to log file #>
                    Add-Content -Path $Global:strUserLogPath"\Analyze\Protection.log" -Value "File           : $Global:strUserLogPath\Analyze\Protection.ptxt"
                    Add-Content -Path $Global:strUserLogPath"\Analyze\Protection.log" -Value "Verification   : Successfull`n"

                }
                Else {

                    <# Console output #>
                    Write-Output (Write-Host "Verification   : Failed (ERROR)`n" -ForegroundColor Red)

                    <# Logging #>
                    fncLogging -strLogFunction "fncAnalyzeProtection" -strLogDescription "Verification" -strLogValue "Failed (ERROR)"

                    <# Add content to log file #>
                    Add-Content -Path $Global:strUserLogPath"\Analyze\Protection.log" -Value "Verification   : Failed (ERROR)`n"

                }

            }

        }
        <# Trying protection with AIPv2 client #>
        ElseIf ($strAIPClientVersion.StartsWith("2") -eq $true) {

            <# Feeding variable with temporary license #>
            $Private:TempLicense = New-AIPCustomPermissions -Users "RMSSupToolEncrTest@microsoft.com" -Permissions Viewer

            <# Add content to log file #>
            Add-Content -Path $Global:strUserLogPath"\Analyze\Protection.log" -Value "License        : {[Users, RMSSupToolEncrTest@microsoft.com], [Permissons, VIEWER]}"

            <# Remember default progress bar status: 'Continue' #>
            $Private:strOriginalPreference = $Global:ProgressPreference 
            $Global:ProgressPreference = "SilentlyContinue" <# Hiding progress bar #>

            <# Protect and check if it was successfull #>
            If ((Set-AIPFileLabel $Global:strUserLogPath"\Analyze\Protection.txt" -CustomPermissions $Private:TempLicense -ErrorAction SilentlyContinue).Status -eq "Success") {

                <# Console output #>
                Write-Output (Write-Host "File           : $Global:strUserLogPath\Analyze\Protection.ptxt" -ForegroundColor Yellow)
                Write-Output (Write-Host "Verification   : Successfull`n" -ForegroundColor Green)

                <# Logging #>
                fncLogging -strLogFunction "fncAnalyzeProtection" -strLogDescription "Verification" -strLogValue "Successfull"

                <# Add content to log file #>
                Add-Content -Path $Global:strUserLogPath"\Analyze\Protection.log" -Value "File           : $Global:strUserLogPath\Analyze\Protection.ptxt"
                Add-Content -Path $Global:strUserLogPath"\Analyze\Protection.log" -Value "Verification   : Successfull`n"

            }
            Else {

                <# Console output #>
                Write-Output (Write-Host "Verification   : Failed (ERROR)`n" -ForegroundColor Red)

                <# Logging #>
                fncLogging -strLogFunction "fncAnalyzeProtection" -strLogDescription "Verification" -strLogValue "Failed (ERROR)"

                <# Add content to log file #>
                Add-Content -Path $Global:strUserLogPath"\Analyze\Protection.log" -Value "Verification   : Failed (ERROR)`n"

            }

            <# Set back progress bar to previous setting #>
            $Global:ProgressPreference = $Private:strOriginalPreference

        }

    }
    Else {

        <# Console output #>
        Write-Output (Write-Host "ATTENTION: Microsoft® Azure Information Protection cmdlets are required to proceed this option!`nPlease review point 1 in the requirements section of the help file for additional information.`n" -ForegroundColor Red)
        
        <# Add content to log file #>
        Add-Content -Path $Global:strUserLogPath"\Analyze\Protection.log" -Value "Verification   : Failed (No AIP client)`n"

        <# Console output #> 
        Write-Output "Log file: $Global:strUserLogPath\Analyze\Protection.log"
        Write-Output (Write-Host "ANALYZE PROTECTION: Failed.`n" -ForegroundColor Red)

        <# Signal sound #>
        [console]::beep(500,200)

        <# Logging if AIP client is not installed #>
        fncLogging -strLogFunction "fncAnalyzeProtection" -strLogDescription "AIP client installed" -strLogValue $false
        fncLogging -strLogFunction "fncAnalyzeProtection" -strLogDescription "Verification" -strLogValue "Failed (No AIP client)"
        fncLogging -strLogFunction "fncAnalyzeProtection" -strLogDescription "Export analyze protection" -strLogValue "Protection.log"
        fncLogging -strLogFunction "fncAnalyzeProtection" -strLogDescription "Analyze protection" -strLogValue "Failed"

        <# Action if function was called from command line #>
        If ($Global:bolCommingFromMenu -eq $false) {

            <# Set back window title to default #>
            $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle

            <# Exit function #>
            Break

        }

        <# Action if function was called from the menu #>
        If ($Global:bolCommingFromMenu -eq $true) {
 

            <# Calling pause function #>
            fncPause
    
            <# Clearing console #>
            Clear-Host

            <# Calling show menu function #>
            fncShowMenu
 
        }

    }

    <# Deleting sample text file #>
    fncDeleteItem "\\?\$Global:strUserLogPath\Analyze\Protection.txt"

    <# Releasing private variables #>
    $Private:TempLicense = $null
    $Private:TempTestFile = $null
    $strAIPClientVersion = $null

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncAnalyzeProtection" -strLogDescription "Export analyze protection" -strLogValue "Protection.log"
    fncLogging -strLogFunction "fncAnalyzeProtection" -strLogDescription "Analyze protection" -strLogValue "Proceeded"

    <# Console output #> 
    Write-Output "Log file: $Global:strUserLogPath\Analyze\Protection.log"
    Write-Output (Write-Host "ANALYZE PROTECTION: Proceeded.`n" -ForegroundColor Green)

    <# Signal sound #>
    [console]::beep(1000,200)

}

<# Function to compress all log files into a .zip archive #>
Function fncCompressLogs {

    <# Console output #> 
    Write-Output "COMPRESS LOGS:`nCompressing logs, please wait...`n"
        
    <# Defining default zip folder path #>
    $Global:strZipSourcePath = $Global:strTempFolder + "\RMS_Support_Tool"

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Compress logs" -strLogValue "Initiated"
    fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Zip source path" -strLogValue $Global:strZipSourcePath

    <# Compress all files into a .zip file #>
    If ($(Test-Path -Path $Global:strZipSourcePath) -Eq $true) { <# Actions, if path exist #>

        <# Defining .zip file name #>
        $Private:strZipFile = "RMS_Support_Tool (" + $env:USERNAME + (Get-Date -UFormat "-%H%M%S") + ").zip".ToString()

        <# Defining user desktop path #>
        $Private:DesktopPath = [Environment]::GetFolderPath("Desktop")

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Zip destination path" -strLogValue $Private:DesktopPath
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Zip file name" -strLogValue $Private:strZipFile
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Compress logs" -strLogValue "Proceeded"

        <# Compress all files and logs into zip file (overwrites) #>
        Compress-Archive -Path $Global:strZipSourcePath"\Logs\*" -DestinationPath "$Private:DesktopPath\$Private:strZipFile" -Force -ErrorAction SilentlyContinue

    }

    <# Console output #> 
    Write-Output "Zip file: $Private:DesktopPath\$Private:strZipFile"
    Write-Output (Write-Host "COMPRESS LOGS: Proceeded.`n" -ForegroundColor Green)

    <# Cleaning Logs folders if .zip archive is on the desktop #>
    If ($(Test-Path -Path $Private:DesktopPath\$Private:strZipFile) -Eq $true) { <# Actions, if file exist on desktop #>

        <# Cleaning Logs folders #>
        Remove-Item "\\?\$Global:strZipSourcePath\Logs" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Log folders cleaned" -strLogValue $true

    }
    Else{

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncCompressLogs" -strLogDescription "Log folders cleaned" -strLogValue $false

    }

    <# Signal sound #>
    [console]::beep(1000,200)

    <# Releasing private variable #>
    $Private:strZipFile = $null
    $Private:DesktopPath = $null

    <# Releasing global variable #>
    $Global:strWindowsEdition = $null
    $Global:strZipSourcePath = $null

}

<# Function to pause menu for message display #>
Function fncPause {

    <# Filling variable with default pause message #>
    $Private:strPauseMessage = "Press any key to continue"

    <# Pausing the script module with a message #>
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

<# Function to call script module menu #>
Function fncShowMenu {

    <# Clearing console #>
    Clear-Host

    <# Helper variable to control menu handling inside function calls #>
    $Global:bolCommingFromMenu = $true

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncShowMenu" -strLogDescription "Main menu" -strLogValue "Called"

    <# Menu output #>
    Write-Output "RMS_Support_Tool:`n"
    Write-Output (Write-Host "  [I] INFORMATION" -ForegroundColor Green)
    Write-Output (Write-Host "  [D] DISCLAIMER" -ForegroundColor Red)
    Write-Output (Write-Host "  [H] HELP" -ForegroundColor Green)
    Write-Output (Write-Host "  [R] RESET" -ForegroundColor Yellow)
    Write-Output (Write-Host "  [P] RECORD PROBLEM" -ForegroundColor Yellow)
    Write-Output (Write-Host "  [C] COLLECT" -ForegroundColor Yellow)
    If (@($Global:MenuCollectExtended) -Match $true) {
        Write-Output (Write-Host "   ├──[A] AIP service configuration" -ForegroundColor Yellow)
        Write-Output (Write-Host "   ├──[O] AIP protection templates" -ForegroundColor Yellow)
        Write-Output (Write-Host "   └──[L] MSC labels and policies" -ForegroundColor Yellow)
        Write-Output (Write-Host "  [Y] ANALYZE" -ForegroundColor Yellow)
        If (@($Global:MenuAnalyzeExtended) -Match $true) {
            Write-Output (Write-Host "   ├──[U] Endpoint URLs" -ForegroundColor Yellow)
            Write-Output (Write-Host "   └──[T] Protection" -ForegroundColor Yellow)
            Write-Output (Write-Host "  [Z] COMPRESS LOGS" -ForegroundColor Yellow)
            Write-Output (Write-Host "  [X] EXIT`n" -ForegroundColor Green)
        }
        Else {
            Write-Output (Write-Host "  [Z] COMPRESS LOGS" -ForegroundColor Yellow)
            Write-Output (Write-Host "  [X] EXIT`n" -ForegroundColor Green)
        }        
    }
    Else {
        Write-Output (Write-Host "  [Y] ANALYZE" -ForegroundColor Yellow)
        If (@($Global:MenuAnalyzeExtended) -Match $true) {
            Write-Output (Write-Host "   ├──[U] Endpoint URLs" -ForegroundColor Yellow)
            Write-Output (Write-Host "   └──[T] Protection" -ForegroundColor Yellow)
            Write-Output (Write-Host "  [Z] COMPRESS LOGS" -ForegroundColor Yellow)
            Write-Output (Write-Host "  [X] EXIT`n" -ForegroundColor Green)
        }
        Else {
            Write-Output (Write-Host "  [Z] COMPRESS LOGS" -ForegroundColor Yellow)
            Write-Output (Write-Host "  [X] EXIT`n" -ForegroundColor Green)
        }         
    }

    <# Defining menu selection variable #>
    $Private:intMenuSelection = Read-Host "Please select an option and press enter"

    <# Actions for information menu selected #>
    If ($Private:intMenuSelection -Eq "I") {
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[I] INFORMATION" -strLogValue "Selected"
        
        <# Clearing console #>
        Clear-Host
        
        <# Calling information function #>
        fncInformation
        
        <# Calling pause function #>
        fncPause

    }

    <# Actions for disclaimer menu selected #>
    If ($Private:intMenuSelection -Eq "D") {
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[D] DISCLAIMER" -strLogValue "Selected"
        
        <# Clearing console #>
        Clear-Host

        <# Calling disclaimer function #>
        fncDisclaimer

        <# Calling pause function #>
        fncPause
    }
   
    <# Actions for help menu selected #>
    If ($Private:intMenuSelection -Eq "H") {
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[H] HELP" -strLogValue "Selected"
        
        <# Clearing console #>
        Clear-Host

        <# Calling help function #>
        fncHelp

    }
    
    <# Actions for reset menu selected #>
    If ($Private:intMenuSelection -Eq "R") {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[R] RESET" -strLogValue "Selected"
        
        <# Clearing console #>
        Clear-Host

        <# Calling reset function #>
        fncReset

        <# Calling pause function #>
        fncPause

    }

    <# Actions for record problem menu selected #>
    If ($Private:intMenuSelection -Eq "P") {
        
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[P] RECORD PROBLEM" -strLogValue "Selected"
        
        <# Clearing console #>
        Clear-Host
        
        <# Calling user logging function #>
        fncRecordProblem
        
        <# Calling pause function #>
        fncPause

    }

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
        
        <# Clearing console #>
        Clear-Host
        
        <# Calling function to collect AIP service configuration #>
        fncCollectAipServiceConfiguration
        
        <# Calling pause function #>
        fncPause

    }

    <# Actions for AIP protection templates menu selected #>
    If ($Private:intMenuSelection -Eq "O") {
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[O] AIP protection templates" -strLogValue "Selected"
        
        <# Clearing console #>
        Clear-Host
        
        <# Calling function to collect AIP protection templates #>
        fncCollectAIPProtectionTemplates
        
        <# Calling pause function #>
        fncPause

    }

    <# Actions for MSC labels and policies menu selected #>
    If ($Private:intMenuSelection -Eq "L") {
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[L] MSC labels and policies" -strLogValue "Selected"
        
        <# Clearing console #>
        Clear-Host
        
        <# Calling Labels and Policies function #>
        fncCollectMSCLabelsAndPolicies
        
        <# Calling pause function #>
        fncPause

    }

    <# Actions,for analyze menu selected #>
    If ($Private:intMenuSelection -Eq "Y") {

        <# Show/Hide menu extenstion  #>
        If (@($Global:MenuAnalyzeExtended) -Match $true) {$Global:MenuAnalyzeExtended = $false}
        Else {$Global:MenuAnalyzeExtended = $true}
        
    }

    <# Actions for AnalyzeEndpointURLs menu selected #>
    If ($Private:intMenuSelection -Eq "U") {
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[U] Endpoint URLs" -strLogValue "Selected"
        
        <# Clearing console #>
        Clear-Host
        
        <# Calling AnalzeEndpointURLs function #>
        fncAnalyzeEndpointURLs
        
        <# Calling pause function #>
        fncPause
        
    }

    <# Actions for AnalyzeProtection menu selected #>
    If ($Private:intMenuSelection -Eq "T") {
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[T] Protection" -strLogValue "Selected"
        
        <# Clearing console #>
        Clear-Host

        <# Calling AnalyzeProtection function #>
        fncAnalyzeProtection
        
        <# Calling pause function #>
        fncPause
        
    }

    <# Actions for compress logs menu selected #>
    If ($Private:intMenuSelection -Eq "Z") {
    
        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[Z] COMPRESS LOGS" -strLogValue "Selected"
        
        <# Clearing console #>
        Clear-Host
        
        <# Calling compress logs function #>
        fncCompressLogs
        
        <# Calling pause function #>
        fncPause
        
    }

    <# Actions for exit menu selected #>
    If ($Private:intMenuSelection -Eq "X") {

        <# Verbose/Logging #>
        fncLogging -strLogFunction "fncShowMenu" -strLogDescription "[X] EXIT" -strLogValue "Selected"

        <# Clear global variables #>
        $Global:bolCommingFromMenu = $false

        <# Set back window title to default #>
        $Global:host.UI.RawUI.WindowTitle = $Global:strDefaultWindowTitle
        
        <# Exit function #>
        Break
        
    }
    Else {

        <# Clearing console #>
        Clear-Host

        <# Calling show menu function #>
        fncShowMenu

    }

}

<# Function to show version #>
Function fncShowVersion {

    <# Verbose/Logging #>
    fncLogging -strLogFunction "fncShowVersion" -strLogDescription "Version" -strLogValue "Called"

    <# Console output version information #>
    Write-Output "You are using version: $Global:strVersion`n"

}

<# Creating default log entries #>
fncCreateDefaultLogEntries

<# Checking whether logging was left enabled #>
fncValidateForActivatedLogging

<# Checking Windows and PowerShell version #>
fncCheckWindowsAndPSVersion

<# Export functions for script module manifest #>
Export-ModuleMember -Function RMS_Support_Tool

# SIG # Begin signature block
# MIIpAQYJKoZIhvcNAQcCoIIo8jCCKO4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUn/UDc2R0YOQihsrA2Eu9JbaZ
# +DaggiLoMIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQG
# EwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxm
# b3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENl
# cnRpZmljYXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1
# OVowezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQ
# MA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAf
# BgNVBAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686td
# UIoWMQuaBtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJ
# VfMiWPPe3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCo
# kcdmtet4YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4
# qMsXeDZRrOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjH
# Ypy+g8cmez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNV
# HQ4EFgQUoBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1Ud
# EwEB/wQFMAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9j
# YS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9j
# cmwuY29tb2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG
# 9w0BAQUFAAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3s
# Ag9g1o1QGE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2
# LX1rzNLzRt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8
# tqtlbgT2G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs
# 1OUIJqsil2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XX
# vi3tPxq3smPi9WIsgtRqAEFQ8TmDn5XpNpaYbjCCBTUwggQdoAMCAQICEQD6qz5L
# Urby8Fq5J0CbhY2DMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAkdCMRswGQYD
# VQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNV
# BAoTD1NlY3RpZ28gTGltaXRlZDEkMCIGA1UEAxMbU2VjdGlnbyBSU0EgQ29kZSBT
# aWduaW5nIENBMB4XDTIwMTAwMjAwMDAwMFoXDTIzMTAwMjIzNTk1OVowfTELMAkG
# A1UEBhMCREUxDjAMBgNVBBEMBTg1Nzc4MRMwEQYDVQQHDApIYWltaGF1c2VuMRcw
# FQYDVQQJDA5Sb3NlbmdhcnRlbiAxMjEXMBUGA1UECgwOQ2xhdXMgU2NoaXJva3kx
# FzAVBgNVBAMMDkNsYXVzIFNjaGlyb2t5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEAql4rdGo8azsKVrEpCinKhNEuYbSU1nZnTSAgulRQ5jd5xaomSH/m
# TrZfLcLRK7nYQN3NCj6dMxvqsgZ5239TxSZ62PcinkeasBTvSlga+zwvgt12H0iW
# hA0bCirAnLfBduo8ZZpaonmj1uWJleENZT7/soESkMSVX2K3eyc0tB+UTU13B7Uv
# wwTj9+j567acb9yIs4mzqqKS6KKOfSBN5vQOiXtfhNZbKQN87KBxeN6IYzxluRXk
# iiWVfa63x9qywtJ5clMxizdKf9KVddfqorUVlOfHzB6Pa1ib5ZB4xmanQwgyl45e
# QS/2BZP0MPQL0FSqSdj6IVLB2oZovmruuQIDAQABo4IBrzCCAaswHwYDVR0jBBgw
# FoAUDuE6qFM6MdWKvsG7rWcaA4WtNA4wHQYDVR0OBBYEFOvLju/LLcXXqoiGhz5p
# rj+K410EMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMBEGCWCGSAGG+EIBAQQEAwIEEDBKBgNVHSAEQzBBMDUGDCsGAQQB
# sjEBAgEDAjAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAI
# BgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5zZWN0aWdvLmNv
# bS9TZWN0aWdvUlNBQ29kZVNpZ25pbmdDQS5jcmwwcwYIKwYBBQUHAQEEZzBlMD4G
# CCsGAQUFBzAChjJodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29SU0FDb2Rl
# U2lnbmluZ0NBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5j
# b20wHQYDVR0RBBYwFIESY2xhdXNAc2NoaXJva3kuY29tMA0GCSqGSIb3DQEBCwUA
# A4IBAQAXcQqm8N5PEolwJKf7Da8rD+G7AyDQGbBHMMShtPr+99aw1+gaLFNiJbLs
# PHDHTMqT/HDx4JVmn/GfL8bhWmIuwtyzmv1dul3pRAcFOZ3mNeCreXHrKs2xFT9U
# BOC7X7wt/jSZN4W4D7XirfU/xSa7uuAA6rnFO38BIYDfWctqEY5aZ2B7e7iRSkCy
# loO9+YQvSBX+CM9fQbldQEh9tqGcRZc4hXvYklTf+5Xrf9csbraKhnxRrQLnhcbV
# b6OFY0XW1RYcujrSDkUErJgMNPv9f0iRSU4cbjLPD2CcQI7oSj97WrOV8ED3bjJL
# G8qjC7aCVF1Umv/cMlgwsuLjgrJ1MIIFgTCCBGmgAwIBAgIQOXJEOvkit1HX02wQ
# 3TE1lTANBgkqhkiG9w0BAQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3Jl
# YXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21v
# ZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2Vz
# MB4XDTE5MDMxMjAwMDAwMFoXDTI4MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwG
# A1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3Qg
# UlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAgBJlFzYOw9sIs9CsVw127c0n00ytUINh4qogTQktZAnczomf
# zD2p7PbPwdzx07HWezcoEStH2jnGvDoZtF+mvX2do2NCtnbyqTsrkfjib9DsFiCQ
# CT7i6HTJGLSR1GJk23+jBvGIGGqQIjy8/hPwhxR79uQfjtTkUcYRZ0YIUcuGFFQ/
# vDP+fmyc/xadGL1RjjWmp2bIcmfbIWax1Jt4A8BQOujM8Ny8nkz+rwWWNR9XWrf/
# zvk9tyy29lTdyOcSOk2uTIq3XJq0tyA9yn8iNK5+O2hmAUTnAU5GU5szYPeUvlM3
# kHND8zLDU+/bqv50TmnHa4xgk97Exwzf4TKuzJM7UXiVZ4vuPVb+DNBpDxsP8yUm
# azNt925H+nND5X4OpWaxKXwyhGNVicQNwZNUMBkTrNN9N6frXTpsNVzbQdcS2qlJ
# C9/YgIoJk2KOtWbPJYjNhLixP6Q5D9kCnusSTJV882sFqV4Wg8y4Z+LoE53MW4LT
# TLPtW//e5XOsIzstAL81VXQJSdhJWBp/kjbmUZIO8yZ9HE0XvMnsQybQv0FfQKlE
# RPSZ51eHnlAfV1SoPv10Yy+xUGUJ5lhCLkMaTLTwJUdZ+gQek9QmRkpQgbLevni3
# /GcV4clXhB4PY9bpYrrWX1Uu6lzGKAgEJTm4Diup8kyXHAc/DVL17e8vgg8CAwEA
# AaOB8jCB7zAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4E
# FgQUU3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wEQYDVR0gBAowCDAGBgRVHSAAMEMGA1UdHwQ8MDowOKA2oDSGMmh0
# dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3Js
# MDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2Rv
# Y2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQAYh1HcdCE9nIrgJ7cz0C7M7PDmy14R
# 3iJvm3WOnnL+5Nb+qh+cli3vA0p+rvSNb3I8QzvAP+u431yqqcau8vzY7qN7Q/aG
# NnwU4M309z/+3ri0ivCRlv79Q2R+/czSAaF9ffgZGclCKxO/WIu6pKJmBHaIkU4M
# iRTOok3JMrO66BQavHHxW/BBC5gACiIDEOUMsfnNkjcZ7Tvx5Dq2+UUTJnWvu6rv
# P3t3O9LEApE9GQDTF1w52z97GA1FzZOFli9d31kWTz9RvdVFGD/tSo7oBmF0Ixa1
# DVBzJ0RHfxBdiSprhTEUxOipakyAvGp4z7h/jnZymQyd/teRCBaho1+VMIIF9TCC
# A92gAwIBAgIQHaJIMG+bJhjQguCWfTPTajANBgkqhkiG9w0BAQwFADCBiDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBD
# aXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVT
# RVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTgxMTAyMDAw
# MDAwWhcNMzAxMjMxMjM1OTU5WjB8MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3Jl
# YXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxJDAiBgNVBAMTG1NlY3RpZ28gUlNBIENvZGUgU2lnbmluZyBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIYijTKFehifSfCWL2MI
# Hi3cfJ8Uz+MmtiVmKUCGVEZ0MWLFEO2yhyemmcuVMMBW9aR1xqkOUGKlUZEQauBL
# Yq798PgYrKf/7i4zIPoMGYmobHutAMNhodxpZW0fbieW15dRhqb0J+V8aouVHltg
# 1X7XFpKcAC9o95ftanK+ODtj3o+/bkxBXRIgCFnoOc2P0tbPBrRXBbZOoT5Xax+Y
# vMRi1hsLjcdmG0qfnYHEckC14l/vC0X/o84Xpi1VsLewvFRqnbyNVlPG8Lp5UEks
# 9wO5/i9lNfIi6iwHr0bZ+UYc3Ix8cSjz/qfGFN1VkW6KEQ3fBiSVfQ+noXw62oY1
# YdMCAwEAAaOCAWQwggFgMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bL
# MB0GA1UdDgQWBBQO4TqoUzox1Yq+wbutZxoDha00DjAOBgNVHQ8BAf8EBAMCAYYw
# EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUEFjAUBggrBgEFBQcDAwYIKwYBBQUH
# AwgwEQYDVR0gBAowCDAGBgRVHSAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9j
# cmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9y
# aXR5LmNybDB2BggrBgEFBQcBAQRqMGgwPwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQu
# dXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FBZGRUcnVzdENBLmNydDAlBggrBgEF
# BQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOC
# AgEATWNQ7Uc0SmGk295qKoyb8QAAHh1iezrXMsL2s+Bjs/thAIiaG20QBwRPvrjq
# iXgi6w9G7PNGXkBGiRL0C3danCpBOvzW9Ovn9xWVM8Ohgyi33i/klPeFM4MtSkBI
# v5rCT0qxjyT0s4E307dksKYjalloUkJf/wTr4XRleQj1qZPea3FAmZa6ePG5yOLD
# CBaxq2NayBWAbXReSnV+pbjDbLXP30p5h1zHQE1jNfYw08+1Cg4LBH+gS667o6XQ
# hACTPlNdNKUANWlsvp8gJRANGftQkGG+OY96jk32nw4e/gdREmaDJhlIlc5KycF/
# 8zoFm/lv34h/wCOe0h5DekUxwZxNqfBZslkZ6GqNKQQCd3xLS81wvjqyVVp4Pry7
# bwMQJXcVNIr5NsxDkuS6T/FikyglVyn7URnHoSVAaoRXxrKdsbwcCtp8Z359Luko
# TBh+xHsxQXGaSynsCz1XUNLK3f2eBVHlRHjdAd6xdZgNVCT98E7j4viDvXK6yz06
# 7vBeF5Jobchh+abxKgoLpbn0nu6YMgWFnuv5gynTxix9vTp3Los3QqBqgu07SqqU
# EKThDfgXxbZaeTMYkuO1dfih6Y4KJR7kHvGfWocj/5+kUZ77OYARzdu1xKeogG/l
# U9Tg46LC0lsa+jImLWpXcBw8pFguo/NbSwfcMlnzh6cabVgwggbsMIIE1KADAgEC
# AhAwD2+s3WaYdHypRjaneC25MA0GCSqGSIb3DQEBDAUAMIGIMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKTmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAc
# BgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0
# IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xOTA1MDIwMDAwMDBaFw0z
# ODAxMTgyMzU5NTlaMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1h
# bmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDElMCMGA1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBDQTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMgbAa/ZLH6ImX0BmD8gkL2cgCFU
# k7nPoD5T77NawHbWGgSlzkeDtevEzEk0y/NFZbn5p2QWJgn71TJSeS7JY8ITm7aG
# PwEFkmZvIavVcRB5h/RGKs3EWsnb111JTXJWD9zJ41OYOioe/M5YSdO/8zm7uaQj
# QqzQFcN/nqJc1zjxFrJw06PE37PFcqwuCnf8DZRSt/wflXMkPQEovA8NT7ORAY5u
# nSd1VdEXOzQhe5cBlK9/gM/REQpXhMl/VuC9RpyCvpSdv7QgsGB+uE31DT/b0OqF
# jIpWcdEtlEzIjDzTFKKcvSb/01Mgx2Bpm1gKVPQF5/0xrPnIhRfHuCkZpCkvRuPd
# 25Ffnz82Pg4wZytGtzWvlr7aTGDMqLufDRTUGMQwmHSCIc9iVrUhcxIe/arKCFiH
# d6QV6xlV/9A5VC0m7kUaOm/N14Tw1/AoxU9kgwLU++Le8bwCKPRt2ieKBtKWh97o
# aw7wW33pdmmTIBxKlyx3GSuTlZicl57rjsF4VsZEJd8GEpoGLZ8DXv2DolNnyrH6
# jaFkyYiSWcuoRsDJ8qb/fVfbEnb6ikEk1Bv8cqUUotStQxykSYtBORQDHin6G6Ui
# rqXDTYLQjdprt9v3GEBXc/Bxo/tKfUU2wfeNgvq5yQ1TgH36tjlYMu9vGFCJ10+d
# M70atZ2h3pVBeqeDAgMBAAGjggFaMIIBVjAfBgNVHSMEGDAWgBRTeb9aqitKz1SA
# 4dibwJ3ysgNmyzAdBgNVHQ4EFgQUGqH4YRkgD8NBd0UojtE1XwYSBFUwDgYDVR0P
# AQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUH
# AwgwEQYDVR0gBAowCDAGBgRVHSAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9j
# cmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9y
# aXR5LmNybDB2BggrBgEFBQcBAQRqMGgwPwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQu
# dXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FBZGRUcnVzdENBLmNydDAlBggrBgEF
# BQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOC
# AgEAbVSBpTNdFuG1U4GRdd8DejILLSWEEbKw2yp9KgX1vDsn9FqguUlZkClsYcu1
# UNviffmfAO9Aw63T4uRW+VhBz/FC5RB9/7B0H4/GXAn5M17qoBwmWFzztBEP1dXD
# 4rzVWHi/SHbhRGdtj7BDEA+N5Pk4Yr8TAcWFo0zFzLJTMJWk1vSWVgi4zVx/AZa+
# clJqO0I3fBZ4OZOTlJux3LJtQW1nzclvkD1/RXLBGyPWwlWEZuSzxWYG9vPWS16t
# oytCiiGS/qhvWiVwYoFzY16gu9jc10rTPa+DBjgSHSSHLeT8AtY+dwS8BDa153fL
# nC6NIxi5o8JHHfBd1qFzVwVomqfJN2Udvuq82EKDQwWli6YJ/9GhlKZOqj0J9QVs
# t9JkWtgqIsJLnfE5XkzeSD2bNJaaCV+O/fexUpHOP4n2HKG1qXUfcb9bQ11lPVCB
# bqvw0NP8srMftpmWJvQ8eYtcZMzN7iea5aDADHKHwW5NWtMe6vBE5jJvHOsXTpTD
# eGUgOw9Bqh/poUGd/rG4oGUqNODeqPk85sEwu8CgYyz8XBYAqNDEf+oRnR4GxqZt
# Ml20OAkrSQeq/eww2vGnL8+3/frQo4TZJ577AWZ3uVYQ4SBuxq6x+ba6yDVdM3aO
# 8XwgDCp3rrWiAoa6Ke60WgCxjKvj+QrJVF3UuWp0nr1IrpgwggcHMIIE76ADAgEC
# AhEAjHegAI/00bDGPZ86SIONazANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJH
# QjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3Jk
# MRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28gUlNB
# IFRpbWUgU3RhbXBpbmcgQ0EwHhcNMjAxMDIzMDAwMDAwWhcNMzIwMTIyMjM1OTU5
# WjCBhDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQ
# MA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYD
# VQQDDCNTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIFNpZ25lciAjMjCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJGHSyyLwfEeoJ7TB8YBylKwvnl5XQlm
# Bi0vNX27wPsn2kJqWRslTOrvQNaafjLIaoF9tFw+VhCBNToiNoz7+CAph6x00Bti
# vD9khwJf78WA7wYc3F5Ok4e4mt5MB06FzHDFDXvsw9njl+nLGdtWRWzuSyBsyT5s
# /fCb8Sj4kZmq/FrBmoIgOrfv59a4JUnCORuHgTnLw7c6zZ9QBB8amaSAAk0dBahV
# 021SgIPmbkilX8GJWGCK7/GszYdjGI50y4SHQWljgbz2H6p818FBzq2rdosggNQt
# lQeNx/ULFx6a5daZaVHHTqadKW/neZMNMmNTrszGKYogwWDG8gIsxPnIIt/5J4Kh
# g1HCvMmCGiGEspe81K9EHJaCIpUqhVSu8f0+SXR0/I6uP6Vy9MNaAapQpYt2lRtm
# 6+/a35Qu2RrrTCd9TAX3+CNdxFfIJgV6/IEjX1QJOCpi1arK3+3PU6sf9kSc1ZlZ
# xVZkW/eOUg9m/Jg/RAYTZG7p4RVgUKWx7M+46MkLvsWE990Kndq8KWw9Vu2/eGe2
# W8heFBy5r4Qtd6L3OZU3b05/HMY8BNYxxX7vPehRfnGtJHQbLNz5fKrvwnZJaGLV
# i/UD3759jg82dUZbk3bEg+6CviyuNxLxvFbD5K1Dw7dmll6UMvqg9quJUPrOoPMI
# gRrRRKfM97gxAgMBAAGjggF4MIIBdDAfBgNVHSMEGDAWgBQaofhhGSAPw0F3RSiO
# 0TVfBhIEVTAdBgNVHQ4EFgQUaXU3e7udNUJOv1fTmtufAdGu3tAwDgYDVR0PAQH/
# BAQDAgbAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwQAYD
# VR0gBDkwNzA1BgwrBgEEAbIxAQIBAwgwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9z
# ZWN0aWdvLmNvbS9DUFMwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2NybC5zZWN0
# aWdvLmNvbS9TZWN0aWdvUlNBVGltZVN0YW1waW5nQ0EuY3JsMHQGCCsGAQUFBwEB
# BGgwZjA/BggrBgEFBQcwAoYzaHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdv
# UlNBVGltZVN0YW1waW5nQ0EuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5z
# ZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEASgN4kEIz7Hsagwk2M5hVu51A
# BjBrRWrxlA4ZUP9bJV474TnEW7rplZA3N73f+2Ts5YK3lcxXVXBLTvSoh90ihaZX
# u7ghJ9SgKjGUigchnoq9pxr1AhXLRFCZjOw+ugN3poICkMIuk6m+ITR1Y7ngLQ/P
# ATfLjaL6uFqarqF6nhOTGVWPCZAu3+qIFxbradbhJb1FCJeA11QgKE/Ke7OzpdIA
# sGA0ZcTjxcOl5LqFqnpp23WkPnlomjaLQ6421GFyPA6FYg2gXnDbZC8Bx8GhxySU
# o7I8brJeotD6qNG4JRwW5sDVf2gaxGUpNSotiLzqrnTWgufAiLjhT3jwXMrAQFzC
# n9UyHCzaPKw29wZSmqNAMBewKRaZyaq3iEn36AslM7U/ba+fXwpW3xKxw+7OkXfo
# IBPpXCTH6kQLSuYThBxN6w21uIagMKeLoZ+0LMzAFiPJkeVCA0uAzuRN5ioBPsBe
# haAkoRdA1dvb55gQpPHqGRuAVPpHieiYgal1wA7f0GiUeaGgno62t0Jmy9nZay9N
# 2N4+Mh4g5OycTUKNncczmYI3RNQmKSZAjngvue76L/Hxj/5QuHjdFJbeHA5wsCqF
# arFsaOkq5BArbiH903ydN+QqBtbD8ddo408HeYEIE/6yZF7psTzm0Hgjsgks4iZi
# vzupl1HMx0QygbKvz98xggWDMIIFfwIBATCBkTB8MQswCQYDVQQGEwJHQjEbMBkG
# A1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxJDAiBgNVBAMTG1NlY3RpZ28gUlNBIENvZGUg
# U2lnbmluZyBDQQIRAPqrPktStvLwWrknQJuFjYMwCQYFKw4DAhoFAKB4MBgGCisG
# AQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHEp
# HFr4B4hymnPKz0ctiId9ILELMA0GCSqGSIb3DQEBAQUABIIBAHKVvwkeJois+lb9
# eLikcsvz9iaejZMks7Fu7oFDkgqq7+Idme+Gnq3pITzOeOLWPCgFy9kXZMbUubeK
# T838TGCKiyOUITwifXDtj+jf2KM/a2U+aOsvzxK52l+TjlGpTC7gOO9RCYlZVn4S
# ZpSJ6WObD78Uz720Fa0RESTyyCnwvOrqMj0gsIzv9N+hgzsF5AIukLWJB7kYU93W
# fvHQi3rD3Y111Tx267n2BDhLT5jZ2vE4r3KuuXGWXhMTO3heZFIp7Z1DG003nAy1
# jCKJlBfCyEYkClOG+c5IxACF0XyV7yGu6pJX7sCZBk0PUqnxiMLziK2i4Obuoue2
# dstGpYqhggNMMIIDSAYJKoZIhvcNAQkGMYIDOTCCAzUCAQEwgZIwfTELMAkGA1UE
# BhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2Fs
# Zm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdv
# IFJTQSBUaW1lIFN0YW1waW5nIENBAhEAjHegAI/00bDGPZ86SIONazANBglghkgB
# ZQMEAgIFAKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkF
# MQ8XDTIxMDMwMjA5MjkxNVowPwYJKoZIhvcNAQkEMTIEMJ5p55VXxxYcTvLN1OD0
# Xy8AbwF933/P5vOW/+u7xTbrqV/TH+9trxVGFFQ7iTcr0jANBgkqhkiG9w0BAQEF
# AASCAgAiyYzpVoj9Ymtlws5z78J2VNnhNcST/nQH//v7DkJ1OKMX3JkRTb5gK5NW
# 54wDo2cXARNVFMaq4Q9rLvg8Tir3LNssYSgwuq1dqWk2HQc6uImgtlWxqBdyDycX
# 25oJ3+GUFCKW5bMKmAvWqYWqlDe+Euri4VblMgMhHaGY7BjeshQr6WFGyGmy2/Vd
# Ou8PIohIrI5JkDksAi7jxokua1g7kQgDshYqiA6hOr34qbK2n59Knjynk1oUaNo+
# baZ4hmIhi9dA3/kOdYRzCe645mz2H+Htv0/bgWnMxLvDNB8m2Y1Bo8ssG0wAjgrS
# z5PtLEsIe7ZmlG7sXK2D9mcf20FBlsD9nxrIDXtGqzc39dDt83Ar1TXCvXk+HU8f
# ugdk17Oq9zOIu1braW9Cvg7RBVa7SdqsqqRAgcA3v7Hp1+EvUILSARh21JOGlCS/
# Lvf7JOcHJFjpxl7dDzfh5EzjdWeOsS9d+7Ft3byTKiuyLp1n6Mvj6qoVUA0jshTF
# yYMS7Uz3wr2NHLVDeEJDa+4yP+v2bg2DBSyeDspNBLWjEG71XqTuM+avMyxY/wKY
# qvgbEb8/PYlnymRs1/2smcpWyLyWPaRAb43OEKK8FRqISMWe6QNi5wfydvKIvqci
# nN937Ygjgifay/hCYZ74a5kopl0wBFrL1G6y9jWwT6doWaBPpA==
# SIG # End signature block
