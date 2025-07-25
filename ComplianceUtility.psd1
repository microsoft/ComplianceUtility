# Copyright (c) Microsoft Corporation
# Licensed under the MIT License

@{

# Script module file associated with this manifest
RootModule = "ComplianceUtility.psm1"

# Version
ModuleVersion = "3.2.2"

# Unique ID
GUID = "31d06e6f-2981-4b97-9a89-5f8599e3a5f4"
   
# Author
Author = "Claus Schiroky"

# Company
CompanyName = "Microsoft Corp."

# Copyright
Copyright = "Copyright (c) Microsoft Corporation."

# Description
Description = "The 'Compliance Utility' is a powerful tool that helps troubleshoot and diagnose sensitivity labels, policies, settings and more. Whether you need to fix issues or reset configurations, this tool has you covered.`n`nHave you ever used the Sensitivity button in a Microsoft 365 App or applied a sensitivity label by right-clicking on a file? If so, you've either used the Microsoft 365 built-in labeling experience or the Purview Information Protection labeling client. If something is not working as expected with your DLP policies, sensitivity labels or you don't see any labels at all the 'Compliance Utility' will help you.`n`nPlease read the online manual for detailed information about the requirements, installation and usage: https://aka.ms/ComplianceUtility/manual`n"

# Minimum version of the Windows PowerShell engine required by this script module
PowerShellVersion = "5.1"

# Functions to export
FunctionsToExport = "ComplianceUtility"

# Packaged files
FileList = "ComplianceUtility.psm1","ComplianceUtility.psd1"

# Private data to pass to the module specified in RootModule/ModuleToProcess
PrivateData = @{

    PSData = @{

        # Tags. These help with module discovery in online galleries
        Tags = "office","365","powershell","microsoft","apple","mac","rms","module","aip","dlp","compliance","purview","mip","protection","template","sensitivity","unified","label","classification","reset","tool","azure","script","support"

        # A URL to the license
        LicenseUri = "https://github.com/microsoft/ComplianceUtility/blob/main/LICENSE"

        # A URL to the main website for this project
        ProjectUri = "https://aka.ms/ComplianceUtility"

        # ReleaseNotes
        ReleaseNotes = "https://github.com/microsoft/ComplianceUtility/releases/tag/3.2.2"

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI
HelpInfoURI = "https://github.com/microsoft/ComplianceUtility/blob/main/Manuals/3.2.2/Manual-Win.md"

}