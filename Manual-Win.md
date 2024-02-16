THIS IS FOR TESTING


# Unified Labeling Support Tool

* [Introduction](#Introduction)
   * [MIT License]([#MIT-License](https://github.com/microsoft/UnifiedLabelingSupportTool/blob/main/Manual-Win.md#mit-license-))
   * [Microsoft Privacy Statement](https://github.com/microsoft/UnifiedLabelingSupportTool/blob/main/Manual-Win.md#microsoft-privacy-statement)
* Requirements
   * Internet access
   * Exchange Online PowerShell module
   * AIPService module
   * Microsoft Azure Information Protection cmdlets
   * Microsoft Graph PowerShell modules
   * Microsoft PowerShell


## Introduction <a name="Introduction"></a>

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
RESET, RECORD PROBLEM, and COLLECT Endpoint URLs.

However, if you run the 'Unified Labeling Support Tool' with local administrative privileges, you will get some more collected logs (RECORD PROBLEM) and a complete RESET of all settings, instead of just user-specific settings being reset. By the way: The latter option is sufficient in most cases to reset Microsoft 365 Apps, while a complete reset is usually useful for all other applications.

## MIT License <a name="MIT-License"></a>

Copyright © Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 

## Microsoft Privacy Statement

Your privacy is important to us. [This privacy statement](https://privacy.microsoft.com/en-US/privacystatement) explains the personal data Microsoft processes, how Microsoft processes it, and for what purposes.
