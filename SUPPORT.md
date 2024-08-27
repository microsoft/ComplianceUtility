# Support

When creating the 'Compliance Utility', great care was taken to ensure quality and functionality. Extensive tests were carried out before publication to intercept and handle any errors. However, there is no guarantee that an error will not occur in a wide variety of configurations and environments.

Should you ever encounter a problem with the 'Compliance Utility', please use the information on this page to report it so that the problem can be resolved.

## Microsoft Support Policy  

Under this policy, the 'Compliance Utility' remains in support if the following criteria are met:

* You're using the [lastet version](https://aka.ms/ComplianceUtility/Latest) of the 'Compliance Utility'.
* You must be licensed with a product or service that uses a [Microsoft Information Protection subscription](https://learn.microsoft.com/en-us/office365/servicedescriptions/azure-information-protection#available-plans).

## How to file issues and get help  

The 'Compliance Utility' uses GitHub [Issues](https://github.com/microsoft/ComplianceUtility/issues) to track problems and feature requests.

Please check for [known issues](https://github.com/microsoft/ComplianceUtility/blob/main/SUPPORT.md#known-issues) before submitting new issues to avoid duplicates.

For new issues, file your bug or feature request as a new Issue. Please describe the Issue as detailed as possible. A screenshot of the error and/or a step-by-step description of how to reproduce a problem would be very helpful for this.

## Known issues

* **Error "End of Central Directory record could not be found" when installing the 'Compliance Utility'**

    When you try to install the 'Compliance Utility', you may see the following error:
    
    ```
    PackageManagement\Install-Package : Package 'ComplianceUtility' failed to be installed because: End of Central Directory
    record could not be found.
    At C:\Programm Files\WindowsPowerShell\Modules\PowerShellGet\1.0.0.1\PSModule.psm1:1809 char:21
    + ...          $null = PackageManagement\Install-Package @PSBoundParameters
    +                      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
       + CategoryInfo            : InvalidResult: (ComplianceUtility:String) [Install-Package], Exception
       + FullQualifiedErrorId    : Package '{0}' failed to be installed because: {1}, Microsoft.PowerShell.PackageManagement
      .Cmdletes.InstallPackage
    ```

    **Resolution:** To solve this issue you need to ensure to have any proxy or network filtering mechanism disabled.

* **Collecting labels and policies raise PowerShell error "not recognized as the name of a cmdlet"**

    When you try to collect 'Labels and policies', you might see the following errors:
    
    ```
    Get-Label : The term 'Get-Label' is not recognized as the name of a cmdlet, function, script file, or operable program.
    Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
    At line:1 char:1
    + Get-Label
    + ~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Get-Label:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
    ```
    
    ```
    Get-LabelPolicy : The term 'Get-LabelPolicy' is not recognized as the name of a cmdlet, function, script file, or operable
    program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
    At line:1 char:1
    + Get-LabelPolicy
    + ~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Get-LabelPolicy:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
    ```    

    This is due to the fact that permissions have expanded through roles in the Purview Compliance Portal.
    
    Additional information: [Global Administrator](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator), 
    [Permissions in the Microsoft Purview compliance portal](https://learn.microsoft.com/en-us/microsoft-365/compliance/microsoft-365-compliance-center-permissions?view=o365-worldwide)    
    
    **Resolution:** You must add the appropriate administrator (usually the global administrator) to the [Information Protection](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/scc-permissions?view=o365-worldwide#role-groups-in-microsoft-defender-for-office-365-and-microsoft-purview-compliance) roles group in the [Microsoft Purview Compliance Center](https://compliance.microsoft.com/compliancecenterpermissions).

* **Running RESET raise PowerShell error "The specified path, file name, or both are too long"**

    This applies only to Windows environments. When you try to run RESET, you may see the following error:

    ```
    Get-ChhildItem : The specified path, file name, or both are too long. The fully qualified file name must be less than
    260 characters, and the directory name must be less than 248 characters.
    At C:\Program Files\WindowsPowerShell\Modules\ComplianceUtility\3.2.1\ComplianceUtility.psm1:1194 char:17
    + ...         Get-ChildItem -Path $Private:objItem -Exclude “Telemetry” ...
    +             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
       + CategoryInfo            : ReadError: (C:\Users...}}.drm:String) [Get-ChildItem], PathTooLongException
       + FullyQualifiedErrorId   : GetItemIOError,Microsoft.PowerShell.Commands.GetChildItemCommand
    ```

    **Resolution:** You need to [enable long paths on Windows.](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry#registry-setting-to-enable-long-paths)

* **Set-ExecutionPolicy has no effect**

    This applies only to a manual installation: If you downloaded the 'Compliance Utility' from its [GitHub website](https://aka.ms/ComplianceUtility/Latest), it will be extended by an [Alternate Data Streams in NTFS](https://blogs.technet.microsoft.com/askcore/2013/03/24/alternate-data-streams-in-ntfs) (ADS). If the corresponding website in the ADS is not trusted in your environment, the PowerShell command "Set-ExecutionPolicy" has no effect.

    **Resolution:** Either you right-click the downloaded script files and "Unblock" it, or you add the corresponding website to your trusted site settings.

* **Script does not start and returns an error**

    If you see this message in a PowerShell command window, you are most likely affected by the Windows® Group Policy setting "Turn on Script Execution":

    ```
    Set-ExecutionPolicy : PowerShell updated your local preference successfully, but the setting is overridden by the group
    policy applied to your system or Set-ExecutionPolicy : Windows PowerShell updated your execution policy successfully,
    but the setting is overridden by a policy defined at a more specific scope.
    ```

    **Resolution:** To resolve this problem, you must remove this Group Policy setting or configure a setting that allows scripts to run. Please request assistance from your administrator to do this. Please also read [Use Group Policy to Manage Execution Policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1#use-group-policy-to-manage-execution-policy) and [Set-ExecutionPolicy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-5.1).

* **Installing PowerShellGet module cause an error**

    This applies only to a manual installation. You may see the following error:

    ```
    PackageManagement\Install-Package : No match was found for the specified search criteria and module name 'PowerShellGet'.
    Try Get-PSRepository to see all available registered module repositories.
    At C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\1.0.0.1\PSModule.psm1:1772 char:21
    + ...          $null = PackageManagement\Install-Package @PSBoundParameters
    +                      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo : ObjectNotFound: (Microsoft.Power....InstallPackage:InstallPackage) [Install-Package],
          Exception
        + FullyQualifiedErrorId : NoMatchFoundForCriteria,Microsoft.PowerShell.PackageManagement.Cmdlets.
          InstallPackage
    ```

    **Resolution:** To resolve this issue, you must run the following Windows PowerShell command to register the default module repositories:

    ```
    PS C:\> Register-PSRepository -Default
    ```

* **"powershell-7.3.4-osx-x64.pkg" can't be opened because Apple cannot check it for malicious software** 

    This applies only on Apple macOS: If you double-click the file the above message is displayed (the version may differ). It happens due to your Security & Privacy preferences.

    **Resolution:** To work around this issue, either you click "Open Anyway" in the general settings of your Security & Privacy preferences, or you request assistance from your administrator.



