# Support

When creating the 'Unified Labeling Support Tool', great care was taken to ensure quality and functionality. Extensive tests were carried out before publication to intercept and handle any errors. However, there is no guarantee that an error will not occur in a wide variety of configurations and environments.

Should you ever encounter a problem with the 'Unified Labeling Support Tool', please use the information on this page to report it so that the problem can be resolved.

## Microsoft Support Policy  

Under this policy, the 'Unified Labeling Support Tool' remains in support if the following criteria are met:

- You're using the [lastet version](https://aka.ms/UnifiedLabelingSupportTool/Latest) of the 'Unified Labeling Support Tool'.
- You must be licensed with a product or service that uses [Microsoft Information Protection and Unified Labeling](https://www.microsoft.com/en-us/us-partner-blog/2018/11/05/microsoft-information-protection-and-unified-labeling/).

## How to file issues and get help  

The 'Unified Labeling Support Tool' uses GitHub [Issues](https://github.com/microsoft/UnifiedLabelingSupportTool/issues) to track problems and feature requests.

Please check for [known issues](https://github.com/microsoft/UnifiedLabelingSupportTool/blob/main/SUPPORT.md#known-issues) before submitting new issues to avoid duplicates.

For new issues, file your bug or feature request as a new Issue. Please describe the Issue as detailed as possible. A screenshot of the error and/or a step-by-step description of how to reproduce a problem would be very helpful for this.

## Known issues

* **Set-ExecutionPolicy has no effect**

    This applies only to a manual installation: If you downloaded the 'Unified Labeling Support Tool' from its [GitHub website](https://aka.ms/UnifiedLabelingSupportTool/Latest), it will be extended by an [Alternate Data Streams in NTFS](https://blogs.technet.microsoft.com/askcore/2013/03/24/alternate-data-streams-in-ntfs) (ADS). If the corresponding website in the ADS is not trusted in your environment, the PowerShell command "Set-ExecutionPolicy" has no effect.

    **Resolution:** Either you right-click the downloaded script files and "Unblock" it, or you add the corresponding website to your trusted site settings.

* **Script does not start and returns an error**

    If you see this message in a PowerShell command window, you are most likely affected by the Windows® Group Policy setting "Turn on Script Execution":

    ```Text
    Set-ExecutionPolicy : PowerShell updated your local preference successfully, but the setting is overridden by the group policy applied to your system or Set-ExecutionPolicy : Windows PowerShell updated your execution policy successfully, but the setting is overridden by a policy defined at a more specific scope.
    ```

    **Resolution:** To resolve this problem, you must remove this Group Policy setting or configure a setting that allows scripts to run. Please request assistance from your administrator to do this. Please also read [Use Group Policy to Manage Execution Policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1#use-group-policy-to-manage-execution-policy) and [Set-ExecutionPolicy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-5.1).

* **Installing PowerShellGet module cause an error**

    This applies only to a manual installation: If you follow step 2. Install PowerShellGet-module from the [step-by-step installation](https://aka.ms/UnifiedLabelingSupportTool/#Step-by-step_installation), you may see the following error:

    ```Text
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

    ```Text
    PS C:\> Register-PSRepository -Default
    ```

* **"powershell-7.1.4-osx-x64.pkg" can't be opened because Apple cannot check it for malicious software** 

    This applies only on Apple macOS: If you double-click the file the above message is displayed (the version may differ). It happens due to your Security & Privacy preferences.

    **Resolution:** To work around this issue, either you click "Open Anyway" in the general settings of your Security & Privacy preferences, or you request assistance from your administrator.



