# Support

When creating the RMS_Support_Tool, great care was taken to ensure quality and functionality. Extensive tests were carried out before publication to intercept and handle any errors. However, there is no guarantee that an error will not occur in a wide variety of configurations and environments.

Should you ever encounter a problem with the RMS_Support_Tool, please use the information on this page to report it so that the problem can be resolved.

## Microsoft Support Policy  

Under this policy, the RMS_Support_Tool remains in support if the following criteria are met:

- You're using the [lastet version](https://aka.ms/RMS_Support_Tool/Latest) of the RMS_Support_Tool.
- You must be licensed with a product or service that uses [Microsoft Information Protection](https://www.microsoft.com/en-us/us-partner-blog/2018/11/05/microsoft-information-protection-and-unified-labeling/).

## How to file issues and get help  

The RMS_Support_Tool uses GitHub [Issues](https://github.com/microsoft/RMS_Support_Tool/issues) to track problems and feature requests. Please search the existing 
issues and the following known issues section before filing new issues to avoid duplicates. For new issues, file your bug or 
feature request as a new Issue. Please describe the Issue as detailed as possible. A screenshot of an error and/or a step-by-step description to reproduce a problem are very helpful.

## Known issues

**Set-ExecutionPolicy has no effect**

This applies only to a manual installation: If you downloaded the RMS_Support_Tool from its [GitHub website](https://aka.ms/RMS_Support_Tool/Latest), it will be extended by an [Alternate Data Streams in NTFS](https://blogs.technet.microsoft.com/askcore/2013/03/24/alternate-data-streams-in-ntfs) (ADS). If the corresponding website in the ADS is not trusted in your environment, the PowerShell command "Set-ExecutionPolicy" has no effect.

**Resolution:** Either you right-click the downloaded script files and "Unblock" it, or you add the corresponding website to your trusted sites settings.

**Script does not start and returns an error**

If you see this message in a PowerShell command window, you are most likely affected by the Windows® Group Policy setting "Turn on Script Execution":

```PowerShell
Set-ExecutionPolicy : PowerShell updated your local preference successfully, but the setting is overridden by the group
policy applied to your system or Set-ExecutionPolicy : Windows PowerShell updated your execution policy successfully,
but the setting is overridden by a policy defined at a more specific scope.
```

**Resolution:** To resolve this problem, you must remove this Group Policy setting or configure a setting that allows scripts to run. Please request assistance from your administrator to do this. Please also read [Use Group Policy to Manage Execution Policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1#use-group-policy-to-manage-execution-policy) and [Set-ExecutionPolicy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-5.1).



