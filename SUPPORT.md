# Support

## How to file issues and get help  

This project uses GitHub Issues to track problems and feature requests. Please search the existing 
issues and the following known issues section before filing new issues to avoid duplicates. For new issues, file your bug or 
feature request as a new Issue.

For help and questions about using this project, please contact the [author](mailto:claus.schiroky@micrososft.com?subject=RMS_Support_Tool).

## Known issues:

**Set-ExecutionPolicy has no effect**

This applies only to a manual installation: If you downloaded the RMS_Support_Tool from its [GitHub website](https://aka.ms/RMS_Support_Tool/Latest), it will be extended by an [Alternate Data Streams in NTFS](https://blogs.technet.microsoft.com/askcore/2013/03/24/alternate-data-streams-in-ntfs) (ADS). If the corresponding website in the ADS is not trusted in your environment, the PowerShell command "Set-ExecutionPolicy" has no effect.

**Resolution:** Either you right-click the downloaded script files and "Unblock" it, or you add the corresponding website to your trusted sites settings.

**Script does not start and returns an error**

If you see this message in a PowerShell command window, you are most likely affected by the Windows® Group Policy setting "Turn on Script Execution":

"Set-ExecutionPolicy : PowerShell updated your local preference successfully, but the setting is overridden by the group policy applied to your system or Set-ExecutionPolicy : Windows PowerShell updated your execution policy successfully, but the setting is overridden by a policy defined at a more specific scope."

**Resolution:** To resolve this problem, you must remove this Group Policy setting or configure a setting that allows scripts to run. Please request assistance from your administrator to do this. Please also read Use Group Policy to Manage Execution Policy and Set-ExecutionPolicy.
