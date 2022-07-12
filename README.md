# MSTeamsCQD
Allows Tenant Admins to connect to the Call Quality Dashboard data API for Teams and Skype for Business Online through PowerShell. 
Requires Report Reader role in Office 365 at a minimum to authenticate.


## Getting started


```PowerShell
Install-Module MSTeamsCQD
```

or

```PowerShell
Install-Module MSTeamsCQD -Scope CurrentUser -Force -RequiredVersion 1.2.0
```

## Examples

you will find example querys inside the Examples folder located in this repo 



## Requirements
  - MS Teams Admin roles
## Known behavior
  - you will need to login every one hour

## Sources

### CQDPowerShell
https://www.powershellgallery.com/packages/CQDPowerShell/2.0.1
### Github Publish to PowershellGallery Action
https://www.codewrecks.com/post/general/powershell-gallery-publish/
