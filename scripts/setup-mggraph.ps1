$ErrorActionPreference = 'Stop'
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
Set-PSRepository PSGallery -InstallationPolicy Trusted
Install-Module Microsoft.Graph.Authentication,Microsoft.Graph.Applications -Scope CurrentUser -Force -AllowClobber
'MODULES_INSTALLED'
