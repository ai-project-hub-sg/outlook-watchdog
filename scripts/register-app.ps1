$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication -Force -DisableNameChecking
Connect-MgGraph -Scopes 'Application.ReadWrite.All' -UseDeviceAuthentication -ClientTimeout 600 -NoWelcome

Write-Host 'CONNECTED_OK'

# 解析 Microsoft Graph 服务主体的 scope id（不硬编码 GUID）
$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$need = @('User.Read','Mail.Read','Mail.Send','MailboxSettings.Read','offline_access')
$scopeIds = @()
foreach ($s in $graph.Oauth2PermissionScopes) {
    if ($need -contains $s.Value) { $scopeIds += $s.Id }
}
Write-Host ("SCOPES_RESOLVED=" + ($scopeIds.Count))

$rra = @{
    ResourceAppId  = '00000003-0000-0000-c000-000000000000'
    ResourceAccess = @($scopeIds | ForEach-Object { @{ Id = $_; Type = 'Scope' } })
}

$app = New-MgApplication -DisplayName 'outlook-watchdog' `
    -SignInAudience 'AzureADandPersonalMicrosoftAccount' `
    -IsFallbackPublicClient `
    -PublicClient @{ RedirectUris = @('https://login.microsoftonline.com/common/oauth2/nativeclient') } `
    -RequiredResourceAccess @($rra)

Write-Host ("APP_CLIENT_ID=" + $app.AppId)
Disconnect-MgGraph | Out-Null
