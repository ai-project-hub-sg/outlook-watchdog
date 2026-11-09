# 负面对账辅助脚本：用 MailboxSettings.ReadWrite scope 建/删一条测试转发规则。
# 凭据纪律：RT 从 .env 内部读取，不回显、不落盘、不进参数。
param([ValidateSet('add','remove')][string]$Action = 'add')

$ErrorActionPreference = 'Stop'
$rt = $null
Get-Content .env | ForEach-Object {
    if ($_ -match '^OUTLOOK_RTW\s*=\s*"(.+)"') { $rt = $matches[1] }
}
if (-not $rt) { Write-Error 'OUTLOOK_RTW not found in .env'; exit 1 }

# RT -> AT（MailboxSettings.ReadWrite scope）
$resp = Invoke-RestMethod -Method Post -Uri 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token' -Body @{
    client_id     = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
    grant_type    = 'refresh_token'
    refresh_token = $rt
    scope         = 'https://graph.microsoft.com/MailboxSettings.ReadWrite offline_access'
}
$at = $resp.access_token
$H = @{ Authorization = "Bearer $at"; 'Content-Type' = 'application/json' }
$rulesUri = 'https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules'

if ($Action -eq 'add') {
    $body = @{
        displayName = 'wd-test-fwd'
        sequence    = 1
        isEnabled   = $true
        conditions  = @{}
        actions     = @{
            forwardTo           = @(@{ emailAddress = @{ address = 'sam_desens0206@outlook.com' } })
            stopProcessingRules = $true
        }
    } | ConvertTo-Json -Depth 6
    $r = Invoke-RestMethod -Method Post -Uri $rulesUri -Headers $H -Body $body
    Write-Host ("RULE_ADDED id=" + $r.id.Substring(0, [Math]::Min(12, $r.id.Length)))
} else {
    $rules = (Invoke-RestMethod -Method Get -Uri $rulesUri -Headers $H).value
    $t = $rules | Where-Object { $_.displayName -eq 'wd-test-fwd' } | Select-Object -First 1
    if (-not $t) { Write-Host 'RULE_NOT_FOUND'; exit 0 }
    Invoke-RestMethod -Method Delete -Uri "$rulesUri/$($t.id)" -Headers $H | Out-Null
    Write-Host 'RULE_REMOVED'
}
