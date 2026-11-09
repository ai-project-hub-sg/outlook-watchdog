# 自建 Entra 应用（解锁完整授权：Graph + IMAP/SMTP 协议探测）

> 背景：公共 client_id（Graph CLI）只注册了 Graph 权限，`完整`授权会因
> `invalid_scope` 失败。MSA 个人账号**无法用 API 建应用**
> （`/applications` 返回 "not supported for MSA"），必须门户手动操作，约 5 分钟。

## 步骤

1. https://entra.microsoft.com → **Identity → Applications → App registrations → New registration**
   - Name：`outlook-watchdog`
   - Supported account types：**Personal Microsoft accounts only**
   - 点 Register → 记下 Overview 页的 **Application (client) ID**

2. **Authentication → Add a platform → Mobile and desktop applications**
   - 勾 `https://login.microsoftonline.com/common/oauth2/nativeclient`
   - 同页 **Allow public client flows = Yes**（device code 必需）

3. **Manifest**（左侧菜单）→ `requiredResourceAccess` **只保留 Graph 块**
   （Exchange Online 不声明——v2 端点支持动态 consent，授权请求带
   scope 即可；若租户无 EXO service principal，声明反而保存报错）：

```json
"requiredResourceAccess": [
  {
    "resourceAppId": "00000003-0000-0000-c000-000000000000",
    "resourceAccess": [
      { "id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope" },
      { "id": "570282fd-fa5c-430d-a7fd-fc8dc98a9dca", "type": "Scope" },
      { "id": "b633e1c5-b582-4048-a93e-9f11b44c7e96", "type": "Scope" },
      { "id": "693c5e45-0940-467d-9b8a-1022fb9d42ef", "type": "Scope" },
      { "id": "7427e0e9-2fba-42fe-b0c0-848c9e6a8182", "type": "Scope" }
    ]
  },
]
```

   - 保存。若 GUID 校验失败（微软偶发变更 id），到 **API permissions →
     Add a permission** 手动搜 `Office 365 Exchange Online` 添加
     `IMAP.AccessAsUser.All`/`SMTP.Send`（Delegated），Graph 侧同理补
     `User.Read/Mail.Read/Mail.Send/MailboxSettings.Read/offline_access`。

4. WebUI：**设置页** → 默认 Client ID 填新 appId → 账号详情 →
   **重新授权 → 完整** → 同意页应出现 IMAP/SMTP 权限项 → 开 c6/c7 →
   立即检查期待 `xoauth2 ok`。

## GUID 对照（备查）

| 权限 | GUID | 资源 |
|---|---|---|
| User.Read | e1fe6dd8-ba31-4d61-89e7-88639da4683d | Graph |
| Mail.Read | 570282fd-fa5c-430d-a7fd-fc8dc98a9dca | Graph |
| Mail.Send | b633e1c5-b582-4048-a93e-9f11b44c7e96 | Graph |
| MailboxSettings.Read | 693c5e45-0940-467d-9b8a-1022fb9d42ef | Graph |
| offline_access | 7427e0e9-2fba-42fe-b0c0-848c9e6a8182 | Graph |
| IMAP.AccessAsUser.All | 652390e4-393a-48de-948d-67205b21a982 | Exchange Online |
| SMTP.Send | 258f6539-9087-4fdd-bfb9-ea5f61e48f31 | Exchange Online |
