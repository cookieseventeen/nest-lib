# 資料模型設計

## 資料模型關聯圖

```
+------------------+                      +----------------------+
|                  |                      |                      |
|      使用者       |                      |   使用者 SSO 連結     |
|                  |                      |                      |
| - id             |                      | - id                 |
| - email          |                      | - userId             |
| - firstName      | 1                  n | - provider           |
| - lastName       +----------------------+ - providerId         |
| - role           | 一個使用者可以有多個   | - createdAt          |
| - createdAt      | SSO 提供者連結        | - updatedAt          |
| - updatedAt      |                      |                      |
+------------------+                      +----------------------+
```

## Prisma Schema 定義

```prisma
model User {
  id             Int                @id @default(autoincrement())
  email          String             @unique
  password       String?            // 可以為 null (SSO 使用者)
  firstName      String?
  lastName       String?
  profilePicture String?
  role           String             @default("user")
  provider       String?            // 主要 SSO 提供者
  providerId     String?            // 主要提供者 ID
  createdAt      DateTime           @default(now())
  updatedAt      DateTime           @updatedAt
  ssoConnections UserSsoConnection[]
}

// 儲存使用者的多個 SSO 連結
model UserSsoConnection {
  id         Int      @id @default(autoincrement())
  userId     Int
  provider   String   // 'google', 'facebook', 'github', 等
  providerId String   // 外部提供者的使用者 ID
  createdAt  DateTime @default(now())
  updatedAt  DateTime @updatedAt
  user       User     @relation(fields: [userId], references: [id])

  @@unique([userId, provider])
}
```

## 模型說明

### User 模型

- **id**: 主鍵，自動增加
- **email**: 使用者電子郵件，唯一值
- **password**: 密碼 (可為null，如使用SSO登入)
- **firstName**: 名字
- **lastName**: 姓氏
- **profilePicture**: 頭像URL
- **role**: 使用者角色，預設為"user"
- **provider**: 主要SSO提供者
- **providerId**: 提供者給的使用者ID
- **createdAt**: 建立時間
- **updatedAt**: 更新時間
- **ssoConnections**: 與UserSsoConnection的一對多關聯

### UserSsoConnection 模型

- **id**: 主鍵，自動增加
- **userId**: 外鍵，連結到User
- **provider**: SSO提供者名稱 (google, facebook, github等)
- **providerId**: 提供者給的使用者ID
- **createdAt**: 建立時間
- **updatedAt**: 更新時間
- **user**: 與User的關聯

## 多提供者連結設計

此資料模型支援使用者關聯多個SSO提供者的情境：

1. **一個使用者可以用多種方式登入**：
   - 使用者可以連結Google、Facebook、GitHub等多個提供者到同一帳號
   - 使用者可以用任一已連結的提供者進行登入

2. **提供者切換/管理**：
   - 使用者可以新增、移除SSO提供者連結
   - 確保使用者至少保留一個登入方式 (密碼或SSO連結)

3. **使用者合併機制**：
   - 如果使用者使用新的SSO提供者登入，且該SSO帳號的email與已存在的使用者匹配，會自動建立連結
   - 這樣可以避免為同一人建立多個帳號

## 權限分層模型

使用role欄位實現基本的權限管理：

```
+------------------+
|    超級管理員     | 最高層級權限 (所有操作)
+------------------+
         |
         v
+------------------+
|     管理員        | 高層級權限 (大部分操作)
+------------------+
         |
         v
+------------------+
|      編輯者       | 中層級權限 (編輯、建立)
+------------------+
         |
         v
+------------------+
|     一般使用者     | 基本權限 (讀取、個人操作)
+------------------+
         |
         v
+------------------+
|     訪客用戶      | 最低權限 (僅公開內容)
+------------------+
```