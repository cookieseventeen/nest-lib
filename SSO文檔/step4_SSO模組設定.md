# SSO模組設定

## 模組結構

SSO模組是整個SSO系統的核心部分，負責整合不同的認證策略並提供統一的介面。以下是模組的基本結構：

```typescript
// sso.module.ts
import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule } from '@nestjs/config';
import { SsoController } from './sso.controller';
import { SsoService } from './sso.service';
import { GoogleStrategy } from './strategies/google.strategy';
import { FacebookStrategy } from './strategies/facebook.strategy';
import { GithubStrategy } from './strategies/github.strategy';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    ConfigModule,
  ],
  controllers: [SsoController],
  providers: [
    SsoService, 
    GoogleStrategy, 
    FacebookStrategy, 
    GithubStrategy
  ],
  exports: [SsoService],
})
export class SsoModule {}
```

## 模組說明

1. **匯入的模組**：
   - `PassportModule`: 提供身分驗證功能，設定預設策略為JWT
   - `ConfigModule`: 用於存取環境變數和應用程式配置

2. **控制器**：
   - `SsoController`: 處理所有與SSO相關的HTTP請求

3. **提供者**：
   - `SsoService`: 提供核心SSO邏輯功能
   - `GoogleStrategy`: Google OAuth 2.0策略
   - `FacebookStrategy`: Facebook OAuth策略
   - `GithubStrategy`: GitHub OAuth策略
   
4. **匯出**：
   - `SsoService`: 讓其他模組可以使用SSO服務

## 環境變數設定

為了使SSO模組正常工作，需要在`.env`檔案中配置以下變數：

```
# 資料庫與 JWT 設定
DATABASE_URL="postgresql://postgres:123456@localhost:5432/nestdb?schema=public"
JWT_SECRET="您的安全密鑰"
JWT_REFRESH_SECRET="您的重新整理token密鑰"
JWT_EXPIRATION="1h"
JWT_REFRESH_EXPIRATION="7d"
JWT_AUDIENCE="myapp-api"
JWT_ISSUER="myapp-auth"
FRONTEND_URL="http://localhost:4200"

# Google OAuth
GOOGLE_CLIENT_ID="您的Google客戶端ID"
GOOGLE_CLIENT_SECRET="您的Google客戶端密鑰"
GOOGLE_CALLBACK_URL="http://localhost:3000/auth/google/callback"

# Facebook OAuth
FACEBOOK_APP_ID="您的Facebook應用程式ID"
FACEBOOK_APP_SECRET="您的Facebook應用程式密鑰"
FACEBOOK_CALLBACK_URL="http://localhost:3000/auth/facebook/callback"

# GitHub OAuth
GITHUB_CLIENT_ID="您的GitHub客戶端ID"
GITHUB_CLIENT_SECRET="您的GitHub客戶端密鑰"
GITHUB_CALLBACK_URL="http://localhost:3000/auth/github/callback"

# Session 設定
SESSION_SECRET="您的session密鑰"
```

## JWT設定

JWT (JSON Web Token) 是實現無狀態身分驗證的重要部分，以下是其在系統中的配置方式：

```typescript
// auth.module.ts
JwtModule.registerAsync({
  imports: [ConfigModule],
  inject: [ConfigService],
  useFactory: (configService: ConfigService) => ({
    secret: configService.get<string>('JWT_SECRET'),
    signOptions: { 
      expiresIn: configService.get('JWT_EXPIRATION', '1h'),
      audience: configService.get('JWT_AUDIENCE'),
      issuer: configService.get('JWT_ISSUER'),
      jwtid: randomUUID(), // 每個 token 唯一識別符
    },
  }),
})
```

此配置確保：

1. JWT使用環境變數中的密鑰
2. 設定合適的過期時間
3. 指定受眾和發行者，增強安全性
4. 為每個token產生唯一識別符

## 提供者註冊與配置

每個SSO提供者都需要在其平台上註冊應用程式並獲取必要的認證資訊：

1. **Google**:
   - 訪問 Google Cloud Console
   - 建立新項目
   - 設定OAuth同意畫面
   - 建立OAuth 2.0客戶端ID
   - 配置授權的重定向URI

2. **Facebook**:
   - 訪問Facebook開發者平台
   - 建立新應用程式
   - 新增Facebook登入產品
   - 設定有效的OAuth重定向URI

3. **GitHub**:
   - 訪問GitHub設定頁面
   - 前往Developer settings
   - 註冊新的OAuth應用程式
   - 設定授權回調URL

獲取認證資訊後，將這些值放入環境變數中即可使用。