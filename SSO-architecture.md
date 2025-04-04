# 多 SSO 提供者整合架構設計

## 系統架構圖

```
+---------------------+    +----------------------+    +----------------------+
|                     |    |                      |    |                      |
|  Google OAuth 2.0   |    |   Facebook OAuth     |    |   其他 SSO 提供者    |
|                     |    |                      |    |                      |
+----------+----------+    +-----------+----------+    +----------+-----------+
           |                           |                          |
           |                           |                          |
           v                           v                          v
+----------+---------------------------+-------------+------------+----------+
|                                                                             |
|                           Passport 策略層                                    |
|                                                                             |
|  +---------------+    +----------------+    +---------------------+         |
|  | GoogleStrategy|    | FacebookStrategy|   | 其他 SSO 策略         |         |
|  +-------+-------+    +--------+-------+    +-----------+---------+         |
|          |                     |                        |                   |
+----------+---------------------+------------------------+-------------------+
           |                     |                        |
           |                     |                        |
           v                     v                        v
+----------+---------------------+------------------------+-------------------+
|                                                                             |
|                             SSO 服務層                                       |
|                                                                             |
|  +------------------------------------------------------------------+       |
|  |                       SsoService                                  |       |
|  |                                                                   |       |
|  |  +---------------------+  +-------------------+  +-------------+  |       |
|  |  | validateOrCreateUser|  | linkProviderToUser|  | 其他服務方法  |  |       |
|  |  +---------------------+  +-------------------+  +-------------+  |       |
|  |                                                                   |       |
|  +------------------------------------------------------------------+       |
|                                      |                                      |
+--------------------------------------+--------------------------------------+
                                       |
                                       v
+--------------------------------------+--------------------------------------+
|                                                                             |
|                             使用者資料儲存層                                  |
|                                                                             |
|  +---------------------------+      +----------------------------+          |
|  |         User 模型          |      |    UserSsoConnection 模型   |          |
|  |                           +----->+                            |          |
|  |  - id                     |      |  - id                      |          |
|  |  - email                  |      |  - userId                  |          |
|  |  - firstName              |      |  - provider                |          |
|  |  - lastName               |      |  - providerId              |          |
|  |  - role                   |      |  - createdAt               |          |
|  |  - ...其他欄位              |      |  - updatedAt               |          |
|  +---------------------------+      +----------------------------+          |
|                                                                             |
+--------------------------------------+--------------------------------------+
                                       |
                                       v
+--------------------------------------+--------------------------------------+
|                                                                             |
|                             API 控制器層                                     |
|                                                                             |
|  +---------------------------+      +----------------------------+          |
|  |      SsoController        |      |       AuthController       |          |
|  |                           |      |                            |          |
|  |  - /auth/google           |      |  - /auth/login            |          |
|  |  - /auth/facebook         |      |  - /auth/register         |          |
|  |  - /auth/github           |      |  - /auth/profile          |          |
|  |  - ...其他 SSO 路由         |      |  - ...其他身分驗證路由       |          |
|  +---------------------------+      +----------------------------+          |
|                                                                             |
+--------------------------------------+--------------------------------------+
                                       |
                                       v
+--------------------------------------+--------------------------------------+
|                                                                             |
|                               前端應用程式                                    |
|                                                                             |
|  +---------------------------+      +----------------------------+          |
|  |       登入頁面             |      |        使用者管理頁面         |          |
|  |                           |      |                            |          |
|  |  [Google 登入按鈕]         |      |  - 顯示連結的 SSO 提供者      |          |
|  |  [Facebook 登入按鈕]       |      |  - 管理提供者連結            |          |
|  |  [其他 SSO 按鈕]           |      |  - 帳號設定                 |          |
|  +---------------------------+      +----------------------------+          |
|                                                                             |
+-----------------------------------------------------------------------------+
```

## SSO 登入流程圖

```
+------------------+          +------------------+          +------------------+
|                  |          |                  |          |                  |
|   使用者/瀏覽器    +--------->+   NestJS 後端    +--------->+  SSO 提供者 (例如  |
|                  |  1. 點擊  |                  | 2. 重定向  |  Google)         |
+--------+---------+  SSO按鈕  +--------+---------+          +--------+---------+
         ^                             |                              |
         |                             |                              |
         |                             |                              |
         |                             |                              |
         |                    6. 返回JWT|                              |
         |                       Token |                              |
         |                             |                              v
+--------+---------+          +--------+---------+          +------------------+
|                  |          |                  |          |                  |
|   前端應用程式     |<---------+   NestJS 後端    |<---------+  SSO 提供者       |
|                  | 5. 重定向  |                  | 3. 使用者  |                  |
+------------------+ 到前端頁面 +--------+---------+ 同意授權後 +------------------+
                                        |           回調 API
                                        |
                                        v
                             +------------------+
                             |                  |
                             |  資料庫 (儲存/更新 |
                             |  使用者資訊)      |
                             |                  |
                             +------------------+
                                        |
                                        | 4. 建立/更新使用者
                                        |    產生 JWT Token
                                        v
```

## 權限分層架構

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

## 程式碼實作指南

### 1. 設定 Prisma Schema

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

### 2. 建立 SSO 模組

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

### 3. 各種 SSO 策略實作

#### Google 策略

```typescript
// strategies/google.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';
import { SsoService } from '../sso.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private readonly configService: ConfigService,
    private readonly ssoService: SsoService,
  ) {
    super({
      clientID: configService.get<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  async validate(accessToken, refreshToken, profile, done) {
    const user = await this.ssoService.validateOrCreateUser({
      email: profile.emails[0].value,
      firstName: profile.name.givenName,
      lastName: profile.name.familyName,
      picture: profile.photos[0].value,
      provider: 'google',
      providerId: profile.id,
    });
    
    done(null, user);
  }
}
```

#### Facebook 策略

```typescript
// strategies/facebook.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-facebook';
import { ConfigService } from '@nestjs/config';
import { SsoService } from '../sso.service';

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
  constructor(
    private readonly configService: ConfigService,
    private readonly ssoService: SsoService,
  ) {
    super({
      clientID: configService.get<string>('FACEBOOK_APP_ID'),
      clientSecret: configService.get<string>('FACEBOOK_APP_SECRET'),
      callbackURL: configService.get<string>('FACEBOOK_CALLBACK_URL'),
      profileFields: ['id', 'emails', 'name', 'picture.type(large)'],
      scope: ['email'],
    });
  }

  async validate(accessToken, refreshToken, profile, done) {
    const user = await this.ssoService.validateOrCreateUser({
      email: profile.emails[0].value,
      firstName: profile.name.givenName,
      lastName: profile.name.familyName,
      picture: profile.photos ? profile.photos[0].value : undefined,
      provider: 'facebook',
      providerId: profile.id,
    });
    
    done(null, user);
  }
}
```

#### GitHub 策略

```typescript
// strategies/github.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-github2';
import { ConfigService } from '@nestjs/config';
import { SsoService } from '../sso.service';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(
    private readonly configService: ConfigService,
    private readonly ssoService: SsoService,
  ) {
    super({
      clientID: configService.get<string>('GITHUB_CLIENT_ID'),
      clientSecret: configService.get<string>('GITHUB_CLIENT_SECRET'),
      callbackURL: configService.get<string>('GITHUB_CALLBACK_URL'),
      scope: ['user:email'],
      passReqToCallback: true, // 將 request 物件傳遞給 validate 方法
    });
  }

  async validate(req, accessToken, refreshToken, profile, done) {
    // 驗證 state
    const { oauthState } = req.session;
    if (oauthState && 
        oauthState.value !== req.query.state || 
        oauthState.provider !== 'github' ||
        Date.now() - new Date(oauthState.createdAt).getTime() > 10 * 60 * 1000) { // 10分鐘過期
      return done(new UnauthorizedException('無效的OAuth state'), null);
    }
    
    // 清除已使用的 state
    if (oauthState) {
      delete req.session.oauthState;
    }

    const user = await this.ssoService.validateOrCreateUser({
      email: profile.emails[0].value,
      firstName: profile.displayName?.split(' ')[0] || '',
      lastName: profile.displayName?.split(' ').slice(1).join(' ') || '',
      picture: profile.photos?.[0]?.value,
      provider: 'github',
      providerId: profile.id,
    });
    
    done(null, user);
  }
}
```

### 4. SSO 服務實作

```typescript
// sso.service.ts
import { Injectable, BadRequestException, InternalServerErrorException, NotFoundException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';

interface SsoUserData {
  email: string;
  firstName?: string;
  lastName?: string;
  picture?: string;
  provider: string;
  providerId: string;
}

@Injectable()
export class SsoService {
  private readonly logger = new Logger(SsoService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  // 處理不同提供者的資料格式差異
  private providerDataMappers = {
    google: (profile: any): SsoUserData => ({
      email: profile.emails[0].value,
      firstName: profile.name.givenName,
      lastName: profile.name.familyName,
      picture: profile.photos?.[0]?.value,
      provider: 'google',
      providerId: profile.id,
    }),
    facebook: (profile: any): SsoUserData => ({
      email: profile.emails[0].value,
      firstName: profile.name.givenName,
      lastName: profile.name.familyName,
      picture: profile.photos?.[0]?.value,
      provider: 'facebook',
      providerId: profile.id,
    }),
    github: (profile: any): SsoUserData => ({
      email: profile.emails[0].value,
      firstName: profile.displayName?.split(' ')[0] || '',
      lastName: profile.displayName?.split(' ').slice(1).join(' ') || '',
      picture: profile.photos?.[0]?.value,
      provider: 'github',
      providerId: profile.id,
    }),
  };

  mapProviderDataToSsoUser(provider: string, profile: any): SsoUserData {
    const mapper = this.providerDataMappers[provider];
    if (!mapper) {
      throw new BadRequestException(`不支援的SSO提供者: ${provider}`);
    }
    return mapper(profile);
  }

  async validateOrCreateUser(ssoUserData: SsoUserData) {
    try {
      // 驗證必要欄位
      if (!ssoUserData.email || !ssoUserData.provider || !ssoUserData.providerId) {
        throw new BadRequestException('缺少必要的SSO資料欄位');
      }
      
      // 檢查email格式
      if (!/^\S+@\S+\.\S+$/.test(ssoUserData.email)) {
        throw new BadRequestException('無效的電子郵件格式');
      }
      
      // 資料清理與驗證
      const sanitizedData = {
        email: ssoUserData.email.toLowerCase().trim(),
        firstName: ssoUserData.firstName ? this.sanitizeInput(ssoUserData.firstName) : '',
        lastName: ssoUserData.lastName ? this.sanitizeInput(ssoUserData.lastName) : '',
        picture: ssoUserData.picture,
        provider: ssoUserData.provider,
        providerId: ssoUserData.providerId,
      };

      // 檢查使用者是否存在 (透過電子郵件)
      let user = await this.prisma.user.findUnique({
        where: { email: sanitizedData.email },
      });

      // 如果使用者不存在，建立新使用者
      if (!user) {
        user = await this.prisma.user.create({
          data: {
            email: sanitizedData.email,
            firstName: sanitizedData.firstName || '',
            lastName: sanitizedData.lastName || '',
            profilePicture: sanitizedData.picture || '',
            provider: sanitizedData.provider,
            providerId: sanitizedData.providerId,
            role: 'user', // 預設角色
          },
        });
      } 
      // 如果使用者已存在，但使用新的提供者登入，更新提供者資訊
      else if (user.provider !== sanitizedData.provider) {
        // 建立新的 SSO 連結
        await this.prisma.userSsoConnection.create({
          data: {
            userId: user.id,
            provider: sanitizedData.provider,
            providerId: sanitizedData.providerId,
          },
        });
      }

      // 產生 JWT Token
      const payload = {
        sub: user.id,
        email: user.email,
        roles: [user.role],
        provider: sanitizedData.provider,
      };

      return {
        user,
        accessToken: this.jwtService.sign(payload),
        refreshToken: this.jwtService.sign(payload, { 
          expiresIn: '7d',
          secret: process.env.JWT_REFRESH_SECRET,
        }),
      };
    } catch (error) {
      this.logger.error(`SSO驗證錯誤: ${error.message}`, error.stack);
      throw new InternalServerErrorException('處理SSO登入時發生錯誤');
    }
  }

  // 連結額外的提供者到現有帳號
  async linkProviderToUser(userId: number, ssoUserData: SsoUserData) {
    // 檢查是否已經連結
    const existingConnection = await this.prisma.userSsoConnection.findUnique({
      where: {
        userId_provider: {
          userId,
          provider: ssoUserData.provider,
        },
      },
    });

    if (existingConnection) {
      return { success: false, message: '此提供者已連結到您的帳號' };
    }

    // 建立新的連結
    await this.prisma.userSsoConnection.create({
      data: {
        userId,
        provider: ssoUserData.provider,
        providerId: ssoUserData.providerId,
      },
    });

    return { success: true, message: '帳號連結成功' };
  }
  
  // 解除提供者連結
  async unlinkProviderFromUser(userId: number, provider: string) {
    // 檢查使用者是否存在
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        ssoConnections: true,
      },
    });
    
    if (!user) {
      throw new NotFoundException('使用者不存在');
    }
    
    // 檢查使用者是否有本地密碼或其他SSO連結
    const hasPassword = !!user.password;
    const otherConnections = user.ssoConnections.filter(conn => conn.provider !== provider);
    
    // 如果沒有其他登入方式，拒絕解除連結
    if (!hasPassword && otherConnections.length === 0) {
      throw new BadRequestException('無法解除連結，這是您唯一的登入方式');
    }
    
    // 執行解除連結
    await this.prisma.userSsoConnection.deleteMany({
      where: {
        userId,
        provider,
      },
    });
    
    return { success: true, message: '提供者連結已解除' };
  }
  
  // 重新整理 token
  async refreshToken(refreshToken: string) {
    try {
      // 驗證 refresh token
      const decoded = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });
      
      // 取得使用者
      const user = await this.prisma.user.findUnique({
        where: { id: decoded.sub },
      });
      
      if (!user) {
        throw new UnauthorizedException('使用者不存在');
      }
      
      // 產生新的 token 對
      return this.generateTokens(user);
    } catch (error) {
      throw new UnauthorizedException('無效的重新整理token');
    }
  }
  
  generateTokens(user: any) {
    const payload = {
      sub: user.id,
      email: user.email,
      roles: [user.role],
    };
    
    return {
      accessToken: this.jwtService.sign(payload, { expiresIn: '1h' }),
      refreshToken: this.jwtService.sign(payload, { 
        expiresIn: '7d',
        secret: process.env.JWT_REFRESH_SECRET,
      }),
    };
  }
  
  private sanitizeInput(input: string): string {
    // 基本的 XSS 防護
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}
```

### 5. SSO 控制器實作

```typescript
// sso.controller.ts
import { Controller, Get, Post, Req, Res, UseGuards, Body } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { SsoService } from './sso.service';
import { Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import * as crypto from 'crypto';

class UnlinkProviderDto {
  provider: string;
}

@Controller('auth')
export class SsoController {
  constructor(
    private readonly ssoService: SsoService,
    private readonly configService: ConfigService,
  ) {}

  // Google 登入
  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth(@Req() req, @Res() res) {
    // 產生安全的隨機 state
    const state = crypto.randomBytes(16).toString('hex');
    
    // 儲存 state 到 session 或 Redis (使用過期時間)
    req.session.oauthState = { value: state, provider: 'google', createdAt: new Date() };
    
    // 重定向到提供者，包含 state 參數
    return res.redirect(`${this.authService.getGoogleAuthUrl(state)}`);
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req, @Res() res: Response) {
    try {
      return this.handleAuthRedirect(req, res);
    } catch (error) {
      // 記錄錯誤
      console.error(`Google SSO 回調失敗: ${error.message}`, error.stack);
      
      // 重新導向到前端錯誤頁面
      return res.redirect(
        `${this.configService.get('FRONTEND_URL')}/auth/error?message=${
          encodeURIComponent('登入失敗，請稍後再試')
        }&provider=google`
      );
    }
  }

  // Facebook 登入
  @Get('facebook')
  @UseGuards(AuthGuard('facebook'))
  async facebookAuth(@Req() req, @Res() res) {
    // 產生安全的隨機 state
    const state = crypto.randomBytes(16).toString('hex');
    
    // 儲存 state 到 session
    req.session.oauthState = { value: state, provider: 'facebook', createdAt: new Date() };
    
    // 重定向到提供者，包含 state 參數
    return res.redirect(`${this.authService.getFacebookAuthUrl(state)}`);
  }

  @Get('facebook/callback')
  @UseGuards(AuthGuard('facebook'))
  async facebookAuthRedirect(@Req() req, @Res() res: Response) {
    return this.handleAuthRedirect(req, res);
  }

  // GitHub 登入
  @Get('github')
  @UseGuards(AuthGuard('github'))
  async githubAuth(@Req() req, @Res() res) {
    // 產生安全的隨機 state
    const state = crypto.randomBytes(16).toString('hex');
    
    // 儲存 state 到 session
    req.session.oauthState = { value: state, provider: 'github', createdAt: new Date() };
    
    // 重定向到提供者，包含 state 參數
    return res.redirect(`${this.authService.getGithubAuthUrl(state)}`);
  }

  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  async githubAuthRedirect(@Req() req, @Res() res: Response) {
    return this.handleAuthRedirect(req, res);
  }
  
  // 解除提供者連結 API
  @Post('unlink-provider')
  @UseGuards(JwtAuthGuard)
  async unlinkProvider(@Req() req, @Body() body: UnlinkProviderDto) {
    const { provider } = body;
    const userId = req.user.id;
    
    return this.ssoService.unlinkProviderFromUser(userId, provider);
  }
  
  // 重新整理 token API
  @Post('refresh-token')
  async refreshToken(@Body() body: { refreshToken: string }) {
    return this.ssoService.refreshToken(body.refreshToken);
  }

  // 共用處理 SSO 登入後的重新導向邏輯
  private handleAuthRedirect(@Req() req, @Res() res: Response) {
    const { accessToken, refreshToken } = req.user;
    const frontendUrl = this.configService.get<string>('FRONTEND_URL');
    
    // 將 token 發送到前端 (使用查詢參數)
    return res.redirect(`${frontendUrl}/auth/callback?token=${accessToken}&refreshToken=${refreshToken}`);
  }
}
```

### 6. 環境變數設定

```
# .env 檔案範例
# 資料庫與 JWT 設定
DATABASE_URL="postgresql://postgres:123456@localhost:5432/nestdb?schema=public"
JWT_SECRET="您的安全密鑰"
JWT_REFRESH_SECRET="您的重新整理token密鑰"  # 新增
JWT_EXPIRATION="1h"  # 新增
JWT_REFRESH_EXPIRATION="7d"  # 新增
JWT_AUDIENCE="myapp-api"  # 新增
JWT_ISSUER="myapp-auth"  # 新增
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

# Session 設定  # 新增
SESSION_SECRET="您的session密鑰"
```

### 7. JWT 安全設定補充

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

### 8. Prisma Schema 擴充 - 多裝置登入管理

```prisma
// 新增到 prisma schema
model UserSession {
  id           String   @id @default(uuid())
  userId       Int
  deviceInfo   String?
  ipAddress    String?
  lastActivity DateTime @default(now())
  isActive     Boolean  @default(true)
  user         User     @relation(fields: [userId], references: [id])

  @@index([userId])
}

// 在 User 模型中新增關聯
model User {
  // ...existing fields
  sessions      UserSession[]
}
```

## 最佳實務建議

1. **提供者資訊標準化**：建立一個標準化的方式來處理不同 SSO 提供者返回的不同資料格式。

2. **錯誤處理**：為每個 SSO 提供者建立特定的錯誤處理邏輯，確保使用者體驗一致。

3. **使用者資料合併策略**：當使用者使用不同的 SSO 提供者登入時，需要考慮如何合併使用者資料。

4. **權限映射**：定義從 SSO 提供者獲取的角色/權限如何映射到您的應用程式權限系統。

5. **安全性考量**：
   - 為每個 SSO 提供者使用唯一的客戶端密鑰
   - 實作 CSRF 保護
   - 使用 HTTPS 進行所有通訊
   - 定期審計登入活動
   - 設定適當的 Token 過期時間
   - 檢查 SSO providerId 是否已與其他帳號綁定（防止帳號被劫持）
   - 建議使用 OAuth2 的 state 機制來對抗 CSRF 攻擊（前端應在登入請求中加入 state 值，後端驗證）
   - 建立清晰的 SSO 連結紀錄表，便於審計與管理
   - 若允許解除綁定，應檢查帳戶是否尚有其他登入方式，避免造成鎖帳

6. **效能最佳化**：
   - 快取頻繁使用的提供者設定
   - 最小化資料庫查詢

7. **前端整合**：
   - 提供一致的登入體驗
   - 清晰的使用者界面以管理多個連結的提供者
   - 支援階層式權限分層顯示

8. **追蹤分析**：記錄哪些 SSO 提供者被最頻繁使用，以便優化登入流程.
9. **流程錯誤處理與 fallback**：
   - 檢查所有流程邏輯是否封閉且具備 fallback，例如登入失敗時提供 onFailureRedirect 行為
   - 記錄登入錯誤並支援 retry 或 user feedback

## 新增章節：使用者帳號連結流程圖

```
+------------------+          +------------------+          +------------------+
|                  |          |                  |          |                  |
|   使用者/瀏覽器    +--------->+   NestJS 後端    +--------->+  SSO 提供者       |
|                  |  1. 點擊  |                  | 2. 重定向  |                  |
+--------+---------+  連結按鈕  +--------+---------+          +--------+---------+
         ^                             |                              |
         |                             |                              |
         |                             |                              |
         |                             |                              |
         |            5. 返回連結結果    |                              |
         |                             |                              |
         |                             |                              v
+--------+---------+          +--------+---------+          +------------------+
|                  |          |                  |          |                  |
|   前端應用程式     |<---------+   NestJS 後端    |<---------+  SSO 提供者       |
|                  | 6. 重定向  |                  | 3. 使用者  |                  |
+------------------+ 到前端頁面 +--------+---------+ 同意授權後 +------------------+
                                        |           回調 API
                                        |
                                        v
                             +------------------+
                             |                  |
                             |  資料庫 (新增     |
                             |  SSO連結記錄)     |
                             |                  |
                             +------------------+
                                        |
                                        | 4. 建立連結記錄
                                        |
                                        v
```

## 新增章節：測試策略建議

### 單元測試
1. SSO策略測試 - 測試各個SSO策略的validate函式
2. SsoService測試 - 測試validateOrCreateUser和linkProviderToUser函式
3. Controller測試 - 測試各個路由的回調處理

### 整合測試
1. 使用模擬的Passport策略測試完整登入流程
2. 測試多提供者情境和帳號連結/解除連結功能

### E2E測試
1. 設定測試環境的OAuth模擬伺服器
2. 測試完整的使用者登入、連結、解除連結流程

### 安全測試
1. 測試CSRF保護和state參數驗證
2. 測試未授權訪問保護路由的場景
3. 測試JWT token過期和重新整理機制

## Angular 前端整合建議

使用者從前端點擊登入按鈕後，會導向 NestJS 後端對應的 `/auth/:provider` 路由。登入成功後，後端會將 JWT token 帶入 query string 並導向前端 `/auth/callback?token=...`。以下為整合建議：

### 1. 建立 Angular 的 Callback 處理頁面

```ts
// auth-callback.component.ts
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

@Component({
  selector: 'app-auth-callback',
  template: '<p>登入中...</p>',
})
export class AuthCallbackComponent implements OnInit {
  constructor(private route: ActivatedRoute, private router: Router) {}

  ngOnInit(): void {
    const token = this.route.snapshot.queryParamMap.get('token');
    if (token) {
      localStorage.setItem('access_token', token);
      this.router.navigate(['/dashboard']); // 登入成功導向
    } else {
      this.router.navigate(['/login']); // 登入失敗 fallback
    }
  }
}
```

### 2. Angular 路由設定

```ts
// app-routing.module.ts
const routes: Routes = [
  { path: 'auth/callback', component: AuthCallbackComponent },
  // 其他路由...
];
```

### 3. 登入按鈕觸發 OAuth

```html
<!-- login.component.html -->
<button (click)="loginWith('google')">使用 Google 登入</button>
<button (click)="loginWith('facebook')">使用 Facebook 登入</button>
```

```ts
// login.component.ts
loginWith(provider: string) {
  window.location.href = `http://localhost:3000/auth/${provider}`;
}
```

### 4. 擴充功能建議

- 登入成功後自動呼叫 `/auth/profile` 拿取使用者資訊
- 建立 `AuthGuard` 保護登入後路由
- 抽出 `AuthService` 管理 token 與登入狀態
- 後端建議透過 OAuth2 的 state 機制防止 CSRF 攻擊

## 新增章節：OAuth2 State 驗證建議

### 7. 補充 - OAuth2 State 驗證建議

在發送 SSO 登入請求時（前端觸發 `/auth/google`），可附加一組隨機字串 state，例如：

```ts
const state = crypto.randomUUID();
localStorage.setItem('oauth_state', state);
window.location.href = `${apiBase}/auth/google?state=${state}`;
```

後端接收到 state 後，應驗證該值是否為預期來源，若無效應拒絕請求。

實作方式：
 - 前端儲存 state 至 localStorage 並附帶至 query string
 - 後端策略可透過 `authorizationParams` 把 state 附回 SSO 提供者，callback 時再比對
 - 搭配 session 或 redis 實作可信的 state 驗證

```ts
// google.strategy.ts 補充
authorizationParams(): Record<string, string> {
  return {
    state: 'your-generated-state',
  };
}
```