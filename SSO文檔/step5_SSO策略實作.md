# SSO策略實作

本文件詳細說明如何實作各種SSO提供者的認證策略，這些策略是整個SSO系統的核心元件，負責與各個身分提供者進行通訊。

## Google 策略

Google OAuth 2.0策略的實作使用`passport-google-oauth20`套件：

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

### 說明：

1. **建構子設定**：
   - 使用環境變數提供OAuth憑證
   - 設定回調URL
   - 申請email和profile權限範圍

2. **validate方法**：
   - 處理Google認證成功後的回調
   - 將Google提供的資料轉換為應用程式格式
   - 呼叫SsoService處理使用者驗證或建立

## Facebook 策略

Facebook OAuth策略的實作使用`passport-facebook`套件：

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

### 說明：

1. **建構子設定**：
   - 使用環境變數提供Facebook應用程式憑證
   - 設定profile欄位包含id、emails、name和picture
   - 設定email權限範圍

2. **validate方法**：
   - 將Facebook資料格式轉換
   - 注意頭像照片可能不存在時的處理

## GitHub 策略

GitHub OAuth策略的實作使用`passport-github2`套件，加入了額外的state驗證：

```typescript
// strategies/github.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
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

### 說明：

1. **建構子設定**：
   - 使用passReqToCallback選項，讓請求物件能傳入validate
   - 申請user:email權限來獲取電子郵件

2. **validate方法**：
   - 實作state檢查邏輯，防止CSRF攻擊
   - 使用session存儲和檢查state
   - 設定state有效期為10分鐘
   - 使用者資料處理，注意GitHub的profile格式與其他提供者略有不同

## 共同點與差異

1. **共同點**：
   - 都繼承自PassportStrategy
   - 都需要設定clientID、clientSecret和callbackURL
   - 都有validate方法處理認證回調

2. **差異**：
   - 各提供者返回的profile格式不同
   - GitHub策略實作了更複雜的state驗證
   - 所需請求的權限範圍不同
   - 頭像和個人資訊的提取方式不同

## OAuth2 State 驗證實作

在GitHub策略實作了完整的state驗證機制，當發起SSO請求時：

```typescript
// sso.controller.ts 中的 githubAuth 方法
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
```

與GitHub策略的validate方法組合，這提供了完整的CSRF保護機制。