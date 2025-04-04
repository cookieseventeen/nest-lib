# SSO控制器實作

SSO控制器是負責處理所有與SSO相關的HTTP請求的組件。它提供各種路由端點來啟動SSO登入流程、處理回調以及管理SSO連結。

## SsoController 實作

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

## 路由端點說明

### 1. SSO 登入起始端點

以Google為例：

```typescript
@Get('google')
@UseGuards(AuthGuard('google'))
async googleAuth(@Req() req, @Res() res) {
  // 產生安全的隨機 state
  const state = crypto.randomBytes(16).toString('hex');
  
  // 儲存 state 到 session
  req.session.oauthState = { value: state, provider: 'google', createdAt: new Date() };
  
  // 重定向到提供者
  return res.redirect(`${this.authService.getGoogleAuthUrl(state)}`);
}
```

此端點：
- 產生安全的隨機state值
- 將state與提供者名稱和時間戳儲存在session中
- 重定向用戶到提供者的OAuth授權頁面

### 2. SSO 回調端點

以Google為例：

```typescript
@Get('google/callback')
@UseGuards(AuthGuard('google'))
async googleAuthRedirect(@Req() req, @Res() res: Response) {
  try {
    return this.handleAuthRedirect(req, res);
  } catch (error) {
    // 錯誤處理
    // ...
  }
}
```

此端點：
- 接收從SSO提供者返回的OAuth回調
- `AuthGuard('google')`處理OAuth流程的剩餘部分
- 成功時，透過`handleAuthRedirect`方法處理重導向

### 3. 通用的重導向處理

```typescript
private handleAuthRedirect(@Req() req, @Res() res: Response) {
  const { accessToken, refreshToken } = req.user;
  const frontendUrl = this.configService.get<string>('FRONTEND_URL');
  
  // 將 token 發送到前端
  return res.redirect(`${frontendUrl}/auth/callback?token=${accessToken}&refreshToken=${refreshToken}`);
}
```

此方法：
- 從request中獲取由SSO策略生成的JWT令牌
- 重導向用戶到前端應用的回調URL
- 將令牌作為查詢參數傳遞

### 4. 解除SSO提供者連結

```typescript
@Post('unlink-provider')
@UseGuards(JwtAuthGuard)
async unlinkProvider(@Req() req, @Body() body: UnlinkProviderDto) {
  const { provider } = body;
  const userId = req.user.id;
  
  return this.ssoService.unlinkProviderFromUser(userId, provider);
}
```

此端點：
- 需要JWT授權
- 接收要解除連結的提供者名稱
- 呼叫SsoService來處理解除連結邏輯

### 5. 刷新令牌

```typescript
@Post('refresh-token')
async refreshToken(@Body() body: { refreshToken: string }) {
  return this.ssoService.refreshToken(body.refreshToken);
}
```

此端點：
- 接收refresh token
- 驗證並產生新的token對

## 錯誤處理

SSO控制器實作了完整的錯誤處理：

```typescript
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
```

當發生錯誤時：
1. 記錄詳細錯誤資訊到日誌
2. 導向用戶到前端的錯誤頁面
3. 提供通用錯誤訊息，而不洩露技術細節

## 安全考量

1. **CSRF保護**：
   - 每個SSO請求都產生隨機state值
   - 驗證回調時的state值與session中的是否匹配

2. **安全重導向**：
   - 使用環境變數中的前端URL，避免硬編碼
   - 確保重定向URL只能指向可信來源

3. **授權檢查**：
   - 使用`JwtAuthGuard`保護需要授權的API
   - 確保使用者只能操作自己的帳戶