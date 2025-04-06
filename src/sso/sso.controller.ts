import { Controller, Get, Post, Req, Res, UseGuards, Body, UnauthorizedException } from '@nestjs/common';
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
    
    // 儲存 state 到 session
    req.session.oauthState = { value: state, provider: 'google', createdAt: new Date() };
    
    // 由於我們使用的是 Passport 的 AuthGuard，實際的重定向由 Passport 處理
    // 這個方法實際上不會執行到這裡，但為了完整性保留
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
    
    // 由於我們使用的是 Passport 的 AuthGuard，實際的重定向由 Passport 處理
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
    
    // 由於我們使用的是 Passport 的 AuthGuard，實際的重定向由 Passport 處理
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
    const userId = req.user.userId;
    
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