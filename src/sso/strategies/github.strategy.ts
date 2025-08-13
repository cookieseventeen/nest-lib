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
      clientID: configService.get('GITHUB_CLIENT_ID') || '',
      clientSecret: configService.get('GITHUB_CLIENT_SECRET') || '',
      callbackURL: configService.get('GITHUB_CALLBACK_URL') || '',
      scope: ['user:email'],
      passReqToCallback: true, // 將 request 物件傳遞給 validate 方法
    });
  }

  async validate(req: any, accessToken: string, refreshToken: string, profile: any, done: any) {
    try {
      // 驗證 state 參數
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
    } catch (error) {
      done(error, null);
    }
  }
}