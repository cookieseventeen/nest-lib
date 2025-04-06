import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, StrategyOptions } from 'passport-facebook';
import { ConfigService } from '@nestjs/config';
import { SsoService } from '../sso.service';

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
  constructor(
    private readonly configService: ConfigService,
    private readonly ssoService: SsoService,
  ) {
    const options: StrategyOptions = {
      clientID: configService.get('FACEBOOK_APP_ID') || '',
      clientSecret: configService.get('FACEBOOK_APP_SECRET') || '',
      callbackURL: configService.get('FACEBOOK_CALLBACK_URL') || '',
      profileFields: ['id', 'emails', 'name', 'picture.type(large)'],
      scope: ['email'],
    };
    super(options);
  }

  async validate(accessToken: string, refreshToken: string, profile: any, done: any) {
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