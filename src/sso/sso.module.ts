import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { SsoController } from './sso.controller';
import { SsoService } from './sso.service';
import { GoogleStrategy } from './strategies/google.strategy';
import { FacebookStrategy } from './strategies/facebook.strategy';
import { GithubStrategy } from './strategies/github.strategy';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    ConfigModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET') || 'defaultSecret',
        signOptions: { 
          expiresIn: configService.get('JWT_EXPIRATION') || '1h',
          audience: configService.get('JWT_AUDIENCE'),
          issuer: configService.get('JWT_ISSUER'),
        },
      }),
      inject: [ConfigService],
    }),
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