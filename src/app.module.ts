import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { SsoModule } from './sso/sso.module';
import { VideoModule } from './video/video.module';

@Module({
  imports: [
    ConfigModule.forRoot(),
    AuthModule, 
    PrismaModule,
    SsoModule,
    VideoModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
