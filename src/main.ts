import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as session from 'express-session';
import * as cookieParser from 'cookie-parser';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  
  // 啟用 CORS
  app.enableCors();
  
  // 設定 Cookie Parser
  app.use(cookieParser());
  
  // 設定 Session 中介軟體
  app.use(
    session({
      secret: process.env.SESSION_SECRET || 'defaultSecret',
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: 60 * 60 * 1000, // 1小時
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
      },
    }),
  );
  
  // 設定靜態檔案目錄，用於存取影片
  app.useStaticAssets('uploads');
  
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
