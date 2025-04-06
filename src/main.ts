import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as session from 'express-session';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
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
  
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
