# SSO服務實作

SSO服務層是整個SSO系統的核心，負責處理使用者驗證、建立和連結SSO提供者的邏輯。本文件詳細說明`SsoService`的實作。

## SsoService 主要功能

```typescript
// sso.service.ts
import { Injectable, BadRequestException, InternalServerErrorException, NotFoundException, Logger, UnauthorizedException } from '@nestjs/common';
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

## 核心方法說明

### 1. 提供者資料映射

```typescript
private providerDataMappers = {
  google: (profile: any): SsoUserData => ({
    email: profile.emails[0].value,
    firstName: profile.name.givenName,
    lastName: profile.name.familyName,
    picture: profile.photos?.[0]?.value,
    provider: 'google',
    providerId: profile.id,
  }),
  // ...其他提供者
};

mapProviderDataToSsoUser(provider: string, profile: any): SsoUserData {
  const mapper = this.providerDataMappers[provider];
  if (!mapper) {
    throw new BadRequestException(`不支援的SSO提供者: ${provider}`);
  }
  return mapper(profile);
}
```

這部分處理不同SSO提供者的資料格式差異，將各種格式統一轉換為應用程式內部的`SsoUserData`格式。

### 2. 驗證或建立使用者

```typescript
async validateOrCreateUser(ssoUserData: SsoUserData) {
  // ...資料驗證和清理
  
  // 檢查使用者是否存在
  let user = await this.prisma.user.findUnique({
    where: { email: sanitizedData.email },
  });

  // 如果不存在則建立新使用者
  if (!user) {
    user = await this.prisma.user.create({
      data: {
        // ...使用者資料
      },
    });
  } 
  // 如果已存在但用新提供者登入，建立連結
  else if (user.provider !== sanitizedData.provider) {
    await this.prisma.userSsoConnection.create({
      data: {
        userId: user.id,
        provider: sanitizedData.provider,
        providerId: sanitizedData.providerId,
      },
    });
  }

  // 產生JWT令牌
  // ...
}
```

這個方法是SSO流程的核心，它:
1. 檢查使用者是否存在
2. 不存在則建立新使用者
3. 已存在則建立新的SSO連結
4. 產生JWT令牌用於後續認證

### 3. 連結提供者到使用者

```typescript
async linkProviderToUser(userId: number, ssoUserData: SsoUserData) {
  // 檢查是否已經連結
  // ...
  
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
```

此方法允許已登入的使用者連結其他SSO提供者到他們的帳號。

### 4. 解除提供者連結

```typescript
async unlinkProviderFromUser(userId: number, provider: string) {
  // ...檢查使用者
  
  // 確保使用者有其他登入方式
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
```

此方法讓使用者移除不再需要的SSO提供者連結，但會確保至少保留一種登入方式。

### 5. 刷新令牌

```typescript
async refreshToken(refreshToken: string) {
  // 驗證刷新令牌
  // ...
  
  // 產生新的令牌對
  return this.generateTokens(user);
}

generateTokens(user: any) {
  // 產生新的令牌
  // ...
}
```

這些方法處理JWT令牌的刷新機制，讓使用者不需要重新登入就能獲取新的訪問令牌。

## 安全考量

1. **輸入清理**：
   ```typescript
   private sanitizeInput(input: string): string {
     // 基本的 XSS 防護
     return input
       .replace(/</g, '&lt;')
       .replace(/>/g, '&gt;')
       .replace(/"/g, '&quot;')
       .replace(/'/g, '&#039;');
   }
   ```
   預防XSS攻擊的基本清理。

2. **電子郵件驗證**：
   ```typescript
   // 檢查email格式
   if (!/^\S+@\S+\.\S+$/.test(ssoUserData.email)) {
     throw new BadRequestException('無效的電子郵件格式');
   }
   ```
   確保電子郵件格式有效。

3. **錯誤處理**：
   ```typescript
   try {
     // ...操作
   } catch (error) {
     this.logger.error(`SSO驗證錯誤: ${error.message}`, error.stack);
     throw new InternalServerErrorException('處理SSO登入時發生錯誤');
   }
   ```
   捕獲和記錄錯誤，但不洩露技術細節給使用者。