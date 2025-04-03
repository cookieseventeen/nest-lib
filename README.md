<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

  <p align="center">一個漸進式的 <a href="http://nodejs.org" target="_blank">Node.js</a> 框架，用於建構高效且具延展性的伺服器端應用程式。</p>
    <p align="center">
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/v/@nestjs/core.svg" alt="NPM 版本" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/l/@nestjs/core.svg" alt="套件授權" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/dm/@nestjs/common.svg" alt="NPM 下載量" /></a>
<a href="https://circleci.com/gh/nestjs/nest" target="_blank"><img src="https://img.shields.io/circleci/build/github/nestjs/nest/master" alt="CircleCI" /></a>
<a href="https://discord.gg/G7Qnnhy" target="_blank"><img src="https://img.shields.io/badge/discord-online-brightgreen.svg" alt="Discord"/></a>
<a href="https://opencollective.com/nest#backer" target="_blank"><img src="https://opencollective.com/nest/backers/badge.svg" alt="Open Collective 贊助者" /></a>
<a href="https://opencollective.com/nest#sponsor" target="_blank"><img src="https://opencollective.com/nest/sponsors/badge.svg" alt="Open Collective 贊助商" /></a>
  <a href="https://paypal.me/kamilmysliwiec" target="_blank"><img src="https://img.shields.io/badge/Donate-PayPal-ff3f59.svg" alt="贊助我們"/></a>
    <a href="https://opencollective.com/nest#sponsor"  target="_blank"><img src="https://img.shields.io/badge/Support%20us-Open%20Collective-41B883.svg" alt="支持我們"></a>
  <a href="https://twitter.com/nestframework" target="_blank"><img src="https://img.shields.io/twitter/follow/nestframework.svg?style=social&label=Follow" alt="在 Twitter 上關注我們"></a>
</p>
  <!--[![Backers on Open Collective](https://opencollective.com/nest/backers/badge.svg)](https://opencollective.com/nest#backer)
  [![Sponsors on Open Collective](https://opencollective.com/nest/sponsors/badge.svg)](https://opencollective.com/nest#sponsor)-->

## 準備資料庫

您可以使用以下連結中的 `docker-compose.yml` 檔案快速建立資料庫環境：[docker-compose.yml](https://github.com/cookieseventeen/DockerFileKeep/blob/main/nest-lib/docker-compose.yml)

執行以下指令啟動資料庫：

```bash
docker compose up -d
```

## 專案描述

[Nest](https://github.com/nestjs/nest) 框架 TypeScript 入門專案庫。

## 專案設定

```bash
$ npm install
```

## 環境變數
在專案根目錄建立一個 `.env` 檔案，並加入以下環境變數：

```bash
DATABASE_URL="your_database_url"
JWT_SECRET="your_jwt_secret"
```

## 建立 Prisma 資料庫
在專案根目錄執行以下指令以建立 Prisma 資料庫：

```bash
$ npx prisma db push
```

## 查看資料庫
```bash
$ npx prisma studio
```

## 編譯並執行專案

```bash
# 開發模式
$ npm run start

# 監控模式
$ npm run start:dev

# 生產模式
$ npm run start:prod
```

## 執行測試

```bash
# 單元測試
$ npm run test

# 端對端測試
$ npm run test:e2e

# 測試覆蓋率
$ npm run test:cov
```

## 部署

當您準備好將 NestJS 應用程式部署到生產環境時，有一些關鍵步驟可以確保它能夠以最高效率執行。查看[部署文件](https://docs.nestjs.com/deployment)以獲取更多資訊。

如果您正在尋找一個雲端平台來部署您的 NestJS 應用程式，請查看 [Mau](https://mau.nestjs.com)，這是我們在 AWS 上部署 NestJS 應用程式的官方平台。Mau 使部署變得簡單快速，只需幾個簡單步驟：

```bash
$ npm install -g mau
$ mau deploy
```

使用 Mau，您只需點擊幾下就可以部署應用程式，讓您專注於建構功能而不是管理基礎設施。

## 資源

以下是一些在使用 NestJS 時可能會派上用場的資源：

- 訪問 [NestJS 文件](https://docs.nestjs.com) 了解更多關於框架的資訊。
- 如有問題和支援需求，請訪問我們的 [Discord 頻道](https://discord.gg/G7Qnnhy)。
- 要深入了解並獲得更多實踐經驗，請查看我們的官方[教學課程](https://courses.nestjs.com/)。
- 使用 [NestJS Mau](https://mau.nestjs.com) 只需點擊幾下就能將應用程式部署到 AWS。
- 使用 [NestJS Devtools](https://devtools.nestjs.com) 視覺化您的應用程式圖表並與 NestJS 應用程式實時互動。
- 需要專案幫助（兼職到全職）？查看我們的官方[企業支援](https://enterprise.nestjs.com)。
- 要獲取最新資訊和更新，請在 [X](https://x.com/nestframework) 和 [LinkedIn](https://linkedin.com/company/nestjs) 上關注我們。
- 尋找工作，或有工作機會提供？查看我們的官方[工作看板](https://jobs.nestjs.com)。

## 支援

Nest 是一個採用 MIT 授權的開源專案。它能夠成長要歸功於贊助商和眾多支持者。如果您想加入他們，請[閱讀更多](https://docs.nestjs.com/support)。

## 保持聯繫

- 作者 - [Kamil Myśliwiec](https://twitter.com/kammysliwiec)
- 網站 - [https://nestjs.com](https://nestjs.com/)
- Twitter - [@nestframework](https://twitter.com/nestframework)

## 授權

Nest 採用 [MIT 授權](https://github.com/nestjs/nest/blob/master/LICENSE)。
