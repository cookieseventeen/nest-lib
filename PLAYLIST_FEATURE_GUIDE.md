# YouTube 播放清單下載功能

## 功能概述

此更新為 NestJS 影片下載 API 添加了 YouTube 播放清單下載功能。系統現在支援：

1. **單一影片下載**（原有功能）
2. **播放清單下載**（新功能）
3. **自動檢測下載**（新功能）

## 資料庫更改

### 新增 Playlist 模型
```sql
CREATE TABLE "Playlist" (
    "id" SERIAL NOT NULL,
    "title" TEXT NOT NULL,
    "originalUrl" TEXT NOT NULL,
    "userId" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "Playlist_pkey" PRIMARY KEY ("id")
);
```

### 更新 Video 模型
新增欄位：
- `playlistId`: 可選的播放清單 ID
- `order`: 在播放清單中的順序

## API 端點

### 播放清單相關 API

#### 1. 下載播放清單
- **端點**: `POST /playlists/download`
- **說明**: 下載整個 YouTube 播放清單中的所有影片
- **請求體**:
  ```json
  {
    "url": "https://www.youtube.com/playlist?list=PLAYLIST_ID",
    "type": "mp4",
    "playlistTitle": "自訂播放清單名稱"
  }
  ```

#### 2. 獲取所有播放清單
- **端點**: `GET /playlists`
- **說明**: 獲取使用者的所有播放清單

#### 3. 獲取特定播放清單
- **端點**: `GET /playlists/:id`
- **說明**: 獲取特定播放清單的詳細資訊

### 影片相關 API（已更新）

#### 1. 自動檢測下載
- **端點**: `POST /videos/download-auto`
- **說明**: 自動檢測 URL 類型並執行對應的下載功能
- **請求體**:
  ```json
  {
    "url": "https://www.youtube.com/watch?v=VIDEO_ID&list=PLAYLIST_ID",
    "type": "mp4"
  }
  ```

#### 2. 原有影片下載
- **端點**: `POST /videos/download`
- **說明**: 下載單一影片（原有功能保持不變）

#### 3. 獲取所有影片
- **端點**: `GET /videos`
- **說明**: 獲取所有影片（現在包含播放清單資訊）

## 播放清單下載流程

1. **URL 檢測**: 系統檢查 URL 是否包含 `list=` 或 `playlist` 關鍵字
2. **播放清單資訊獲取**: 使用 `yt-dlp --flat-playlist` 獲取播放清單中所有影片的標題和 URL
3. **播放清單建立**: 在資料庫中建立播放清單記錄
   - 預設標題：第一個影片名稱 + "合集"
   - 可自訂標題
4. **影片下載**: 依序下載播放清單中的每個影片
5. **影片記錄**: 每個影片儲存時包含：
   - 播放清單 ID 關聯
   - 在播放清單中的順序
   - 原始 URL 和下載路徑

## 特色功能

### 智慧播放清單命名
- 預設使用第一個影片名稱加上「合集」二字
- 支援自訂播放清單標題
- 範例：「宮崎駿 天空之城主題曲合集」

### 容錯處理
- 如果某個影片下載失敗，會跳過該影片繼續下載下一個
- 最終回傳成功下載的影片數量和總影片數量

### 權限控制
- 使用者只能存取自己下載的播放清單和影片
- JWT 身份驗證保護所有 API 端點

### 限制設定
- 目前限制每個播放清單最多下載前 3 個影片（示範用途）
- 可在 `PlaylistService` 中調整此限制

## 使用範例

### 1. 下載播放清單
```bash
curl -X POST http://localhost:3000/playlists/download \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://www.youtube.com/playlist?list=PLrAKf1sIcnV2mW5Sf8QrVfhvB9K8pOT-B",
    "type": "mp4",
    "playlistTitle": "我的音樂合集"
  }'
```

### 2. 自動檢測下載
```bash
curl -X POST http://localhost:3000/videos/download-auto \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://www.youtube.com/watch?v=VIDEO_ID&list=PLAYLIST_ID",
    "type": "mp4"
  }'
```

### 3. 獲取播放清單
```bash
curl -X GET http://localhost:3000/playlists \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 回應格式

### 播放清單下載回應
```json
{
  "playlist": {
    "id": 1,
    "title": "宮崎駿音樂合集",
    "createdAt": "2025-05-26T15:30:36.000Z",
    "totalVideos": 5,
    "downloadedVideos": 3
  },
  "videos": [
    {
      "id": 1,
      "title": "宮崎駿 天空之城主題曲",
      "fileSize": 52428800,
      "order": 1
    }
  ]
}
```

## 注意事項

1. **yt-dlp 相依性**: 確保系統已安裝 `yt-dlp`
2. **儲存空間**: 播放清單下載會消耗更多儲存空間
3. **下載時間**: 播放清單下載需要更長時間，建議使用背景工作佇列
4. **錯誤處理**: 個別影片下載失敗不會中斷整個播放清單下載
5. **權限管理**: 只有影片擁有者可以存取串流和下載

這個更新保持了與原有 API 的完全相容性，同時添加了強大的播放清單下載功能。
