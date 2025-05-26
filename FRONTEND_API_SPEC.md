# 影片 API 前端對接規格書

## 專案概述

本專案是一個基於 NestJS 建構的影片下載與串流服務，提供完整的影片管理功能，包含用戶認證、影片下載、串流播放等核心功能。

### 技術堆疊
- **後端框架**: NestJS (Node.js)
- **資料庫**: PostgreSQL + Prisma ORM
- **身份驗證**: JWT (JSON Web Token)
- **影片處理**: yt-dlp
- **檔案儲存**: 本地檔案系統

## API 基礎資訊

### 基礎 URL
```
https://your-domain.com/api
```

### 認證方式
所有需要身份驗證的 API 都使用 Bearer Token，需在請求標頭中加入：
```
Authorization: Bearer <your_jwt_token>
```

## API 端點規格

### 1. 身份驗證 API

#### 1.1 用戶註冊
```http
POST /auth/register
```

**請求體**:
```json
{
  "email": "user@example.com",
  "password": "password123",
  "name": "用戶姓名"
}
```

**回應**:
```json
{
  "id": 1,
  "email": "user@example.com",
  "name": "用戶姓名",
  "createdAt": "2025-05-26T10:00:00.000Z"
}
```

#### 1.2 用戶登入
```http
POST /auth/login
```

**請求體**:
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**回應**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 2. 影片管理 API

#### 2.1 下載影片
```http
POST /videos/download
Authorization: Bearer <token>
```

**請求體**:
```json
{
  "url": "https://www.youtube.com/watch?v=example",
  "type": "mp4"
}
```

**參數說明**:
- `url` (必填): 影片來源 URL
- `type` (選填): 影片格式，預設為 mp4，支援 mp4、webm、flv 等

**回應**:
```json
{
  "id": 123,
  "title": "影片標題",
  "fileSize": 15728640,
  "createdAt": "2025-05-26T10:00:00.000Z"
}
```

#### 2.2 取得所有影片
```http
GET /videos
Authorization: Bearer <token>
```

**回應**:
```json
[
  {
    "id": 123,
    "title": "影片標題",
    "originalUrl": "https://www.youtube.com/watch?v=example",
    "filePath": "/uploads/videos/uuid.mp4",
    "fileName": "uuid.mp4",
    "fileSize": 15728640,
    "format": "mp4",
    "userId": 1,
    "createdAt": "2025-05-26T10:00:00.000Z",
    "updatedAt": "2025-05-26T10:00:00.000Z"
  }
]
```

#### 2.3 取得特定影片資訊
```http
GET /videos/:id
Authorization: Bearer <token>
```

**回應**:
```json
{
  "id": 123,
  "title": "影片標題",
  "originalUrl": "https://www.youtube.com/watch?v=example",
  "filePath": "/uploads/videos/uuid.mp4",
  "fileName": "uuid.mp4",
  "fileSize": 15728640,
  "format": "mp4",
  "userId": 1,
  "createdAt": "2025-05-26T10:00:00.000Z",
  "updatedAt": "2025-05-26T10:00:00.000Z",
  "user": {
    "id": 1,
    "name": "用戶姓名",
    "profilePicture": null
  }
}
```

#### 2.4 串流播放影片
```http
GET /videos/stream/:id
Authorization: Bearer <token>
```

**特色功能**:
- 支援 HTTP Range 請求（分段載入）
- 適用於影片播放器的串流播放
- 自動設定適當的 Content-Type 標頭

**回應標頭**:
```
Content-Type: video/mp4
Content-Length: 15728640
Accept-Ranges: bytes
Content-Disposition: inline; filename="video.mp4"
```

### 3. 簡易影片下載 API

#### 3.1 批量下載影片
```http
POST /simple-videos/download
```

**請求體**:
```json
{
  "urls": [
    "https://www.youtube.com/watch?v=example1",
    "https://www.youtube.com/watch?v=example2"
  ],
  "type": "mp4"
}
```

**回應**:
```json
{
  "folderName": "download_uuid",
  "downloadDetails": [
    {
      "url": "https://www.youtube.com/watch?v=example1",
      "title": "影片標題1",
      "author": "影片作者1",
      "success": true,
      "path": "/uploads/simple-videos/folder/video1.mp4"
    },
    {
      "url": "https://www.youtube.com/watch?v=example2",
      "title": "影片標題2",
      "author": "影片作者2",
      "success": false,
      "error": "下載失敗原因"
    }
  ],
  "summary": {
    "total": 2,
    "successful": 1,
    "failed": 1
  }
}
```

## 錯誤處理

### HTTP 狀態碼
- `200` - 成功
- `201` - 建立成功
- `206` - 部分內容（範圍請求）
- `400` - 請求參數錯誤
- `401` - 未授權
- `403` - 無權限存取
- `404` - 資源不存在
- `416` - 請求範圍無效
- `500` - 內部伺服器錯誤

### 錯誤回應格式
```json
{
  "statusCode": 400,
  "message": "錯誤描述",
  "error": "Bad Request"
}
```

## 前端對接範例

### JavaScript/TypeScript 範例

#### 1. 身份驗證類別
```javascript
class AuthAPI {
  constructor(baseURL) {
    this.baseURL = baseURL;
    this.token = localStorage.getItem('access_token');
  }

  async register(email, password, name) {
    const response = await fetch(`${this.baseURL}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password, name }),
    });
    return response.json();
  }

  async login(email, password) {
    const response = await fetch(`${this.baseURL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });
    const data = await response.json();
    if (data.access_token) {
      this.token = data.access_token;
      localStorage.setItem('access_token', this.token);
    }
    return data;
  }

  getAuthHeaders() {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.token}`,
    };
  }
}
```

#### 2. 影片 API 類別
```javascript
class VideoAPI {
  constructor(baseURL, authAPI) {
    this.baseURL = baseURL;
    this.auth = authAPI;
  }

  async downloadVideo(url, type = 'mp4') {
    const response = await fetch(`${this.baseURL}/videos/download`, {
      method: 'POST',
      headers: this.auth.getAuthHeaders(),
      body: JSON.stringify({ url, type }),
    });
    return response.json();
  }

  async getAllVideos() {
    const response = await fetch(`${this.baseURL}/videos`, {
      headers: this.auth.getAuthHeaders(),
    });
    return response.json();
  }

  async getVideoById(id) {
    const response = await fetch(`${this.baseURL}/videos/${id}`, {
      headers: this.auth.getAuthHeaders(),
    });
    return response.json();
  }

  getStreamURL(id) {
    return `${this.baseURL}/videos/stream/${id}`;
  }

  async batchDownload(urls, type = 'mp4') {
    const response = await fetch(`${this.baseURL}/simple-videos/download`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ urls, type }),
    });
    return response.json();
  }
}
```

#### 3. 使用範例
```javascript
// 初始化 API
const auth = new AuthAPI('https://your-domain.com/api');
const video = new VideoAPI('https://your-domain.com/api', auth);

// 登入
await auth.login('user@example.com', 'password123');

// 下載影片
const downloadResult = await video.downloadVideo(
  'https://www.youtube.com/watch?v=example'
);

// 取得所有影片
const videos = await video.getAllVideos();

// 批量下載
const batchResult = await video.batchDownload([
  'https://www.youtube.com/watch?v=example1',
  'https://www.youtube.com/watch?v=example2'
]);
```

### React 實作範例

#### 1. 影片播放元件
```jsx
import React, { useState, useEffect } from 'react';

const VideoPlayer = ({ videoId, authToken }) => {
  const [videoURL, setVideoURL] = useState('');

  useEffect(() => {
    if (videoId && authToken) {
      setVideoURL(`https://your-domain.com/api/videos/stream/${videoId}`);
    }
  }, [videoId, authToken]);

  return (
    <video 
      controls 
      width="100%" 
      height="400"
      src={videoURL}
      style={{ maxWidth: '800px' }}
    >
      <source src={videoURL} type="video/mp4" />
      您的瀏覽器不支援影片播放。
    </video>
  );
};

export default VideoPlayer;
```

#### 2. 影片下載元件
```jsx
import React, { useState } from 'react';

const VideoDownloader = ({ onDownloadComplete }) => {
  const [url, setUrl] = useState('');
  const [type, setType] = useState('mp4');
  const [isLoading, setIsLoading] = useState(false);

  const handleDownload = async () => {
    setIsLoading(true);
    try {
      const video = new VideoAPI('https://your-domain.com/api', auth);
      const result = await video.downloadVideo(url, type);
      onDownloadComplete(result);
      setUrl('');
    } catch (error) {
      console.error('下載失敗:', error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="video-downloader">
      <h3>下載影片</h3>
      <input
        type="url"
        placeholder="請輸入影片 URL"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        style={{ width: '100%', marginBottom: '10px' }}
      />
      <select
        value={type}
        onChange={(e) => setType(e.target.value)}
        style={{ marginBottom: '10px' }}
      >
        <option value="mp4">MP4</option>
        <option value="webm">WebM</option>
        <option value="flv">FLV</option>
      </select>
      <button
        onClick={handleDownload}
        disabled={!url || isLoading}
        style={{ 
          width: '100%', 
          padding: '10px',
          backgroundColor: isLoading ? '#ccc' : '#007bff',
          color: 'white',
          border: 'none',
          borderRadius: '4px'
        }}
      >
        {isLoading ? '下載中...' : '開始下載'}
      </button>
    </div>
  );
};

export default VideoDownloader;
```

#### 3. 影片列表元件
```jsx
import React, { useState, useEffect } from 'react';

const VideoList = ({ onVideoSelect }) => {
  const [videos, setVideos] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadVideos();
  }, []);

  const loadVideos = async () => {
    try {
      const video = new VideoAPI('https://your-domain.com/api', auth);
      const videoList = await video.getAllVideos();
      setVideos(videoList);
    } catch (error) {
      console.error('載入影片列表失敗:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatFileSize = (bytes) => {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Byte';
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  if (loading) return <div>載入中...</div>;

  return (
    <div className="video-list">
      <h3>我的影片</h3>
      {videos.length === 0 ? (
        <p>尚未下載任何影片</p>
      ) : (
        <div style={{ display: 'grid', gap: '10px' }}>
          {videos.map(video => (
            <div
              key={video.id}
              style={{
                border: '1px solid #ddd',
                padding: '15px',
                borderRadius: '8px',
                cursor: 'pointer'
              }}
              onClick={() => onVideoSelect(video)}
            >
              <h4 style={{ margin: '0 0 10px 0' }}>{video.title}</h4>
              <p style={{ margin: '5px 0', fontSize: '14px', color: '#666' }}>
                格式: {video.format} | 大小: {formatFileSize(video.fileSize)}
              </p>
              <p style={{ margin: '5px 0', fontSize: '12px', color: '#999' }}>
                下載時間: {new Date(video.createdAt).toLocaleString()}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default VideoList;
```

## 對接情境與開發功能

### 1. 基礎影片管理平台

**功能描述**: 建構一個完整的影片管理平台，用戶可以下載、管理和播放影片。

**實作步驟**:
1. 實作用戶註冊/登入功能
2. 建立影片下載介面
3. 實作影片列表展示
4. 整合影片播放器

**核心功能**:
- 用戶身份驗證
- 影片下載與儲存
- 影片串流播放
- 個人影片庫管理

### 2. 批量影片下載工具

**功能描述**: 專為內容建立者設計的批量下載工具，支援多個影片同時下載。

**實作步驟**:
1. 建立批量 URL 輸入介面
2. 實作下載進度追蹤
3. 顯示下載結果統計
4. 提供下載失敗重試功能

**核心功能**:
- 多 URL 批量下載
- 即時下載狀態更新
- 錯誤處理與重試
- 下載結果摘要

### 3. 影片分享平台

**功能描述**: 建立一個影片分享社群平台，用戶可以下載並分享影片。

**實作步驟**:
1. 實作用戶權限管理
2. 建立影片分享功能
3. 實作影片評論系統
4. 新增影片搜尋功能

**核心功能**:
- 用戶權限控制
- 影片公開/私人設定
- 社交互動功能
- 內容搜尋與過濾

### 4. 企業影片管理系統

**功能描述**: 為企業提供專業的影片內容管理解決方案。

**實作步驟**:
1. 實作多租戶架構
2. 建立角色權限系統
3. 新增影片分類管理
4. 實作使用量統計

**核心功能**:
- 多租戶支援
- 細粒度權限控制
- 影片分類與標籤
- 使用量分析報告

## 最佳實踐建議

### 1. 安全性
- 始終使用 HTTPS
- 妥善保管 JWT Token
- 實作 Token 自動重新整理機制
- 驗證用戶輸入的 URL

### 2. 效能最佳化
- 實作影片串流的範圍請求
- 使用適當的快取策略
- 實作檔案壓縮
- 考慮 CDN 部署

### 3. 用戶體驗
- 提供下載進度指示
- 實作錯誤重試機制
- 支援多種影片格式
- 響應式設計支援

### 4. 監控與日誌
- 記錄 API 呼叫日誌
- 監控下載成功率
- 追蹤錯誤發生頻率
- 實作效能監控

這份規格書提供了完整的 API 對接指南，包含詳細的端點說明、實作範例和開發建議。開發者可以根據具體需求選擇合適的功能實作，打造符合業務需求的影片管理應用。
