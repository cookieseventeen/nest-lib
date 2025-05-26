# 影片 API 展示範例

## 概述

這是一個完整的前端展示範例，展示如何與影片 API 進行對接。包含用戶認證、影片下載、播放和管理等功能。

## 快速開始

### 1. 環境需求
- Node.js 16+
- 現代瀏覽器 (Chrome, Firefox, Safari, Edge)
- 有效的 API 伺服器地址

### 2. 設定
將 `config.js` 中的 API 基礎 URL 修改為您的伺服器地址：
```javascript
const API_BASE_URL = 'https://your-domain.com/api';
```

### 3. 執行
直接在瀏覽器中開啟 `index.html` 即可使用。

## 檔案結構

```
demo/
├── index.html          # 主頁面
├── styles.css          # 樣式檔案
├── script.js           # 主要邏輯
├── config.js           # 設定檔案
├── api/
│   ├── auth.js         # 身份驗證 API
│   ├── video.js        # 影片 API
│   └── utils.js        # 工具函式
└── components/
    ├── auth.js         # 認證元件
    ├── video-player.js # 影片播放器元件
    ├── video-list.js   # 影片列表元件
    └── downloader.js   # 下載元件
```

## 功能特色

### 🔐 身份驗證
- 用戶註冊與登入
- JWT Token 管理
- 自動登入狀態維護

### 📥 影片下載
- 單一影片下載
- 批量影片下載
- 即時下載狀態更新
- 錯誤處理與重試

### 🎬 影片播放
- HTML5 影片播放器
- 支援串流播放
- 範圍請求支援
- 響應式設計

### 📋 影片管理
- 個人影片庫
- 影片資訊展示
- 檔案大小格式化
- 下載時間顯示

## API 測試案例

### 1. 身份驗證測試
```javascript
// 註冊新用戶
const registerResult = await auth.register({
  email: 'test@example.com',
  password: 'password123',
  name: '測試用戶'
});

// 用戶登入
const loginResult = await auth.login({
  email: 'test@example.com',
  password: 'password123'
});
```

### 2. 影片下載測試
```javascript
// 下載單一影片
const downloadResult = await video.downloadVideo({
  url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
  type: 'mp4'
});

// 批量下載影片
const batchResult = await video.batchDownload({
  urls: [
    'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
    'https://www.youtube.com/watch?v=9bZkp7q19f0'
  ],
  type: 'mp4'
});
```

### 3. 影片管理測試
```javascript
// 取得所有影片
const videos = await video.getAllVideos();

// 取得特定影片
const specificVideo = await video.getVideoById(123);

// 播放影片
const streamURL = video.getStreamURL(123);
```

## 錯誤處理範例

### 1. 網路錯誤處理
```javascript
try {
  const result = await api.call();
} catch (error) {
  if (error.name === 'NetworkError') {
    showNotification('網路連線錯誤，請檢查網路設定', 'error');
  } else if (error.status === 401) {
    showNotification('登入已過期，請重新登入', 'warning');
    redirectToLogin();
  } else {
    showNotification(`操作失敗: ${error.message}`, 'error');
  }
}
```

### 2. 下載錯誤處理
```javascript
const handleDownloadError = (error, url) => {
  const errorMessages = {
    'Video unavailable': '影片不可用或已被移除',
    'Network timeout': '網路連線超時',
    'Invalid URL': '無效的影片網址',
    'Format not available': '請求的格式不可用'
  };
  
  const message = errorMessages[error.type] || `下載失敗: ${error.message}`;
  updateDownloadStatus(url, 'failed', message);
};
```

## 效能最佳化建議

### 1. 懶載入實作
```javascript
// 影片列表懶載入
const loadVideosWithPagination = async (page = 1, limit = 10) => {
  const videos = await video.getAllVideos({ page, limit });
  appendToVideoList(videos);
};

// 滾動載入更多
window.addEventListener('scroll', debounce(() => {
  if (isNearBottom() && !isLoading) {
    loadVideosWithPagination(++currentPage);
  }
}, 300));
```

### 2. 快取策略
```javascript
// API 回應快取
const cache = new Map();
const getCachedOrFetch = async (key, fetchFn, ttl = 300000) => {
  if (cache.has(key)) {
    const { data, timestamp } = cache.get(key);
    if (Date.now() - timestamp < ttl) {
      return data;
    }
  }
  
  const data = await fetchFn();
  cache.set(key, { data, timestamp: Date.now() });
  return data;
};
```

### 3. 影片預載
```javascript
// 預載下一個影片
const preloadNextVideo = (currentIndex, videoList) => {
  if (currentIndex < videoList.length - 1) {
    const nextVideo = videoList[currentIndex + 1];
    const video = document.createElement('video');
    video.preload = 'metadata';
    video.src = video.getStreamURL(nextVideo.id);
  }
};
```

## 安全性考量

### 1. Token 管理
```javascript
// 安全的 Token 儲存
class SecureTokenStorage {
  static set(token) {
    // 使用 sessionStorage 而非 localStorage 增加安全性
    sessionStorage.setItem('access_token', token);
    // 設定 Token 過期時間
    sessionStorage.setItem('token_expires', Date.now() + 3600000);
  }
  
  static get() {
    const token = sessionStorage.getItem('access_token');
    const expires = sessionStorage.getItem('token_expires');
    
    if (!token || !expires || Date.now() > parseInt(expires)) {
      this.clear();
      return null;
    }
    
    return token;
  }
  
  static clear() {
    sessionStorage.removeItem('access_token');
    sessionStorage.removeItem('token_expires');
  }
}
```

### 2. URL 驗證
```javascript
// 驗證影片 URL
const validateVideoURL = (url) => {
  const allowedDomains = [
    'youtube.com',
    'youtu.be',
    'vimeo.com',
    'dailymotion.com'
  ];
  
  try {
    const urlObj = new URL(url);
    return allowedDomains.some(domain => 
      urlObj.hostname.includes(domain)
    );
  } catch {
    return false;
  }
};
```

## 響應式設計

### 1. 行動裝置適配
```css
/* 平板裝置 */
@media (max-width: 768px) {
  .video-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .video-player {
    width: 100%;
    height: auto;
  }
}

/* 手機裝置 */
@media (max-width: 480px) {
  .video-grid {
    grid-template-columns: 1fr;
  }
  
  .navbar {
    flex-direction: column;
  }
}
```

### 2. 觸控支援
```javascript
// 觸控手勢支援
let startY = 0;
let currentY = 0;

videoContainer.addEventListener('touchstart', (e) => {
  startY = e.touches[0].clientY;
}, { passive: true });

videoContainer.addEventListener('touchmove', (e) => {
  currentY = e.touches[0].clientY;
  const deltaY = startY - currentY;
  
  if (Math.abs(deltaY) > 50) {
    if (deltaY > 0) {
      // 向上滑動 - 顯示控制項
      showVideoControls();
    } else {
      // 向下滑動 - 隱藏控制項
      hideVideoControls();
    }
  }
}, { passive: true });
```

## 測試指引

### 1. 功能測試清單
- [ ] 用戶註冊功能
- [ ] 用戶登入功能
- [ ] Token 自動重新整理
- [ ] 單一影片下載
- [ ] 批量影片下載
- [ ] 影片列表載入
- [ ] 影片播放功能
- [ ] 串流範圍請求
- [ ] 錯誤處理機制
- [ ] 響應式設計

### 2. 效能測試
```javascript
// 下載速度測試
const testDownloadSpeed = async (url) => {
  const startTime = performance.now();
  await video.downloadVideo({ url, type: 'mp4' });
  const endTime = performance.now();
  
  console.log(`下載耗時: ${endTime - startTime}ms`);
};

// 批量下載效能測試
const testBatchDownload = async (urls) => {
  const startTime = performance.now();
  const results = await video.batchDownload({ urls });
  const endTime = performance.now();
  
  const successCount = results.downloadDetails.filter(r => r.success).length;
  console.log(`批量下載: ${successCount}/${urls.length} 成功，耗時: ${endTime - startTime}ms`);
};
```

## 部署建議

### 1. 生產環境設定
```javascript
// 環境變數設定
const config = {
  development: {
    apiURL: 'http://localhost:3000/api',
    debug: true
  },
  production: {
    apiURL: 'https://your-domain.com/api',
    debug: false
  }
};

const currentConfig = config[process.env.NODE_ENV || 'development'];
```

### 2. CDN 資源最佳化
```html
<!-- 使用 CDN 載入常用函式庫 -->
<script src="https://cdn.jsdelivr.net/npm/axios@0.24.0/dist/axios.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>
```

## 進階功能擴展

### 1. 離線支援
```javascript
// Service Worker 註冊
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js');
}

// 離線快取策略
self.addEventListener('fetch', (event) => {
  if (event.request.url.includes('/videos/stream/')) {
    event.respondWith(
      caches.match(event.request)
        .then(response => response || fetch(event.request))
    );
  }
});
```

### 2. 推播通知
```javascript
// 下載完成通知
const notifyDownloadComplete = (videoTitle) => {
  if ('Notification' in window && Notification.permission === 'granted') {
    new Notification('下載完成', {
      body: `影片「${videoTitle}」已下載完成`,
      icon: '/icons/download-complete.png'
    });
  }
};
```

這個展示範例提供了完整的前端實作指引，涵蓋了從基礎功能到進階特性的所有面向，幫助開發者快速建構專業的影片管理應用。
