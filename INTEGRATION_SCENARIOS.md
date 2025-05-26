# 前端對接情境指南

## 概述

本文件詳細說明各種前端應用與NestJS影片API的對接情境，提供實際的程式碼範例和最佳實踐。

## 對接情境分類

### 1. 🎓 教育平台對接情境

#### 情境描述
線上教育平台需要為學生提供課程影片的下載和離線觀看功能。

#### 核心需求
- 學生認證和課程存取權限
- 批量下載課程影片
- 離線播放支援
- 學習進度追蹤

#### 實作範例

**1.1 課程管理介面**
```html
<!-- 課程列表頁面 -->
<div class="course-container">
  <div class="course-header">
    <h2>JavaScript進階課程</h2>
    <button id="downloadAllBtn" class="btn-primary">下載全部影片</button>
  </div>
  
  <div class="lesson-list">
    <div class="lesson-item" data-video-url="https://youtube.com/watch?v=lesson1">
      <h3>第1課：ES6新特性</h3>
      <div class="lesson-actions">
        <button class="btn-download" onclick="downloadLesson(this)">下載</button>
        <button class="btn-play" onclick="playLesson(this)">播放</button>
      </div>
      <div class="download-progress" style="display: none;">
        <div class="progress-bar"></div>
        <span class="progress-text">0%</span>
      </div>
    </div>
  </div>
</div>
```

**1.2 課程下載邏輯**
```javascript
class CourseDownloader {
  constructor() {
    this.api = new VideoAPI();
    this.downloadQueue = [];
    this.currentDownloads = new Map();
  }

  async downloadCourse(courseId) {
    try {
      // 取得課程資訊
      const course = await this.getCourseInfo(courseId);
      const lessons = course.lessons;

      // 顯示下載確認對話框
      const confirmed = await this.showDownloadConfirmation(lessons.length);
      if (!confirmed) return;

      // 開始批量下載
      const urls = lessons.map(lesson => lesson.videoUrl);
      const result = await this.api.batchDownload(urls, 'mp4');

      this.showDownloadResults(result);
      this.updateCourseStatus(courseId, 'downloaded');

    } catch (error) {
      this.showError('課程下載失敗', error.message);
    }
  }

  async downloadLesson(lessonElement) {
    const videoUrl = lessonElement.dataset.videoUrl;
    const progressElement = lessonElement.querySelector('.download-progress');
    const progressBar = progressElement.querySelector('.progress-bar');
    const progressText = progressElement.querySelector('.progress-text');

    try {
      progressElement.style.display = 'block';
      
      // 模擬下載進度（實際應用中需要WebSocket或輪詢）
      const downloadId = this.startProgressSimulation(progressBar, progressText);
      
      const result = await this.api.downloadVideo(videoUrl, 'mp4');
      
      this.stopProgressSimulation(downloadId);
      this.markLessonAsDownloaded(lessonElement, result);

    } catch (error) {
      progressElement.style.display = 'none';
      this.showError('課程下載失敗', error.message);
    }
  }

  startProgressSimulation(progressBar, progressText) {
    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 10;
      if (progress > 100) progress = 100;
      
      progressBar.style.width = `${progress}%`;
      progressText.textContent = `${Math.round(progress)}%`;
      
      if (progress >= 100) {
        clearInterval(interval);
      }
    }, 500);
    
    return interval;
  }

  async getCourseInfo(courseId) {
    // 從教育平台API取得課程資訊
    const response = await fetch(`/api/courses/${courseId}`);
    return response.json();
  }

  showDownloadConfirmation(lessonCount) {
    return new Promise((resolve) => {
      const modal = document.createElement('div');
      modal.className = 'modal';
      modal.innerHTML = `
        <div class="modal-content">
          <h3>下載確認</h3>
          <p>即將下載 ${lessonCount} 個課程影片，這可能需要較長時間。</p>
          <div class="modal-actions">
            <button class="btn-confirm" onclick="resolve(true)">確認下載</button>
            <button class="btn-cancel" onclick="resolve(false)">取消</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    });
  }
}
```

### 2. 📱 社交媒體平台對接情境

#### 情境描述
社交媒體應用需要讓使用者下載和分享影片內容。

#### 核心需求
- 使用者產生內容(UGC)下載
- 社交分享功能
- 內容審核機制
- 多平台支援

#### 實作範例

**2.1 社交分享元件**
```javascript
class SocialVideoSharer {
  constructor() {
    this.api = new VideoAPI();
    this.supportedPlatforms = ['youtube', 'tiktok', 'instagram', 'twitter'];
  }

  async shareVideo(videoData) {
    const shareModal = this.createShareModal(videoData);
    document.body.appendChild(shareModal);
  }

  createShareModal(videoData) {
    const modal = document.createElement('div');
    modal.className = 'share-modal';
    modal.innerHTML = `
      <div class="share-content">
        <h3>分享影片</h3>
        <div class="video-preview">
          <img src="${videoData.thumbnail}" alt="${videoData.title}">
          <h4>${videoData.title}</h4>
        </div>
        
        <div class="share-options">
          <div class="platform-selection">
            <label>選擇分享平台：</label>
            <select id="platformSelect">
              <option value="youtube">YouTube</option>
              <option value="tiktok">TikTok</option>
              <option value="instagram">Instagram</option>
            </select>
          </div>
          
          <div class="share-settings">
            <label>分享描述：</label>
            <textarea id="shareDescription" placeholder="為這個影片寫一段描述..."></textarea>
            
            <label>標籤：</label>
            <input type="text" id="shareTags" placeholder="#標籤1 #標籤2">
          </div>
          
          <div class="share-actions">
            <button onclick="this.processShare()" class="btn-share">立即分享</button>
            <button onclick="this.downloadAndShare()" class="btn-download-share">下載後分享</button>
            <button onclick="this.closeModal()" class="btn-cancel">取消</button>
          </div>
        </div>
      </div>
    `;
    
    return modal;
  }

  async downloadAndShare() {
    const platform = document.getElementById('platformSelect').value;
    const description = document.getElementById('shareDescription').value;
    const tags = document.getElementById('shareTags').value;

    try {
      // 1. 先下載影片
      const downloadResult = await this.api.downloadVideo(
        this.currentVideoData.url, 
        this.getPlatformFormat(platform)
      );

      // 2. 最佳化影片以符合平台需求
      const optimizedVideo = await this.optimizeForPlatform(
        downloadResult.id, 
        platform
      );

      // 3. 上傳到目標平台
      await this.uploadToPlatform(optimizedVideo, platform, {
        description,
        tags
      });

      this.showSuccess('影片已成功分享到 ' + platform);
      
    } catch (error) {
      this.showError('分享失敗', error.message);
    }
  }

  getPlatformFormat(platform) {
    const formatMap = {
      'youtube': 'mp4',
      'tiktok': 'mp4',
      'instagram': 'mp4'
    };
    return formatMap[platform] || 'mp4';
  }

  async optimizeForPlatform(videoId, platform) {
    // 根據平台需求最佳化影片
    const optimizationSettings = {
      'tiktok': { aspectRatio: '9:16', maxDuration: 60 },
      'instagram': { aspectRatio: '1:1', maxDuration: 60 },
      'youtube': { aspectRatio: '16:9', maxDuration: 3600 }
    };

    const settings = optimizationSettings[platform];
    
    // 呼叫影片處理API
    return await this.api.processVideo(videoId, settings);
  }
}
```

### 3. 🏢 企業內容管理對接情境

#### 情境描述
企業需要建立內部影片庫，管理培訓教材、會議錄影等內容。

#### 核心需求
- 企業SSO整合
- 權限分級管理
- 內容分類和標籤
- 搜尋和分析功能

#### 實作範例

**3.1 企業影片管理介面**
```javascript
class EnterpriseVideoManager {
  constructor() {
    this.api = new VideoAPI();
    this.ssoProvider = new SSOProvider();
    this.permissionManager = new PermissionManager();
  }

  async initialize() {
    // 企業SSO認證
    try {
      const ssoToken = await this.ssoProvider.authenticate();
      const apiToken = await this.exchangeTokens(ssoToken);
      this.api.setToken(apiToken);
      
      await this.loadUserPermissions();
      await this.loadVideoLibrary();
      
    } catch (error) {
      this.redirectToSSO();
    }
  }

  async loadVideoLibrary() {
    const videos = await this.api.getVideos();
    const categorizedVideos = this.categorizeVideos(videos);
    this.renderVideoLibrary(categorizedVideos);
  }

  categorizeVideos(videos) {
    const categories = {
      'training': { name: '培訓教材', videos: [] },
      'meetings': { name: '會議錄影', videos: [] },
      'announcements': { name: '公司公告', videos: [] },
      'others': { name: '其他', videos: [] }
    };

    videos.forEach(video => {
      const category = this.detectVideoCategory(video);
      categories[category].videos.push(video);
    });

    return categories;
  }

  renderVideoLibrary(categories) {
    const container = document.getElementById('video-library');
    container.innerHTML = '';

    Object.entries(categories).forEach(([key, category]) => {
      if (category.videos.length === 0) return;

      const categorySection = document.createElement('div');
      categorySection.className = 'video-category';
      categorySection.innerHTML = `
        <h3>${category.name} (${category.videos.length})</h3>
        <div class="video-grid">
          ${category.videos.map(video => this.createVideoCard(video)).join('')}
        </div>
      `;
      container.appendChild(categorySection);
    });
  }

  createVideoCard(video) {
    const canEdit = this.permissionManager.canEdit(video);
    const canDelete = this.permissionManager.canDelete(video);

    return `
      <div class="video-card" data-video-id="${video.id}">
        <div class="video-thumbnail">
          <img src="${video.thumbnail || '/default-thumbnail.jpg'}" alt="${video.title}">
          <div class="video-duration">${this.formatDuration(video.duration)}</div>
        </div>
        
        <div class="video-info">
          <h4>${video.title}</h4>
          <p class="video-meta">
            <span class="upload-date">${this.formatDate(video.createdAt)}</span>
            <span class="file-size">${this.formatFileSize(video.fileSize)}</span>
          </p>
          <div class="video-tags">
            ${video.tags?.map(tag => `<span class="tag">${tag}</span>`).join('') || ''}
          </div>
        </div>
        
        <div class="video-actions">
          <button onclick="this.playVideo('${video.id}')" class="btn-play">播放</button>
          <button onclick="this.downloadVideo('${video.id}')" class="btn-download">下載</button>
          ${canEdit ? `<button onclick="this.editVideo('${video.id}')" class="btn-edit">編輯</button>` : ''}
          ${canDelete ? `<button onclick="this.deleteVideo('${video.id}')" class="btn-delete">刪除</button>` : ''}
        </div>
      </div>
    `;
  }

  async uploadNewVideo() {
    const uploadModal = this.createUploadModal();
    document.body.appendChild(uploadModal);
  }

  createUploadModal() {
    return `
      <div class="upload-modal">
        <div class="modal-content">
          <h3>上傳新影片</h3>
          
          <div class="upload-methods">
            <div class="upload-method">
              <h4>從URL下載</h4>
              <input type="url" id="videoUrl" placeholder="輸入影片URL">
              <select id="videoCategory">
                <option value="training">培訓教材</option>
                <option value="meetings">會議錄影</option>
                <option value="announcements">公司公告</option>
                <option value="others">其他</option>
              </select>
            </div>
            
            <div class="upload-method">
              <h4>檔案上傳</h4>
              <input type="file" id="videoFile" accept="video/*">
              <div class="upload-progress" style="display: none;">
                <div class="progress-bar"></div>
                <span class="progress-text">0%</span>
              </div>
            </div>
          </div>
          
          <div class="video-metadata">
            <input type="text" id="videoTitle" placeholder="影片標題">
            <textarea id="videoDescription" placeholder="影片描述"></textarea>
            <input type="text" id="videoTags" placeholder="標籤 (用逗號分隔)">
          </div>
          
          <div class="modal-actions">
            <button onclick="this.processUpload()" class="btn-upload">開始上傳</button>
            <button onclick="this.closeModal()" class="btn-cancel">取消</button>
          </div>
        </div>
      </div>
    `;
  }
}
```

### 4. 🎮 遊戲平台對接情境

#### 情境描述
遊戲平台需要讓玩家錄製、分享和觀看遊戲影片。

#### 核心需求
- 遊戲影片錄製
- 精彩時刻剪輯
- 社群分享功能
- 競賽影片管理

#### 實作範例

**4.1 遊戲影片錄製器**
```javascript
class GameVideoRecorder {
  constructor() {
    this.api = new VideoAPI();
    this.recorder = null;
    this.isRecording = false;
    this.recordedChunks = [];
  }

  async startRecording() {
    try {
      // 取得螢幕錄製權限
      const stream = await navigator.mediaDevices.getDisplayMedia({
        video: { mediaSource: 'screen' },
        audio: true
      });

      this.recorder = new MediaRecorder(stream);
      this.recordedChunks = [];

      this.recorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          this.recordedChunks.push(event.data);
        }
      };

      this.recorder.onstop = () => {
        this.processRecording();
      };

      this.recorder.start();
      this.isRecording = true;
      this.updateRecordingUI();

    } catch (error) {
      console.error('錄製失敗:', error);
      alert('無法開始錄製，請檢查權限設定');
    }
  }

  stopRecording() {
    if (this.recorder && this.isRecording) {
      this.recorder.stop();
      this.isRecording = false;
      this.updateRecordingUI();
    }
  }

  async processRecording() {
    const blob = new Blob(this.recordedChunks, { type: 'video/webm' });
    const videoFile = new File([blob], `gameplay-${Date.now()}.webm`, {
      type: 'video/webm'
    });

    // 顯示預覽和編輯選項
    this.showRecordingPreview(videoFile);
  }

  showRecordingPreview(videoFile) {
    const previewModal = document.createElement('div');
    previewModal.className = 'recording-preview-modal';
    previewModal.innerHTML = `
      <div class="preview-content">
        <h3>錄製完成</h3>
        
        <div class="video-preview">
          <video controls width="640" height="360" id="previewVideo"></video>
        </div>
        
        <div class="recording-options">
          <div class="highlight-detection">
            <button onclick="this.detectHighlights()" class="btn-detect">
              自動偵測精彩時刻
            </button>
          </div>
          
          <div class="trim-controls">
            <label>修剪影片：</label>
            <input type="range" id="startTime" min="0" max="100" value="0">
            <input type="range" id="endTime" min="0" max="100" value="100">
          </div>
          
          <div class="metadata-input">
            <input type="text" id="gameTitle" placeholder="遊戲名稱">
            <input type="text" id="recordingTitle" placeholder="影片標題">
            <textarea id="recordingDescription" placeholder="描述這段精彩時刻..."></textarea>
          </div>
          
          <div class="share-options">
            <label>
              <input type="checkbox" id="shareToFeed"> 分享到社群動態
            </label>
            <label>
              <input type="checkbox" id="submitToContest"> 提交到競賽
            </label>
          </div>
        </div>
        
        <div class="modal-actions">
          <button onclick="this.saveRecording()" class="btn-save">儲存影片</button>
          <button onclick="this.discardRecording()" class="btn-discard">捨棄</button>
        </div>
      </div>
    `;

    // 設定預覽影片
    document.body.appendChild(previewModal);
    const videoElement = document.getElementById('previewVideo');
    videoElement.src = URL.createObjectURL(videoFile);
  }

  async detectHighlights() {
    // 使用AI分析遊戲影片中的精彩時刻
    // 這裡可以整合機器學習模型來偵測
    const highlights = await this.analyzeGameplayVideo();
    this.showHighlightOptions(highlights);
  }

  async analyzeGameplayVideo() {
    // 模擬AI分析結果
    return [
      { startTime: 45, endTime: 52, type: 'kill', confidence: 0.95 },
      { startTime: 128, endTime: 135, type: 'victory', confidence: 0.89 },
      { startTime: 203, endTime: 210, type: 'skillshot', confidence: 0.76 }
    ];
  }
}
```

### 5. 📺 串流媒體平台對接情境

#### 情境描述
串流媒體平台需要提供影片上傳、轉碼和播放功能。

#### 核心需求
- 多格式支援
- 自適應位元率串流
- 內容分發網路(CDN)整合
- 即時串流功能

#### 實作範例

**5.1 自適應播放器**
```javascript
class AdaptiveVideoPlayer {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.api = new VideoAPI();
    this.qualityLevels = [];
    this.currentQuality = 'auto';
    this.player = null;
  }

  async loadVideo(videoId) {
    try {
      // 取得影片資訊和可用品質
      const videoInfo = await this.api.getVideo(videoId);
      this.qualityLevels = await this.api.getVideoQualities(videoId);
      
      this.createPlayer(videoInfo);
      this.setupQualitySelector();
      this.setupAdaptiveBitrate();
      
    } catch (error) {
      this.showError('影片載入失敗', error.message);
    }
  }

  createPlayer(videoInfo) {
    this.container.innerHTML = `
      <div class="video-player">
        <video id="mainVideo" controls preload="metadata">
          <source src="${this.api.getStreamURL(videoInfo.id)}" type="video/mp4">
          您的瀏覽器不支援影片播放。
        </video>
        
        <div class="player-overlay">
          <div class="player-controls">
            <button class="play-pause-btn">⏯️</button>
            <div class="progress-container">
              <div class="progress-bar">
                <div class="progress-filled"></div>
              </div>
            </div>
            <div class="volume-container">
              <button class="volume-btn">🔊</button>
              <input type="range" class="volume-slider" min="0" max="100" value="100">
            </div>
            <div class="quality-selector">
              <select id="qualitySelect">
                <option value="auto">自動</option>
                ${this.qualityLevels.map(q => 
                  `<option value="${q.height}">${q.height}p</option>`
                ).join('')}
              </select>
            </div>
            <button class="fullscreen-btn">⛶</button>
          </div>
        </div>
      </div>
    `;

    this.player = document.getElementById('mainVideo');
    this.setupPlayerEvents();
  }

  setupAdaptiveBitrate() {
    // 監控網路狀況並自動調整品質
    if ('connection' in navigator) {
      const connection = navigator.connection;
      
      connection.addEventListener('change', () => {
        if (this.currentQuality === 'auto') {
          this.adjustQualityBasedOnConnection(connection);
        }
      });
    }

    // 監控播放緩衝事件
    this.player.addEventListener('waiting', () => {
      this.handleBuffering();
    });

    this.player.addEventListener('canplay', () => {
      this.handleBufferingEnd();
    });
  }

  adjustQualityBasedOnConnection(connection) {
    const effectiveType = connection.effectiveType;
    let recommendedQuality;

    switch (effectiveType) {
      case 'slow-2g':
      case '2g':
        recommendedQuality = 240;
        break;
      case '3g':
        recommendedQuality = 480;
        break;
      case '4g':
        recommendedQuality = 1080;
        break;
      default:
        recommendedQuality = 720;
    }

    this.switchQuality(recommendedQuality);
  }

  async switchQuality(height) {
    const currentTime = this.player.currentTime;
    const wasPlaying = !this.player.paused;

    try {
      // 切換到新品質的串流
      const newStreamURL = await this.api.getStreamURL(this.videoId, height);
      this.player.src = newStreamURL;
      
      // 恢復播放位置
      this.player.currentTime = currentTime;
      
      if (wasPlaying) {
        await this.player.play();
      }

      this.showQualityChangeNotification(height);
      
    } catch (error) {
      console.error('品質切換失敗:', error);
    }
  }

  handleBuffering() {
    // 顯示載入指示器
    this.showLoadingSpinner();
    
    // 如果是自動模式且經常緩衝，降低品質
    if (this.currentQuality === 'auto' && this.isFrequentBuffering()) {
      this.downgradeQuality();
    }
  }

  isFrequentBuffering() {
    // 檢查最近是否頻繁緩衝
    const now = Date.now();
    const recentBuffers = this.bufferEvents.filter(
      time => now - time < 30000
    );
    return recentBuffers.length > 3;
  }
}
```

## 通用對接最佳實踐

### 1. 錯誤處理策略

```javascript
class ErrorHandler {
  static async handleAPIError(error, context) {
    const errorMap = {
      401: { message: '請重新登入', action: 'redirect-login' },
      403: { message: '權限不足', action: 'show-permission-error' },
      404: { message: '資源不存在', action: 'show-not-found' },
      429: { message: '請求過於頻繁', action: 'show-rate-limit' },
      500: { message: '伺服器錯誤', action: 'show-server-error' }
    };

    const errorInfo = errorMap[error.status] || { 
      message: '未知錯誤', 
      action: 'show-generic-error' 
    };

    // 記錄錯誤
    console.error(`API錯誤 [${context}]:`, error);
    
    // 執行對應的錯誤處理動作
    await this.executeErrorAction(errorInfo.action, error);
    
    // 顯示使用者友善的錯誤訊息
    this.showUserNotification(errorInfo.message, 'error');
  }

  static async executeErrorAction(action, error) {
    switch (action) {
      case 'redirect-login':
        window.location.href = '/login';
        break;
      case 'show-permission-error':
        this.showPermissionDialog();
        break;
      case 'show-rate-limit':
        this.showRateLimitDialog();
        break;
      default:
        console.log('執行預設錯誤處理');
    }
  }
}
```

### 2. 效能監控

```javascript
class PerformanceMonitor {
  constructor() {
    this.metrics = {
      apiCalls: [],
      loadTimes: [],
      errors: []
    };
  }

  trackAPICall(endpoint, duration, success) {
    this.metrics.apiCalls.push({
      endpoint,
      duration,
      success,
      timestamp: Date.now()
    });

    // 如果API呼叫過慢，記錄警告
    if (duration > 5000) {
      console.warn(`慢速API呼叫: ${endpoint} 耗時 ${duration}ms`);
    }
  }

  trackPageLoad(page, loadTime) {
    this.metrics.loadTimes.push({
      page,
      loadTime,
      timestamp: Date.now()
    });
  }

  generateReport() {
    const avgAPITime = this.calculateAverageAPITime();
    const errorRate = this.calculateErrorRate();
    const avgLoadTime = this.calculateAverageLoadTime();

    return {
      averageAPIResponseTime: avgAPITime,
      errorRate: errorRate,
      averagePageLoadTime: avgLoadTime,
      totalAPIRequests: this.metrics.apiCalls.length
    };
  }

  calculateAverageAPITime() {
    const successfulCalls = this.metrics.apiCalls.filter(call => call.success);
    if (successfulCalls.length === 0) return 0;
    
    const totalTime = successfulCalls.reduce((sum, call) => sum + call.duration, 0);
    return totalTime / successfulCalls.length;
  }
}
```

### 3. 使用者體驗最佳化

```javascript
class UXOptimizer {
  static showLoadingState(element, message = '載入中...') {
    const originalContent = element.innerHTML;
    element.innerHTML = `
      <div class="loading-state">
        <div class="spinner"></div>
        <span>${message}</span>
      </div>
    `;
    
    return () => {
      element.innerHTML = originalContent;
    };
  }

  static implementProgressiveLoading(container) {
    // 實作漸進式載入
    const items = container.querySelectorAll('.video-item');
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          this.loadVideoItem(entry.target);
          observer.unobserve(entry.target);
        }
      });
    });

    items.forEach(item => observer.observe(item));
  }

  static async loadVideoItem(element) {
    const videoId = element.dataset.videoId;
    try {
      const videoInfo = await api.getVideo(videoId);
      this.renderVideoInfo(element, videoInfo);
    } catch (error) {
      this.renderVideoError(element, error);
    }
  }

  static debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }
}
```

## 總結

這些對接情境展示了NestJS影片API在不同應用場景中的靈活運用：

1. **教育平台**：重點在課程管理和學習體驗
2. **社交媒體**：強調分享和社群互動功能
3. **企業管理**：注重權限控制和內容分類
4. **遊戲平台**：突出錄製和競賽功能
5. **串流媒體**：專注於播放品質和使用者體驗

每個情境都提供了完整的實作範例，包含前端介面、API對接邏輯、錯誤處理和效能最佳化，可以作為實際專案開發的參考基礎。
