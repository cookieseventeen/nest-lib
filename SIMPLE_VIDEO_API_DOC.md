# 簡易影片下載API文檔

## 簡介

這個API提供簡單的批次影片下載功能，不需要驗證和資料庫操作。

## API端點

### 批次下載影片

**URL**: `/simple-videos/download`

**方法**: `POST`

**描述**: 傳入一組影片連結陣列，系統會依照CPU核心數進行平行處理下載。

**請求內容**:
```json
{
  "urls": [
    "https://www.youtube.com/watch?v=example1",
    "https://www.youtube.com/watch?v=example2",
    "https://vimeo.com/example3",
    ...
  ]
}
```

**回應內容**:
```json
{
  "totalRequested": 3,
  "successful": 2,
  "failed": 1,
  "details": [
    {
      "success": true,
      "url": "https://www.youtube.com/watch?v=example1",
      "path": "/uploads/simple-videos/uuid1.mp4",
      "fileName": "uuid1.mp4"
    },
    {
      "success": true,
      "url": "https://www.youtube.com/watch?v=example2",
      "path": "/uploads/simple-videos/uuid2.mp4",
      "fileName": "uuid2.mp4"
    },
    {
      "success": false,
      "url": "https://vimeo.com/example3",
      "error": "下載錯誤描述"
    }
  ]
}
```

## 附註

1. 所有下載的影片都會被存放在 `uploads/simple-videos/` 目錄下
2. 檔名以UUID格式命名，以避免衝突
3. 系統會根據CPU核心數自動調整同時下載的數量
