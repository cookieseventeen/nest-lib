# 播放清單 API 測試文件

## 下載 YouTube 播放清單

### 端點
`POST /videos/download-playlist`

### 請求標頭
```
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json
```

### 請求主體
```json
{
  "url": "https://www.youtube.com/playlist?list=PLrAKf1sIcnV2mW5Sf8QrVfhvB9K8pOT-B",
  "type": "mp4",
  "playlistTitle": "我的自訂播放清單名稱"  // 可選，不提供則會使用第一個影片名稱 + "合集"
}
```

### 回應範例
```json
{
  "playlist": {
    "id": 1,
    "title": "宮崎駿音樂合集",
    "createdAt": "2025-05-26T15:30:36.000Z",
    "totalVideos": 5,
    "downloadedVideos": 4
  },
  "videos": [
    {
      "id": 1,
      "title": "宮崎駿 天空之城主題曲",
      "fileSize": 52428800,
      "order": 1
    },
    {
      "id": 2,
      "title": "千與千尋主題曲",
      "fileSize": 43542400,
      "order": 2
    }
  ]
}
```

## 自動檢測下載（單一影片或播放清單）

### 端點
`POST /videos/download-auto`

### 請求主體
```json
{
  "url": "https://www.youtube.com/watch?v=VIDEO_ID&list=PLAYLIST_ID",
  "type": "mp4"
}
```

系統會自動檢測 URL 是播放清單還是單一影片，並呼叫對應的下載方法。

## 獲取所有播放清單

### 端點
`GET /videos/playlists`

### 回應範例
```json
[
  {
    "id": 1,
    "title": "宮崎駿音樂合集",
    "originalUrl": "https://www.youtube.com/playlist?list=...",
    "createdAt": "2025-05-26T15:30:36.000Z",
    "_count": {
      "videos": 4
    },
    "videos": [
      {
        "id": 1,
        "title": "宮崎駿 天空之城主題曲",
        "fileSize": 52428800,
        "order": 1,
        "createdAt": "2025-05-26T15:31:00.000Z"
      }
    ]
  }
]
```

## 獲取特定播放清單詳情

### 端點
`GET /videos/playlists/:id`

### 回應範例
```json
{
  "id": 1,
  "title": "宮崎駿音樂合集",
  "originalUrl": "https://www.youtube.com/playlist?list=...",
  "createdAt": "2025-05-26T15:30:36.000Z",
  "user": {
    "id": 1,
    "name": "使用者名稱",
    "profilePicture": null
  },
  "videos": [
    {
      "id": 1,
      "title": "宮崎駿 天空之城主題曲",
      "originalUrl": "https://www.youtube.com/watch?v=...",
      "filePath": "/path/to/video.mp4",
      "fileName": "uuid.mp4",
      "fileSize": 52428800,
      "format": "mp4",
      "order": 1,
      "createdAt": "2025-05-26T15:31:00.000Z"
    }
  ]
}
```

## 注意事項

1. 播放清單下載會依序下載每個影片，如果某個影片下載失敗，會跳過該影片繼續下載下一個
2. 播放清單標題預設使用第一個影片名稱加上「合集」二字
3. 每個影片在播放清單中都有一個 `order` 欄位，表示在播放清單中的順序
4. 用戶只能存取自己下載的播放清單和影片
5. 影片檔案格式預設為 mp4，可以透過 `type` 參數指定其他格式
