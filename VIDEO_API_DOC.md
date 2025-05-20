# Video API 功能與規格說明

---

## 1. 下載影片
- **路徑**：`POST /videos/download`
- **權限**：需 JWT 驗證（`JwtAuthGuard`）
- **Body 參數**（`DownloadVideoDto`）：
  - `url` (string, 必填)：影片來源網址，需為合法 URL。
  - `type` (string, 選填)：影片格式（如 mp4、flv、webm），預設 mp4。
- **流程**：
  1. 產生唯一檔名與儲存路徑。
  2. 使用 `yt-dlp` 下載影片，格式依 `type` 決定。
  3. 下載完成後取得檔案大小與影片標題。
  4. 將影片資訊（標題、原始網址、檔案路徑、檔名、大小、格式、userId）存入資料庫。
  5. 回傳影片基本資訊（id、title、fileSize、createdAt）。
- **錯誤處理**：下載失敗時回傳 500 錯誤與詳細訊息。

**Request 範例**
```json
POST /videos/download
Authorization: Bearer <JWT>
Content-Type: application/json
{
  "url": "https://www.youtube.com/watch?v=xxxxxxx",
  "type": "mp4"
}
```

**成功 Response 範例**
```json
{
  "id": 1,
  "title": "影片標題",
  "fileSize": 12345678,
  "createdAt": "2025-05-04T12:34:56.000Z"
}
```

**失敗 Response 範例**
```json
{
  "statusCode": 500,
  "message": "下載影片失敗: ...",
  "error": "Internal Server Error"
}
```

---

## 2. 取得所有影片
- **路徑**：`GET /videos`
- **權限**：需 JWT 驗證
- **功能**：取得目前登入用戶的所有影片清單，依建立時間倒序排列。

**Request 範例**
```http
GET /videos
Authorization: Bearer <JWT>
```

**成功 Response 範例**
```json
[
  {
    "id": 1,
    "title": "影片標題1",
    "fileSize": 12345678,
    "createdAt": "2025-05-04T12:34:56.000Z"
  },
  {
    "id": 2,
    "title": "影片標題2",
    "fileSize": 23456789,
    "createdAt": "2025-05-03T11:22:33.000Z"
  }
]
```

---

## 3. 取得單一影片資訊
- **路徑**：`GET /videos/:id`
- **權限**：需 JWT 驗證
- **功能**：根據影片 id 取得影片詳細資訊。
- **錯誤處理**：找不到影片時回傳 404。

**Request 範例**
```http
GET /videos/1
Authorization: Bearer <JWT>
```

**成功 Response 範例**
```json
{
  "id": 1,
  "title": "影片標題",
  "fileSize": 12345678,
  "createdAt": "2025-05-04T12:34:56.000Z"
}
```

**失敗 Response 範例**
```json
{
  "statusCode": 404,
  "message": "找不到影片",
  "error": "Not Found"
}
```

---

## 4. 串流播放影片
- **路徑**：`GET /videos/stream/:id`
- **權限**：需 JWT 驗證
- **功能**：根據影片 id 串流回傳影片檔案（Content-Type: video/mp4）。
- **錯誤處理**：找不到檔案時回傳 404。

**Request 範例**
```http
GET /videos/stream/1
Authorization: Bearer <JWT>
```

**成功 Response**
- 直接回傳影片串流內容，`Content-Type: video/mp4`

**失敗 Response 範例**
```json
{
  "statusCode": 404,
  "message": "找不到影片檔案",
  "error": "Not Found"
}
```

---

## 其他規格
- **安全性**：所有 API 皆需 JWT 驗證，僅允許操作自己的影片。
- **檔案儲存**：所有影片存於 `uploads/videos/` 目錄，檔名唯一。
- **資料庫欄位**：title、originalUrl、filePath、fileName、fileSize、format、userId、createdAt。
