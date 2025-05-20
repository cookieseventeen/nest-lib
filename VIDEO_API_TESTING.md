# 視頻 API Postman Collection 測試指南

本文檔提供了如何使用 Postman 來測試我們的視頻 API 的步驟說明。

## 準備工作

1. 確保 NestJS 應用正在運行（默認在 http://localhost:3000）
2. 導入 Postman Collection 和 Environment
   - 導入 `video_api.postman_collection.json`
   - 導入 `video_api_environment.postman_environment.json`
3. 選擇「Video API 環境配置」環境

## 測試步驟

### 1. 註冊和登錄

1. 首先執行「用戶註冊」請求
   - 使用有效的電子郵件地址
   - 設置一個安全的密碼
   - 提供您的名字

2. 然後執行「用戶登入」請求
   - 使用相同的電子郵件和密碼
   - 如果成功，JWT 令牌將自動設置到環境變量中

### 2. 下載影片

1. 執行「下載影片」請求
   - 將 "url" 值更改為您想要下載的 YouTube 視頻的 URL
   - 可選：更改 "type" 值來指定所需的視頻格式（默認為 mp4）
   - 注意：下載大型視頻可能需要一些時間

### 3. 獲取視頻列表

1. 執行「取得所有影片」請求
   - 這將返回您已下載的所有視頻列表
   - 記下您感興趣的視頻的 ID，以便在後續請求中使用

### 4. 獲取單個視頻詳情

1. 執行「取得單一影片資訊」請求
   - 將 URL 中的 `:id` 更改為您想要獲取詳情的視頻 ID
   - 或使用 Postman 的路徑變量來設置 ID 值

### 5. 串流播放視頻

1. 執行「串流播放影片」請求
   - 將 URL 中的 `:id` 更改為您想要播放的視頻 ID
   - 或使用 Postman 的路徑變量來設置 ID 值
   - 如果成功，您將看到視頻內容，可以在 Postman 的「Visualize」選項卡中預覽

## 故障排除

如果您遇到任何問題：

1. 檢查 JWT 令牌是否正確設置
2. 確認 API 服務器正在運行
3. 檢查視頻 ID 是否正確
4. 對於下載失敗，檢查 URL 是否有效並且可公開訪問

## 環境變量

該 Collection 使用以下環境變量：

- `baseUrl`：API 服務器的基本 URL（默認為 http://localhost:3000）
- `jwt`：身份驗證令牌（在登錄後自動設置）

您可以在 Postman 環境設置中隨時更改這些值。
