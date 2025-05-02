# 簡易影片下載API測試指南

## 測試環境準備

### 前置需求
1. 確保您的系統已安裝 `yt-dlp` 工具（API內部使用此工具下載影片）
   ```bash
   # macOS 安裝方式
   brew install yt-dlp
   
   # 或使用pip安裝
   pip install yt-dlp
   ```

2. 確保您的NestJS應用程式正在執行
   ```bash
   npm run start:dev
   ```

## 使用Postman進行測試

我已經為您建立了一個名為 `simple_video_api.postman_collection.json` 的Postman Collection，包含兩個測試請求：

1. **下載單一影片** - 使用您提供的YouTube範例連結進行測試
2. **批次下載多個影片** - 同時下載多個影片示範平行處理功能

### 匯入Postman Collection
1. 打開Postman
2. 點擊左上角的「Import」按鈕
3. 選擇檔案 `simple_video_api.postman_collection.json`
4. 點擊「Import」完成匯入

### 執行測試
1. 在Postman的Collections清單中找到「簡易影片下載API測試」
2. 確認環境變數中的 `baseUrl` 設定為您的API伺服器位址（預設為 `http://localhost:3000`）
3. 選擇任一請求：
   - **下載單一影片** - 測試單一影片下載功能
   - **批次下載多個影片** - 測試多執行緒批次下載功能
4. 點擊「Send」按鈕發送請求

### 預期回應
```json
{
  "totalRequested": 1,  // 或更多（根據請求數量）
  "successful": 1,      // 成功下載的數量
  "failed": 0,          // 下載失敗的數量
  "details": [
    {
      "success": true,
      "url": "https://www.youtube.com/watch?v=NUUJ2PXdEH0&pp=ygUG6LWk5Ly2",
      "path": "/Users/.../uploads/simple-videos/uuid.mp4",
      "fileName": "uuid.mp4"
    }
  ]
}
```

## 檢查下載結果

下載的影片會儲存在專案根目錄的 `uploads/simple-videos/` 資料夾中，使用UUID作為檔名。

```bash
# 查看下載的影片檔案
ls -la uploads/simple-videos/
```

## 疑難排解

如果遇到問題：

1. **確保 yt-dlp 正確安裝**：在終端機執行 `yt-dlp --version` 確認
2. **檢查伺服器日誌**：查看NestJS應用程式的控制台輸出，了解下載過程和錯誤訊息
3. **確認影片目錄存在**：檢查 `uploads/simple-videos/` 目錄是否已建立
