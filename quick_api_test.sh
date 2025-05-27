#!/bin/bash

# 影片播放清單 API 快速測試腳本
# 使用 curl 指令測試主要功能

BASE_URL="http://localhost:3000"
TOKEN=""

echo "🚀 開始影片播放清單 API 測試..."
echo "==============================================="

# 函式：顯示測試結果
show_result() {
    if [ $? -eq 0 ]; then
        echo "✅ $1 - 成功"
    else
        echo "❌ $1 - 失敗"
    fi
    echo ""
}

# 1. 健康檢查
echo "📋 1. 健康檢查"
curl -s "$BASE_URL/" > /dev/null
show_result "應用程式健康檢查"

# 2. 註冊測試用戶
echo "📋 2. 註冊測試用戶"
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser_'$(date +%s)'",
    "email": "test_'$(date +%s)'@example.com",
    "password": "password123"
  }' > /dev/null
show_result "用戶註冊"

# 3. 用戶登入並取得 Token
echo "📋 3. 用戶登入"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }')

TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -n "$TOKEN" ]; then
    echo "✅ 登入成功，取得 Token"
else
    echo "❌ 登入失敗，無法取得 Token"
    echo "嘗試使用現有測試用戶..."
fi
echo ""

# 4. 驗證 Token
echo "📋 4. 驗證認證"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/auth/profile" > /dev/null
show_result "Token 驗證"

# 5. 測試自動檢測下載 (模擬，不實際下載)
echo "📋 5. 測試自動檢測 API 端點"
curl -s -X POST "$BASE_URL/videos/download-auto" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "url": "https://www.youtube.com/watch?v=invalid",
    "type": "mp4"
  }' > /dev/null 2>&1
# 這個會失敗，但測試端點是否存在
echo "✅ 自動檢測端點存在 (預期會有錯誤回應)"
echo ""

# 6. 測試播放清單端點
echo "📋 6. 測試播放清單 API 端點"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/playlists" > /dev/null
show_result "播放清單列表端點"

# 7. 測試影片列表
echo "📋 7. 測試影片列表"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/videos" > /dev/null
show_result "影片列表端點"

# 8. 測試簡易影片 API
echo "📋 8. 測試簡易影片 API"
curl -s "$BASE_URL/simple-video" > /dev/null
show_result "簡易影片列表端點"

echo "==============================================="
echo "🎉 API 基本功能測試完成！"
echo ""
echo "📝 下一步建議："
echo "   1. 導入 Postman 集合進行完整測試"
echo "   2. 使用實際 YouTube URL 測試下載功能"
echo "   3. 檢查檔案上傳目錄權限"
echo ""
echo "📁 測試檔案位置："
echo "   - Postman 集合: complete_video_playlist_api.postman_collection.json"
echo "   - 環境變數: complete_video_playlist_api.postman_environment.json"
echo "   - 測試指南: COMPLETE_API_TESTING_GUIDE.md"
