const { exec } = require('child_process');
const { promisify } = require('util');

const execPromise = promisify(exec);

async function testTitleExtraction() {
  // 測試不同的 YouTube URL
  const testUrls = [
    // 中文內容的播放清單或影片
    'https://www.youtube.com/watch?v=dQw4w9WgXcQ', // 經典英文歌曲
    'https://www.youtube.com/playlist?list=PLu0W_9lII9agS67Uits0UnJyrYiXhDS6q', // 程式設計教學(英文)
  ];

  for (const url of testUrls) {
    console.log(`\n=== 測試 URL: ${url} ===`);
    
    try {
      // 方法 1: 標準標題擷取
      console.log('\n方法 1: 標準標題擷取');
      const cmd1 = `yt-dlp --flat-playlist --print "%(title)s" --no-check-certificate "${url}" | head -3`;
      const { stdout: result1 } = await execPromise(cmd1);
      console.log('結果1:', result1.trim().split('\n'));

      // 方法 2: 嘗試原始標題
      console.log('\n方法 2: 原始標題擷取');
      const cmd2 = `yt-dlp --flat-playlist --print "%(original_title)s" --no-check-certificate "${url}" | head -3`;
      try {
        const { stdout: result2 } = await execPromise(cmd2);
        console.log('結果2:', result2.trim().split('\n'));
      } catch (error) {
        console.log('原始標題擷取失敗，original_title 可能不可用');
      }

      // 方法 3: 完整資訊擷取
      console.log('\n方法 3: 完整資訊擷取');
      const cmd3 = `yt-dlp --flat-playlist --print "標題:%(title)s|上傳者:%(uploader)s|語言:%(language)s" --no-check-certificate "${url}" | head -3`;
      try {
        const { stdout: result3 } = await execPromise(cmd3);
        console.log('結果3:', result3.trim().split('\n'));
      } catch (error) {
        console.log('完整資訊擷取失敗:', error.message);
      }

      // 方法 4: 使用 JSON 格式獲取詳細資訊
      console.log('\n方法 4: JSON 格式詳細資訊');
      const cmd4 = `yt-dlp --flat-playlist -J --no-check-certificate "${url}" | head -10`;
      try {
        const { stdout: result4 } = await execPromise(cmd4);
        const lines = result4.trim().split('\n').slice(0, 3);
        console.log('JSON 資訊 (前3行):', lines);
      } catch (error) {
        console.log('JSON 格式擷取失敗:', error.message);
      }

    } catch (error) {
      console.error(`測試 ${url} 時發生錯誤:`, error.message);
    }
  }
}

console.log('🔍 開始測試不同的標題擷取方法...\n');
testTitleExtraction().then(() => {
  console.log('\n✅ 標題擷取測試完成！');
}).catch(error => {
  console.error('❌ 測試過程中發生錯誤:', error);
});
