import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { SimpleDownloadVideoDto } from './dto/simple-download-video.dto';
import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { v4 as uuidv4 } from 'uuid';
import * as os from 'os';

const execPromise = promisify(exec);

@Injectable()
export class SimpleVideoService {
  private readonly videoDir = path.join(process.cwd(), 'uploads', 'simple-videos');
  private maxConcurrentDownloads: number;

  constructor() {
    // 確保影片目錄存在
    if (!fs.existsSync(this.videoDir)) {
      fs.mkdirSync(this.videoDir, { recursive: true });
    }
    
    // 設定同時下載的執行緒數量，使用可用CPU核心數作為預設值
    this.maxConcurrentDownloads = os.cpus().length;
  }

  async downloadVideos(downloadDto: SimpleDownloadVideoDto) {
    const { urls, type } = downloadDto;
    const totalVideos = urls.length;
    const formatType = type || 'mp4'; // 預設 mp4
    
    console.log(`開始下載 ${totalVideos} 個影片，最大平行處理數：${this.maxConcurrentDownloads}，格式：${formatType}`);
    
    // 為此次下載操作建立唯一的資料夾，使用第一個影片的名稱
    const firstVideoInfo = await this.getVideoInfo(urls[0]);
    // 使用第一個影片的標題作為資料夾名稱的一部分，並確保檔名合法
    const folderName = firstVideoInfo.title
      ? this.sanitizeFilename(firstVideoInfo.title)
      : 'unnamed-videos';
    
    const downloadFolderPath = path.join(this.videoDir, folderName);
    
    // 確保資料夾存在
    if (!fs.existsSync(downloadFolderPath)) {
      fs.mkdirSync(downloadFolderPath, { recursive: true });
    }
    
    const results = {
      totalRequested: totalVideos,
      successful: 0,
      failed: 0,
      folderPath: downloadFolderPath,
      details: []
    };
    
    // 使用 Promise.all 和切割陣列來進行控制同時下載數量
    const downloadBatches: Promise<{success: boolean, url: string, path?: string, error?: string}[]>[] = [];
    
    // 將 URLs 分批處理，每批最多同時處理 maxConcurrentDownloads 個下載
    for (let i = 0; i < totalVideos; i += this.maxConcurrentDownloads) {
      const batch = urls.slice(i, i + this.maxConcurrentDownloads);
      const batchPromises = batch.map(url => this.downloadSingleVideo(url, downloadFolderPath, results.details, formatType));
      downloadBatches.push(Promise.all(batchPromises));
    }
    
    // 依序處理每一批下載
    for (const batchPromise of downloadBatches) {
      const batchResults = await batchPromise;
      results.successful += batchResults.filter(r => r.success).length;
      results.failed += batchResults.filter(r => !r.success).length;
    }
    
    return results;
  }
  
  private async downloadSingleVideo(url: string, folderPath: string, details: any[], formatType = 'mp4'): Promise<{success: boolean, url: string, path?: string, error?: string}> {
    try {
      // 先檢查影片是否可用
      const videoInfo = await this.getVideoInfo(url);
      
      // 如果標題為 'unknown'，可能表示影片不可用
      if (videoInfo.title === 'unknown') {
        const result = {
          success: false,
          url: url,
          error: '影片不可用或無法獲取資訊'
        };
        
        details.push(result);
        return result;
      }
      
      // 使用影片標題作為檔名基礎，確保檔名合法
      const cleanTitle = this.sanitizeFilename(videoInfo.title);
      const outputTemplate = `${folderPath}/${cleanTitle}`;

      // 改善格式選擇策略，加入多個備援選項
      const formatSelectors = [
        `best[ext=${formatType}][height<=1080]`,  // 首選：指定格式，限制解析度
        `best[ext=${formatType}]`,                // 備援1：指定格式
        `best[height<=1080]`,                     // 備援2：任意格式，限制解析度
        `best`,                                   // 備援3：最佳品質
        `worst`                                   // 最後備援：最低品質
      ];
      
      const formatString = formatSelectors.join('/');
      
      // 使用改良的 yt-dlp 命令，加入更多參數來處理 YouTube 問題
      const cmd = `yt-dlp -o "${outputTemplate}.%(ext)s" -f "${formatString}" --no-playlist --no-warnings --ignore-errors --no-check-certificate --user-agent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" "${url}"`;
      console.log(`執行命令: ${cmd} - 開始下載: ${url}`);
      
      const { stdout } = await execPromise(cmd);
      
      // 分析下載輸出，嘗試找出實際下載的檔案名稱
      let downloadedFilename = '';
      const matchFilename = stdout.match(/\[download\] (.+?) has already been downloaded/);
      if (matchFilename) {
        downloadedFilename = path.basename(matchFilename[1]);
      }

      // 下載完成後，檢查資料夾中是否有以此標題為開頭的檔案
      const files = fs.readdirSync(folderPath);
      const downloadedFile = downloadedFilename || files.find(file => file.startsWith(cleanTitle));
      
      if (downloadedFile) {
        const actualFilePath = path.join(folderPath, downloadedFile);
        // 再次確認檔案是否真的存在
        if (fs.existsSync(actualFilePath)) {
          const result = {
            success: true,
            url: url,
            title: videoInfo.title,
            path: actualFilePath,
            fileName: downloadedFile
          };
          
          details.push(result);
          return result;
        }
      }
      
      // 列出資料夾中的所有檔案，協助除錯
      console.error(`資料夾 ${folderPath} 的內容:`, fs.readdirSync(folderPath));
      throw new Error(`檔案下載失敗或找不到檔案 (清楚標題: ${cleanTitle})`);
      
    } catch (error) {
      console.error(`下載影片失敗 [${url}]:`, error.message);
      
      // 如果是格式問題，嘗試最基本的下載
      if (error.message.includes('Requested format is not available') || 
          error.message.includes('nsig extraction failed')) {
        console.log(`嘗試基本格式下載: ${url}`);
        return this.downloadWithBasicFormat(url, folderPath, details);
      }
      
      const result = {
        success: false,
        url: url,
        error: error.message || '下載過程中發生未知錯誤'
      };
      
      details.push(result);
      return result;
    }
  }
  
  // 基本格式下載作為備援
  private async downloadWithBasicFormat(url: string, folderPath: string, details: any[]): Promise<{success: boolean, url: string, path?: string, error?: string}> {
    try {
      const videoInfo = await this.getVideoInfo(url);
      const cleanTitle = this.sanitizeFilename(videoInfo.title);
      const outputTemplate = `${folderPath}/${cleanTitle}`;
      
      // 使用最基本的下載命令，不指定格式
      const cmd = `yt-dlp -o "${outputTemplate}.%(ext)s" --no-playlist --no-warnings --ignore-errors --no-check-certificate "${url}"`;
      console.log(`基本格式下載: ${cmd}`);
      
      await execPromise(cmd);
      
      // 檢查下載結果
      const files = fs.readdirSync(folderPath);
      const downloadedFile = files.find(file => file.startsWith(cleanTitle));
      
      if (downloadedFile) {
        const actualFilePath = path.join(folderPath, downloadedFile);
        if (fs.existsSync(actualFilePath)) {
          const result = {
            success: true,
            url: url,
            title: videoInfo.title,
            path: actualFilePath,
            fileName: downloadedFile,
            note: '使用基本格式下載'
          };
          
          details.push(result);
          return result;
        }
      }
      
      throw new Error('基本格式下載也失敗');
      
    } catch (error) {
      const result = {
        success: false,
        url: url,
        error: `所有下載方式都失敗: ${error.message}`
      };
      
      details.push(result);
      return result;
    }
  }
  
  // 獲取影片的基本資訊 (標題、作者等)
  private async getVideoInfo(url: string): Promise<{ title: string, author?: string }> {
    try {
      // 修改命令避免使用 pipe，並增加錯誤檢查參數
      const cmd = `yt-dlp --dump-json --no-playlist --no-warnings "${url}"`;
      const { stdout, stderr } = await execPromise(cmd);
      
      // 檢查是否有輸出
      if (!stdout || stdout.trim() === '') {
        console.warn(`影片 [${url}] 未獲取到資訊`);
        return { title: 'unknown' };
      }
      
      // 解析 JSON 結果 - 僅取得第一行
      const jsonLine = stdout.split('\n')[0].trim();
      
      if (!jsonLine) {
        return { title: 'unknown' };
      }
      
      try {
        const info = JSON.parse(jsonLine);
        return {
          title: info.title || 'unknown',
          author: info.uploader || 'unknown'
        };
      } catch (jsonError) {
        console.error(`解析影片 JSON 資訊失敗 [${url}]:`, jsonError.message);
        return { title: 'unknown' };
      }
    } catch (error) {
      // 檢查是否是影片不可用的錯誤
      const errorMessage = error.message || '';
      if (errorMessage.includes('Video unavailable') || 
          errorMessage.includes('This video is unavailable')) {
        console.error(`影片不可用 [${url}]`);
      } else {
        console.error(`獲取影片資訊失敗 [${url}]:`, errorMessage);
      }
      return { title: 'unknown' };
    }
  }
  
  // 淨化檔名，移除不允許的字元
  private sanitizeFilename(filename: string): string {
    // 移除檔名中不合法的字元
    let sanitized = filename.replace(/[\\/:*?"<>|]/g, '-');
    // 限制長度避免過長的檔名
    sanitized = sanitized.substring(0, 100);
    return sanitized;
  }
}
