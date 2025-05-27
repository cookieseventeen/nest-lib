import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { DownloadPlaylistDto } from './dto/download-playlist.dto';
import { exec } from 'child_process';
import { promisify } from 'util';
import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs';
import * as path from 'path';

const execPromise = promisify(exec);

@Injectable()
export class PlaylistService {
  private readonly videoDir = path.join(process.cwd(), 'uploads', 'videos');

  constructor(private prisma: PrismaService) {
    // 確保影片目錄存在
    if (!fs.existsSync(this.videoDir)) {
      fs.mkdirSync(this.videoDir, { recursive: true });
    }
  }

  /**
   * 檢查 URL 是否為播放清單
   */
  isPlaylistUrl(url: string): boolean {
    return url.includes('list=') || url.includes('playlist');
  }

  /**
   * 下載播放清單中的所有影片
   */
  async downloadPlaylist(userId: number, downloadDto: DownloadPlaylistDto) {
    const { url, type, playlistTitle } = downloadDto;
    const formatType = type || 'mp4';
    
    console.log('下載播放清單 for userId:', userId);

    if (!userId || isNaN(userId)) {
      throw new HttpException(
        'Invalid user ID provided: ' + userId,
        HttpStatus.BAD_REQUEST
      );
    }

    try {
      // 首先獲取播放清單資訊，嘗試取得原始語言標題
      // 使用多種方法嘗試獲得更準確的標題
      
      // 方法1: 標準擷取
      const playlistInfoCmd = `yt-dlp --flat-playlist --print "%(title)s" --geo-bypass --no-check-certificate "${url}"`;
      console.log(`執行播放清單資訊命令: ${playlistInfoCmd}`);
      
      const { stdout: playlistInfo } = await execPromise(playlistInfoCmd);
      const videoTitles = playlistInfo.trim().split('\n').filter(title => title.trim());
      
      console.log('取得的影片標題 (前3個):', videoTitles.slice(0, 3)); // 顯示前3個標題用於除錯

      // 方法2: 嘗試取得更詳細的資訊 (如果標題看起來不正確)
      let alternativeTitles: string[] = [];
      try {
        const altCmd = `yt-dlp --flat-playlist --print "%(original_title)s||%(title)s||%(uploader)s" --geo-bypass --no-check-certificate "${url}" | head -3`;
        console.log(`嘗試取得詳細標題資訊: ${altCmd}`);
        const { stdout: altInfo } = await execPromise(altCmd);
        alternativeTitles = altInfo.trim().split('\n').filter(line => line.trim());
        console.log('詳細標題資訊:', alternativeTitles);
      } catch (altError) {
        console.log('無法取得詳細標題資訊，使用標準方法');
      }
      
      // 獲取播放清單本身的標題
      let playlistOriginalTitle = '';
      try {
        const playlistTitleCmd = `yt-dlp --flat-playlist -J --no-check-certificate "${url}" | head -1 | jq -r '.title // empty'`;
        console.log(`取得播放清單原始標題: ${playlistTitleCmd}`);
        const { stdout: playlistTitleResult } = await execPromise(playlistTitleCmd);
        playlistOriginalTitle = playlistTitleResult.trim();
        console.log('播放清單原始標題:', playlistOriginalTitle);
      } catch (titleError) {
        console.log('無法取得播放清單原始標題，將使用第一個影片標題');
      }

      if (videoTitles.length === 0) {
        throw new HttpException('無法獲取播放清單資訊或播放清單為空', HttpStatus.BAD_REQUEST);
      }

      // 建立播放清單標題的優先順序：
      // 1. 用戶自訂標題
      // 2. 播放清單原始標題 (如果可取得)
      // 3. 第一個影片名稱 + "合集"
      let defaultPlaylistTitle: string;
      if (playlistOriginalTitle && playlistOriginalTitle !== '' && playlistOriginalTitle !== 'null') {
        defaultPlaylistTitle = playlistOriginalTitle;
      } else {
        defaultPlaylistTitle = `${videoTitles[0]}合集`;
      }
      
      const finalPlaylistTitle = playlistTitle || defaultPlaylistTitle;
      console.log('最終使用的播放清單標題:', finalPlaylistTitle);

      // 在資料庫中建立播放清單記錄（使用原始 Prisma Client）
      const playlist = await (this.prisma as any).playlist.create({
        data: {
          title: finalPlaylistTitle,
          originalUrl: url,
          userId: userId
        }
      });

      // 獲取播放清單中所有影片的 URL
      const videoUrlsCmd = `yt-dlp --flat-playlist --print "%(url)s" --no-check-certificate "${url}"`;
      console.log(`執行影片 URL 命令: ${videoUrlsCmd}`);
      
      const { stdout: videoUrlsOutput } = await execPromise(videoUrlsCmd);
      const videoUrls = videoUrlsOutput.trim().split('\n').filter(url => url.trim());

      const downloadedVideos: Array<{
        id: number;
        title: string;
        fileSize: number | null;
        order: number;
      }> = [];
      
      // 逐一下載播放清單中的每個影片
      for (let i = 0; i < Math.min(videoUrls.length, 3); i++) { // 限制前3個影片作為示範
        const videoUrl = videoUrls[i];
        const videoTitle = videoTitles[i] || `影片 ${i + 1}`;
        
        try {
          console.log(`下載第 ${i + 1} 個影片: ${videoTitle}`);
          
          // 建立唯一檔名
          const videoId = uuidv4();
          const fileName = `${videoId}.${formatType}`;
          const filePath = path.join(this.videoDir, fileName);

          // 使用簡化的格式選擇策略
          const cmd = `yt-dlp -o "${filePath}" -f "best/worst" --no-check-certificate "${videoUrl}"`;
          console.log(`執行命令: ${cmd}`);
          
          const { stdout } = await execPromise(cmd);
          console.log(`影片 ${i + 1} 下載輸出:`, stdout);

          // 檢查檔案是否存在
          if (!fs.existsSync(filePath)) {
            console.log(`影片 ${i + 1} 下載失敗，跳過該影片`);
            continue;
          }

          const fileStats = fs.statSync(filePath);
          const fileSize = fileStats.size;

          // 存儲影片資訊到資料庫
          const video = await (this.prisma as any).video.create({
            data: {
              title: videoTitle,
              originalUrl: videoUrl,
              filePath,
              fileName,
              fileSize,
              format: formatType,
              userId: userId,
              playlistId: playlist.id,
              order: i + 1
            }
          });

          downloadedVideos.push({
            id: video.id,
            title: video.title,
            fileSize: video.fileSize,
            order: i + 1
          });

        } catch (videoError) {
          console.error(`下載影片 ${i + 1} 時發生錯誤:`, videoError);
          continue;
        }
      }

      return {
        playlist: {
          id: playlist.id,
          title: playlist.title,
          createdAt: playlist.createdAt,
          totalVideos: videoUrls.length,
          downloadedVideos: downloadedVideos.length
        },
        videos: downloadedVideos
      };

    } catch (error) {
      console.error('下載播放清單時發生錯誤:', error);
      throw new HttpException(
        `下載播放清單失敗: ${error.message}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * 獲取使用者的所有播放清單
   */
  async getAllPlaylists(userId: number) {
    const playlists = await (this.prisma as any).playlist.findMany({
      where: { userId },
      include: {
        videos: {
          select: {
            id: true,
            title: true,
            fileSize: true,
            order: true,
            createdAt: true
          },
          orderBy: { order: 'asc' }
        },
        _count: {
          select: { videos: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    return playlists;
  }

  /**
   * 根據 ID 獲取播放清單詳情
   */
  async getPlaylistById(playlistId: number, userId: number) {
    const playlist = await (this.prisma as any).playlist.findFirst({
      where: { 
        id: playlistId,
        userId
      },
      include: {
        videos: {
          orderBy: { order: 'asc' }
        }
      }
    });

    if (!playlist) {
      throw new HttpException('找不到播放清單或無權存取', HttpStatus.NOT_FOUND);
    }

    return playlist;
  }
}
