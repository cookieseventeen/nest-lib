import { Injectable, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { DownloadVideoDto } from './dto/download-video.dto';
import { DownloadPlaylistDto } from './dto/download-playlist.dto';
import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { v4 as uuidv4 } from 'uuid';
import { createReadStream, ReadStream } from 'fs';

const execPromise = promisify(exec);

@Injectable()
export class VideoService {
  private readonly videoDir = path.join(process.cwd(), 'uploads', 'videos');
  private readonly logger = new Logger(VideoService.name);

  constructor(private prisma: PrismaService) {
    // 確保影片目錄存在
    if (!fs.existsSync(this.videoDir)) {
      fs.mkdirSync(this.videoDir, { recursive: true });
    }
  }

  async downloadVideo(userId: number, downloadDto: DownloadVideoDto) {
    const { url, type } = downloadDto;
    const formatType = type || 'mp4'; // 預設 mp4
    
    console.log('Downloading video for userId:', userId);

    if (!userId || isNaN(userId)) {
      throw new HttpException(
        'Invalid user ID provided: ' + userId,
        HttpStatus.BAD_REQUEST
      );
    }

    try {
      // 建立唯一檔名
      const videoId = uuidv4();
      const fileName = `${videoId}.${formatType}`;
      const filePath = path.join(this.videoDir, fileName);

      // 使用更靈活的格式選擇策略
      // 優先嘗試合併格式，如果不可用則使用最佳品質並自動合併音視頻
      let formatSelector: string;
      
      if (formatType === 'mp4') {
        // 對於 mp4，使用多種後備選項
        formatSelector = 'best[ext=mp4][height<=1080]/best[ext=mp4]/bestvideo[ext=mp4]+bestaudio[ext=m4a]/bestvideo+bestaudio/best';
      } else {
        // 對於其他格式，使用通用策略
        formatSelector = `best[ext=${formatType}]/bestvideo[ext=${formatType}]+bestaudio/bestvideo+bestaudio/best`;
      }

      // 添加額外的 yt-dlp 選項以提高成功率
      const cmd = `yt-dlp -o "${filePath}" -f "${formatSelector}" --merge-output-format ${formatType} --no-check-certificate --ignore-errors "${url}"`;
      console.log(`執行命令: ${cmd}`);
      
      try {
        const { stdout } = await execPromise(cmd);
        console.log('下載輸出:', stdout);
      } catch (downloadError) {
        // 如果下載失敗，嘗試使用更簡單的格式選擇
        console.log('第一次下載嘗試失敗，嘗試簡化格式選擇...');
        const fallbackCmd = `yt-dlp -o "${filePath}" -f "best/worst" --no-check-certificate "${url}"`;
        console.log(`執行後備命令: ${fallbackCmd}`);
        
        const { stdout: fallbackStdout } = await execPromise(fallbackCmd);
        console.log('後備下載輸出:', fallbackStdout);
      }

      // 獲取影片的一些基本資訊
      const fileStats = fs.statSync(filePath);
      const fileSize = fileStats.size;
      
      // 使用 yt-dlp 獲取影片標題
      let title = 'Untitled Video';
      try {
        const { stdout: titleOutput } = await execPromise(`yt-dlp --get-title --no-check-certificate "${url}"`);
        title = titleOutput.trim() || 'Untitled Video';
      } catch (titleError) {
        console.log('無法獲取影片標題，使用預設標題:', titleError.message);
        // 嘗試從 URL 提取標題
        try {
          const { stdout: metadataOutput } = await execPromise(`yt-dlp --print "%(title)s" --no-download --no-check-certificate "${url}"`);
          title = metadataOutput.trim() || 'Untitled Video';
        } catch (metadataError) {
          console.log('無法從 metadata 獲取標題，保持預設標題');
        }
      }

      // 存儲影片資訊到資料庫
      const video = await this.prisma.video.create({
        data: {
          title,
          originalUrl: url,
          filePath,
          fileName,
          fileSize,
          format: formatType,
          user: {
            connect: {
              id: userId
            }
          }
        },
      });

      return {
        id: video.id,
        title: video.title,
        fileSize: video.fileSize,
        createdAt: video.createdAt,
      };
    } catch (error) {
      console.error('下載影片時發生錯誤:', error);
      throw new HttpException(
        `下載影片失敗: ${error.message}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async getVideoById(id: number) {
    const video = await this.prisma.video.findUnique({
      where: { id },
      include: { 
        user: {
          select: {
            id: true,
            name: true,
            profilePicture: true,
            // 只返回必要的用戶公開資料
            // 敏感資料如 email、password 等不返回
          }
        }
      },
    });

    if (!video) {
      throw new HttpException('找不到影片', HttpStatus.NOT_FOUND);
    }

    return video;
  }

  async getAllVideos(userId?: number) {
    const where = userId ? { user: { id: userId } } : {};
    
    const videos = await this.prisma.video.findMany({
      where,
      include: {
        playlist: {
          select: {
            id: true,
            title: true
          }
        }
      },
      orderBy: { createdAt: 'desc' },
    });

    return videos;
  }

  createVideoStream(videoPath: string): ReadStream {
    if (!fs.existsSync(videoPath)) {
      throw new HttpException('找不到影片檔案', HttpStatus.NOT_FOUND);
    }
    
    try {
      return createReadStream(videoPath);
    } catch (error) {
      this.logger.error(`建立影片串流錯誤: ${error.message}`, error.stack);
      throw new HttpException('無法建立影片串流', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * 建立具有範圍請求支援的影片串流
   * @param videoPath 影片檔案路徑
   * @param start 開始位元組
   * @param end 結束位元組
   */
  createRangeVideoStream(videoPath: string, start: number, end: number): ReadStream {
    if (!fs.existsSync(videoPath)) {
      throw new HttpException('找不到影片檔案', HttpStatus.NOT_FOUND);
    }
    
    try {
      // 使用 createReadStream 的 start 和 end 選項來實現範圍請求
      const stream = createReadStream(videoPath, { start, end });
      
      // 添加錯誤處理
      stream.on('error', (error) => {
        this.logger.error(`影片範圍串流錯誤: ${error.message}`, error.stack);
      });
      
      return stream;
    } catch (error) {
      this.logger.error(`建立範圍影片串流錯誤: ${error.message}`, error.stack);
      throw new HttpException('無法建立影片串流', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * 檢查 URL 是否為播放清單
   */
  private isPlaylistUrl(url: string): boolean {
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
      // 首先獲取播放清單資訊
      const playlistInfoCmd = `yt-dlp --flat-playlist --print "%(title)s" --no-check-certificate "${url}"`;
      console.log(`執行播放清單資訊命令: ${playlistInfoCmd}`);
      
      const { stdout: playlistInfo } = await execPromise(playlistInfoCmd);
      const videoTitles = playlistInfo.trim().split('\n').filter(title => title.trim());
      
      if (videoTitles.length === 0) {
        throw new HttpException('無法獲取播放清單資訊或播放清單為空', HttpStatus.BAD_REQUEST);
      }

      // 建立播放清單標題（使用第一個影片名稱 + "合集"）
      const defaultPlaylistTitle = `${videoTitles[0]}合集`;
      const finalPlaylistTitle = playlistTitle || defaultPlaylistTitle;

      // 在資料庫中建立播放清單記錄
      const playlist = await this.prisma.playlist.create({
        data: {
          title: finalPlaylistTitle,
          originalUrl: url,
          user: {
            connect: {
              id: userId
            }
          }
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
      for (let i = 0; i < videoUrls.length; i++) {
        const videoUrl = videoUrls[i];
        const videoTitle = videoTitles[i] || `影片 ${i + 1}`;
        
        try {
          console.log(`下載第 ${i + 1} 個影片: ${videoTitle}`);
          
          // 建立唯一檔名
          const videoId = uuidv4();
          const fileName = `${videoId}.${formatType}`;
          const filePath = path.join(this.videoDir, fileName);

          // 使用與單一影片相同的格式選擇策略
          let formatSelector: string;
          
          if (formatType === 'mp4') {
            formatSelector = 'best[ext=mp4][height<=1080]/best[ext=mp4]/bestvideo[ext=mp4]+bestaudio[ext=m4a]/bestvideo+bestaudio/best';
          } else {
            formatSelector = `best[ext=${formatType}]/bestvideo[ext=${formatType}]+bestaudio/bestvideo+bestaudio/best`;
          }

          const cmd = `yt-dlp -o "${filePath}" -f "${formatSelector}" --merge-output-format ${formatType} --no-check-certificate --ignore-errors "${videoUrl}"`;
          console.log(`執行命令: ${cmd}`);
          
          try {
            const { stdout } = await execPromise(cmd);
            console.log(`影片 ${i + 1} 下載輸出:`, stdout);
          } catch (downloadError) {
            console.log(`影片 ${i + 1} 第一次下載嘗試失敗，嘗試簡化格式選擇...`);
            const fallbackCmd = `yt-dlp -o "${filePath}" -f "best/worst" --no-check-certificate "${videoUrl}"`;
            console.log(`執行後備命令: ${fallbackCmd}`);
            
            const { stdout: fallbackStdout } = await execPromise(fallbackCmd);
            console.log(`影片 ${i + 1} 後備下載輸出:`, fallbackStdout);
          }

          // 檢查檔案是否存在
          if (!fs.existsSync(filePath)) {
            console.log(`影片 ${i + 1} 下載失敗，跳過該影片`);
            continue;
          }

          const fileStats = fs.statSync(filePath);
          const fileSize = fileStats.size;

          // 存儲影片資訊到資料庫
          const video = await this.prisma.video.create({
            data: {
              title: videoTitle,
              originalUrl: videoUrl,
              filePath,
              fileName,
              fileSize,
              format: formatType,
              order: i + 1, // 在播放清單中的順序
              user: {
                connect: {
                  id: userId
                }
              },
              playlist: {
                connect: {
                  id: playlist.id
                }
              }
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
          // 繼續下載下一個影片，不中斷整個播放清單下載
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
   * 自動檢測並下載影片或播放清單
   */
  async downloadVideoOrPlaylist(userId: number, downloadDto: DownloadVideoDto | DownloadPlaylistDto) {
    const { url } = downloadDto;
    
    if (this.isPlaylistUrl(url)) {
      console.log('檢測到播放清單 URL，執行播放清單下載');
      return this.downloadPlaylist(userId, downloadDto as DownloadPlaylistDto);
    } else {
      console.log('檢測到單一影片 URL，執行單一影片下載');
      return this.downloadVideo(userId, downloadDto as DownloadVideoDto);
    }
  }

  /**
   * 獲取使用者的所有播放清單
   */
  async getAllPlaylists(userId: number) {
    const playlists = await this.prisma.playlist.findMany({
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
    const playlist = await this.prisma.playlist.findFirst({
      where: { 
        id: playlistId,
        userId // 確保只能存取自己的播放清單
      },
      include: {
        videos: {
          orderBy: { order: 'asc' }
        },
        user: {
          select: {
            id: true,
            name: true,
            profilePicture: true
          }
        }
      }
    });

    if (!playlist) {
      throw new HttpException('找不到播放清單或無權存取', HttpStatus.NOT_FOUND);
    }

    return playlist;
  }
}