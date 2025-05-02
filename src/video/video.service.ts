import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { DownloadVideoDto } from './dto/download-video.dto';
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

  constructor(private prisma: PrismaService) {
    // 確保影片目錄存在
    if (!fs.existsSync(this.videoDir)) {
      fs.mkdirSync(this.videoDir, { recursive: true });
    }
  }

  async downloadVideo(userId: number, downloadDto: DownloadVideoDto) {
    const { url } = downloadDto;

    try {
      // 建立唯一檔名
      const videoId = uuidv4();
      const fileName = `${videoId}.mp4`;
      const filePath = path.join(this.videoDir, fileName);

      // 使用 yt-dlp 下載影片
      const cmd = `yt-dlp -o "${filePath}" "${url}"`;
      console.log(`執行命令: ${cmd}`);
      
      const { stdout } = await execPromise(cmd);
      console.log('下載輸出:', stdout);

      // 獲取影片的一些基本資訊
      const fileStats = fs.statSync(filePath);
      const fileSize = fileStats.size;
      
      // 使用 yt-dlp 獲取影片標題
      const { stdout: titleOutput } = await execPromise(`yt-dlp --get-title "${url}"`);
      const title = titleOutput.trim() || 'Untitled Video';

      // 存儲影片資訊到資料庫
      const video = await this.prisma.video.create({
        data: {
          title,
          originalUrl: url,
          filePath,
          fileName,
          fileSize,
          format: 'mp4',
          userId,
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
    });

    if (!video) {
      throw new HttpException('找不到影片', HttpStatus.NOT_FOUND);
    }

    return video;
  }

  async getAllVideos(userId?: number) {
    const where = userId ? { userId } : {};
    
    const videos = await this.prisma.video.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });

    return videos;
  }

  createVideoStream(videoPath: string): ReadStream {
    if (!fs.existsSync(videoPath)) {
      throw new HttpException('找不到影片檔案', HttpStatus.NOT_FOUND);
    }
    return createReadStream(videoPath);
  }
}