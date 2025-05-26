import { Controller, Post, Get, Param, Body, UseGuards, Req, Res, HttpStatus, StreamableFile, HttpException, Logger } from '@nestjs/common';
import { VideoService } from './video.service';
import { DownloadVideoDto } from './dto/download-video.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import { statSync } from 'fs';

@Controller('videos')
export class VideoController {
  private readonly logger = new Logger(VideoController.name);
  
  constructor(private readonly videoService: VideoService) {}

  @Post('download')
  @UseGuards(JwtAuthGuard)
  async downloadVideo(@Req() req, @Body() downloadDto: DownloadVideoDto) {
    const userId = req.user.id;
    if (!userId) {
      throw new HttpException('User ID not found in token', HttpStatus.UNAUTHORIZED);
    }
    return this.videoService.downloadVideo(userId, downloadDto);
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  async getAllVideos(@Req() req) {
    // 只獲取自己的影片
    const userId = req.user.id;
    if (!userId) {
      throw new HttpException('User ID not found in token', HttpStatus.UNAUTHORIZED);
    }
    return this.videoService.getAllVideos(userId);
  }

  @Get('stream/:id')
  @UseGuards(JwtAuthGuard)
  async streamVideo(@Param('id') id: string, @Req() req, @Res({ passthrough: false }) res: Response) {
    try {
      const userId = req.user.id;
      if (!userId) {
        throw new HttpException('User ID not found in token', HttpStatus.UNAUTHORIZED);
      }
      
      const video = await this.videoService.getVideoById(parseInt(id));
      
      // 權限檢查：確保用戶只能存取自己的影片
      if (video.userId !== userId) {
        throw new HttpException('無權存取此影片', HttpStatus.FORBIDDEN);
      }
      
      const filePath = video.filePath;
      
      // 檢查檔案是否存在
      if (!fs.existsSync(filePath)) {
        throw new HttpException('影片檔案不存在', HttpStatus.NOT_FOUND);
      }
      
      // 取得檔案狀態以獲取檔案大小
      const stat = statSync(filePath);
      const fileSize = stat.size;
      
      // 處理範圍請求 (Range request)
      const range = req.headers.range;
      
      if (!range) {
        // 如果沒有範圍請求，回傳整個檔案
        res.set({
          'Content-Length': fileSize,
          'Content-Type': 'video/mp4',
          'Content-Disposition': `inline; filename="${video.fileName}"`,
          'Accept-Ranges': 'bytes',
        });
        
        const fileStream = this.videoService.createVideoStream(filePath);
        fileStream.pipe(res);
        
        // 處理串流錯誤
        fileStream.on('error', (error) => {
          this.logger.error(`串流錯誤: ${error.message}`, error.stack);
          if (!res.headersSent) {
            res.status(HttpStatus.INTERNAL_SERVER_ERROR).send('影片串流錯誤');
          }
          res.end();
        });
        
        return;
      }
      
      // 解析範圍請求標頭
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      
      // 驗證範圍
      if (
        isNaN(start) || 
        isNaN(end) || 
        start < 0 || 
        end >= fileSize || 
        start > end
      ) {
        res.set('Content-Range', `bytes */${fileSize}`);
        throw new HttpException('請求範圍無效', HttpStatus.REQUESTED_RANGE_NOT_SATISFIABLE);
      }
      
      // 計算 content-length
      const chunkSize = (end - start) + 1;
      const headers = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunkSize,
        'Content-Type': 'video/mp4',
        'Content-Disposition': `inline; filename="${video.fileName}"`,
      };
      
      // 設置 206 Partial Content 狀態碼和標頭
      res.writeHead(206, headers);
      
      // 建立範圍串流
      const stream = this.videoService.createRangeVideoStream(filePath, start, end);
      
      // 處理串流錯誤
      stream.on('error', (error) => {
        this.logger.error(`範圍串流錯誤: ${error.message}`, error.stack);
        if (!res.headersSent) {
          res.status(HttpStatus.INTERNAL_SERVER_ERROR).send('影片串流錯誤');
        }
        res.end();
      });
      
      // 串流至回應
      stream.pipe(res);
    } catch (error) {
      this.logger.error(`影片串流錯誤: ${error.message}`, error.stack);
      if (!res.headersSent) {
        res.status(
          error instanceof HttpException ? error.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR
        ).send(error instanceof HttpException ? error.message : '內部伺服器錯誤');
      }
      res.end();
    }
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  async getVideo(@Param('id') id: string) {
    return this.videoService.getVideoById(parseInt(id));
  }
}