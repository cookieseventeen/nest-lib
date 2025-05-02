import { Controller, Post, Get, Param, Body, UseGuards, Req, Res, HttpStatus, StreamableFile } from '@nestjs/common';
import { VideoService } from './video.service';
import { DownloadVideoDto } from './dto/download-video.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { Response } from 'express';

@Controller('videos')
export class VideoController {
  constructor(private readonly videoService: VideoService) {}

  @Post('download')
  @UseGuards(JwtAuthGuard)
  async downloadVideo(@Req() req, @Body() downloadDto: DownloadVideoDto) {
    const userId = req.user.id;
    return this.videoService.downloadVideo(userId, downloadDto);
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  async getAllVideos(@Req() req) {
    // 只獲取自己的影片
    const userId = req.user.id;
    return this.videoService.getAllVideos(userId);
  }

  @Get('stream/:id')
  @UseGuards(JwtAuthGuard)
  async streamVideo(@Param('id') id: string, @Res({ passthrough: true }) res: Response) {
    const video = await this.videoService.getVideoById(parseInt(id));
    
    const fileStream = this.videoService.createVideoStream(video.filePath);
    
    res.set({
      'Content-Type': 'video/mp4',
      'Content-Disposition': `inline; filename="${video.fileName}"`,
    });
    
    return new StreamableFile(fileStream);
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  async getVideo(@Param('id') id: string) {
    return this.videoService.getVideoById(parseInt(id));
  }
}