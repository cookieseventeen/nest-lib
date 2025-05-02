// filepath: /Users/xiebingqi/Documents/mylab/nest-lib/src/video/simple-video.controller.ts
import { Controller, Post, Body } from '@nestjs/common';
import { SimpleVideoService } from './simple-video.service';
import { SimpleDownloadVideoDto } from './dto/simple-download-video.dto';

@Controller('simple-videos')
export class SimpleVideoController {
  constructor(private readonly simpleVideoService: SimpleVideoService) {}

  @Post('download')
  async downloadVideos(@Body() downloadDto: SimpleDownloadVideoDto) {
    return this.simpleVideoService.downloadVideos(downloadDto);
  }
}
