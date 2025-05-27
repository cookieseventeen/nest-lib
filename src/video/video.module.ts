import { Module } from '@nestjs/common';
import { VideoController } from './video.controller';
import { VideoService } from './video.service';
import { PlaylistController } from './playlist.controller';
import { PlaylistService } from './playlist.service';
import { PrismaModule } from '../prisma/prisma.module';
import { SimpleVideoController } from './simple-video.controller';
import { SimpleVideoService } from './simple-video.service';

@Module({
  imports: [PrismaModule],
  controllers: [VideoController, SimpleVideoController, PlaylistController],
  providers: [VideoService, SimpleVideoService, PlaylistService],
  exports: [VideoService, SimpleVideoService, PlaylistService],
})
export class VideoModule {}