import { Module } from '@nestjs/common';
import { VideoController } from './video.controller';
import { VideoService } from './video.service';
import { PrismaModule } from '../prisma/prisma.module';
import { SimpleVideoController } from './simple-video.controller';
import { SimpleVideoService } from './simple-video.service';

@Module({
  imports: [PrismaModule],
  controllers: [VideoController, SimpleVideoController],
  providers: [VideoService, SimpleVideoService],
  exports: [VideoService, SimpleVideoService],
})
export class VideoModule {}