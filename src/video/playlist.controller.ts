import { Controller, Post, Get, Param, Body, UseGuards, Req, HttpException, HttpStatus } from '@nestjs/common';
import { PlaylistService } from './playlist.service';
import { DownloadPlaylistDto } from './dto/download-playlist.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';

@Controller('playlists')
export class PlaylistController {
  constructor(private readonly playlistService: PlaylistService) {}

  @Post('download')
  @UseGuards(JwtAuthGuard)
  async downloadPlaylist(@Req() req, @Body() downloadDto: DownloadPlaylistDto) {
    const userId = req.user.id;
    if (!userId) {
      throw new HttpException('User ID not found in token', HttpStatus.UNAUTHORIZED);
    }
    return this.playlistService.downloadPlaylist(userId, downloadDto);
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  async getAllPlaylists(@Req() req) {
    const userId = req.user.id;
    if (!userId) {
      throw new HttpException('User ID not found in token', HttpStatus.UNAUTHORIZED);
    }
    return this.playlistService.getAllPlaylists(userId);
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  async getPlaylistById(@Param('id') id: string, @Req() req) {
    const userId = req.user.id;
    if (!userId) {
      throw new HttpException('User ID not found in token', HttpStatus.UNAUTHORIZED);
    }
    return this.playlistService.getPlaylistById(parseInt(id), userId);
  }
}
