import { IsUrl, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class DownloadPlaylistDto {
  @IsNotEmpty()
  @IsUrl()
  url: string;

  @IsOptional()
  @IsString()
  type?: string; // 影片格式，如 mp4/flv/webm

  @IsOptional()
  @IsString()
  playlistTitle?: string; // 自訂播放清單標題
}
