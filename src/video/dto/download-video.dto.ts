import { IsUrl, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class DownloadVideoDto {
  @IsNotEmpty()
  @IsUrl()
  url: string;

  @IsOptional()
  @IsString()
  type?: string; // 影片格式，如 mp4/flv/webm
}
