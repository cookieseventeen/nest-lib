import { IsUrl, IsNotEmpty, IsArray, IsOptional, IsString } from 'class-validator';

export class SimpleDownloadVideoDto {
  @IsNotEmpty()
  @IsArray()
  @IsUrl({}, { each: true })
  urls: string[];

  @IsOptional()
  @IsString()
  type?: string; // 影片格式，如 mp4/flv/webm
}
