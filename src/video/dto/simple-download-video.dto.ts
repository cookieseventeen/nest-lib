import { IsUrl, IsNotEmpty, IsArray } from 'class-validator';

export class SimpleDownloadVideoDto {
  @IsNotEmpty()
  @IsArray()
  @IsUrl({}, { each: true })
  urls: string[];
}
