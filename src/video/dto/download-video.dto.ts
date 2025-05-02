import { IsUrl, IsNotEmpty } from 'class-validator';

export class DownloadVideoDto {
  @IsNotEmpty()
  @IsUrl()
  url: string;
}
