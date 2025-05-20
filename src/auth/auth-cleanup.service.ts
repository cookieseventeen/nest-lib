import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';

const unlinkAsync = promisify(fs.unlink);

@Injectable()
export class AuthCleanupService {
  private readonly videoDir = path.join(process.cwd(), 'uploads', 'videos');

  constructor(private prisma: PrismaService) {}

  /**
   * 刪除使用者時同時刪除其所有影片檔案
   * 注意：資料庫中的影片記錄將因為 onDelete: Cascade 設定而自動刪除
   * 這個方法處理實際檔案系統中的檔案
   */
  async deleteUserWithCleanup(userId: number): Promise<void> {
    // 先取得所有該使用者的影片，以獲取實體檔案路徑
    const userVideos = await this.prisma.video.findMany({
      where: { userId },
      select: { filePath: true },
    });

    // 刪除使用者（這將觸發級聯刪除影片記錄）
    await this.prisma.user.delete({
      where: { id: userId },
    });

    // 刪除實際的影片檔案
    for (const video of userVideos) {
      try {
        if (fs.existsSync(video.filePath)) {
          await unlinkAsync(video.filePath);
          console.log(`已刪除影片檔案: ${video.filePath}`);
        }
      } catch (error) {
        console.error(`刪除影片檔案失敗: ${video.filePath}`, error);
        // 繼續處理其他檔案，不中斷流程
      }
    }
  }
}
