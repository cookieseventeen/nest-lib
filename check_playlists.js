const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function checkPlaylists() {
  try {
    console.log('=== 查詢現有播放清單 ===');
    
    const playlists = await prisma.playlist.findMany({
      include: {
        videos: {
          select: {
            id: true,
            title: true,
            order: true
          },
          orderBy: { order: 'asc' },
          take: 3
        }
      },
      orderBy: { createdAt: 'desc' },
      take: 5
    });

    if (playlists.length === 0) {
      console.log('目前沒有播放清單資料');
    } else {
      playlists.forEach((playlist, index) => {
        console.log(`\n播放清單 ${index + 1}:`);
        console.log(`ID: ${playlist.id}`);
        console.log(`標題: ${playlist.title}`);
        console.log(`原始 URL: ${playlist.originalUrl}`);
        console.log(`建立時間: ${playlist.createdAt}`);
        
        if (playlist.videos.length > 0) {
          console.log('包含的影片:');
          playlist.videos.forEach(video => {
            console.log(`  - [${video.order}] ${video.title}`);
          });
        } else {
          console.log('沒有影片');
        }
      });
    }
  } catch (error) {
    console.error('查詢錯誤:', error);
  } finally {
    await prisma.$disconnect();
  }
}

checkPlaylists();
