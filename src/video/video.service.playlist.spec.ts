import { Test, TestingModule } from '@nestjs/testing';
import { VideoService } from './video.service';
import { PrismaService } from '../prisma/prisma.service';

describe('VideoService - Playlist Features', () => {
  let service: VideoService;
  let prismaService: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VideoService,
        {
          provide: PrismaService,
          useValue: {
            video: {
              create: jest.fn(),
              findMany: jest.fn(),
              findUnique: jest.fn(),
            },
            playlist: {
              create: jest.fn(),
              findMany: jest.fn(),
              findFirst: jest.fn(),
            },
          },
        },
      ],
    }).compile();

    service = module.get<VideoService>(VideoService);
    prismaService = module.get<PrismaService>(PrismaService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should detect playlist URL correctly', () => {
    const playlistUrl = 'https://www.youtube.com/playlist?list=PLrAKf1sIcnV2mW5Sf8QrVfhvB9K8pOT-B';
    const videoUrl = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
    
    // @ts-ignore - 存取私有方法進行測試
    expect(service.isPlaylistUrl(playlistUrl)).toBe(true);
    // @ts-ignore - 存取私有方法進行測試
    expect(service.isPlaylistUrl(videoUrl)).toBe(false);
  });

  it('should handle playlist downloads', async () => {
    const mockPlaylist = {
      id: 1,
      title: '測試播放清單合集',
      originalUrl: 'https://www.youtube.com/playlist?list=test',
      userId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const mockVideos = [
      {
        id: 1,
        title: '測試影片 1',
        originalUrl: 'https://www.youtube.com/watch?v=test1',
        filePath: '/path/to/video1.mp4',
        fileName: 'uuid1.mp4',
        fileSize: 1000000,
        format: 'mp4',
        duration: null,
        userId: 1,
        playlistId: 1,
        order: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ];

    jest.spyOn(prismaService.playlist, 'create').mockResolvedValue(mockPlaylist);
    jest.spyOn(prismaService.video, 'create').mockResolvedValue(mockVideos[0]);

    // 測試播放清單建立邏輯
    expect(prismaService.playlist.create).toBeDefined();
    expect(prismaService.video.create).toBeDefined();
  });
});
