export interface ScreenSharingResolution {
  id: string;
  name: string;
  width: number;
  height: number;
  isNative?: boolean;
}

export interface ScreenSharingSettings {
  resolution: ScreenSharingResolution;
  frameRate: number;
  quality: 'low' | 'medium' | 'high';
}

export const SCREEN_SHARING_RESOLUTIONS: ScreenSharingResolution[] = [
  { id: 'native', name: 'Native Resolution', width: 0, height: 0, isNative: true },
  { id: '720p', name: '720p (1280×720)', width: 1280, height: 720 },
  { id: '1080p', name: '1080p (1920×1080)', width: 1920, height: 1080 },
  { id: '1440p', name: '1440p (2560×1440)', width: 2560, height: 1440 },
  { id: '4k', name: '4K (3840×2160)', width: 3840, height: 2160 },
];

export const SCREEN_SHARING_FRAMERATES = [15, 30, 60] as const;
export type ScreenSharingFrameRate = typeof SCREEN_SHARING_FRAMERATES[number];
