import { QualityOption } from '../constants';

export interface ScreenSource {
  readonly id: string;
  readonly name: string;
  readonly type: 'screen' | 'window';
}

export interface ScreenSharingSettings {
  quality: QualityOption;
}

export const cloneScreenSharingSettings = (
  settings: ScreenSharingSettings,
): ScreenSharingSettings => ({
  quality: settings.quality,
});
