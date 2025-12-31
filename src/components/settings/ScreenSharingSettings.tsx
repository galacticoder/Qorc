import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Label } from '../../components/ui/label';
import { Button } from '../../components/ui/button';
import { Separator } from '../../components/ui/separator';
import {
  ScreenSharingSettings as ScreenSharingSettingsType,
  SCREEN_SHARING_RESOLUTIONS,
  SCREEN_SHARING_FRAMERATES
} from '../../lib/screen-sharing-consts';
import { screenSharingSettings } from '../../lib/screen-sharing-settings';
import {
  QUALITY_OPTIONS,
  QUALITY_LABELS,
  QUALITY_DESCRIPTIONS,
  QualityOption,
  DEFAULT_QUALITY,
  RESET_FEEDBACK_DURATION_MS
} from '../../lib/constants';


function validateQualityOption(value: string): value is QualityOption {
  return QUALITY_OPTIONS.includes(value as any);
}

function getDefaultSettings(): ScreenSharingSettingsType {
  return {
    resolution: SCREEN_SHARING_RESOLUTIONS[0],
    frameRate: SCREEN_SHARING_FRAMERATES[0],
    quality: DEFAULT_QUALITY
  };
}

export function ScreenSharingSettings() {
  const [settings, setSettings] = useState<ScreenSharingSettingsType>(getDefaultSettings);
  const [isResetting, setIsResetting] = useState<boolean>(false);

  useEffect(() => {
    let mounted = true;

    const loadInitialSettings = async () => {
      try {
        const current = await screenSharingSettings.getSettings();
        if (mounted) {
          setSettings(current);
        }
      } catch {
        if (mounted) {
          setSettings(getDefaultSettings());
        }
      }
    };

    loadInitialSettings();

    const unsubscribe = screenSharingSettings.subscribe((newSettings) => {
      if (mounted) {
        setSettings(newSettings);
      }
    });

    return () => {
      mounted = false;
      unsubscribe();
    };
  }, []);

  const handleResolutionChange = useCallback((resolutionId: string) => {
    const resolution = SCREEN_SHARING_RESOLUTIONS.find(r => r.id === resolutionId);
    if (resolution) {
      screenSharingSettings.setResolution(resolution).catch(() => {
        setSettings(prev => prev);
      });
    }
  }, []);

  const handleFrameRateChange = useCallback((frameRateStr: string) => {
    const frameRate = Number.parseInt(frameRateStr, 10);
    if (Number.isFinite(frameRate) && SCREEN_SHARING_FRAMERATES.includes(frameRate as typeof SCREEN_SHARING_FRAMERATES[number])) {
      screenSharingSettings.setFrameRate(frameRate).catch(() => {
        setSettings(prev => prev);
      });
    }
  }, []);

  const handleQualityChange = useCallback((qualityStr: string) => {
    if (validateQualityOption(qualityStr)) {
      screenSharingSettings.setQuality(qualityStr).catch(() => {
        setSettings(prev => prev);
      });
    }
  }, []);

  const handleReset = useCallback(() => {
    if (isResetting) return;
    setIsResetting(true);
    screenSharingSettings.resetToDefaults().catch(() => { });
    setTimeout(() => setIsResetting(false), RESET_FEEDBACK_DURATION_MS);
  }, [isResetting]);

  const qualityDescription = useMemo(() => {
    return QUALITY_DESCRIPTIONS[settings.quality] || '';
  }, [settings.quality]);

  const resolutionDescription = useMemo(() => {
    if (settings.resolution.isNative) {
      return 'Uses display native resolution';
    }
    return `Fixed resolution: ${settings.resolution.width} × ${settings.resolution.height}`;
  }, [settings.resolution]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Screen Sharing</CardTitle>
        <CardDescription>Configure resolution and frame rate.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label htmlFor="resolution-select">Resolution</Label>
          <select
            id="resolution-select"
            value={settings.resolution.id}
            onChange={(e) => handleResolutionChange(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md bg-white dark:bg-gray-700 dark:border-gray-600 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            aria-label="Screen sharing resolution"
          >
            {SCREEN_SHARING_RESOLUTIONS.map((resolution) => (
              <option key={resolution.id} value={resolution.id}>
                {resolution.name}
              </option>
            ))}
          </select>
          <div className="text-sm text-muted-foreground">
            {resolutionDescription}
          </div>
        </div>

        <Separator />

        <div className="space-y-2">
          <Label htmlFor="framerate-select">Frame Rate</Label>
          <select
            id="framerate-select"
            value={settings.frameRate.toString()}
            onChange={(e) => handleFrameRateChange(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md bg-white dark:bg-gray-700 dark:border-gray-600 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            aria-label="Screen sharing frame rate"
          >
            {SCREEN_SHARING_FRAMERATES.map((frameRate) => (
              <option key={frameRate} value={frameRate.toString()}>
                {frameRate} FPS
              </option>
            ))}
          </select>
          <div className="text-sm text-muted-foreground">
            Higher frame rates use more bandwidth
          </div>
        </div>

        <Separator />

        <div className="space-y-2">
          <Label htmlFor="quality-select">Quality</Label>
          <select
            id="quality-select"
            value={settings.quality}
            onChange={(e) => handleQualityChange(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md bg-white dark:bg-gray-700 dark:border-gray-600 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            aria-label="Screen sharing quality"
          >
            {QUALITY_OPTIONS.map((quality) => (
              <option key={quality} value={quality}>
                {QUALITY_LABELS[quality]}
              </option>
            ))}
          </select>
          <div className="text-sm text-muted-foreground">
            {qualityDescription}
          </div>
        </div>

        <div className="flex gap-2 pt-4">
          <Button onClick={handleReset} variant="outline" size="sm" disabled={isResetting} aria-label="Reset to default settings">
            {isResetting ? 'Resetting…' : 'Reset to Defaults'}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
