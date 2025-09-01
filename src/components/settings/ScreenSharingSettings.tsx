/**
 * Screen Sharing Settings Component
 * Provides UI for configuring screen sharing resolution and framerate preferences
 */

import React, { useState, useEffect } from 'react';
import { Monitor, Settings } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { 
  ScreenSharingSettings as ScreenSharingSettingsType,
  SCREEN_SHARING_RESOLUTIONS,
  SCREEN_SHARING_FRAMERATES 
} from '@/lib/webrtc-calling';
import { screenSharingSettings } from '@/lib/screen-sharing-settings';

export function ScreenSharingSettings() {
  const [settings, setSettings] = useState<ScreenSharingSettingsType>(
    screenSharingSettings.getSettings()
  );

  useEffect(() => {
    // Subscribe to settings changes
    const unsubscribe = screenSharingSettings.subscribe((newSettings) => {
      console.log('[ScreenSharingSettings UI] Settings updated:', newSettings);
      setSettings(newSettings);
    });

    return unsubscribe;
  }, []);

  const handleResolutionChange = (resolutionId: string) => {
    const resolution = SCREEN_SHARING_RESOLUTIONS.find(r => r.id === resolutionId);
    if (resolution) {
      console.log('[ScreenSharingSettings UI] Resolution changing to:', resolution.name);
      screenSharingSettings.setResolution(resolution);
      // Settings will be updated via the subscription
    }
  };

  const handleFrameRateChange = (frameRateStr: string) => {
    const frameRate = Number.parseInt(frameRateStr, 10);
    if (Number.isFinite(frameRate) && SCREEN_SHARING_FRAMERATES.includes(frameRate as typeof SCREEN_SHARING_FRAMERATES[number])) {
      console.log('[ScreenSharingSettings UI] Frame rate changing to:', frameRate, 'FPS');
      screenSharingSettings.setFrameRate(frameRate);
      // Settings will be updated via the subscription
    }
  };

  const handleQualityChange = (quality: 'low' | 'medium' | 'high') => {
    console.log('[ScreenSharingSettings UI] Quality changing to:', quality);
    screenSharingSettings.setQuality(quality);
    // Settings will be updated via the subscription
  };

  const handleReset = () => {
    console.log('[ScreenSharingSettings UI] Resetting to defaults');
    screenSharingSettings.resetToDefaults();
  };

  const getQualityDescription = (quality: string) => {
    switch (quality) {
      case 'low':
        return 'Lower bandwidth usage, suitable for slow connections';
      case 'medium':
        return 'Balanced quality and bandwidth usage';
      case 'high':
        return 'Best quality, higher bandwidth usage';
      default:
        return '';
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Monitor className="h-5 w-5" />
          <CardTitle>Screen Sharing</CardTitle>
        </div>
        <CardDescription>
          Configure resolution and framerate for screen sharing
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Resolution Setting */}
        <div className="space-y-2">
          <Label htmlFor="resolution-select">Resolution</Label>
          <select
            id="resolution-select"
            value={settings.resolution.id}
            onChange={(e) => handleResolutionChange(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md bg-white dark:bg-gray-700 dark:border-gray-600 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {SCREEN_SHARING_RESOLUTIONS.map((resolution) => (
              <option key={resolution.id} value={resolution.id}>
                {resolution.name}
                {!resolution.isNative && ` (${resolution.width} × ${resolution.height})`}
              </option>
            ))}
          </select>
          <div className="text-sm text-muted-foreground">
            {settings.resolution.isNative
              ? 'Uses your display\'s native resolution for best quality'
              : `Fixed resolution: ${settings.resolution.width} × ${settings.resolution.height}`
            }
          </div>
        </div>

        <Separator />

        {/* Frame Rate Setting */}
        <div className="space-y-2">
          <Label htmlFor="framerate-select">Frame Rate</Label>
          <select
            id="framerate-select"
            value={settings.frameRate.toString()}
            onChange={(e) => handleFrameRateChange(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md bg-white dark:bg-gray-700 dark:border-gray-600 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {SCREEN_SHARING_FRAMERATES.map((frameRate) => (
              <option key={frameRate} value={frameRate.toString()}>
                {frameRate} FPS
              </option>
            ))}
          </select>
          <div className="text-sm text-muted-foreground">
            Higher frame rates provide smoother motion but use more bandwidth
          </div>
        </div>

        <Separator />

        {/* Quality Setting */}
        <div className="space-y-2">
          <Label htmlFor="quality-select">Quality</Label>
          <select
            id="quality-select"
            value={settings.quality}
            onChange={(e) => handleQualityChange(e.target.value as 'low' | 'medium' | 'high')}
            className="w-full px-3 py-2 border border-gray-300 rounded-md bg-white dark:bg-gray-700 dark:border-gray-600 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
          </select>
          <div className="text-sm text-muted-foreground">
            {getQualityDescription(settings.quality)}
          </div>
        </div>

        <Separator />

        {/* Current Settings Summary */}
        <div className="space-y-2">
          <Label>Current Settings</Label>
          <div className="text-sm text-muted-foreground space-y-1">
            <div>Resolution: {settings.resolution.name}</div>
            <div>Frame Rate: {settings.frameRate} FPS</div>
            <div>Quality: {settings.quality.charAt(0).toUpperCase() + settings.quality.slice(1)}</div>
          </div>
        </div>

        {/* Reset Button */}
        <div className="flex gap-2 pt-4">
          <Button onClick={handleReset} variant="outline" size="sm">
            Reset to Defaults
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
