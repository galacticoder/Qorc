/**
 * Screen Sharing Debug Component
 * Shows actual video constraints and stream properties to verify settings are working
 */

import { useState, useEffect } from 'react';
import { Monitor, Info, Play, Square } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { screenSharingSettings } from '@/lib/screen-sharing-settings';

interface VideoTrackInfo {
  width: number;
  height: number;
  frameRate: number;
  aspectRatio: number;
  facingMode?: string;
  deviceId?: string;
}

interface ConstraintsInfo {
  browser: MediaTrackConstraints;
  electron: any;
  settings: any;
}

export function ScreenSharingDebug() {
  const [isCapturing, setIsCapturing] = useState(false);
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [trackInfo, setTrackInfo] = useState<VideoTrackInfo | null>(null);
  const [constraintsInfo, setConstraintsInfo] = useState<ConstraintsInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Load current constraints info
    const updateConstraints = () => {
      const settings = screenSharingSettings.getSettings();
      const browserConstraints = screenSharingSettings.getVideoConstraints();
      const electronConstraints = screenSharingSettings.getElectronVideoConstraints();

      console.log('[ScreenSharingDebug] Constraints updated:', { settings, browserConstraints, electronConstraints });

      setConstraintsInfo({
        browser: browserConstraints,
        electron: electronConstraints,
        settings: settings
      });
    };

    updateConstraints();

    // Subscribe to settings changes for real-time updates
    const unsubscribe = screenSharingSettings.subscribe(() => {
      console.log('[ScreenSharingDebug] Settings changed, updating constraints...');
      updateConstraints();
    });

    return unsubscribe;
  }, []);

  const startCapture = async () => {
    setError(null);
    setIsCapturing(true);
    
    try {
      // Get the current video constraints
      const videoConstraints = screenSharingSettings.getVideoConstraints();
      
      console.log('[ScreenSharingDebug] Using constraints:', videoConstraints);
      
      // Feature detection for screen capture APIs
      const hasModernAPI = typeof navigator !== 'undefined' && !!navigator.mediaDevices && typeof navigator.mediaDevices.getDisplayMedia === 'function';
      const hasLegacyAPI = typeof navigator !== 'undefined' && typeof (navigator as any).getDisplayMedia === 'function';

      if (!hasModernAPI && !hasLegacyAPI) {
        throw new Error('Screen sharing is not supported in this browser.');
      }

      // Start screen capture with our constraints using modern or legacy API
      const capturedStream = hasModernAPI
        ? await navigator.mediaDevices.getDisplayMedia({ video: videoConstraints, audio: false })
        : await (navigator as any).getDisplayMedia({ video: true });
      
      setStream(capturedStream);
      
      // Get the actual video track properties
      const videoTrack = capturedStream.getVideoTracks()[0];
      if (videoTrack) {
        const settings = videoTrack.getSettings();
        console.log('[ScreenSharingDebug] Actual track settings:', settings);
        
        setTrackInfo({
          width: settings.width || 0,
          height: settings.height || 0,
          frameRate: settings.frameRate || 0,
          aspectRatio: settings.aspectRatio || 0,
          facingMode: settings.facingMode,
          deviceId: settings.deviceId
        });
        
        // Log capabilities for comparison
        const capabilities = videoTrack.getCapabilities();
        console.log('[ScreenSharingDebug] Track capabilities:', capabilities);
      }
      
    } catch (err) {
      console.error('[ScreenSharingDebug] Capture failed:', err);
      setError(err instanceof Error ? err.message : 'Failed to start screen capture');
      setIsCapturing(false);
    }
  };

  const stopCapture = () => {
    if (stream) {
      stream.getTracks().forEach(track => track.stop());
      setStream(null);
      setTrackInfo(null);
    }
    setIsCapturing(false);
  };

  const refreshConstraints = () => {
    const settings = screenSharingSettings.getSettings();
    const browserConstraints = screenSharingSettings.getVideoConstraints();
    const electronConstraints = screenSharingSettings.getElectronVideoConstraints();
    
    setConstraintsInfo({
      browser: browserConstraints,
      electron: electronConstraints,
      settings: settings
    });
  };

  return (
    <Card className="w-full max-w-4xl">
      <CardHeader>
        <div className="flex items-center gap-2">
          <Monitor className="h-5 w-5" />
          <CardTitle>Screen Sharing Debug Tool</CardTitle>
        </div>
        <CardDescription>
          Verify that resolution and framerate settings are actually being applied
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        
        {/* Controls */}
        <div className="flex gap-2">
          {!isCapturing ? (
            <Button onClick={startCapture} className="flex items-center gap-2">
              <Play className="h-4 w-4" />
              Start Test Capture
            </Button>
          ) : (
            <Button onClick={stopCapture} variant="destructive" className="flex items-center gap-2">
              <Square className="h-4 w-4" />
              Stop Capture
            </Button>
          )}
          <Button onClick={refreshConstraints} variant="outline">
            Refresh Constraints
          </Button>
        </div>

        {error && (
          <div className="p-3 bg-red-100 border border-red-300 rounded text-red-700">
            <strong>Error:</strong> {error}
          </div>
        )}

        {/* Current Settings */}
        {constraintsInfo && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-3">
              <h3 className="font-semibold flex items-center gap-2">
                <Info className="h-4 w-4" />
                Current Settings
              </h3>
              <div className="bg-gray-50 p-3 rounded text-sm font-mono">
                <div><strong>Resolution:</strong> {constraintsInfo.settings.resolution.name}</div>
                <div><strong>Frame Rate:</strong> {constraintsInfo.settings.frameRate} FPS</div>
                <div><strong>Quality:</strong> {constraintsInfo.settings.quality}</div>
              </div>
            </div>

            <div className="space-y-3">
              <h3 className="font-semibold">Generated Constraints</h3>
              <div className="bg-gray-50 p-3 rounded text-sm font-mono">
                <div><strong>Width:</strong> {JSON.stringify(constraintsInfo.browser.width)}</div>
                <div><strong>Height:</strong> {JSON.stringify(constraintsInfo.browser.height)}</div>
                <div><strong>Frame Rate:</strong> {JSON.stringify(constraintsInfo.browser.frameRate)}</div>
              </div>
            </div>
          </div>
        )}

        {/* Actual Stream Properties */}
        {trackInfo && (
          <div className="space-y-3">
            <h3 className="font-semibold text-green-600">Actual Stream Properties (PROOF)</h3>
            <div className="bg-green-50 border border-green-200 p-4 rounded">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <strong>Actual Width:</strong>
                  <div className="text-lg font-mono">{trackInfo.width}px</div>
                </div>
                <div>
                  <strong>Actual Height:</strong>
                  <div className="text-lg font-mono">{trackInfo.height}px</div>
                </div>
                <div>
                  <strong>Actual Frame Rate:</strong>
                  <div className="text-lg font-mono">{trackInfo.frameRate} FPS</div>
                </div>
                <div>
                  <strong>Aspect Ratio:</strong>
                  <div className="text-lg font-mono">{trackInfo.aspectRatio?.toFixed(2)}</div>
                </div>
              </div>
              
              <div className="mt-4 p-3 bg-white rounded border">
                <strong>Verification:</strong>
                <div className="mt-2 space-y-1 text-sm">
                  <div className={`${constraintsInfo?.settings.resolution.isNative || 
                    (trackInfo.width === constraintsInfo?.settings.resolution.width && 
                     trackInfo.height === constraintsInfo?.settings.resolution.height) 
                    ? 'text-green-600' : 'text-red-600'}`}>
                    Resolution: {constraintsInfo?.settings.resolution.isNative
                      ? `Native resolution (as expected)`
                      : trackInfo.width === constraintsInfo?.settings.resolution.width &&
                        trackInfo.height === constraintsInfo?.settings.resolution.height
                        ? `Matches configured resolution (${trackInfo.width}x${trackInfo.height} vs ${constraintsInfo?.settings.resolution.width}x${constraintsInfo?.settings.resolution.height})`
                        : `Does not match configured resolution (got ${trackInfo.width}x${trackInfo.height}, expected ${constraintsInfo?.settings.resolution.width}x${constraintsInfo?.settings.resolution.height})`}
                  </div>
                  <div className={`${Math.abs(trackInfo.frameRate - (constraintsInfo?.settings.frameRate || 0)) <= 1
                    ? 'text-green-600' : 'text-red-600'}`}>
                    Frame Rate: {Math.abs(trackInfo.frameRate - (constraintsInfo?.settings.frameRate || 0)) <= 1
                      ? `Matches configured frame rate (${trackInfo.frameRate} vs ${(constraintsInfo?.settings.frameRate ?? 0)})`
                      : `Does not match configured frame rate (${trackInfo.frameRate} vs ${(constraintsInfo?.settings.frameRate ?? 0)})`}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Raw Data for Debugging */}
        {constraintsInfo && (
          <details className="space-y-3">
            <summary className="font-semibold cursor-pointer">Raw Constraint Data (for debugging)</summary>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h4 className="font-medium mb-2">Browser Constraints</h4>
                <pre className="bg-gray-100 p-3 rounded text-xs overflow-auto">
                  {JSON.stringify(constraintsInfo.browser, null, 2)}
                </pre>
              </div>
              <div>
                <h4 className="font-medium mb-2">Electron Constraints</h4>
                <pre className="bg-gray-100 p-3 rounded text-xs overflow-auto">
                  {JSON.stringify(constraintsInfo.electron, null, 2)}
                </pre>
              </div>
            </div>
          </details>
        )}

        {/* Instructions */}
        <div className="bg-blue-50 border border-blue-200 p-4 rounded">
          <h4 className="font-semibold text-blue-800 mb-2">How to Test:</h4>
          <ol className="text-sm text-blue-700 space-y-1 list-decimal list-inside">
            <li>Go to Settings → Audio & Video → Screen Sharing and change the resolution/framerate</li>
            <li>Come back here and click "Refresh Constraints" to see the new settings</li>
            <li>Click "Start Test Capture" to actually capture your screen</li>
            <li>Check the "Actual Stream Properties" section to see if the settings were applied</li>
            <li>The verification section will tell you if the settings match what you configured</li>
          </ol>
        </div>
      </CardContent>
    </Card>
  );
}
