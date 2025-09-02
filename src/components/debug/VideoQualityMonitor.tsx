/**
 * Video Quality Monitor Component
 * Shows real-time quality stats for received video streams (viewer side)
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { Activity, Eye } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

interface VideoStats {
  resolution: { width: number; height: number };
  frameRate: number;
  bitrate: number;
  packetsLost: number; // delta since last sample
  packetsReceived: number; // cumulative
  bytesReceived: number;
  timestamp: number;
  codecName?: string;
  jitter?: number;
}

interface VideoQualityMonitorProps {
  peerConnection: RTCPeerConnection | null;
  remoteStream: MediaStream | null;
  isVisible?: boolean;
}

export function VideoQualityMonitor({ peerConnection, remoteStream, isVisible = true }: VideoQualityMonitorProps) {
  const [stats, setStats] = useState<VideoStats | null>(null);
  // Internal monitoring state is derived from intervalRef; avoid extra state churn
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastInboundRef = useRef<{
    id: string;
    bytesReceived: number;
    framesReceived?: number;
    packetsReceived: number;
    packetsLostTotal: number;
    timestamp: number;
  } | null>(null);
  const failureCountRef = useRef(0);
  const MAX_FAILURES = 5;

  const stopMonitoring = useCallback(() => {
    console.log('[VideoQualityMonitor] Stopping quality monitoring...');
    // intervalRef presence determines monitoring state; no state flip needed
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    setStats(null);
  }, []);

  const startMonitoring = useCallback(() => {
    if (!peerConnection) return;
    if (intervalRef.current) return; // already monitoring

    console.log('[VideoQualityMonitor] Starting quality monitoring...');
    // intervalRef presence determines monitoring state; no state flip needed

    const updateStats = async () => {
      try {
        const statsReport = await peerConnection.getStats();
        const videoStats = extractVideoStats(statsReport);
        if (videoStats) {
          setStats(videoStats);
          failureCountRef.current = 0; // Reset on success
        }
      } catch (error) {
        console.warn('[VideoQualityMonitor] Failed to get stats:', error);
        failureCountRef.current++;
        if (failureCountRef.current >= MAX_FAILURES) {
          console.warn('[VideoQualityMonitor] Too many failures, stopping monitoring');
          stopMonitoring();
        }
      }
    };

    // Update stats every second
    intervalRef.current = setInterval(updateStats, 1000);
    updateStats(); // Initial update
  }, [peerConnection, stopMonitoring]);

  const extractVideoStats = (statsReport: RTCStatsReport): VideoStats | null => {
    // Prefer mapping inbound-rtp to the actual remote video track from props.remoteStream
    const preferredTrackId = remoteStream?.getVideoTracks()?.[0]?.id;

    const inboundCandidates: any[] = [];
    const trackById: Record<string, any> = {};
    const videoTracks: any[] = [];

    statsReport.forEach((report: any) => {
      // Collect inbound-rtp for video (support kind or mediaType)
      if (
        report.type === 'inbound-rtp' &&
        (report.kind === 'video' || report.mediaType === 'video')
      ) {
        inboundCandidates.push(report);
      }
      // Collect track reports for video
      if (
        report.type === 'track' &&
        (report.kind === 'video' || report.mediaType === 'video')
      ) {
        trackById[report.id] = report;
        videoTracks.push(report);
      }
    });

    if (inboundCandidates.length === 0) return null;

    // Try to find inbound tied to our visible remote track
    let inboundVideoStats: any = null;
    let trackStats: any = null;
    if (preferredTrackId) {
      inboundVideoStats = inboundCandidates.find((inb: any) => {
        const t = trackById[inb.trackId];
        return t && t.trackIdentifier === preferredTrackId;
      }) || null;
      if (inboundVideoStats) {
        trackStats = trackById[inboundVideoStats.trackId] || null;
      }
    }
    // Fallbacks: pick an active inbound with bytes/packets flowing, else the first
    if (!inboundVideoStats) {
      inboundVideoStats =
        inboundCandidates.find((r) => (r.bytesReceived || 0) > 0 || (r.packetsReceived || 0) > 0) ||
        inboundCandidates[0];
      trackStats = trackById[inboundVideoStats.trackId] || videoTracks[0] || null;
    }

    // Calculate bitrate using last inbound snapshot, reset when SSRC/ID changes
    let bitrate = 0;
    const currentId: string = inboundVideoStats.id || '';
    const currentTime: number = inboundVideoStats.timestamp;
    const currentBytes: number = inboundVideoStats.bytesReceived || 0;
    const currentFrames: number | undefined = inboundVideoStats.framesReceived;
    const currentPacketsReceived: number = inboundVideoStats.packetsReceived || 0;
    const currentPacketsLostTotal: number = inboundVideoStats.packetsLost || 0;

    const prevInboundSnapshot = lastInboundRef.current ? { ...lastInboundRef.current } : null;

    if (prevInboundSnapshot && prevInboundSnapshot.id === currentId) {
      const prevTimestamp = prevInboundSnapshot.timestamp;
      const timesAreValid = Number.isFinite(currentTime) && Number.isFinite(prevTimestamp) && currentTime > prevTimestamp;
      if (timesAreValid) {
        const timeDiff = (currentTime - prevTimestamp) / 1000;
        const bytesDiff = currentBytes - prevInboundSnapshot.bytesReceived;
        if (timeDiff > 0 && bytesDiff >= 0) {
          bitrate = Math.round((bytesDiff * 8) / timeDiff);
        }
      } else {
        // Leave bitrate at 0 on invalid timestamps
      }
    }

    // Derive frame rate: prefer track.framesPerSecond, then inbound.framesPerSecond,
    // else compute from framesReceived delta
    let frameRate = (trackStats?.framesPerSecond || inboundVideoStats.framesPerSecond || 0) as number;

    // Compute frameRate using delta frames if needed
    if (!trackStats?.framesPerSecond && !inboundVideoStats.framesPerSecond && prevInboundSnapshot && prevInboundSnapshot.id === currentId) {
      if (typeof inboundVideoStats.framesReceived === 'number' && typeof prevInboundSnapshot.framesReceived === 'number') {
        const tDiffRaw = inboundVideoStats.timestamp - prevInboundSnapshot.timestamp;
        const timesAreValid = Number.isFinite(inboundVideoStats.timestamp) && Number.isFinite(prevInboundSnapshot.timestamp) && tDiffRaw > 0;
        if (timesAreValid) {
          const tDiff = tDiffRaw / 1000;
          const fDiff = inboundVideoStats.framesReceived - prevInboundSnapshot.framesReceived;
          if (tDiff >= 0.2 && fDiff >= 0) {
            frameRate = fDiff / tDiff;
          }
        }
      }
    }

    // Now update snapshots after calculations
    lastInboundRef.current = {
      id: currentId,
      bytesReceived: currentBytes,
      framesReceived: currentFrames,
      packetsReceived: currentPacketsReceived,
      packetsLostTotal: currentPacketsLostTotal,
      timestamp: currentTime
    };

    // Compute packet loss delta for the interval (more actionable than cumulative)
    let packetsLostDelta = 0;
    if (prevInboundSnapshot && prevInboundSnapshot.id === currentId) {
      const lostDiff = currentPacketsLostTotal - prevInboundSnapshot.packetsLostTotal;

      // Log when packet loss total decreases (indicates stat reset or connection change)
      if (lostDiff < 0) {
        console.warn('[VideoQualityMonitor] Packet loss total decreased - possible stat reset or connection change', {
          currentId,
          prevId: prevInboundSnapshot.id,
          prevPacketsLost: prevInboundSnapshot.packetsLostTotal,
          currentPacketsLost: currentPacketsLostTotal,
          timestamp: currentTime
        });
      }

      packetsLostDelta = lostDiff >= 0 ? lostDiff : 0;
    }
    
    // Resolve codec from codecId if present
    const codecStats = inboundVideoStats.codecId ? statsReport.get(inboundVideoStats.codecId) : undefined;
    const resolvedCodecName = (codecStats?.mimeType as string | undefined) ?? (inboundVideoStats.codecId ? 'Unknown' : undefined);

    return {
      resolution: {
        width: trackStats?.frameWidth || inboundVideoStats.frameWidth || 0,
        height: trackStats?.frameHeight || inboundVideoStats.frameHeight || 0
      },
      frameRate: frameRate || 0,
      bitrate,
      packetsLost: packetsLostDelta,
      packetsReceived: inboundVideoStats.packetsReceived || 0,
      bytesReceived: inboundVideoStats.bytesReceived || 0,
      timestamp: inboundVideoStats.timestamp || Date.now(),
      codecName: resolvedCodecName,
      jitter: inboundVideoStats.jitter
    };
  };

  // Auto-start monitoring when peer connection and stream are available
  useEffect(() => {
    if (!peerConnection) {
      stopMonitoring();
      return;
    }
    startMonitoring();
    return () => {
      stopMonitoring();
    };
  }, [peerConnection, startMonitoring, stopMonitoring]);

  // Reset baseline when remote stream changes (e.g., start/stop/restart share)
  useEffect(() => {
    lastInboundRef.current = null;
    // Keep monitoring running; next tick will repopulate baselines
  }, [remoteStream]);



  if (!isVisible || !stats) {
    return null;
  }

  const formatBitrate = (bitrate: number): string => {
    if (bitrate >= 1000000) {
      return `${(bitrate / 1000000).toFixed(1)} Mbps`;
    } else if (bitrate >= 1000) {
      return `${(bitrate / 1000).toFixed(0)} Kbps`;
    } else {
      return `${bitrate} bps`;
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes >= 1000000) {
      return `${(bytes / 1000000).toFixed(1)} MB`;
    } else if (bytes >= 1000) {
      return `${(bytes / 1000).toFixed(0)} KB`;
    } else {
      return `${bytes} B`;
    }
  };

  const getQualityIndicator = (): { color: string; label: string } => {
    if (stats.frameRate >= 25 && stats.bitrate >= 1000000) {
      return { color: 'text-green-600', label: 'Excellent' };
    } else if (stats.frameRate >= 15 && stats.bitrate >= 500000) {
      return { color: 'text-yellow-600', label: 'Good' };
    } else if (stats.frameRate >= 10 && stats.bitrate >= 200000) {
      return { color: 'text-orange-600', label: 'Fair' };
    } else {
      return { color: 'text-red-600', label: 'Poor' };
    }
  };

  const quality = getQualityIndicator();

  return (
    <Card className="w-full">
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <Eye className="h-4 w-4" />
          <CardTitle className="text-sm">Received Video Quality</CardTitle>
          <div className={`ml-auto text-xs font-medium ${quality.color}`}>
            {quality.label}
          </div>
        </div>
        <CardDescription className="text-xs">
          Real-time stats from the viewer's perspective
        </CardDescription>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-gray-600">Resolution:</span>
              <span className="font-mono font-medium">
                {stats.resolution.width}×{stats.resolution.height}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Frame Rate:</span>
              <span className="font-mono font-medium">
                {stats.frameRate.toFixed(1)} FPS
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Bitrate:</span>
              <span className="font-mono font-medium">
                {formatBitrate(stats.bitrate)}
              </span>
            </div>
          </div>
          
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-gray-600">Packets Lost:</span>
              <span className={`font-mono font-medium ${stats.packetsLost > 0 ? 'text-red-600' : 'text-green-600'}`}>
                {stats.packetsLost}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Data Received:</span>
              <span className="font-mono font-medium">
                {formatBytes(stats.bytesReceived)}
              </span>
            </div>
            {stats.jitter !== undefined && (
              <div className="flex justify-between">
                <span className="text-gray-600">Jitter:</span>
                <span className="font-mono font-medium">
                  {(stats.jitter * 1000).toFixed(1)}ms
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Quality indicator bar */}
        <div className="mt-3 pt-3 border-t">
          <div className="flex items-center gap-2 text-xs">
            <Activity className="h-3 w-3" />
            <span className="text-gray-600">Quality:</span>
            <div className="flex-1 bg-gray-200 rounded-full h-2">
              <div 
                className={`h-2 rounded-full transition-all duration-300 ${
                  quality.label === 'Excellent' ? 'bg-green-500 w-full' :
                  quality.label === 'Good' ? 'bg-yellow-500 w-3/4' :
                  quality.label === 'Fair' ? 'bg-orange-500 w-1/2' :
                  'bg-red-500 w-1/4'
                }`}
              />
            </div>
            <span className={`font-medium ${quality.color}`}>
              {quality.label}
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}