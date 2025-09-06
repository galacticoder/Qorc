/**
 * Call History Component
 * Shows recent calls with status indicators
 */

import React, { useMemo } from 'react';
import { Phone, PhoneIncoming, PhoneOutgoing, PhoneMissed, Video } from 'lucide-react';
import { CallState } from '../../lib/webrtc-calling';
import { isHashedUsername } from '@/lib/unified-username-display';
import { useUnifiedUsernameDisplay } from '@/hooks/useUnifiedUsernameDisplay';

interface CallHistoryProps {
  calls: CallState[];
  onCallUser?: (username: string, type: 'audio' | 'video') => void;
  getDisplayUsername?: (username: string) => Promise<string>;
}

export const CallHistory: React.FC<CallHistoryProps> = ({ calls, onCallUser, getDisplayUsername }) => {
  const formatDuration = (duration?: number): string => {
    if (!duration) return '';
    const mins = Math.floor(duration / 60000);
    const secs = Math.floor((duration % 60000) / 1000);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const formatTime = (timestamp?: number): string => {
    if (!timestamp) return '';
    const date = new Date(timestamp);
    const now = new Date();
    const isToday = date.toDateString() === now.toDateString();
    
    if (isToday) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else {
      return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    }
  };

  const getCallIcon = (call: CallState) => {
    const iconClass = "w-4 h-4";
    
    if (call.status === 'missed') {
      return <PhoneMissed className={`${iconClass} text-red-500`} />;
    }
    
    if (call.direction === 'incoming') {
      return <PhoneIncoming className={`${iconClass} text-green-500`} />;
    } else {
      return <PhoneOutgoing className={`${iconClass} text-blue-500`} />;
    }
  };

  const getStatusText = (call: CallState): string => {
    switch (call.status) {
      case 'connected':
        return call.duration ? formatDuration(call.duration) : 'Connected';
      case 'missed':
        return 'Missed';
      case 'declined':
        return 'Declined';
      case 'ended':
        return call.duration ? formatDuration(call.duration) : 'Ended';
      default:
        return call.status;
    }
  };

  if (calls.length === 0) {
    return (
      <div className="p-4 text-center text-gray-500">
        <Phone className="w-8 h-8 mx-auto mb-2 opacity-50" />
        <p className="text-sm">No recent calls</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-medium text-gray-700 px-4 py-2 border-b">Recent Calls</h3>
      {calls.map((call) => {
        const { displayName } = useUnifiedUsernameDisplay({
          username: call.peer,
          getDisplayUsername,
          fallbackToOriginal: true
        });
        return (
        <div
          key={call.id}
          className="flex items-center justify-between p-3 hover:bg-gray-50 cursor-pointer group"
          onClick={() => onCallUser?.(call.peer, call.type)}
        >
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2">
              {getCallIcon(call)}
              {call.type === 'video' && (
                <Video className="w-3 h-3 text-gray-400" />
              )}
            </div>
            <div>
              <p className="font-medium text-sm">{displayName}</p>
              <p className="text-xs text-gray-500">
                {getStatusText(call)} • {formatTime(call.startTime)}
              </p>
            </div>
          </div>
          
          <div className="flex items-center space-x-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <button
              onClick={(e) => {
                e.stopPropagation();
                onCallUser?.(call.peer, 'audio');
              }}
              className="p-1 rounded-full hover:bg-gray-200"
              title="Audio call"
            >
              <Phone className="w-4 h-4 text-gray-600" />
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onCallUser?.(call.peer, 'video');
              }}
              className="p-1 rounded-full hover:bg-gray-200"
              title="Video call"
            >
              <Video className="w-4 h-4 text-gray-600" />
            </button>
          </div>
        </div>
        );
      })}
    </div>
  );
};

export default CallHistory;