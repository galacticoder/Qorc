import React, { useMemo, useCallback, useState } from 'react';
import { Phone, PhoneIncoming, PhoneOutgoing, PhoneMissed, Video } from 'lucide-react';
import { CallState } from '../../lib/webrtc-calling';
import { useUnifiedUsernameDisplay } from '@/hooks/useUnifiedUsernameDisplay';

interface CallHistoryProps {
  readonly calls: readonly CallState[];
  readonly onCallUser?: (username: string, type: 'audio' | 'video') => void;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
}

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
  }
  return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
};

const getCallIcon = (call: CallState): JSX.Element => {
  const iconClass = "w-4 h-4";

  if (call.status === 'missed') {
    return <PhoneMissed className={`${iconClass} text-red-500`} />;
  }

  if (call.direction === 'incoming') {
    return <PhoneIncoming className={`${iconClass} text-green-500`} />;
  }
  return <PhoneOutgoing className={`${iconClass} text-gray-500`} />;
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

export const CallHistory: React.FC<CallHistoryProps> = ({ calls, onCallUser, getDisplayUsername }) => {
  const [callingUser, setCallingUser] = useState<string | null>(null);

  const callsWithKeys = useMemo(() => {
    return calls.map(call => ({
      ...call,
      _key: `${call.id}_${call.peer}_${call.startTime || 0}`
    }));
  }, [calls]);

  const handleSetCallingUser = useCallback((user: string | null) => {
    setCallingUser(user);
  }, []);

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
      {callsWithKeys.map((call) => (
        <CallHistoryItem
          key={call._key}
          call={call}
          onCallUser={onCallUser}
          getDisplayUsername={getDisplayUsername}
          callingUser={callingUser}
          setCallingUser={handleSetCallingUser}
        />
      ))}
    </div>
  );
};

interface CallHistoryItemProps {
  readonly call: CallState;
  readonly onCallUser?: (username: string, type: 'audio' | 'video') => void;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
  readonly callingUser: string | null;
  readonly setCallingUser: (user: string | null) => void;
}

const CallHistoryItem: React.FC<CallHistoryItemProps> = React.memo(({
  call,
  onCallUser,
  getDisplayUsername,
  callingUser,
  setCallingUser
}) => {
  const { displayName } = useUnifiedUsernameDisplay({
    username: call.peer,
    getDisplayUsername,
    fallbackToOriginal: true
  });

  const handleMainClick = useCallback(() => {
    if (!callingUser && onCallUser) {
      setCallingUser(call.peer);
      onCallUser(call.peer, call.type);
      setTimeout(() => setCallingUser(null), 3000);
    }
  }, [callingUser, onCallUser, setCallingUser, call.peer, call.type]);

  const handleAudioCall = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    if (!callingUser && onCallUser) {
      setCallingUser(call.peer);
      onCallUser(call.peer, 'audio');
      setTimeout(() => setCallingUser(null), 3000);
    }
  }, [callingUser, onCallUser, setCallingUser, call.peer]);

  const handleVideoCall = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    if (!callingUser && onCallUser) {
      setCallingUser(call.peer);
      onCallUser(call.peer, 'video');
      setTimeout(() => setCallingUser(null), 3000);
    }
  }, [callingUser, onCallUser, setCallingUser, call.peer]);

  return (
    <div
      className="flex items-center justify-between p-3 hover:bg-gray-50 cursor-pointer group"
      onClick={handleMainClick}
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
          onClick={handleAudioCall}
          disabled={!!callingUser}
          className="p-1 rounded-full hover:bg-gray-200 disabled:opacity-50 disabled:cursor-not-allowed"
          title="Audio call"
          type="button"
        >
          <Phone className="w-4 h-4 text-gray-600" />
        </button>
        <button
          onClick={handleVideoCall}
          disabled={!!callingUser}
          className="p-1 rounded-full hover:bg-gray-200 disabled:opacity-50 disabled:cursor-not-allowed"
          title="Video call"
          type="button"
        >
          <Video className="w-4 h-4 text-gray-600" />
        </button>
      </div>
    </div>
  );
});

CallHistoryItem.displayName = 'CallHistoryItem';

export default CallHistory;
