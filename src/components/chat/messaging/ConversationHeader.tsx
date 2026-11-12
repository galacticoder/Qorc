import type { ReactNode } from 'react';
import { UserAvatar } from '../../ui/UserAvatar';
import { useDisplayUsername } from '../../../hooks/database/useDisplayUsername';
import { ConversationBackButton } from './ConversationBackButton';

interface ConversationHeaderProps {
  username: string;
  onBack?: () => void;
  children?: ReactNode;
}

export function ConversationHeader({ username, onBack, children }: ConversationHeaderProps) {
  const displayName = useDisplayUsername({ username });
  return (
    <div className={`qorc-toolbar${onBack ? ' has-mobile-back' : ''}`}>
      {onBack && <ConversationBackButton onBack={onBack} />}
      <div className="qorc-chat-peer" role="group" aria-label={`Chat with ${displayName}`}>
        <UserAvatar username={username} size="md" className="qorc-chat-peer-avatar" />
        <span className="qorc-chat-peer-name" title={displayName}>{displayName}</span>
      </div>
      {children}
    </div>
  );
}
