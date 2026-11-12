import React from 'react';
import { ConversationHeader } from '../chat/messaging/ConversationHeader';

export const ConversationSkeleton = React.memo(function ConversationSkeleton({
  username = '',
  hasAttachedCall = false,
  onBack,
}: {
  username?: string;
  hasAttachedCall?: boolean;
  onBack?: () => void;
}) {
  return (
    <div className={`qorc-interface qorc-conversation-skeleton${hasAttachedCall ? ' has-attached-call' : ''}`}>
      <ConversationHeader username={username} onBack={onBack} />
      <div className="qorc-skeleton qorc-loading-thread" role="status" aria-label="Loading conversation">
        {[56, 72, 48].map((width, index) => (
          <span key={index} className={`qorc-skeleton-block qorc-loading-bubble${index === 1 ? ' is-mine' : ''}`} style={{ width: `${width}%` }} />
        ))}
      </div>
      <div className="qorc-composer-wrap qorc-skeleton" aria-hidden="true">
        <div className="qorc-skeleton-block qorc-loading-compose" />
      </div>
    </div>
  );
});

export const CallLogRowsSkeleton = React.memo(function CallLogRowsSkeleton() {
  return (
    <div className="qorc-skeleton qorc-call-log-skeleton-rows" role="status" aria-label="Loading call history">
      <span className="qorc-skeleton-block qorc-call-log-skeleton-group" />
      {Array.from({ length: 5 }, (_, index) => (
        <div className="qorc-call-log-skeleton-row" key={index}>
          <span className="qorc-skeleton-block qorc-call-log-skeleton-avatar" />
          <span className="qorc-call-log-skeleton-copy">
            <span className="qorc-skeleton-block qorc-call-log-skeleton-name" />
            <span className="qorc-skeleton-block qorc-call-log-skeleton-detail" />
          </span>
          <span className="qorc-skeleton-block qorc-call-log-skeleton-time" />
        </div>
      ))}
    </div>
  );
});

export const CallLogsSkeleton = React.memo(function CallLogsSkeleton() {
  return (
    <section className="qorc-call-log-page qorc-skeleton qorc-skeleton-page" role="status" aria-label="Loading call logs">
      <header className="qorc-call-log-header">
        <span className="qorc-call-log-skeleton-heading">
          <span className="qorc-skeleton-block qorc-call-log-skeleton-title-icon" />
          <span className="qorc-skeleton-block qorc-call-log-skeleton-title" />
        </span>
        <div className="qorc-call-log-header-actions">
          <span className="qorc-skeleton-block qorc-call-log-skeleton-search" />
          <span className="qorc-skeleton-block qorc-call-log-skeleton-options" />
        </div>
      </header>
      <div className="qorc-call-log-content">
        <CallLogRowsSkeleton />
      </div>
    </section>
  );
});

export const SettingsSkeleton = React.memo(function SettingsSkeleton() {
  return (
    <section className="qorc-skeleton qorc-settings-page-skeleton" role="status" aria-label="Loading settings">
      <span className="qorc-skeleton-block qorc-settings-skeleton-title" />
      {[0, 1, 2].map(index => <span key={index} className="qorc-skeleton-block qorc-settings-loading-row" />)}
    </section>
  );
});
