import React from 'react';
import { ScrollArea } from './scroll-area';

const MESSAGE_ROWS = [
  { side: 'incoming', width: 248, height: 42, grouped: false, kind: 'text' },
  { side: 'incoming', width: 174, height: 42, grouped: true, kind: 'text' },
  { side: 'outgoing', width: 286, height: 42, grouped: false, kind: 'reply' },
  { side: 'incoming', width: 320, height: 64, grouped: false, kind: 'file' },
  { side: 'outgoing', width: 208, height: 42, grouped: false, kind: 'text' },
  { side: 'incoming', width: 338, height: 64, grouped: false, kind: 'text' },
] as const;

export const ConversationSkeleton = React.memo(function ConversationSkeleton({
  hasAttachedCall = false,
}: {
  hasAttachedCall?: boolean;
}) {
  return (
    <div
      className={`qorc-interface qorc-skeleton qorc-conversation-skeleton${hasAttachedCall ? ' has-attached-call' : ''}`}
      role="status"
      aria-label="Loading conversation"
    >
      <div className="qorc-toolbar">
        <div className="min-w-0 flex-1 pr-3" />
        <div className="qorc-call-pill qorc-conversation-skeleton-actions" aria-hidden="true">
          {Array.from({ length: 3 }, (_, index) => (
            <span className="qorc-call-pill-btn qorc-conversation-skeleton-action" key={index}>
              <span className="qorc-skeleton-block" />
            </span>
          ))}
        </div>
      </div>

      <ScrollArea className="qorc-message-scroll qorc-conversation-skeleton-scroll">
        <div className="qorc-message-stack qorc-conversation-skeleton-stack">
          <div className="qorc-conversation-skeleton-system">
            <span className="qorc-skeleton-block" />
          </div>

          {MESSAGE_ROWS.map((row, index) => {
            const mine = row.side === 'outgoing';
            return (
              <div
                className={`qorc-conversation-skeleton-message flex gap-3 mb-4 ${mine ? 'flex-row-reverse' : 'flex-row'}`}
                key={`${row.side}-${index}`}
              >
                <div className="flex-shrink-0 w-10">
                  {!row.grouped && <span className="qorc-skeleton-block qorc-conversation-skeleton-avatar" />}
                </div>
                <div
                  className={`flex flex-col min-w-0 ${mine ? 'items-end' : 'items-start'}`}
                  style={{ maxWidth: 'var(--message-bubble-max-width)' }}
                >
                  {!row.grouped && (
                    <div className={`qorc-conversation-skeleton-meta flex items-center gap-2 mb-1 ${mine ? 'flex-row-reverse' : 'flex-row'}`}>
                      <span className="qorc-skeleton-block qorc-conversation-skeleton-name" />
                      <span className="qorc-skeleton-block qorc-conversation-skeleton-time" />
                    </div>
                  )}

                  {row.kind === 'reply' && (
                    <div className="qorc-message-reply-preview qorc-conversation-skeleton-reply mb-1">
                      <span className="qorc-skeleton-block qorc-conversation-skeleton-reply-avatar" />
                      <span className="qorc-conversation-skeleton-reply-copy">
                        <span className="qorc-skeleton-block" />
                        <span className="qorc-skeleton-block" />
                      </span>
                    </div>
                  )}

                  {row.kind === 'file' ? (
                    <div className="qorc-file-card qorc-conversation-skeleton-file">
                      <span className="qorc-skeleton-block qorc-conversation-skeleton-file-icon" />
                      <span className="qorc-conversation-skeleton-file-copy">
                        <span className="qorc-skeleton-block" />
                        <span className="qorc-skeleton-block" />
                      </span>
                      <span className="qorc-skeleton-block qorc-conversation-skeleton-file-action" />
                    </div>
                  ) : (
                    <span
                      className={`qorc-skeleton-block qorc-conversation-skeleton-bubble ${mine ? 'is-mine' : 'is-received'}`}
                      style={{ width: row.width, height: row.height }}
                    />
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </ScrollArea>

      <div className="qorc-composer-wrap qorc-conversation-skeleton-composer">
        <div className="qorc-input-shell">
          <div className="qorc-message-box">
            <span className="qorc-conversation-skeleton-composer-button"><span className="qorc-skeleton-block" /></span>
            <span className="qorc-conversation-skeleton-composer-button"><span className="qorc-skeleton-block" /></span>
            <span className="qorc-skeleton-block qorc-conversation-skeleton-input" />
            <span className="qorc-conversation-skeleton-composer-button"><span className="qorc-skeleton-block" /></span>
          </div>
        </div>
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
          <span className="qorc-skeleton-block qorc-call-log-skeleton-actions" />
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

const SETTINGS_SECTIONS = [3, 3, 3, 2] as const;

export const SettingsSkeleton = React.memo(function SettingsSkeleton() {
  return (
    <section className="qorc-skeleton qorc-settings-page-skeleton" role="status" aria-label="Loading settings">
      <span className="qorc-settings-skeleton-title-row">
        <span className="qorc-skeleton-block qorc-settings-skeleton-title-icon" />
        <span className="qorc-skeleton-block qorc-settings-skeleton-title" />
      </span>
      {SETTINGS_SECTIONS.map((rowCount, sectionIndex) => (
        <section className="qorc-settings-skeleton-section" key={sectionIndex}>
          <span className="qorc-settings-skeleton-heading-row">
            <span className="qorc-skeleton-block qorc-settings-skeleton-heading-icon" />
            <span className="qorc-skeleton-block qorc-settings-skeleton-heading" />
          </span>
          {Array.from({ length: rowCount }, (_, rowIndex) => (
            <div className="qorc-settings-skeleton-row" key={rowIndex}>
              <span className="qorc-settings-skeleton-copy">
                <span className="qorc-skeleton-block qorc-settings-skeleton-label" />
                <span className="qorc-skeleton-block qorc-settings-skeleton-description" />
              </span>
              <span className="qorc-skeleton-block qorc-settings-skeleton-control" />
            </div>
          ))}
        </section>
      ))}
    </section>
  );
});
