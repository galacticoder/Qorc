import { useState } from 'react';
import { createPortal } from 'react-dom';

interface ConnectionIssueSheetProps {
  readonly error: string;
  readonly onRetry: () => Promise<void> | void;
  readonly onChangeServer: () => void;
}

export function ConnectionIssueSheet({ error, onRetry, onChangeServer }: ConnectionIssueSheetProps) {
  const [isRetrying, setIsRetrying] = useState(false);

  const handleRetry = async () => {
    if (isRetrying) return;
    setIsRetrying(true);
    try {
      await onRetry();
    } finally {
      setIsRetrying(false);
    }
  };

  return createPortal(
    <div className="conn-sheet" role="status" aria-live="polite">
      <div className="conn-sheet-text">
        <span className="conn-sheet-title">Can&rsquo;t reach the server</span>
        <span className="conn-sheet-detail">{error || 'Qor could not connect through Tor.'}</span>
      </div>
      <div className="conn-sheet-actions">
        <button
          type="button"
          className="conn-sheet-btn is-primary"
          onClick={handleRetry}
          disabled={isRetrying}
        >
          {isRetrying ? 'Retrying' : 'Retry'}
        </button>
        <button
          type="button"
          className="conn-sheet-btn"
          onClick={onChangeServer}
          disabled={isRetrying}
        >
          Change server
        </button>
      </div>
    </div>,
    document.body
  );
}
