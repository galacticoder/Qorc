import { useState } from 'react';
import { createPortal } from 'react-dom';

interface ConnectionIssueSheetProps {
  readonly error: string;
  readonly target: 'tor' | 'server';
  readonly onRetry: () => Promise<void> | void;
  readonly onChangeServer: () => void;
}

export function ConnectionIssueSheet({ error, target, onRetry, onChangeServer }: ConnectionIssueSheetProps) {
  const [isRetrying, setIsRetrying] = useState(false);
  const isTorFailure = target === 'tor';

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
        <span className="conn-sheet-title">
          {isTorFailure ? 'Can\'t connect to Tor' : 'Can\'t reach the server'}
        </span>
        <span className="conn-sheet-detail">
          {error || (isTorFailure ? 'Tor could not start.' : 'qorc could not reach the server.')}
        </span>
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
          {isTorFailure ? 'Tor settings' : 'Change server'}
        </button>
      </div>
    </div>,
    document.body
  );
}
