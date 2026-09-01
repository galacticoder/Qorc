import { LoaderCircle, ShieldAlert } from 'lucide-react';

import { usePendingIdentityChanges } from '../../lib/security/identity-change-store';

export function PeerIdentityVerificationAlert() {
  const pending = usePendingIdentityChanges();
  if (pending.length === 0) return null;

  return (
    <div
      className="fixed bottom-4 left-1/2 z-50 flex w-[90%] max-w-md -translate-x-1/2 flex-col gap-2"
      role="alert"
      aria-live="assertive"
      aria-label="Automatic peer identity verification pending"
    >
      {pending.map(({ peer, heldCount }) => (
        <div
          key={peer}
          className="rounded-lg border border-amber-500/40 bg-amber-950/95 p-3 text-amber-50 shadow-lg backdrop-blur"
        >
          <div className="flex items-start gap-2">
            <ShieldAlert aria-hidden className="mt-0.5 size-5 shrink-0 text-amber-400" />
            <div className="min-w-0 text-sm">
              <div className="font-semibold">Verifying {peer}'s new security keys</div>
              <p className="mt-0.5 opacity-90">
                Messaging and calls are paused while Qorc checks the exact Signal identity
                against the anonymous key-transparency log. Unverified keys cannot be accepted manually.
              </p>
              {heldCount > 0 && (
                <p className="mt-2 flex items-center gap-1.5 text-xs opacity-80">
                  <LoaderCircle aria-hidden className="size-3.5 animate-spin" />
                  {heldCount} encrypted message{heldCount === 1 ? '' : 's'} queued
                </p>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
