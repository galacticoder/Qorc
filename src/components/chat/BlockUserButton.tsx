import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import { BlockIcon, UnblockIcon } from './icons';
import { blockingSystem } from '@/lib/blocking-system';
import { blockStatusCache } from '@/lib/block-status-cache';
import { truncateUsername } from '@/lib/utils';

const BLOCK_STATUS_EVENT_RATE_WINDOW_MS = 10_000;
const BLOCK_STATUS_EVENT_RATE_MAX = 200;
const MAX_BLOCK_STATUS_EVENT_USERNAME_LENGTH = 256;

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

const hasPrototypePollutionKeys = (obj: unknown): boolean => {
  if (obj == null || typeof obj !== 'object') return false;
  const keys = Object.keys(obj as Record<string, unknown>);
  return keys.some((key) => key === '__proto__' || key === 'constructor' || key === 'prototype');
};

const sanitizeEventUsername = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_BLOCK_STATUS_EVENT_USERNAME_LENGTH) return null;
  const cleaned = trimmed.replace(/[\x00-\x1F\x7F]/g, '');
  if (!cleaned) return null;
  return cleaned.slice(0, MAX_BLOCK_STATUS_EVENT_USERNAME_LENGTH);
};

interface BlockUserButtonProps {
  readonly username: string;
  readonly passphraseRef?: React.MutableRefObject<string>;
  readonly kyberSecretRef?: React.MutableRefObject<Uint8Array | null>;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
  readonly onPassphraseRequired?: () => void;
  readonly variant?: 'default' | 'outline' | 'ghost' | 'destructive' | 'secondary' | 'link';
  readonly size?: 'default' | 'sm' | 'lg' | 'icon';
  readonly className?: string;
  readonly showText?: boolean;
  readonly onBlockStatusChange?: (username: string, isBlocked: boolean) => void;
  readonly initialBlocked?: boolean;
}

export function BlockUserButton({
  username,
  passphraseRef,
  kyberSecretRef,
  getDisplayUsername,
  variant = 'outline',
  size = 'sm',
  className = '',
  showText = true,
  onBlockStatusChange,
  initialBlocked,
}: BlockUserButtonProps) {
  const [isBlocked, setIsBlocked] = useState(false);
  const [loading, setLoading] = useState(false);

  const blockStatusEventRateRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

  const [resolvedName, setResolvedName] = useState<string>(username);

  const checkBlockStatus = useCallback(async () => {
    if (!username) return;

    const passphrase = passphraseRef?.current;
    const kyber = kyberSecretRef?.current || null;
    await new Promise((r) => setTimeout(r, 0));
    try {
      const keyArg: any = passphrase ? passphrase : (kyber ? { kyberSecret: kyber } : '');
      const blocked = await blockingSystem.isUserBlocked(username, keyArg);
      setIsBlocked(blocked);
      blockStatusCache.set(username, blocked);
    } catch {
      const cached = blockStatusCache.get(username);
      if (cached !== null) {
        setIsBlocked(cached);
      }
    }
  }, [username, passphraseRef, kyberSecretRef]);

  useEffect(() => {
    if (typeof initialBlocked === 'boolean') {
      setIsBlocked(initialBlocked);
    }
    checkBlockStatus();
  }, [username, initialBlocked, checkBlockStatus]);

  useEffect(() => {
    let canceled = false;
    (async () => {
      try {
        if (typeof getDisplayUsername === 'function' && typeof username === 'string' && username) {
          const dn = await getDisplayUsername(username);
          if (!canceled && typeof dn === 'string' && dn) {
            setResolvedName(truncateUsername(dn));
          }
        } else {
          setResolvedName(truncateUsername(username));
        }
      } catch {
        setResolvedName(truncateUsername(username));
      }
    })();
    return () => { canceled = true; };
  }, [username, getDisplayUsername]);

  const handleVisibilityChange = useCallback(() => {
    if (document.visibilityState === 'visible') {
      checkBlockStatus();
    }
  }, [checkBlockStatus]);

  useEffect(() => {
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [handleVisibilityChange]);

  const handleBlockStatusChangeEvent = useCallback((event: Event) => {
    try {
      const now = Date.now();
      const bucket = blockStatusEventRateRef.current;
      if (now - bucket.windowStart > BLOCK_STATUS_EVENT_RATE_WINDOW_MS) {
        bucket.windowStart = now;
        bucket.count = 0;
      }
      bucket.count += 1;
      if (bucket.count > BLOCK_STATUS_EVENT_RATE_MAX) {
        return;
      }

      if (!(event instanceof CustomEvent)) return;
      const detail = event.detail;
      if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

      const changedUsername = sanitizeEventUsername((detail as any).username);
      if (!changedUsername) return;
      const newBlockedState = (detail as any).isBlocked === true;

      if (changedUsername === username) {
        setIsBlocked(newBlockedState);
      }
    } catch { }
  }, [username]);

  useEffect(() => {
    window.addEventListener('block-status-changed', handleBlockStatusChangeEvent as EventListener);
    return () => window.removeEventListener('block-status-changed', handleBlockStatusChangeEvent as EventListener);
  }, [handleBlockStatusChangeEvent]);


  const handleBlockUser = useCallback(async () => {
    if (!username) return;

    const passphrase = passphraseRef?.current;
    const kyber = kyberSecretRef?.current || null;
    if (!passphrase && !kyber) {
      toast.error('Please log in.');
      return;
    }

    setLoading(true);

    try {
      const keyArg: any = passphrase ? passphrase : { kyberSecret: kyber! };
      await blockingSystem.blockUser(username, keyArg);
      setIsBlocked(true);
      blockStatusCache.set(username, true);
      onBlockStatusChange?.(username, true);
      toast.success(`Blocked ${resolvedName}`);
    } catch {
      toast.error('Failed to block user. Please try again.');
    } finally {
      setLoading(false);
    }
  }, [username, passphraseRef, kyberSecretRef, onBlockStatusChange, resolvedName]);

  const handleUnblockUser = useCallback(async () => {
    if (!username) return;

    const passphrase = passphraseRef?.current;
    const kyber = kyberSecretRef?.current || null;
    if (!passphrase && !kyber) {
      toast.error('Please log in.');
      return;
    }

    setLoading(true);

    try {
      const keyArg: any = passphrase ? passphrase : { kyberSecret: kyber! };
      await blockingSystem.unblockUser(username, keyArg);
      setIsBlocked(false);
      blockStatusCache.set(username, false);
      onBlockStatusChange?.(username, false);
      toast.success(`Unblocked ${resolvedName}`);
    } catch {
      toast.error('Failed to unblock user. Please try again.');
    } finally {
      setLoading(false);
    }
  }, [username, passphraseRef, kyberSecretRef, onBlockStatusChange, resolvedName]);

  const buttonClassName = useMemo(() => {
    if (isBlocked) {
      return `${className} flex items-center gap-1`;
    }
    return `${className} flex items-center gap-1`;
  }, [isBlocked, className]);

  if (isBlocked) {
    return (
      <Button
        variant={variant}
        size={size}
        className={buttonClassName}
        disabled={loading}
        onClick={handleUnblockUser}
      >
        <UnblockIcon className="h-4 w-4" />
        {showText && <span>{loading ? 'Unblocking...' : 'Unblock'}</span>}
      </Button>
    );
  }

  return (
    <Button
      variant={variant}
      size={size}
      className={buttonClassName}
      disabled={loading}
      onClick={handleBlockUser}
    >
      <BlockIcon className="h-4 w-4" />
      {showText && <span>{loading ? 'Blocking...' : 'Block'}</span>}
    </Button>
  );
}
