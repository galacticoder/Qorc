import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import { BlockIcon, UnblockIcon } from './icons';
import { blockingSystem } from '@/lib/blocking-system';
import { blockStatusCache } from '@/lib/block-status-cache';

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
            setResolvedName(dn);
          }
        } else {
          setResolvedName(username);
        }
      } catch {
        setResolvedName(username);
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

  const handleBlockStatusChangeEvent = useCallback((event: CustomEvent) => {
    const { username: changedUsername, isBlocked: newBlockedState } = event.detail;
    if (changedUsername === username) {
      setIsBlocked(newBlockedState);
    }
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
