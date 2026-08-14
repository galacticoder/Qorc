import { useState, useEffect, useCallback, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import { BlockIcon, UnblockIcon } from '../assets/icons';
import { blockingSystem } from '@/lib/blocking/blocking-system';
import { blockStatusCache } from '@/lib/blocking/block-status-cache';
import { truncateUsername } from '@/lib/utils/avatar-utils';
import { useBlockStatus } from '@/hooks/useBlockStatus';

interface BlockUserButtonProps {
  readonly username: string;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
  readonly variant?: 'default' | 'outline' | 'ghost' | 'destructive' | 'secondary' | 'link';
  readonly size?: 'default' | 'sm' | 'lg' | 'icon';
  readonly className?: string;
  readonly showText?: boolean;
  readonly onBlockStatusChange?: (username: string, isBlocked: boolean) => void;
  readonly initialBlocked?: boolean;
}

export function BlockUserButton({
  username,
  getDisplayUsername,
  variant = 'outline',
  size = 'sm',
  className = '',
  showText = true,
  onBlockStatusChange,
  initialBlocked,
}: BlockUserButtonProps) {
  const isBlocked = useBlockStatus(username, { initialBlocked, refreshOnVisible: true });
  const [loading, setLoading] = useState(false);
  const [resolvedName, setResolvedName] = useState<string>(username);
  const mountedRef = useRef(true);
  const usernameRef = useRef(username);
  const mutationRef = useRef<object | null>(null);
  usernameRef.current = username;

  useEffect(() => {
    mountedRef.current = true;
    mutationRef.current = null;
    setLoading(false);
    return () => {
      mountedRef.current = false;
      mutationRef.current = null;
    };
  }, [username]);

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
        if (!canceled) setResolvedName(truncateUsername(username));
      }
    })();
    return () => { canceled = true; };
  }, [username, getDisplayUsername]);

  const handleBlockUser = useCallback(async () => {
    if (!username || mutationRef.current) return;

    const target = username;
    const operation = {};
    mutationRef.current = operation;
    const isCurrent = () => (
      mountedRef.current &&
      usernameRef.current === target &&
      mutationRef.current === operation
    );
    setLoading(true);

    try {
      await blockingSystem.blockUser(target);
      if (!isCurrent()) return;
      blockStatusCache.set(target, true);
      onBlockStatusChange?.(target, true);
      toast.success(`Blocked ${resolvedName}`);
    } catch {
      if (!isCurrent()) return;
      toast.error('Failed to block user. Please try again.');
    } finally {
      if (mutationRef.current === operation) mutationRef.current = null;
      if (mountedRef.current && usernameRef.current === target) setLoading(false);
    }
  }, [username, onBlockStatusChange, resolvedName]);

  const handleUnblockUser = useCallback(async () => {
    if (!username || mutationRef.current) return;

    const target = username;
    const operation = {};
    mutationRef.current = operation;
    const isCurrent = () => (
      mountedRef.current &&
      usernameRef.current === target &&
      mutationRef.current === operation
    );
    setLoading(true);

    try {
      await blockingSystem.unblockUser(target);
      if (!isCurrent()) return;
      blockStatusCache.set(target, false);
      onBlockStatusChange?.(target, false);
      toast.success(`Unblocked ${resolvedName}`);
    } catch {
      if (!isCurrent()) return;
      toast.error('Failed to unblock user. Please try again.');
    } finally {
      if (mutationRef.current === operation) mutationRef.current = null;
      if (mountedRef.current && usernameRef.current === target) setLoading(false);
    }
  }, [username, onBlockStatusChange, resolvedName]);

  const buttonClassName = `${className} flex items-center gap-1`;

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
