import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';
import { Label } from '../../components/ui/label';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '../../components/ui/dialog';
import { blockingSystem, BlockedUser } from '../../lib/blocking-system';
import { format } from 'date-fns';

interface BlockedUsersSettingsProps {
  passphraseRef?: React.MutableRefObject<string>;
  kyberSecretRef?: React.MutableRefObject<Uint8Array | null>;
  getDisplayUsername?: (username: string) => Promise<string>;
}

const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,32}$/;

const BLOCK_STATUS_EVENT_RATE_WINDOW_MS = 10_000;
const BLOCK_STATUS_EVENT_RATE_MAX = 200;
const MAX_BLOCK_STATUS_EVENT_USERNAME_LENGTH = 256;

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) return false;
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

const validateUsername = (username: string): boolean => USERNAME_REGEX.test(username);

export function BlockedUsersSettings({ passphraseRef, kyberSecretRef, getDisplayUsername }: BlockedUsersSettingsProps) {
  const [blockedUsers, setBlockedUsers] = useState<BlockedUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newBlockUsername, setNewBlockUsername] = useState('');
  const [showBlockDialog, setShowBlockDialog] = useState(false);
  const [displayMap, setDisplayMap] = useState<Record<string, string>>({});

  const blockStatusEventRateRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

  const loadBlockedUsers = useCallback(async () => {
    const passphrase = passphraseRef?.current;
    const kyberSecret = kyberSecretRef?.current || null;

    if (!passphrase && !kyberSecret) {
      setError('Please log in.');
      setBlockedUsers([]);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const key = passphrase ? passphrase : { kyberSecret: kyberSecret! } as any;
      const users = await blockingSystem.getBlockedUsers(key);
      setBlockedUsers(users);
    } catch (_err) {
      console.error('Error loading blocked users:', _err);
      setError('Failed to load blocked users.');
      setBlockedUsers([]);
    } finally {
      setLoading(false);
    }
  }, [passphraseRef, kyberSecretRef]);

  useEffect(() => {
    if (passphraseRef?.current || kyberSecretRef?.current) {
      loadBlockedUsers();
    }
  }, [passphraseRef, kyberSecretRef, loadBlockedUsers]);

  useEffect(() => {
    let canceled = false;
    (async () => {
      if (!Array.isArray(blockedUsers) || blockedUsers.length === 0) {
        setDisplayMap({});
        return;
      }
      try {
        if (!getDisplayUsername) {
          setDisplayMap({});
          return;
        }
        const entries = await Promise.all(
          blockedUsers.map(async (u) => {
            try {
              const dn = await getDisplayUsername(u.username);
              return [u.username, dn] as const;
            } catch {
              return [u.username, u.username] as const;
            }
          })
        );
        if (!canceled) {
          const next: Record<string, string> = {};
          for (const [k, v] of entries) next[k] = v;
          setDisplayMap(next);
        }
      } catch { }
    })();
    return () => { canceled = true; };
  }, [blockedUsers, getDisplayUsername]);

  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && (passphraseRef?.current || kyberSecretRef?.current)) {
        loadBlockedUsers();
      }
    };

    const handleBlockStatusChange = (event: Event) => {
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

        const username = sanitizeEventUsername((detail as any).username);
        if (!username) return;

        if (passphraseRef?.current || kyberSecretRef?.current) {
          loadBlockedUsers();
        }
      } catch { }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('block-status-changed', handleBlockStatusChange as EventListener);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('block-status-changed', handleBlockStatusChange as EventListener);
    };
  }, [passphraseRef, kyberSecretRef, loadBlockedUsers]);

  const handleBlockUser = async () => {
    const username = newBlockUsername.trim();
    if (!username) {
      setError('Please enter a username to block');
      return;
    }

    const passphrase = passphraseRef?.current;
    const kyberSecret = kyberSecretRef?.current || null;
    if (!passphrase && !kyberSecret) {
      setError('Please log in.');
      return;
    }

    if (!validateUsername(username)) {
      setError('Invalid username format');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const key = passphrase ? passphrase : { kyberSecret: kyberSecret! } as any;
      await blockingSystem.blockUser(username, key);
      await loadBlockedUsers();
      setNewBlockUsername('');
      setShowBlockDialog(false);
    } catch (_err) {
      console.error('Error blocking user:', _err);
      setError('Failed to block user. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleUnblockUser = async (username: string) => {
    const passphrase = passphraseRef?.current;
    const kyberSecret = kyberSecretRef?.current || null;
    if (!passphrase && !kyberSecret) {
      setError('Please log in.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const key = passphrase ? passphrase : { kyberSecret: kyberSecret! } as any;
      await blockingSystem.unblockUser(username, key);
      await loadBlockedUsers();
    } catch (_err) {
      console.error('Error unblocking user:', _err);
      setError('Failed to unblock user. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const passphrase = passphraseRef?.current;
  const isValidUsername = newBlockUsername && validateUsername(newBlockUsername);

  // If neither key is present, show a prompt
  if (!passphrase && !kyberSecretRef?.current) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Blocked Users</CardTitle>
          <CardDescription>Manage users you have blocked.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8 text-muted-foreground">
            <p>Please log in to view blocked users.</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Blocked Users</CardTitle>
        <CardDescription>Manage users you have blocked.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <div className="text-sm text-red-600 dark:text-red-400 p-3 rounded-md bg-red-50 dark:bg-red-950">
            {error}
          </div>
        )}

        <Dialog open={showBlockDialog} onOpenChange={setShowBlockDialog}>
          <DialogTrigger asChild>
            <Button variant="outline" size="sm" disabled={loading}>Block user</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Block User</DialogTitle>
              <DialogDescription>Block a username to prevent messages from them.</DialogDescription>
            </DialogHeader>

            <div className="space-y-2">
              <Label htmlFor="block-username" className="text-sm font-medium">Username</Label>
              <Input
                id="block-username"
                value={newBlockUsername}
                onChange={(e) => setNewBlockUsername(e.target.value)}
                placeholder="username"
                autoComplete="off"
              />
              {newBlockUsername && !isValidUsername && (
                <div className="text-xs text-muted-foreground">Username must be 3-32 characters; letters, numbers, underscore or hyphen only.</div>
              )}
            </div>

            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => setShowBlockDialog(false)}
                disabled={loading}
              >
                Cancel
              </Button>
              <Button
                onClick={handleBlockUser}
                disabled={loading || !isValidUsername}
              >
                Block
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label className="text-sm font-medium">Blocked Users ({blockedUsers.length})</Label>
            <Button variant="ghost" size="sm" onClick={loadBlockedUsers} disabled={loading}>
              {loading ? 'Loading…' : 'Refresh'}
            </Button>
          </div>

          {blockedUsers.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <p>No blocked users</p>
              <p className="text-xs mt-1">Users you block will appear here</p>
            </div>
          ) : (
            <div className="space-y-2">
              {blockedUsers.map((user) => {
                const dn = displayMap[user.username] || user.username;
                return (
                  <div key={user.username} className="flex items-center justify-between p-3 rounded-md border bg-card">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium truncate select-auto" title={dn}>{dn}</span>
                        <span className="text-xs text-muted-foreground">Blocked</span>
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">
                        {format(new Date(user.blockedAt), "MMM d, yyyy 'at' h:mm a")}
                      </div>
                    </div>
                    <Dialog>
                      <DialogTrigger asChild>
                        <Button variant="ghost" size="sm" disabled={loading}>Unblock</Button>
                      </DialogTrigger>
                      <DialogContent>
                        <DialogHeader>
                          <DialogTitle>Unblock User</DialogTitle>
                          <DialogDescription>Unblock {dn}?</DialogDescription>
                        </DialogHeader>
                        <DialogFooter>
                          <Button variant="outline">Cancel</Button>
                          <Button onClick={() => handleUnblockUser(user.username)}>Unblock</Button>
                        </DialogFooter>
                      </DialogContent>
                    </Dialog>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
