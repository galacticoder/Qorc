import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';
import { Label } from '../../components/ui/label';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '../../components/ui/dialog';
import { blockingSystem, BlockedUser } from '../../lib/blocking/blocking-system';
import { format } from 'date-fns';
import { isPlainObject, hasPrototypePollutionKeys, sanitizeEventUsername, isValidUsername } from '../../lib/sanitizers';
import { EventType } from '../../lib/types/event-types';
import {
  DEFAULT_EVENT_RATE_WINDOW_MS,
  DEFAULT_EVENT_RATE_MAX,
  MAX_EVENT_USERNAME_LENGTH
} from '../../lib/constants';

interface BlockedUsersSettingsProps {
  passphraseRef?: React.RefObject<string>;
  kyberSecretRef?: React.RefObject<Uint8Array | null>;
  getDisplayUsername?: (username: string) => Promise<string>;
}

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
        if (now - bucket.windowStart > DEFAULT_EVENT_RATE_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        if (bucket.count > DEFAULT_EVENT_RATE_MAX) {
          return;
        }

        if (!(event instanceof CustomEvent)) return;
        const detail = event.detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

        const username = sanitizeEventUsername((detail as any).username, MAX_EVENT_USERNAME_LENGTH);
        if (!username) return;

        if (passphraseRef?.current || kyberSecretRef?.current) {
          loadBlockedUsers();
        }
      } catch { }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener(EventType.BLOCK_STATUS_CHANGED, handleBlockStatusChange as EventListener);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener(EventType.BLOCK_STATUS_CHANGED, handleBlockStatusChange as EventListener);
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

    if (!isValidUsername(username)) {
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
  const isAValidUsername = newBlockUsername && isValidUsername(newBlockUsername);

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
              {newBlockUsername && !isAValidUsername && (
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
                disabled={loading || !isAValidUsername}
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
