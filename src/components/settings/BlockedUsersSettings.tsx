import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { UserX, UserPlus, Shield, Trash2, AlertCircle, Eye, EyeOff } from 'lucide-react';
import { blockingSystem, BlockedUser } from '@/lib/blocking-system';
import { format } from 'date-fns';

interface BlockedUsersSettingsProps {
  passphrase?: string;
  onPassphraseRequired?: () => void;
}

export function BlockedUsersSettings({ passphrase, onPassphraseRequired }: BlockedUsersSettingsProps) {
  const [blockedUsers, setBlockedUsers] = useState<BlockedUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newBlockUsername, setNewBlockUsername] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [showBlockDialog, setShowBlockDialog] = useState(false);
  const [showPassphraseInput, setShowPassphraseInput] = useState(!passphrase);
  const [tempPassphrase, setTempPassphrase] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);

  // Load blocked users on component mount
  useEffect(() => {
    if (passphrase) {
      loadBlockedUsers();
    }
  }, [passphrase]);

  const loadBlockedUsers = async () => {
    if (!passphrase && !tempPassphrase) {
      setError('Passphrase required to load blocked users');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const users = await blockingSystem.getBlockedUsers(passphrase || tempPassphrase);
      setBlockedUsers(users);
      // If we successfully loaded with tempPassphrase, it's valid
      if (tempPassphrase && !passphrase) {
        setShowPassphraseInput(false);
      }
    } catch (err) {
      console.error('Error loading blocked users:', err);
      setError('Invalid passphrase. Please try again.');
      // Reset blocked users on error
      setBlockedUsers([]);
      // If using tempPassphrase, show input again
      if (tempPassphrase && !passphrase) {
        setShowPassphraseInput(true);
        setTempPassphrase('');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleBlockUser = async () => {
    if (!newBlockUsername.trim()) {
      setError('Please enter a username to block');
      return;
    }

    if (!passphrase && !tempPassphrase) {
      setError('Passphrase required to block users');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await blockingSystem.blockUser(
        newBlockUsername.trim(),
        passphrase || tempPassphrase,
        blockReason.trim() || undefined
      );
      
      // Reload the list
      await loadBlockedUsers();
      
      // Reset form
      setNewBlockUsername('');
      setBlockReason('');
      setShowBlockDialog(false);
    } catch (err) {
      console.error('Error blocking user:', err);
      setError('Failed to block user. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleUnblockUser = async (username: string) => {
    if (!passphrase && !tempPassphrase) {
      setError('Passphrase required to unblock users');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await blockingSystem.unblockUser(username, passphrase || tempPassphrase);
      await loadBlockedUsers();
    } catch (err) {
      console.error('Error unblocking user:', err);
      setError('Failed to unblock user. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handlePassphraseSubmit = async () => {
    if (!tempPassphrase.trim()) {
      setError('Please enter your passphrase');
      return;
    }

    setShowPassphraseInput(false);
    await loadBlockedUsers();
  };

  const validateUsername = (username: string): boolean => {
    // Basic validation - adjust based on your username requirements
    const usernameRegex = /^[a-zA-Z0-9_-]{3,32}$/;
    return usernameRegex.test(username);
  };

  if (showPassphraseInput) {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            <CardTitle>Blocked Users</CardTitle>
          </div>
          <CardDescription>
            Enter your passphrase to view and manage blocked users
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <div className="flex items-center gap-2 text-sm text-red-600 dark:text-red-400">
              <AlertCircle className="h-4 w-4" />
              {error}
            </div>
          )}
          
          <div className="space-y-2">
            <Label htmlFor="passphrase">Passphrase</Label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Input
                  id="passphrase"
                  type={showPassphrase ? 'text' : 'password'}
                  placeholder="Enter your passphrase"
                  value={tempPassphrase}
                  onChange={(e) => setTempPassphrase(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handlePassphraseSubmit()}
                />
                <Button
                  variant="ghost"
                  size="sm"
                  className="absolute right-0 top-0 h-full px-3"
                  onClick={() => setShowPassphrase(!showPassphrase)}
                >
                  {showPassphrase ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
              <Button
                onClick={handlePassphraseSubmit}
                disabled={loading || !tempPassphrase.trim()}
              >
                {loading ? 'Loading...' : 'Access'}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          <CardTitle>Blocked Users</CardTitle>
        </div>
        <CardDescription>
          Manage users you have blocked. Blocked users cannot send you messages or calls.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <div className="flex items-center gap-2 text-sm text-red-600 dark:text-red-400 p-3 rounded-md bg-red-50 dark:bg-red-950">
            <AlertCircle className="h-4 w-4" />
            {error}
          </div>
        )}

        {/* Block new user */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label className="text-sm font-medium">Block New User</Label>
            <Dialog open={showBlockDialog} onOpenChange={setShowBlockDialog}>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm" className="flex items-center gap-2">
                  <UserX className="h-4 w-4" />
                  Block User
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Block User</DialogTitle>
                  <DialogDescription>
                    Enter the username of the user you want to block. They will not be able to send you messages or calls.
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="block-username">Username</Label>
                    <Input
                      id="block-username"
                      placeholder="Enter username to block"
                      value={newBlockUsername}
                      onChange={(e) => {
                        setNewBlockUsername(e.target.value);
                        setError(null);
                      }}
                    />
                    {newBlockUsername && !validateUsername(newBlockUsername) && (
                      <p className="text-xs text-red-600 dark:text-red-400">
                        Username must be 3-32 characters and contain only letters, numbers, underscores, or hyphens
                      </p>
                    )}
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="block-reason">Reason (optional)</Label>
                    <Input
                      id="block-reason"
                      placeholder="Reason for blocking (optional)"
                      value={blockReason}
                      onChange={(e) => setBlockReason(e.target.value)}
                      maxLength={100}
                    />
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setShowBlockDialog(false)}>Cancel</Button>
                  <Button
                    onClick={handleBlockUser}
                    disabled={loading || !newBlockUsername.trim() || !validateUsername(newBlockUsername)}
                    className="bg-red-600 hover:bg-red-700 text-white"
                  >
                    {loading ? 'Blocking...' : 'Block User'}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        <Separator />

        {/* Blocked users list */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label className="text-sm font-medium">
              Blocked Users ({blockedUsers.length})
            </Label>
            <Button
              variant="ghost"
              size="sm"
              onClick={loadBlockedUsers}
              disabled={loading}
            >
              {loading ? 'Loading...' : 'Refresh'}
            </Button>
          </div>

          {blockedUsers.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <UserPlus className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p>No blocked users</p>
              <p className="text-xs">Users you block will appear here</p>
            </div>
          ) : (
            <div className="space-y-2">
              {blockedUsers.map((user, index) => (
                <div
                  key={`${user.username}-${index}`}
                  className="flex items-center justify-between p-3 rounded-md border bg-card"
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{user.username}</span>
                      <Badge variant="secondary" className="text-xs">
                        Blocked
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      Blocked on {format(new Date(user.blockedAt), 'MMM d, yyyy \'at\' h:mm a')}
                      {user.reason && (
                        <span className="block mt-1">
                          Reason: {user.reason}
                        </span>
                      )}
                    </div>
                  </div>
                  <Dialog>
                    <DialogTrigger asChild>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-950"
                        disabled={loading}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Unblock User</DialogTitle>
                        <DialogDescription>
                          Are you sure you want to unblock {user.username}? They will be able to send you messages and calls again.
                        </DialogDescription>
                      </DialogHeader>
                      <DialogFooter>
                        <Button variant="outline">Cancel</Button>
                        <Button
                          onClick={() => handleUnblockUser(user.username)}
                          className="bg-green-600 hover:bg-green-700 text-white"
                        >
                          Unblock
                        </Button>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="text-xs text-muted-foreground border-t pt-3">
          <p><strong>Note:</strong> Blocking is end-to-end encrypted and private.</p>
          <p>The server cannot see who you have blocked.</p>
          <p>Blocked users will not know they have been blocked.</p>
        </div>
      </CardContent>
    </Card>
  );
}
