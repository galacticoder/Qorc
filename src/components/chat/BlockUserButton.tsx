import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { UserX, UserCheck, Shield } from 'lucide-react';
import { blockingSystem } from '@/lib/blocking-system';

interface BlockUserButtonProps {
  username: string;
  passphrase?: string;
  onPassphraseRequired?: () => void;
  variant?: 'default' | 'outline' | 'ghost' | 'destructive' | 'secondary' | 'link';
  size?: 'default' | 'sm' | 'lg' | 'icon';
  className?: string;
  showText?: boolean;
  onBlockStatusChange?: (username: string, isBlocked: boolean) => void;
}

export function BlockUserButton({ 
  username, 
  passphrase, 
  onPassphraseRequired,
  variant = 'outline',
  size = 'sm',
  className = '',
  showText = true,
  onBlockStatusChange
}: BlockUserButtonProps) {
  const [isBlocked, setIsBlocked] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showBlockDialog, setShowBlockDialog] = useState(false);
  const [showUnblockDialog, setShowUnblockDialog] = useState(false);
  const [blockReason, setBlockReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [tempPassphrase, setTempPassphrase] = useState('');
  const [needsPassphrase, setNeedsPassphrase] = useState(!passphrase);

  // Check if user is blocked on mount
  useEffect(() => {
    checkBlockStatus();
  }, [username, passphrase]);

  const checkBlockStatus = async () => {
    if (!username || (!passphrase && !tempPassphrase)) return;
    
    try {
      const blocked = await blockingSystem.isUserBlocked(username, passphrase || tempPassphrase);
      setIsBlocked(blocked);
    } catch (error) {
      console.error('Error checking block status:', error);
    }
  };

  const handleBlockUser = async () => {
    if (!username) return;
    
    if (!passphrase && !tempPassphrase) {
      setNeedsPassphrase(true);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await blockingSystem.blockUser(
        username,
        passphrase || tempPassphrase,
        blockReason.trim() || undefined
      );
      
      setIsBlocked(true);
      setShowBlockDialog(false);
      setBlockReason('');
      
      // Emit blocking status change event
      window.dispatchEvent(new CustomEvent('block-status-changed', {
        detail: { username, isBlocked: true }
      }));
      
      onBlockStatusChange?.(username, true);
    } catch (err) {
      console.error('Error blocking user:', err);
      setError('Failed to block user. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleUnblockUser = async () => {
    if (!username) return;
    
    if (!passphrase && !tempPassphrase) {
      setNeedsPassphrase(true);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await blockingSystem.unblockUser(username, passphrase || tempPassphrase);
      setIsBlocked(false);
      setShowUnblockDialog(false);
      
      // Emit blocking status change event
      window.dispatchEvent(new CustomEvent('block-status-changed', {
        detail: { username, isBlocked: false }
      }));
      
      onBlockStatusChange?.(username, false);
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
    
    setNeedsPassphrase(false);
    await checkBlockStatus();
  };

  if (needsPassphrase && !passphrase) {
    return (
      <Dialog open={needsPassphrase} onOpenChange={setNeedsPassphrase}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Passphrase Required</DialogTitle>
            <DialogDescription>
              Enter your passphrase to manage blocked users.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            {error && (
              <div className="text-sm text-red-600 dark:text-red-400">
                {error}
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="temp-passphrase">Passphrase</Label>
              <Input
                id="temp-passphrase"
                type="password"
                placeholder="Enter your passphrase"
                value={tempPassphrase}
                onChange={(e) => setTempPassphrase(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handlePassphraseSubmit()}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setNeedsPassphrase(false)}>Cancel</Button>
            <Button
              onClick={handlePassphraseSubmit}
              disabled={!tempPassphrase.trim()}
            >
              Continue
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    );
  }

  if (isBlocked) {
    return (
      <Dialog open={showUnblockDialog} onOpenChange={setShowUnblockDialog}>
        <DialogTrigger asChild>
          <Button
            variant={variant}
            size={size}
            className={`text-green-600 hover:text-green-700 hover:bg-green-50 dark:hover:bg-green-950 ${className}`}
            disabled={loading}
          >
            <UserCheck className="h-4 w-4" />
            {showText && <span className="ml-1">Unblock</span>}
          </Button>
        </DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Unblock User</DialogTitle>
            <DialogDescription>
              Are you sure you want to unblock {username}? They will be able to send you messages and calls again.
            </DialogDescription>
          </DialogHeader>
          {error && (
            <div className="text-sm text-red-600 dark:text-red-400">
              {error}
            </div>
          )}
          <DialogFooter>
            <Button variant="outline">Cancel</Button>
            <Button
              onClick={handleUnblockUser}
              disabled={loading}
              className="bg-green-600 hover:bg-green-700 text-white"
            >
              {loading ? 'Unblocking...' : 'Unblock'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open={showBlockDialog} onOpenChange={setShowBlockDialog}>
      <DialogTrigger asChild>
        <Button
          variant={variant}
          size={size}
          className={`text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-950 ${className}`}
          disabled={loading}
        >
          <UserX className="h-4 w-4" />
          {showText && <span className="ml-1">Block</span>}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Block User</DialogTitle>
          <DialogDescription>
            Are you sure you want to block {username}? They will not be able to send you messages or calls.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          {error && (
            <div className="text-sm text-red-600 dark:text-red-400">
              {error}
            </div>
          )}
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
          <Button variant="outline">Cancel</Button>
          <Button
            onClick={handleBlockUser}
            disabled={loading}
            className="bg-red-600 hover:bg-red-700 text-white"
          >
            {loading ? 'Blocking...' : 'Block User'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
