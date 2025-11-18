import React, { useState, useCallback, useMemo, useRef, useEffect } from "react";
import { cn } from "../../lib/utils";
import { MessageSquare, Settings, LogOut, Pencil } from "lucide-react";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import { sanitizeTextInput } from "../../lib/sanitizers";

export interface User {
  readonly id: string;
  readonly username: string;
  readonly isOnline: boolean;
  readonly isTyping?: boolean;
  readonly hybridPublicKeys?: {
    readonly x25519PublicBase64: string;
    readonly kyberPublicBase64: string;
  };
}

interface SidebarProps {
  readonly className?: string;
  readonly children?: React.ReactNode;
  readonly currentUsername?: string;
  readonly onAddConversation?: (username: string) => Promise<void>;
  readonly onLogout?: () => void;
  readonly onActiveTabChange?: (tab: string) => void;
}

export const Sidebar = React.memo<SidebarProps>(({ className, children, currentUsername, onAddConversation, onLogout, onActiveTabChange }) => {
  const [activeTab, setActiveTab] = useState<string>("messages");
  const [showAddUser, setShowAddUser] = useState<boolean>(false);
  const [newUsername, setNewUsername] = useState<string>("");
  const [isValidating, setIsValidating] = useState<boolean>(false);
  const [validationError, setValidationError] = useState<string>("");
  const [isCollapsed] = useState<boolean>(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    return () => {
      abortControllerRef.current?.abort();
    };
  }, []);

  useEffect(() => {
    if (showAddUser && inputRef.current) {
      inputRef.current.focus();
    }
  }, [showAddUser]);

  // Listen for global compose event to open "New Chat" modal
  useEffect(() => {
    const openNewChat = () => {
      setShowAddUser(true); // keep sidebar open on messages
    };
    window.addEventListener('open-new-chat', openNewChat as EventListener);
    return () => window.removeEventListener('open-new-chat', openNewChat as EventListener);
  }, []);

  const validateUsername = useCallback((username: string): boolean => {
    if (typeof username !== 'string' || !username) return false;
    const usernameRegex = /^[a-zA-Z0-9_-]{3,32}$/;
    return usernameRegex.test(username);
  }, []);

  const handleAddUser = useCallback(async () => {
    const sanitized = sanitizeTextInput(newUsername, { maxLength: 32, allowNewlines: false });
    const username = sanitized.trim();
    
    if (!username || username === currentUsername) return;
    
    if (!validateUsername(username)) {
      setValidationError("Username must be 3-32 characters; letters, numbers, underscore or hyphen only");
      return;
    }

    abortControllerRef.current?.abort();
    abortControllerRef.current = new AbortController();

    setIsValidating(true);
    setValidationError("");

    try {
      await onAddConversation?.(username);
      setNewUsername("");
      setShowAddUser(false);
      setActiveTab("messages");
      onActiveTabChange?.("messages");
    } catch (_error) {
      if (_error instanceof Error && _error.name === 'AbortError') return;
      setValidationError(_error instanceof Error ? _error.message : 'Failed to add conversation');
    } finally {
      setIsValidating(false);
      abortControllerRef.current = null;
    }
  }, [newUsername, currentUsername, validateUsername, onAddConversation, onActiveTabChange]);

  const handleKeyPress = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !isValidating) {
      e.preventDefault();
      const sanitized = sanitizeTextInput(newUsername, { maxLength: 32, allowNewlines: false }).trim();
      if (sanitized && validateUsername(sanitized)) {
        handleAddUser();
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setShowAddUser(false);
      setNewUsername("");
      setValidationError("");
    }
  }, [newUsername, isValidating, validateUsername, handleAddUser]);

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const sanitized = sanitizeTextInput(e.target.value, { maxLength: 32, allowNewlines: false });
    setNewUsername(sanitized);
    setValidationError("");
  }, []);

  const handleCloseModal = useCallback(() => {
    setShowAddUser(false);
    setNewUsername("");
    setValidationError("");
    setActiveTab("messages");
  }, []);

  const navigationItems = useMemo(() => [
    { 
      id: 'messages', 
      icon: MessageSquare, 
      label: 'Messages', 
      action: () => { setActiveTab('messages'); onActiveTabChange?.('messages'); }
    },
  ], [onActiveTabChange]);

  const secondaryItems = useMemo(() => [
    { 
      id: 'settings', 
      icon: Settings, 
      label: 'Settings', 
      action: () => { 
        setActiveTab('settings');
        onActiveTabChange?.('settings');
        window.dispatchEvent(new CustomEvent('openSettings'));
      }
    },
  ], [onActiveTabChange]);

  const handleLogout = useCallback(() => {
    setActiveTab('logout');
    onActiveTabChange?.('logout');
    onLogout?.();
  }, [onActiveTabChange, onLogout]);

  const userInitial = useMemo(() => 
    currentUsername?.charAt(0).toUpperCase() || "U",
    [currentUsername]
  );

  return (
    <div className={cn(
      "fixed left-0 top-0 h-full transition-all duration-300 ease-in-out z-40",
      isCollapsed ? "w-16" : "w-60",
      className
    )}>
      {/* Main Sidebar */}
      <div 
        className="h-full flex flex-col"
        style={{
          backgroundColor: 'var(--color-panel)',
          borderRight: '1px solid var(--color-border)'
        }}
      >
        {/* App Logo / Header */}
        <div className="p-4 border-b" style={{ borderColor: 'var(--color-border)' }}>
          <div className="flex items-center gap-3">
            <div 
              className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ backgroundColor: 'var(--color-accent-primary)' }}
            >
              <MessageSquare className="w-5 h-5 text-white" />
            </div>
            {!isCollapsed && (
              <span 
                className="font-semibold text-lg"
                style={{ color: 'var(--color-text-primary)' }}
              >
                endtoend
              </span>
            )}
          </div>
        </div>

        {/* Primary Navigation */}
        <div className="flex-1 py-4">
          <nav className="space-y-1 px-3">
            {navigationItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              
              return (
                <button
                  key={item.id}
                  onClick={item.action}
                  className={cn(
                    "w-full flex items-center gap-3 px-3 py-3 rounded-lg transition-all duration-200",
                    "hover:bg-opacity-80",
                    isActive ? "bg-opacity-100" : "bg-opacity-0 hover:bg-opacity-10"
                  )}
                  style={{
                    backgroundColor: isActive ? 'var(--color-accent-primary)' : 'transparent',
                    color: isActive ? 'white' : 'var(--color-text-primary)',
                    height: 'var(--sidebar-item-height)'
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive) {
                      e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.1)';
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive) {
                      e.currentTarget.style.backgroundColor = 'transparent';
                    }
                  }}
                >
                  <Icon size={20} />
                  {!isCollapsed && (
                    <span className="font-medium">{item.label}</span>
                  )}
                  {isActive && (
                    <div 
                      className="absolute left-0 w-1 h-6 rounded-r"
                      style={{ backgroundColor: 'var(--color-accent-secondary)' }}
                    />
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Secondary Links */}
        <div className="border-t px-3 py-4" style={{ borderColor: 'var(--color-border)' }}>
          {secondaryItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            
            return (
              <button
                key={item.id}
                onClick={item.action}
                className={cn(
                  "w-full flex items-center gap-3 px-3 py-3 rounded-lg transition-all duration-200",
                  "hover:bg-opacity-80",
                  isActive ? "bg-opacity-100" : "bg-opacity-0 hover:bg-opacity-10"
                )}
                style={{
                  backgroundColor: isActive ? 'var(--color-accent-primary)' : 'transparent',
                  color: isActive ? 'white' : 'var(--color-text-primary)',
                  height: 'var(--sidebar-item-height)'
                }}
                onMouseEnter={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.1)';
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.backgroundColor = 'transparent';
                  }
                }}
              >
                <Icon size={20} />
                {!isCollapsed && (
                  <span className="font-medium">{item.label}</span>
                )}
              </button>
            );
          })}
        </div>

        {/* User Profile Area */}
        <div className="border-t px-3 py-4" style={{ borderColor: 'var(--color-border)' }}>
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-3 py-3 rounded-lg transition-all duration-200 hover:bg-opacity-10"
            style={{
              color: 'var(--color-text-primary)',
              height: 'var(--sidebar-item-height)'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'transparent';
            }}
            aria-label="Logout"
          >
            <div 
              className="w-8 h-8 rounded-full flex items-center justify-center text-white font-medium text-sm"
              style={{ backgroundColor: 'var(--color-accent-secondary)' }}
              aria-hidden="true"
            >
              {userInitial}
            </div>
            {!isCollapsed && (
              <div className="flex-1 text-left min-w-0 mr-2">
                <div
                  className="font-medium text-sm truncate"
                  style={{ color: 'var(--color-text-primary)' }}
                  title={currentUsername || 'User'}
                >
                  {currentUsername || 'User'}
                </div>
                <div className="text-xs truncate" style={{ color: 'var(--color-text-secondary)' }}>
                  Click to logout
                </div>
              </div>
            )}
            <LogOut size={16} className="opacity-60" />
          </button>
        </div>
      </div>

      {showAddUser && (
        <div 
          className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={handleCloseModal}
          role="dialog"
          aria-modal="true"
          aria-labelledby="new-conversation-title"
        >
          <div 
            className="bg-white rounded-lg p-6 w-80 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 id="new-conversation-title" className="text-lg font-semibold mb-4">Start New Conversation</h3>
            <div className="space-y-4">
              <div>
                <label htmlFor="username-input" className="text-sm text-gray-600 mb-2 block">
                  Enter username to chat with:
                </label>
                <Input
                  id="username-input"
                  ref={inputRef}
                  placeholder="e.g., alice, bob, charlie..."
                  value={newUsername}
                  onChange={handleInputChange}
                  onKeyDown={handleKeyPress}
                  className="w-full"
                  disabled={isValidating}
                  autoCapitalize="off"
                  autoCorrect="off"
                  spellCheck={false}
                  inputMode="text"
                  maxLength={32}
                  aria-invalid={!!validationError}
                  aria-describedby={validationError ? "username-error" : undefined}
                />
                {newUsername.trim() === currentUsername && (
                  <p id="username-error" className="text-xs text-red-500 mt-1" role="alert">
                    Cannot start conversation with yourself
                  </p>
                )}
                {validationError && (
                  <p id="username-error" className="text-xs text-red-500 mt-1" role="alert">
                    {validationError}
                  </p>
                )}
                {isValidating && (
                  <p className="text-xs text-blue-500 mt-1" role="status">
                    Validating user...
                  </p>
                )}
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={handleAddUser}
                  className="flex-1"
                  disabled={!newUsername.trim() || newUsername.trim() === currentUsername || isValidating}
                  aria-label="Start chat"
                >
                  {isValidating ? "Validating..." : "Start Chat"}
                </Button>
                <Button
                  onClick={handleCloseModal}
                  variant="outline"
                  className="flex-1"
                  disabled={isValidating}
                  aria-label="Cancel"
                >
                  Cancel
                </Button>
              </div>
              <div className="text-xs text-gray-500">
                You can message any username. If they're online, they'll receive your message instantly.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Conversations panel - only show when messages tab is active */}
      {activeTab === "messages" && (
        <div 
          className={cn(
            "fixed top-0 h-full transition-all duration-300 z-30",
            isCollapsed ? "left-16 w-80" : "left-60 w-80"
          )}
          style={{
            backgroundColor: 'var(--color-surface)',
            borderRight: '1px solid var(--color-border)',
            boxShadow: 'var(--shadow-elevation-low)'
          }}
        >
          <div className="h-full flex flex-col">
            <div className="p-4 border-b flex items-center justify-between" style={{ borderColor: 'var(--color-border)' }}>
              <h2 
                className="text-lg font-semibold"
                style={{ color: 'var(--color-text-primary)' }}
              >
                Conversations
              </h2>
              <Button
                variant="ghost"
                size="sm"
                aria-label="Compose new chat"
                onClick={() => {
                  setShowAddUser(true);
                }}
              >
                <Pencil className="h-4 w-4" />
              </Button>
            </div>
            <div className="flex-1 overflow-hidden">
              {children}
            </div>
          </div>
        </div>
      )}

    </div>
  );
});
