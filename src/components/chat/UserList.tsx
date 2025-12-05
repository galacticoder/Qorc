import React, { useState, useCallback, useMemo, useRef, useEffect } from "react";
import { cn } from "../../lib/utils";
import { MessageSquare, Settings, LogOut } from "lucide-react";
import { ComposeIcon } from "./icons";
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
    readonly dilithiumPublicBase64: string;
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

  useEffect(() => {
    const openNewChat = () => {
      setShowAddUser(true);
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
        className="h-full flex flex-col bg-card border-r border-border"
      >
        {/* App Logo / Header */}
        <div className="p-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center bg-primary text-primary-foreground"
            >
              <MessageSquare className="w-5 h-5" />
            </div>
            {!isCollapsed && (
              <span
                className="font-semibold text-lg text-foreground"
              >
                
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
                    "h-[var(--sidebar-item-height)]",
                    isActive ? "bg-primary text-primary-foreground" : "text-foreground hover:bg-primary/10"
                  )}
                >
                  <Icon size={20} />
                  {!isCollapsed && (
                    <span className="font-medium">{item.label}</span>
                  )}
                  {isActive && (
                    <div
                      className="absolute left-0 w-1 h-6 rounded-r bg-secondary"
                    />
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Secondary Links */}
        <div className="px-3 py-4">
          {secondaryItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={item.action}
                className={cn(
                  "w-full flex items-center gap-3 px-3 py-3 rounded-lg transition-all duration-200",
                  "h-[var(--sidebar-item-height)]",
                  isActive ? "bg-primary text-primary-foreground" : "text-foreground hover:bg-primary/10"
                )}
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
        <div className="px-3 py-4">
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-3 py-3 rounded-lg transition-all duration-200 hover:bg-destructive/10 text-foreground h-[var(--sidebar-item-height)]"
            aria-label="Logout"
          >
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center text-secondary-foreground font-medium text-sm bg-secondary"
              aria-hidden="true"
            >
              {userInitial}
            </div>
            {!isCollapsed && (
              <div className="flex-1 text-left min-w-0 mr-2">
                <div
                  className="font-medium text-sm truncate text-foreground"
                  title={currentUsername || 'User'}
                >
                  {currentUsername || 'User'}
                </div>
                <div className="text-xs truncate text-muted-foreground">
                  Click to logout
                </div>
              </div>
            )}
            <LogOut size={16} className="opacity-60" />
          </button>
        </div>
      </div>

      {/* Conversations panel */}
      {activeTab === "messages" && (
        <div
          className={cn(
            "fixed top-0 h-full transition-all duration-300 z-30 bg-card border-r border-border shadow-sm",
            isCollapsed ? "left-16 w-80" : "left-60 w-80"
          )}
        >
          <div className="h-full flex flex-col">
            <div className="p-4 border-b flex items-center justify-between border-border">
              <h2
                className="text-lg font-semibold text-foreground"
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
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = 'scale(1.15) rotate(-5deg)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'scale(1) rotate(0deg)';
                }}
                style={{ transition: 'transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1)', transformOrigin: 'center' }}
              >
                <ComposeIcon className="h-4 w-4" />
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
