import React, { useState } from "react";
import { cn } from "@/lib/utils";
import { Plus, MessageSquare, Settings, LogOut, Home, Users, Phone } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export interface User {
  id: string;
  username: string;
  isOnline: boolean;
  isTyping?: boolean;
  hybridPublicKeys?: {
    x25519PublicBase64: string;
    kyberPublicBase64: string;
  };
}

interface SidebarProps {
  className?: string;
  children?: React.ReactNode;
  currentUsername?: string;
  onAddConversation?: (username: string) => Promise<any>;
  onLogout?: () => void;
  onActiveTabChange?: (tab: string) => void;
}

export function Sidebar({ className, children, currentUsername, onAddConversation, onLogout, onActiveTabChange }: SidebarProps) {
  const [activeTab, setActiveTab] = useState("messages");
  const [showAddUser, setShowAddUser] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [isValidating, setIsValidating] = useState(false);
  const [validationError, setValidationError] = useState("");
  const [isCollapsed, setIsCollapsed] = useState(false);

  const handleAddUser = async () => {
    const username = newUsername.trim();
    if (!username || username === currentUsername) return;

    setIsValidating(true);
    setValidationError("");

    try {
      // Create conversation and automatically select it
      await onAddConversation?.(username);
      setNewUsername("");
      setShowAddUser(false);
      // Switch to messages tab after adding conversation
      setActiveTab("messages");
      onActiveTabChange?.("messages");
    } catch (error) {
      console.error('[UserList] Failed to add conversation:', error);
      setValidationError(error instanceof Error ? error.message : 'Failed to add user');
    } finally {
      setIsValidating(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isValidating) {
      handleAddUser();
    } else if (e.key === 'Escape') {
      setShowAddUser(false);
      setNewUsername("");
      setValidationError("");
    }
  };

  const navigationItems = [
    { id: 'home', icon: Home, label: 'Home', action: () => {} },
    { id: 'messages', icon: MessageSquare, label: 'Messages', action: () => { setActiveTab('messages'); onActiveTabChange?.('messages'); } },
    { id: 'newchat', icon: Plus, label: 'New Chat', action: () => { setActiveTab('newchat'); setShowAddUser(true); onActiveTabChange?.('newchat'); } },
  ];

  const secondaryItems = [
    { id: 'settings', icon: Settings, label: 'Settings', action: () => { 
      // Set active tab for visual highlighting
      setActiveTab('settings');
      onActiveTabChange?.('settings');
      // Open settings in main screen instead of sidebar tab
      window.dispatchEvent(new CustomEvent('openSettings'));
    } },
  ];

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
            onClick={() => {
              setActiveTab('logout');
              onActiveTabChange?.('logout');
              onLogout?.();
            }}
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
          >
            <div 
              className="w-8 h-8 rounded-full flex items-center justify-center text-white font-medium text-sm"
              style={{ backgroundColor: 'var(--color-accent-secondary)' }}
            >
              {currentUsername?.charAt(0).toUpperCase() || "U"}
            </div>
            {!isCollapsed && (
              <div className="flex-1 text-left min-w-0 mr-2">
                <div
                  className="font-medium text-sm truncate"
                  style={{ color: 'var(--color-text-primary)' }}
                  title={currentUsername || 'User'} // Show full username on hover
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

      {/* Add user modal/overlay */}
      {showAddUser && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-80 shadow-xl">
            <h3 className="text-lg font-semibold mb-4">Start New Conversation</h3>
            <div className="space-y-4">
              <div>
                <label className="text-sm text-gray-600 mb-2 block">
                  Enter username to chat with:
                </label>
                <Input
                  placeholder="e.g., alice, bob, charlie..."
                  value={newUsername}
                  onChange={(e) => {
                    setNewUsername(e.target.value);
                    setValidationError(""); // Clear error when user types
                  }}
                  onKeyDown={handleKeyPress}
                  className="w-full"
                  autoFocus
                  disabled={isValidating}
                />
                {newUsername.trim() === currentUsername && (
                  <p className="text-xs text-red-500 mt-1">
                    Cannot start conversation with yourself
                  </p>
                )}
                {validationError && (
                  <p className="text-xs text-red-500 mt-1">
                    {validationError}
                  </p>
                )}
                {isValidating && (
                  <p className="text-xs text-blue-500 mt-1">
                    Validating user...
                  </p>
                )}
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={handleAddUser}
                  className="flex-1"
                  disabled={!newUsername.trim() || newUsername.trim() === currentUsername || isValidating}
                >
                  {isValidating ? "Validating..." : "Start Chat"}
                </Button>
                <Button
                  onClick={() => {
                    setShowAddUser(false);
                    setNewUsername("");
                    setValidationError("");
                    setActiveTab("messages");
                  }}
                  variant="outline"
                  className="flex-1"
                  disabled={isValidating}
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
            <div className="p-4 border-b" style={{ borderColor: 'var(--color-border)' }}>
              <h2 
                className="text-lg font-semibold"
                style={{ color: 'var(--color-text-primary)' }}
              >
                Conversations
              </h2>
            </div>
            <div className="flex-1 overflow-hidden">
              {children}
            </div>
          </div>
        </div>
      )}

    </div>
  );
}