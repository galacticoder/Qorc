import React, { useState } from "react";
import { cn } from "@/lib/utils";
import { Plus, MessageSquare, Settings, LogOut } from "lucide-react";
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
  settingsContent?: React.ReactNode;
}

export function Sidebar({ className, children, currentUsername, onAddConversation, onLogout, onActiveTabChange, settingsContent }: SidebarProps) {
  const [activeTab, setActiveTab] = useState("messages");
  const [showAddUser, setShowAddUser] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [isValidating, setIsValidating] = useState(false);
  const [validationError, setValidationError] = useState("");

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

  return (
    <div className={cn("flex flex-col justify-start items-center relative transition-all duration-500 ease-in-out w-16", className)}>
      <article className="border border-solid border-gray-300 dark:border-gray-700 w-full ease-in-out duration-500 left-0 rounded-2xl inline-block shadow-lg shadow-black/15 bg-white dark:bg-gray-900 h-full flex flex-col">
        {/* Top navigation buttons */}
        <div className="flex flex-col">
          <label
            className={cn(
              "has-[:checked]:shadow-lg relative w-full h-16 p-4 ease-in-out duration-300 border-solid border-black/10 has-[:checked]:border group flex flex-row gap-3 items-center justify-center text-black rounded-xl cursor-pointer",
              activeTab === "newchat" && "shadow-lg border border-black/10"
            )}
            onClick={() => {
              setActiveTab("newchat");
              setShowAddUser(true);
              onActiveTabChange?.("newchat");
            }}
          >
            <input
              className="hidden peer/expand"
              type="radio"
              name="path"
              id="newchat"
              checked={activeTab === "newchat"}
              onChange={() => {}}
            />
            <Plus className="peer-hover/expand:scale-125 peer-hover/expand:text-blue-400 peer-checked/expand:text-blue-400 text-2xl peer-checked/expand:scale-125 ease-in-out duration-300 w-6 h-6" />
          </label>

          <label
            className={cn(
              "has-[:checked]:shadow-lg relative w-full h-16 p-4 ease-in-out duration-300 border-solid border-black/10 has-[:checked]:border group flex flex-row gap-3 items-center justify-center text-black rounded-xl cursor-pointer",
              activeTab === "messages" && "shadow-lg border border-black/10"
            )}
            onClick={() => {
              setActiveTab("messages");
              onActiveTabChange?.("messages");
            }}
          >
            <input
              className="hidden peer/expand"
              type="radio"
              name="path"
              id="messages"
              checked={activeTab === "messages"}
              onChange={() => {}}
            />
            <MessageSquare className="peer-hover/expand:scale-125 peer-hover/expand:text-blue-400 peer-checked/expand:text-blue-400 text-2xl peer-checked/expand:scale-125 ease-in-out duration-300 w-6 h-6" />
          </label>
        </div>

        {/* Spacer to push bottom buttons down */}
        <div className="flex-1"></div>

        {/* Bottom navigation buttons */}
        <div className="flex flex-col">
          <label
            className={cn(
              "has-[:checked]:shadow-lg relative w-full h-16 p-4 ease-in-out duration-300 border-solid border-black/10 has-[:checked]:border group flex flex-row gap-3 items-center justify-center text-black rounded-xl cursor-pointer",
              activeTab === "settings" && "shadow-lg border border-black/10"
            )}
            onClick={() => {
              setActiveTab("settings");
              onActiveTabChange?.("settings");
            }}
          >
            <input
              className="hidden peer/expand"
              type="radio"
              name="path"
              id="settings"
              checked={activeTab === "settings"}
              onChange={() => {}}
            />
            <Settings className="peer-hover/expand:scale-125 peer-hover/expand:text-blue-400 peer-checked/expand:text-blue-400 text-2xl peer-checked/expand:scale-125 ease-in-out duration-300 w-6 h-6" />
          </label>

          <label
            className={cn(
              "has-[:checked]:shadow-lg relative w-full h-16 p-4 ease-in-out duration-300 border-solid border-black/10 has-[:checked]:border group flex flex-row gap-3 items-center justify-center text-black rounded-xl cursor-pointer",
              activeTab === "logout" && "shadow-lg border border-black/10"
            )}
            onClick={() => {
              setActiveTab("logout");
              onActiveTabChange?.("logout");
              onLogout?.();
            }}
          >
            <input
              className="hidden peer/expand"
              type="radio"
              name="path"
              id="logout"
              checked={activeTab === "logout"}
              onChange={() => {}}
            />
            <div className="peer-hover/expand:scale-125 peer-checked/expand:scale-125 ease-in-out duration-300 w-6 h-6 bg-orange-500 rounded-full flex items-center justify-center">
              <span className="text-white text-xs font-medium">
                {currentUsername?.charAt(0).toUpperCase() || "U"}
              </span>
            </div>
          </label>
        </div>

      </article>

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
        <div className="fixed left-16 top-0 h-full w-64 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-r-2xl shadow-lg shadow-black/15 z-30">
          <div className="h-full flex flex-col">
            <div className="p-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Conversations</h2>
            </div>
            <div className="flex-1 overflow-hidden">
              {children}
            </div>
          </div>
        </div>
      )}

      {/* Settings panel - only show when settings tab is active */}
      {activeTab === "settings" && (
        <div className="fixed left-16 top-0 h-full w-96 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-r-2xl shadow-lg shadow-black/15 z-30 overflow-y-auto">
          <div className="h-full flex flex-col">
            <div className="flex-1">
              {settingsContent}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}