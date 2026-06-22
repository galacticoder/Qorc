import React, { useState, useRef } from 'react';
import { LogOut } from 'lucide-react';
import { ChatBubbleIcon, SettingsIcon, CallIcon } from '../chat/assets/icons';
import { cn } from '@/lib/utils/shared-utils';
import { UserAvatar } from './UserAvatar';
import { useTheme } from 'next-themes';
import { QorBrandLogo } from './QorBrandLogo';

interface SidebarProps {
    activeTab: 'chats' | 'calls' | 'settings';
    onTabChange: (tab: 'chats' | 'calls' | 'settings') => void;
    currentUser?: {
        username: string;
        avatarUrl?: string;
    };
    onLogout?: () => void;
}

export function Sidebar({ activeTab, onTabChange, currentUser, onLogout }: SidebarProps) {
    const { theme, resolvedTheme, setTheme } = useTheme();
    const [isCollapsed, setIsCollapsed] = useState(true);
    const logoutTimerRef = useRef<NodeJS.Timeout | null>(null);
    const [logoutProgress, setLogoutProgress] = useState(0);
    const [isHoldingLogout, setIsHoldingLogout] = useState(false);
    const activeTheme = theme === 'system' ? resolvedTheme : theme;

    const navItems = [
        { id: 'chats', icon: ChatBubbleIcon, label: 'Chats' },
        { id: 'calls', icon: CallIcon, label: 'Calls' },
        { id: 'settings', icon: SettingsIcon, label: 'Settings' },
    ] as const;

    const handleLogoutMouseDown = () => {
        setIsHoldingLogout(true);
        const startTime = Date.now();
        const duration = 2500;

        const updateProgress = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min((elapsed / duration) * 100, 100);
            setLogoutProgress(progress);

            if (progress < 100) {
                logoutTimerRef.current = setTimeout(updateProgress, 16);
            } else {
                onLogout?.();
            }
        };

        updateProgress();
    };

    const handleLogoutMouseUp = () => {
        setIsHoldingLogout(false);
        setLogoutProgress(0);
        if (logoutTimerRef.current) {
            clearTimeout(logoutTimerRef.current);
            logoutTimerRef.current = null;
        }
    };

    return (
        <aside className={cn("qor-rail", !isCollapsed && "is-expanded")}>
            <button
                type="button"
                className="qor-rail-row qor-rail-head"
                onClick={() => setIsCollapsed(!isCollapsed)}
                title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
                aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
                <span className="qor-rail-icon-slot">
                    <QorBrandLogo className="brand-square qor-brand-square" imageClassName="qor-brand-logo" />
                </span>
                <span className="qor-rail-label qor-brand-label">Qor</span>
            </button>

            <div className="qor-rail-spacer">
                {navItems.map((item) => (
                    <button
                        key={item.id}
                        type="button"
                        onClick={() => onTabChange(item.id)}
                        className={cn(
                            "qor-rail-row qor-rail-button",
                            activeTab === item.id && "is-active"
                        )}
                        aria-pressed={activeTab === item.id}
                    >
                        <span className="qor-rail-icon-slot">
                            <item.icon
                                className={cn(
                                    "qor-rail-icon",
                                    activeTab === item.id ? "fill-current" : "fill-none"
                                )}
                                width={22}
                                height={22}
                                strokeWidth={activeTab === item.id ? 2.5 : 2}
                                aria-hidden="true"
                            />
                        </span>
                        <span className="qor-rail-label">{item.label}</span>
                    </button>
                ))}
            </div>

            <div className="qor-rail-foot">
                <button
                    type="button"
                    className="qor-rail-row qor-rail-theme theme-toggle-btn"
                    onClick={() => setTheme(activeTheme === 'dark' ? 'light' : 'dark')}
                    aria-label={activeTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
                >
                    <span className="qor-rail-icon-slot">
                        <span className="themeToggle st-sunMoonThemeToggleBtn" aria-hidden="true">
                            <input
                                type="checkbox"
                                className="themeToggleInput"
                                checked={activeTheme === 'light'}
                                readOnly
                            />
                            <svg
                                width="18"
                                height="18"
                                viewBox="0 0 20 20"
                                fill="currentColor"
                                stroke="none"
                            >
                                <mask id="moon-mask">
                                    <rect x="0" y="0" width="20" height="20" fill="white"></rect>
                                    <circle cx="11" cy="3" r="8" fill="black"></circle>
                                </mask>
                                <circle className="sunMoon" cx="10" cy="10" r="8" mask="url(#moon-mask)"></circle>
                                <g>
                                    <circle className="sunRay sunRay1" cx="18" cy="10" r="1.5"></circle>
                                    <circle className="sunRay sunRay2" cx="14" cy="16.928" r="1.5"></circle>
                                    <circle className="sunRay sunRay3" cx="6" cy="16.928" r="1.5"></circle>
                                    <circle className="sunRay sunRay4" cx="2" cy="10" r="1.5"></circle>
                                    <circle className="sunRay sunRay5" cx="6" cy="3.1718" r="1.5"></circle>
                                    <circle className="sunRay sunRay6" cx="14" cy="3.1718" r="1.5"></circle>
                                </g>
                            </svg>
                        </span>
                    </span>
                    <span className="qor-rail-label">Theme</span>
                </button>

                {currentUser && (
                    <button
                        type="button"
                        className={cn(
                            "qor-rail-row qor-rail-profile",
                            isHoldingLogout && "is-holding"
                        )}
                        onMouseDown={handleLogoutMouseDown}
                        onMouseUp={handleLogoutMouseUp}
                        onMouseLeave={handleLogoutMouseUp}
                        onTouchStart={handleLogoutMouseDown}
                        onTouchEnd={handleLogoutMouseUp}
                        aria-label="Hold to logout"
                    >
                        <span
                            className="qor-logout-progress"
                            style={{ width: `${logoutProgress}%` }}
                            aria-hidden="true"
                        />
                        <span className="qor-rail-icon-slot qor-profile-icon-slot">
                            <UserAvatar
                                username={currentUser.username}
                                isCurrentUser={true}
                                size="sm"
                                className="qor-profile-avatar"
                            />
                            <LogOut className="qor-logout-icon" aria-hidden="true" />
                        </span>
                        <span className="qor-profile-stack">
                            <span className="qor-profile-name">{isHoldingLogout ? 'Logging out' : currentUser.username}</span>
                            <span className="qor-profile-help">{isHoldingLogout ? 'Hold to confirm' : 'Hold to logout'}</span>
                        </span>
                    </button>
                )}
            </div>
        </aside>
    );
}
