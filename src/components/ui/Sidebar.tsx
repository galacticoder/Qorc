import { useEffect, useId, useState, useRef, type PointerEvent } from 'react';
import { LogOut } from 'lucide-react';
import { ChatBubbleIcon, SettingsIcon, CallIcon } from '../chat/assets/icons';
import { cn } from '@/lib/utils/shared-utils';
import { UserAvatar } from './UserAvatar';
import { useTheme } from '../../contexts/ThemeContext';
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
    const themeMaskId = useId();
    const [isCollapsed, setIsCollapsed] = useState(true);
    const logoutTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const logoutHoldGenerationRef = useRef(0);
    const logoutHoldActiveRef = useRef(false);
    const logoutCommittedRef = useRef(false);
    const [logoutProgress, setLogoutProgress] = useState(0);
    const [isHoldingLogout, setIsHoldingLogout] = useState(false);
    const activeTheme = theme === 'system' ? resolvedTheme : theme;

    const navItems = [
        { id: 'chats', icon: ChatBubbleIcon, label: 'Chats' },
        { id: 'calls', icon: CallIcon, label: 'Calls' },
    ] as const;

    useEffect(() => {
        logoutCommittedRef.current = false;
        logoutHoldActiveRef.current = false;
        logoutHoldGenerationRef.current += 1;
        setIsHoldingLogout(false);
        setLogoutProgress(0);
        return () => {
            logoutHoldActiveRef.current = false;
            logoutHoldGenerationRef.current += 1;
            if (logoutTimerRef.current) clearTimeout(logoutTimerRef.current);
            logoutTimerRef.current = null;
        };
    }, [currentUser?.username]);

    const handleLogoutPointerDown = (event: PointerEvent<HTMLButtonElement>) => {
        if (event.button !== 0 || logoutHoldActiveRef.current || logoutCommittedRef.current) return;
        event.preventDefault();
        logoutHoldActiveRef.current = true;
        const generation = ++logoutHoldGenerationRef.current;
        setIsHoldingLogout(true);
        const startTime = Date.now();
        const duration = 2500;

        const updateProgress = () => {
            if (
                !logoutHoldActiveRef.current ||
                logoutHoldGenerationRef.current !== generation ||
                logoutCommittedRef.current
            ) return;
            const elapsed = Date.now() - startTime;
            const progress = Math.min((elapsed / duration) * 100, 100);
            setLogoutProgress(progress);

            if (progress < 100) {
                logoutTimerRef.current = setTimeout(updateProgress, 16);
            } else {
                logoutTimerRef.current = null;
                logoutHoldActiveRef.current = false;
                logoutCommittedRef.current = true;
                setIsHoldingLogout(false);
                onLogout?.();
            }
        };

        updateProgress();
    };

    const cancelLogoutHold = () => {
        logoutHoldGenerationRef.current += 1;
        logoutHoldActiveRef.current = false;
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
                                width="22"
                                height="22"
                                viewBox="0 0 20 20"
                                fill="currentColor"
                                stroke="none"
                            >
                                <mask
                                    id={themeMaskId}
                                    maskUnits="userSpaceOnUse"
                                    maskContentUnits="userSpaceOnUse"
                                    x="-4"
                                    y="-4"
                                    width="28"
                                    height="28"
                                >
                                    <rect x="0" y="0" width="20" height="20" fill="white"></rect>
                                    <circle cx="11" cy="3" r="8" fill="black"></circle>
                                </mask>
                                <circle
                                    className="sunMoon"
                                    cx="10"
                                    cy="10"
                                    r="8"
                                    mask={`url(#${themeMaskId})`}
                                ></circle>
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

                <button
                    type="button"
                    onClick={() => onTabChange('settings')}
                    className={cn(
                        "qor-rail-row qor-rail-button",
                        activeTab === 'settings' && "is-active"
                    )}
                    aria-pressed={activeTab === 'settings'}
                >
                    <span className="qor-rail-icon-slot">
                        <SettingsIcon
                            className={cn(
                                "qor-rail-icon",
                                activeTab === 'settings' ? "fill-current" : "fill-none"
                            )}
                            width={22}
                            height={22}
                            strokeWidth={activeTab === 'settings' ? 2.5 : 2}
                            aria-hidden="true"
                        />
                    </span>
                    <span className="qor-rail-label">Settings</span>
                </button>

                {currentUser && (
                    <button
                        type="button"
                        className={cn(
                            "qor-rail-row qor-rail-profile",
                            isHoldingLogout && "is-holding"
                        )}
                        onPointerDown={handleLogoutPointerDown}
                        onPointerUp={cancelLogoutHold}
                        onPointerLeave={cancelLogoutHold}
                        onPointerCancel={cancelLogoutHold}
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
