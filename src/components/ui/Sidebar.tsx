import React, { useState, useRef } from 'react';
import { LogOut } from 'lucide-react';
import { ChatBubbleIcon, SettingsIcon, CallIcon } from '../chat/assets/icons';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { UserAvatar } from './UserAvatar';
import { useTheme } from 'next-themes';

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
    const { theme, setTheme } = useTheme();
    const [isCollapsed, setIsCollapsed] = useState(true);
    const logoutTimerRef = useRef<NodeJS.Timeout | null>(null);
    const [logoutProgress, setLogoutProgress] = useState(0);
    const [isHoldingLogout, setIsHoldingLogout] = useState(false);

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
        <div
            className={cn(
                "flex flex-col h-full border-r border-border transition-all duration-300 ease-in-out relative z-20",
                isCollapsed ? "w-13" : "w-35"
            )}
            style={{ backgroundColor: 'var(--chats-section-bg)' }}
        >
            {/* Header */}
            <div
                className={cn(
                    "h-18 flex items-center transition-all duration-300 justify-start p-0 pl-0 cursor-pointer hover:bg-accent/30 select-none",
                )}
                onClick={() => setIsCollapsed(!isCollapsed)}
                title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
                <div className="flex items-center overflow-hidden">
                    <div className="w-13 flex items-center justify-center shrink-0">
                        <div className="w-12 h-12 bg-primary rounded-lg flex items-center justify-center text-primary-foreground">
                            <ChatBubbleIcon className="!w-[25px] !h-[25px]" />
                        </div>
                    </div>
                    <div className={cn(
                        "overflow-hidden transition-[width] duration-300 ease-in-out",
                        isCollapsed ? "w-0 ml-0" : "w-[100px]"
                    )}>
                        <span className={cn(
                            "font-semibold text-lg truncate block whitespace-nowrap transition-opacity duration-300",
                            isCollapsed ? "opacity-0" : "opacity-100 delay-150"
                        )}>
                            Qor
                        </span>
                    </div>
                </div>
            </div>

            {/* Navigation */}
            <div className="flex-1 py-2 space-y-1">
                {navItems.map((item) => (
                    <Button
                        key={item.id}
                        variant="ghost"
                        onClick={() => onTabChange(item.id)}
                        className={cn(
                            "w-full h-12 mb-1 transition-all duration-300 ease-in-out flex items-center justify-start p-0 pl-0 select-none cursor-pointer",
                            activeTab === item.id
                                ? "bg-secondary text-secondary-foreground"
                                : "text-muted-foreground hover:bg-accent/30 hover:text-foreground"
                        )}
                    >
                        <div className="flex items-center overflow-hidden">
                            <div className="w-13 h-12 flex items-center justify-center shrink-0">
                                <item.icon
                                    className={cn(
                                        "!h-[25px] !w-[25px] transition-all duration-300",
                                        activeTab === item.id ? "fill-current" : "fill-none"
                                    )}
                                    width={25}
                                    height={25}
                                    strokeWidth={activeTab === item.id ? 2.5 : 2}
                                />
                            </div>
                            <div className={cn(
                                "overflow-hidden transition-all duration-300 ease-in-out",
                                isCollapsed ? "w-0 ml-0 delay-150" : "w-[100px]"
                            )}>
                                <span className={cn(
                                    "truncate block text-left text-base whitespace-nowrap transition-opacity duration-300",
                                    isCollapsed ? "opacity-0" : "opacity-100 delay-150"
                                )}>
                                    {item.label}
                                </span>
                            </div>
                        </div>
                    </Button>
                ))}
            </div>

            {/* Footer */}
            <div className="py-2 space-y-1">
                {/* Theme Toggle */}
                <Button
                    variant="ghost"
                    size="icon"
                    className={cn(
                        "w-full h-12 transition-all duration-300 ease-in-out flex items-center justify-start p-0 pl-0 theme-toggle-btn select-none hover:bg-accent/30 cursor-pointer",
                    )}
                    onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                >
                    <div className="flex items-center overflow-hidden">
                        <div className="w-13 h-12 flex items-center justify-center shrink-0">
                            <div className="themeToggle st-sunMoonThemeToggleBtn">
                                <input
                                    type="checkbox"
                                    className="themeToggleInput"
                                    checked={theme === 'light'}
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
                                    <circle
                                        className="sunMoon"
                                        cx="10"
                                        cy="10"
                                        r="8"
                                        mask="url(#moon-mask)"
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
                            </div>
                        </div>
                        <div className={cn(
                            "overflow-hidden transition-[width] duration-300 ease-in-out",
                            isCollapsed ? "w-0 ml-0" : "w-[150px]"
                        )}>
                            <span className={cn(
                                "truncate block text-left text-base whitespace-nowrap transition-opacity duration-300",
                                isCollapsed ? "opacity-0" : "opacity-100 delay-150"
                            )}>
                                Theme
                            </span>
                        </div>
                    </div>
                </Button>

                {/* Profile */}
                {currentUser && (
                    <Button
                        variant="ghost"
                        className={cn(
                            "w-full h-auto transition-all duration-300 ease-in-out flex items-center justify-start p-0 pl-0 select-none relative overflow-hidden cursor-pointer",
                            isHoldingLogout ? "bg-[#6b2c2b]" : "hover:bg-accent/30"
                        )}
                        onMouseDown={handleLogoutMouseDown}
                        onMouseUp={handleLogoutMouseUp}
                        onMouseLeave={handleLogoutMouseUp}
                    >
                        {/* Progress bar overlay */}
                        <div
                            className="absolute inset-0 bg-[#89302d] transition-all duration-75 ease-linear"
                            style={{ width: `${logoutProgress}%` }}
                        />

                        <div className="flex items-center overflow-hidden relative z-10">
                            <div className="w-13 h-14 flex items-center justify-center shrink-0">
                                <div className="relative w-full h-full flex items-center justify-center">
                                    {/* Avatar  */}
                                    <div className={cn(
                                        "absolute transition-all duration-200",
                                        isHoldingLogout ? "opacity-0 invisible translate-y-2 scale-90" : "opacity-100 visible translate-y-0 scale-100"
                                    )}>
                                        <UserAvatar
                                            username={currentUser.username}
                                            isCurrentUser={true}
                                            size="sm"
                                        />
                                    </div>

                                    {/* Logout icon */}
                                    <div className={cn(
                                        "absolute transition-all duration-200",
                                        isHoldingLogout ? "opacity-100 visible translate-y-0 scale-100" : "opacity-0 invisible -translate-y-2 scale-90"
                                    )}>
                                        <LogOut className="h-6 w-6 text-[#e3616a]" />
                                    </div>
                                </div>
                            </div>

                            {/* Text section */}
                            <div className={cn(
                                "flex flex-col items-start overflow-hidden transition-all duration-300 ease-in-out",
                                isCollapsed ? "w-0 ml-0 delay-150" : "w-[150px]"
                            )}>
                                <div className={cn(
                                    "w-full transition-opacity duration-300",
                                    isCollapsed ? "opacity-0" : "opacity-100 delay-150"
                                )}>
                                    {/* Top line: Username or "Logging out" */}
                                    <div className="relative h-5 mb-1">
                                        {/* Username text */}
                                        <span className={cn(
                                            "text-sm font-medium truncate w-full text-left block whitespace-nowrap transition-all duration-200 absolute top-0 left-0",
                                            isHoldingLogout ? "opacity-0 invisible translate-y-2 scale-90" : "opacity-100 visible translate-y-0 scale-100"
                                        )}>{currentUser.username}</span>

                                        <span className={cn(
                                            "text-sm font-medium truncate w-full text-left block whitespace-nowrap transition-all duration-200 absolute top-0 left-0 text-[#e3616a]",
                                            isHoldingLogout ? "opacity-100 visible translate-y-0 scale-100" : "opacity-0 invisible -translate-y-2 scale-90"
                                        )}>Logging out</span>
                                    </div>

                                    {/* Bottom line: Subtitle text */}
                                    <div className="relative h-4">
                                        <span className={cn(
                                            "text-[10px] truncate w-full text-left block whitespace-nowrap transition-all duration-200 absolute top-0 left-0 text-muted-foreground opacity-70",
                                            isHoldingLogout ? "opacity-0 invisible translate-y-2 scale-90" : "opacity-70 visible translate-y-0 scale-100"
                                        )}>Hold to logout</span>

                                        <span className={cn(
                                            "text-[10px] truncate w-full text-left block whitespace-nowrap transition-all duration-200 absolute top-0 left-0 text-[#e3616a]",
                                            isHoldingLogout ? "opacity-100 visible translate-y-0 scale-100" : "opacity-0 invisible -translate-y-2 scale-90"
                                        )}>Hold to Confirm</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </Button>
                )}
            </div>
        </div>
    );
}
