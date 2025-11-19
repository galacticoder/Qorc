import React, { useState } from 'react';
import { MessageSquare, Phone, Settings, LogOut, User as UserIcon, Moon, Sun, ChevronLeft, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Separator } from '@/components/ui/separator';
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

    const navItems = [
        { id: 'chats', icon: MessageSquare, label: 'Chats' },
        { id: 'calls', icon: Phone, label: 'Calls' },
        { id: 'settings', icon: Settings, label: 'Settings' },
    ] as const;

    return (
        <div className={cn(
            "flex flex-col h-full bg-card border-r border-border transition-all duration-300 ease-in-out relative z-20",
            isCollapsed ? "w-16" : "w-60"
        )}>
            {/* Header */}
            <div
                className={cn(
                    "h-18 flex items-center transition-all duration-300 justify-start p-0 pl-0 cursor-pointer hover:bg-accent/50 select-none",
                )}
                onClick={() => setIsCollapsed(!isCollapsed)}
                title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
                <div className="flex items-center overflow-hidden">
                    <div className="w-16 flex items-center justify-center shrink-0">
                        <div className="w-12 h-12 bg-primary rounded-lg flex items-center justify-center text-primary-foreground">
                            <MessageSquare className="!w-[25px] !h-[25px]" size={25} />
                        </div>
                    </div>
                    <div className={cn(
                        "overflow-hidden transition-[width] duration-300 ease-in-out",
                        isCollapsed ? "w-0 ml-0" : "w-[150px]"
                    )}>
                        <span className={cn(
                            "font-semibold text-lg truncate block whitespace-nowrap transition-opacity duration-300",
                            isCollapsed ? "opacity-0" : "opacity-100 delay-150"
                        )}>
                            End2End
                        </span>
                    </div>
                </div>
            </div>

            {/* Navigation */}
            <div className="flex-1 py-4 space-y-1">
                {navItems.map((item) => (
                    <Button
                        key={item.id}
                        variant="ghost"
                        onClick={() => onTabChange(item.id)}
                        className={cn(
                            "w-full h-12 mb-1 transition-all duration-300 ease-in-out flex items-center justify-start p-0 pl-0 select-none",
                            activeTab === item.id ? "bg-secondary text-secondary-foreground" : "text-muted-foreground hover:bg-secondary/50 hover:text-foreground"
                        )}
                    >
                        <div className="w-16 h-12 flex items-center justify-center shrink-0">
                            <item.icon
                                className={cn(
                                    "!h-[25px] !w-[25px] transition-all duration-300",
                                    activeTab === item.id ? "fill-current" : "fill-none"
                                )}
                                size={25}
                                strokeWidth={activeTab === item.id ? 2.5 : 2}
                            />
                        </div>
                        <div className={cn(
                            "overflow-hidden transition-all duration-300 ease-in-out",
                            isCollapsed ? "w-0 ml-0 delay-150" : "w-[150px]"
                        )}>
                            <span className={cn(
                                "truncate block text-left text-base whitespace-nowrap transition-opacity duration-300",
                                isCollapsed ? "opacity-0" : "opacity-100 delay-150"
                            )}>
                                {item.label}
                            </span>
                        </div>
                    </Button>
                ))}
            </div>

            {/* Footer */}
            <div className="py-2 border-t border-border space-y-4">
                {/* Theme Toggle */}
                <Button
                    variant="ghost"
                    size="icon"
                    className={cn(
                        "w-full h-12 transition-all duration-300 ease-in-out flex items-center justify-start p-0 pl-0 theme-toggle-btn select-none",
                    )}
                    onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                >
                    <div className="w-16 h-12 flex items-center justify-center shrink-0">
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
                            Toggle Theme
                        </span>
                    </div>
                </Button>

                {/* Profile */}
                {currentUser && (
                    <Popover>
                        <PopoverTrigger asChild>
                            <Button variant="ghost" className={cn(
                                "w-full h-auto hover:bg-secondary/50 transition-all duration-300 ease-in-out flex items-center justify-start p-0 pl-0 select-none",
                            )}>
                                <div className="w-16 h-14 flex items-center justify-center shrink-0">
                                    <Avatar className="!h-[25px] !w-[25px] border border-border shrink-0">
                                        <AvatarImage src={currentUser.avatarUrl} />
                                        <AvatarFallback>{currentUser.username.slice(0, 2).toUpperCase()}</AvatarFallback>
                                    </Avatar>
                                </div>
                                <div className={cn(
                                    "flex flex-col items-start overflow-hidden transition-all duration-300 ease-in-out",
                                    isCollapsed ? "w-0 ml-0 delay-150" : "w-[150px]"
                                )}>
                                    <div className={cn(
                                        "w-full transition-opacity duration-300",
                                        isCollapsed ? "opacity-0" : "opacity-100 delay-150"
                                    )}>
                                        <span className="text-sm font-medium truncate w-full text-left block whitespace-nowrap">{currentUser.username}</span>
                                        <span className="text-xs text-muted-foreground truncate w-full text-left block whitespace-nowrap">View profile</span>
                                    </div>
                                </div>
                            </Button>
                        </PopoverTrigger>
                        <PopoverContent className="w-56 select-none" align={isCollapsed ? "center" : "start"} side={isCollapsed ? "right" : "top"} sideOffset={10}>
                            <div className="flex flex-col space-y-1 p-2">
                                <p className="text-sm font-medium leading-none">{currentUser.username}</p>
                            </div>
                            <Separator className="my-2" />
                            <Button variant="ghost" className="w-full justify-start text-destructive hover:text-destructive hover:bg-destructive/10" onClick={onLogout}>
                                <LogOut className="mr-2 h-4 w-4" />
                                Log out
                            </Button>
                        </PopoverContent>
                    </Popover>
                )}
            </div>
        </div>
    );
}
