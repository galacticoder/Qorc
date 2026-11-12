import { useId, useLayoutEffect, useRef, useState } from 'react';
import { ChatBubbleIcon, SettingsIcon, CallIcon } from '../chat/assets/icons';
import { cn } from '@/lib/utils/shared-utils';
import { UserAvatar } from './UserAvatar';
import { useTheme } from '../../contexts/ThemeContext';
import { QorcBrandLogo } from './QorcBrandLogo';
import type { SectionNavigationMotion } from '../../lib/ui/section-navigation';

const sectionIds = ['chats', 'calls', 'settings'] as const;
type HighlightRect = { x: number; y: number; width: number; height: number };

function useNavigationHighlight(variant: string, expanded: boolean, activeTab: string, motion?: SectionNavigationMotion | null) {
    const ref = useRef<HTMLElement>(null);
    const [rects, setRects] = useState<HighlightRect[]>([]);
    useLayoutEffect(() => {
        const element = ref.current;
        if (!element) return;
        const measure = () => {
            const parent = element.getBoundingClientRect();
            const next = sectionIds.map(id => {
                const rect = element.querySelector<HTMLElement>(`[data-nav-section="${id}"]`)!.getBoundingClientRect();
                return { x: rect.left - parent.left, y: rect.top - parent.top, width: rect.width, height: rect.height };
            });
            setRects(previous => JSON.stringify(previous) === JSON.stringify(next) ? previous : next);
        };
        measure();
        const observer = new ResizeObserver(measure);
        observer.observe(element);
        element.querySelectorAll('[data-nav-section]').forEach(button => observer.observe(button));
        window.addEventListener('resize', measure);
        return () => { observer.disconnect(); window.removeEventListener('resize', measure); };
    }, [variant, expanded]);
    const index = Math.max(0, Math.min(2, motion?.index ?? sectionIds.indexOf(activeTab as typeof sectionIds[number])));
    const from = rects[Math.floor(index)], to = rects[Math.ceil(index)];
    const amount = index % 1;
    const mix = (key: keyof HighlightRect) => from[key] + (to[key] - from[key]) * amount;
    const highlight = <span aria-hidden="true" className="qorc-nav-highlight" style={from && to ? {
        width: mix('width'), height: mix('height'), transform: `translate3d(${mix('x')}px, ${mix('y')}px, 0)`,
    } : { display: 'none' }} />;
    return { ref, highlight };
}

interface SidebarProps {
    variant?: 'sidebar' | 'top' | 'bottom';
    activeTab: 'chats' | 'calls' | 'settings';
    onTabChange: (tab: 'chats' | 'calls' | 'settings') => void;
    navigationMotion?: SectionNavigationMotion | null;
    currentUser: {
        username: string;
        avatarUrl?: string;
    };
}

export function Sidebar({ variant = 'sidebar', activeTab, onTabChange, currentUser, navigationMotion }: SidebarProps) {
    const { theme, resolvedTheme, setTheme } = useTheme();
    const themeMaskId = useId();
    const [isCollapsed, setIsCollapsed] = useState(true);
    const { ref: navigationRef, highlight } = useNavigationHighlight(variant, !isCollapsed, activeTab, navigationMotion);
    const activeTheme = theme === 'system' ? resolvedTheme : theme;

    const navItems = [
        { id: 'chats', icon: ChatBubbleIcon, label: 'Chats' },
        { id: 'calls', icon: CallIcon, label: 'Calls' },
    ] as const;

    if (variant === 'bottom') {
        const mobileItems = [
            { id: 'chats', icon: ChatBubbleIcon, label: 'Chats' },
            { id: 'calls', icon: CallIcon, label: 'Calls' },
            { id: 'settings', icon: SettingsIcon, label: 'Settings' },
        ] as const;
        return (
            <nav ref={navigationRef} className="qorc-bottom-nav" aria-label="Qorc sections" data-nav-motion={navigationMotion?.phase ?? 'idle'}>
                {highlight}
                {mobileItems.map(item => (
                    <button key={item.id} data-nav-section={item.id} type="button" className={cn('qorc-bottom-nav-button', activeTab === item.id && 'is-active')}
                        onClick={() => onTabChange(item.id)} aria-pressed={activeTab === item.id}>
                        <item.icon className={activeTab === item.id ? 'fill-current' : 'fill-none'} width={23} height={23} strokeWidth={2} aria-hidden="true" />
                        <span>{item.label}</span>
                    </button>
                ))}
            </nav>
        );
    }

    const themeIcon = (
        <span className="themeToggle st-sunMoonThemeToggleBtn" aria-hidden="true">
            <input
                type="checkbox"
                className="themeToggleInput"
                checked={activeTheme === 'light'}
                readOnly
            />
            <svg width="22" height="22" viewBox="0 0 20 20" fill="currentColor" stroke="none">
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
                <circle className="sunMoon" cx="10" cy="10" r="8" mask={`url(#${themeMaskId})`}></circle>
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
    );

    if (variant === 'top') {
        return (
            <header className="qorc-top-nav">
                <div className="qorc-top-nav-cluster">
                    <div className="qorc-top-nav-brand" aria-hidden="true">
                        <QorcBrandLogo className="brand-square qorc-brand-square" imageClassName="qorc-brand-logo" />
                    </div>
                    <nav ref={navigationRef} className="qorc-top-nav-sections" aria-label="Qorc sections" data-nav-motion={navigationMotion?.phase ?? 'idle'}>
                        {highlight}
                        {navItems.map((item) => (
                            <button
                                key={item.id}
                                data-nav-section={item.id}
                                type="button"
                                onClick={() => onTabChange(item.id)}
                                className={cn("qorc-top-nav-button", activeTab === item.id && "is-active")}
                                aria-label={item.label}
                                title={item.label}
                                aria-pressed={activeTab === item.id}
                            >
                                <item.icon
                                    className={cn("qorc-top-nav-icon", activeTab === item.id ? "fill-current" : "fill-none")}
                                    width={22}
                                    height={22}
                                    strokeWidth={activeTab === item.id ? 2.5 : 2}
                                    aria-hidden="true"
                                />
                            </button>
                        ))}
                        <button
                            type="button"
                            onClick={() => onTabChange('settings')}
                            className={cn("qorc-top-nav-button qorc-top-nav-settings", activeTab === 'settings' && "is-active")}
                            data-nav-section="settings"
                            aria-label="Settings"
                            title="Settings"
                            aria-pressed={activeTab === 'settings'}
                        >
                            <SettingsIcon
                                className={cn("qorc-top-nav-icon", activeTab === 'settings' ? "fill-current" : "fill-none")}
                                width={22}
                                height={22}
                                strokeWidth={activeTab === 'settings' ? 2.5 : 2}
                                aria-hidden="true"
                            />
                        </button>
                        <button
                            type="button"
                            className="qorc-top-nav-button qorc-top-nav-theme theme-toggle-btn"
                            onClick={() => setTheme(activeTheme === 'dark' ? 'light' : 'dark')}
                            aria-label={activeTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
                            title="Theme"
                        >
                            {themeIcon}
                        </button>
                        {currentUser && (
                            <div
                                className="qorc-top-nav-profile"
                                role="img"
                                aria-label={currentUser.username}
                                title={currentUser.username}
                            >
                                <UserAvatar username={currentUser.username} isCurrentUser={true} size="sm" />
                            </div>
                        )}
                    </nav>
                </div>
            </header>
        );
    }

    return (
        <aside ref={navigationRef} className={cn("qorc-rail", !isCollapsed && "is-expanded")} data-nav-motion={navigationMotion?.phase ?? 'idle'}>
            {highlight}
            <button
                type="button"
                className="qorc-rail-row qorc-rail-head"
                onClick={() => setIsCollapsed(!isCollapsed)}
                title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
                aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
                <span className="qorc-rail-icon-slot">
                    <QorcBrandLogo className="brand-square qorc-brand-square" imageClassName="qorc-brand-logo" />
                </span>
                <span className="qorc-rail-label qorc-brand-label">Qorc</span>
            </button>

            <div className="qorc-rail-spacer">
                {navItems.map((item) => (
                    <button
                        key={item.id}
                        data-nav-section={item.id}
                        type="button"
                        onClick={() => onTabChange(item.id)}
                        className={cn(
                            "qorc-rail-row qorc-rail-button",
                            activeTab === item.id && "is-active"
                        )}
                        aria-pressed={activeTab === item.id}
                    >
                        <span className="qorc-rail-icon-slot">
                            <item.icon
                                className={cn(
                                    "qorc-rail-icon",
                                    activeTab === item.id ? "fill-current" : "fill-none"
                                )}
                                width={22}
                                height={22}
                                strokeWidth={activeTab === item.id ? 2.5 : 2}
                                aria-hidden="true"
                            />
                        </span>
                        <span className="qorc-rail-label">{item.label}</span>
                    </button>
                ))}
            </div>

            <div className="qorc-rail-foot">
                <button
                    type="button"
                    onClick={() => onTabChange('settings')}
                    className={cn(
                        "qorc-rail-row qorc-rail-button",
                        activeTab === 'settings' && "is-active"
                    )}
                    aria-pressed={activeTab === 'settings'}
                    data-nav-section="settings"
                >
                    <span className="qorc-rail-icon-slot">
                        <SettingsIcon
                            className={cn(
                                "qorc-rail-icon",
                                activeTab === 'settings' ? "fill-current" : "fill-none"
                            )}
                            width={22}
                            height={22}
                            strokeWidth={activeTab === 'settings' ? 2.5 : 2}
                            aria-hidden="true"
                        />
                    </span>
                    <span className="qorc-rail-label">Settings</span>
                </button>

                <button
                    type="button"
                    className="qorc-rail-row qorc-rail-theme theme-toggle-btn"
                    onClick={() => setTheme(activeTheme === 'dark' ? 'light' : 'dark')}
                    aria-label={activeTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
                >
                    <span className="qorc-rail-icon-slot">
                        {themeIcon}
                    </span>
                    <span className="qorc-rail-label">Theme</span>
                </button>

                {currentUser && (
                    <div
                        className="qorc-rail-row qorc-rail-profile"
                        role="img"
                        aria-label={currentUser.username}
                        title={currentUser.username}
                    >
                        <span className="qorc-rail-icon-slot">
                            <UserAvatar
                                username={currentUser.username}
                                isCurrentUser={true}
                                size="sm"
                            />
                        </span>
                        <span className="qorc-rail-label qorc-profile-name">{currentUser.username}</span>
                    </div>
                )}
            </div>
        </aside>
    );
}
