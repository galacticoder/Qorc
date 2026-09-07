import React, { useEffect, useState } from 'react';
import { Sidebar } from './Sidebar';
import { readNavigationLayout, type NavigationLayout } from '../../lib/ui/navigation-layout';
import { EventType } from '../../lib/types/event-types';
import { syncEncryptedStorage } from '../../lib/database/encrypted-storage';

interface LayoutProps {
    children: React.ReactNode;
    activeTab: 'chats' | 'calls' | 'settings';
    onTabChange: (tab: 'chats' | 'calls' | 'settings') => void;
    currentUser: {
        username: string;
        avatarUrl?: string;
    };
    onLogout: () => void;
}

export function Layout({
    children,
    activeTab,
    onTabChange,
    currentUser,
    onLogout
}: LayoutProps) {
    const [navigationLayout, setNavigationLayout] = useState<NavigationLayout>(readNavigationLayout);

    useEffect(() => {
        const refreshLayout = () => setNavigationLayout(readNavigationLayout());
        const handleLayoutChange = (event: Event) => {
            const layout = event instanceof CustomEvent ? event.detail?.layout : null;
            setNavigationLayout(layout === 'top' ? 'top' : layout === 'sidebar' ? 'sidebar' : readNavigationLayout());
        };
        const unsubscribe = syncEncryptedStorage.subscribe(refreshLayout);
        window.addEventListener(EventType.NAVIGATION_LAYOUT_CHANGED, handleLayoutChange);
        return () => {
            unsubscribe();
            window.removeEventListener(EventType.NAVIGATION_LAYOUT_CHANGED, handleLayoutChange);
        };
    }, []);

    return (
        <div className={`qorc-app-shell ${navigationLayout === 'top' ? 'qorc-has-top-nav' : ''}`}>
            <Sidebar
                variant={navigationLayout}
                activeTab={activeTab}
                onTabChange={onTabChange}
                currentUser={currentUser}
                onLogout={onLogout}
            />
            <main className="qorc-main-pane">
                {children}
            </main>
        </div>
    );
}
