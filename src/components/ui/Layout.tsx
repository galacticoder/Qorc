import React, { useCallback, useEffect, useState } from 'react';
import { Sidebar } from './Sidebar';
import { readNavigationLayout, type NavigationLayout } from '../../lib/ui/navigation-layout';
import { EventType } from '../../lib/types/event-types';
import { syncEncryptedStorage } from '../../lib/database/encrypted-storage';
import { useMobileLayout } from '../../hooks/useMobileLayout';
import { ScreenContext } from './StandaloneScreen';
import { SectionNavigationContext, type SectionNavigationMotion } from '../../lib/ui/section-navigation';

interface LayoutProps {
    children: React.ReactNode;
    activeTab: 'chats' | 'calls' | 'settings';
    onTabChange: (tab: 'chats' | 'calls' | 'settings') => void;
    conversationOpen?: boolean;
    standaloneScreenOpen?: boolean;
    currentUser: {
        username: string;
        avatarUrl?: string;
    };
}

export function Layout({
    children,
    activeTab,
    onTabChange,
    conversationOpen = false,
    standaloneScreenOpen = false,
    currentUser
}: LayoutProps) {
    const [navigationLayout, setNavigationLayout] = useState<NavigationLayout>(readNavigationLayout);
    const mobile = useMobileLayout();
    const [screens, setScreens] = useState<Set<symbol>>(() => new Set());
    const [navigationMotion, setNavigationMotion] = useState<SectionNavigationMotion | null>(null);
    const registerScreen = useCallback((id: symbol, open: boolean) => {
        setScreens(previous => {
            if (previous.has(id) === open) return previous;
            const next = new Set(previous);
            if (open) next.add(id); else next.delete(id);
            return next;
        });
    }, []);
    const effectiveLayout = mobile ? 'bottom' : navigationLayout;
    const screenOpen = standaloneScreenOpen || screens.size > 0;
    const hideNavigation = mobile && (screenOpen || (activeTab === 'chats' && conversationOpen));

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
        <ScreenContext.Provider value={registerScreen}><SectionNavigationContext.Provider value={setNavigationMotion}><div className={`qorc-app-shell${mobile ? ' is-mobile' : ''} ${effectiveLayout === 'top' ? 'qorc-has-top-nav' : effectiveLayout === 'bottom' ? 'qorc-has-bottom-nav' : ''}`}>
            {!hideNavigation && <Sidebar
                variant={effectiveLayout}
                activeTab={activeTab}
                onTabChange={onTabChange}
                currentUser={currentUser}
                navigationMotion={navigationMotion}
            />}
            <main className="qorc-main-pane">
                <div className="qorc-primary-screen" inert={screenOpen}>{children}</div>
            </main>
        </div></SectionNavigationContext.Provider></ScreenContext.Provider>
    );
}
