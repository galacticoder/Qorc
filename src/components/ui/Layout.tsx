import React from 'react';
import { Sidebar } from './Sidebar';

interface LayoutProps {
    children: React.ReactNode;
    activeTab: 'chats' | 'calls' | 'settings';
    onTabChange: (tab: 'chats' | 'calls' | 'settings') => void;
    currentUser?: {
        username: string;
        avatarUrl?: string;
    };
    onLogout?: () => void;
}

export function Layout({
    children,
    activeTab,
    onTabChange,
    currentUser,
    onLogout
}: LayoutProps) {
    return (
        <div className="qor-app-shell">
            <Sidebar
                activeTab={activeTab}
                onTabChange={onTabChange}
                currentUser={currentUser}
                onLogout={onLogout}
            />
            <main className="qor-main-pane">
                {children}
            </main>
        </div>
    );
}
