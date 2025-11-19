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
        <div className="flex h-screen w-full bg-background overflow-hidden">
            <Sidebar
                activeTab={activeTab}
                onTabChange={onTabChange}
                currentUser={currentUser}
                onLogout={onLogout}
            />
            <main className="flex-1 h-full overflow-hidden relative flex flex-col min-w-0">
                {children}
            </main>
        </div>
    );
}
