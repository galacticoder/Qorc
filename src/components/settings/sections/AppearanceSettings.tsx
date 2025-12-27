import React from 'react';

interface AppearanceSettingsProps {
    theme: string | undefined;
    setTheme: (theme: string) => void;
}

export const AppearanceSettings = ({ theme, setTheme }: AppearanceSettingsProps) => {
    return (
        <div>
            <h2 className="settings-section-title">Appearance</h2>

            <div className="settings-group">
                <div className="settings-group-title">Theme</div>
                <div className="settings-description" style={{ marginBottom: '16px' }}>
                    Choose how the app looks to you. Select a theme or sync with your system settings.
                </div>
                <div style={{ display: 'flex', gap: '12px' }}>
                    <button
                        className={`theme-option ${theme === 'light' ? 'active' : ''}`}
                        onClick={() => setTheme('light')}
                    >
                        <div className="theme-icon">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <circle cx="12" cy="12" r="5" />
                                <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
                            </svg>
                        </div>
                        <span style={{ fontSize: '13px', fontWeight: 500 }}>Light</span>
                    </button>
                    <button
                        className={`theme-option ${theme === 'dark' ? 'active' : ''}`}
                        onClick={() => setTheme('dark')}
                    >
                        <div className="theme-icon">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                            </svg>
                        </div>
                        <span style={{ fontSize: '13px', fontWeight: 500 }}>Dark</span>
                    </button>
                    <button
                        className={`theme-option ${theme === 'system' ? 'active' : ''}`}
                        onClick={() => setTheme('system')}
                    >
                        <div className="theme-icon">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                                <path d="M8 21h8M12 17v4" />
                            </svg>
                        </div>
                        <span style={{ fontSize: '13px', fontWeight: 500 }}>System</span>
                    </button>
                </div>
            </div>
        </div>
    );
};

export default AppearanceSettings;
