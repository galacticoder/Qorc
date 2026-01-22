import React, { useState, useEffect } from 'react';
import { AnimatedSwitch } from '../../ui/AnimatedSwitch';
import { tray } from '../../../lib/tauri-bindings';

export const GeneralSettings = () => {
    const [closeToTray, setCloseToTray] = useState(true);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        tray.getCloseToTray()
            .then(value => {
                setCloseToTray(value);
                setLoading(false);
            })
            .catch(() => setLoading(false));
    }, []);

    const handleCloseToTrayChange = async (enabled: boolean) => {
        setCloseToTray(enabled);
        try {
            await tray.setCloseToTray(enabled);
        } catch {
            setCloseToTray(!enabled);
        }
    };

    return (
        <div>
            <h2 className="settings-section-title">General</h2>

            <div className="settings-group">
                <div className="settings-row">
                    <div>
                        <div className="settings-label">Minimize to system tray on close</div>
                        <div className="settings-description">
                            When enabled, closing the window keeps the app running in the background
                        </div>
                    </div>
                    <AnimatedSwitch
                        checked={closeToTray}
                        onCheckedChange={handleCloseToTrayChange}
                    />
                </div>
            </div>
        </div>
    );
};

export default GeneralSettings;
