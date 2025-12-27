import React from 'react';
import { Button } from '../../ui/button';
import { AnimatedSwitch } from '../../ui/AnimatedSwitch';

interface DownloadSettingsProps {
    downloadSettings: { downloadPath: string; autoSave: boolean };
    isChoosingPath: boolean;
    handleChooseDownloadPath: () => void;
    handleAutoSaveToggle: (autoSave: boolean) => void;
}

export const DownloadSettings = ({
    downloadSettings,
    isChoosingPath,
    handleChooseDownloadPath,
    handleAutoSaveToggle
}: DownloadSettingsProps) => {
    return (
        <div>
            <h2 className="settings-section-title">Downloads</h2>

            <div className="settings-group">
                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '12px' }}>
                    <div>
                        <div className="settings-label">Download Location</div>
                        <div className="settings-description">
                            Choose where files are saved when you download them
                        </div>
                    </div>
                    <div style={{ display: 'flex', gap: '12px', width: '100%' }}>
                        <input
                            type="text"
                            readOnly
                            value={downloadSettings.downloadPath || ''}
                            className="custom-select"
                            style={{ flex: 1 }}
                        />
                        <Button
                            onClick={handleChooseDownloadPath}
                            variant="outline"
                            disabled={isChoosingPath}
                        >
                            {isChoosingPath ? 'Choosing...' : 'Browse'}
                        </Button>
                    </div>
                </div>

                <div className="settings-row">
                    <div>
                        <div className="settings-label">Auto-save Files</div>
                        <div className="settings-description">
                            Automatically save received files to your download location
                        </div>
                    </div>
                    <AnimatedSwitch
                        checked={downloadSettings.autoSave || false}
                        onCheckedChange={handleAutoSaveToggle}
                    />
                </div>
            </div>
        </div>
    );
};

export default DownloadSettings;
