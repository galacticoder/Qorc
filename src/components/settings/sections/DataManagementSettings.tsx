import React from 'react';
import { Button } from '../../ui/button';

interface DataManagementSettingsProps {
    handleClearData: () => void;
    isClearingData: boolean;
}

export const DataManagementSettings = ({ handleClearData, isClearingData }: DataManagementSettingsProps) => {
    return (
        <div>
            <h2 className="settings-section-title">Data Management</h2>

            <div className="settings-group">
                <div className="danger-zone">
                    <div className="settings-label" style={{ color: 'hsl(0 70% 50%)' }}>
                        Clear All Data
                    </div>
                    <div className="settings-description" style={{ marginBottom: '16px' }}>
                        This will permanently delete all your messages, conversations, and settings.
                        You will be logged out and this action cannot be undone.
                    </div>
                    <Button
                        variant="destructive"
                        onClick={handleClearData}
                        disabled={isClearingData}
                    >
                        {isClearingData ? 'Clearing...' : 'Clear All Data'}
                    </Button>
                </div>
            </div>
        </div>
    );
};

export default DataManagementSettings;
