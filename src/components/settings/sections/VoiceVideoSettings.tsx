import React from 'react';
import { Button } from '../../ui/button';
import { screenSharingSettings } from '../../../lib/screen-sharing-settings';
import { SCREEN_SHARING_RESOLUTIONS, SCREEN_SHARING_FRAMERATES } from '../../../lib/screen-sharing-consts';
import {
    QUALITY_OPTIONS,
    QUALITY_LABELS,
    QualityOption
} from '../../../lib/constants';

interface VoiceVideoSettingsProps {
    screenSettings: any;
}

export const VoiceVideoSettings = ({ screenSettings }: VoiceVideoSettingsProps) => {
    return (
        <div>
            <h2 className="settings-section-title">Voice & Video</h2>

            <div className="settings-group">
                <div className="settings-group-title">Screen Sharing</div>

                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '12px' }}>
                    <div>
                        <div className="settings-label">Resolution</div>
                        <div className="settings-description">
                            {screenSettings.resolution.isNative
                                ? 'Uses your display\'s native resolution'
                                : `Fixed resolution: ${screenSettings.resolution.width} × ${screenSettings.resolution.height}`}
                        </div>
                    </div>
                    <select
                        className="custom-select"
                        value={screenSettings.resolution.id}
                        onChange={(e) => {
                            const resolution = SCREEN_SHARING_RESOLUTIONS.find(r => r.id === e.target.value);
                            if (resolution) screenSharingSettings.setResolution(resolution);
                        }}
                    >
                        {SCREEN_SHARING_RESOLUTIONS.map((res) => (
                            <option key={res.id} value={res.id}>{res.name}</option>
                        ))}
                    </select>
                </div>

                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '12px' }}>
                    <div>
                        <div className="settings-label">Frame Rate</div>
                        <div className="settings-description">
                            Higher frame rates provide smoother video but use more bandwidth
                        </div>
                    </div>
                    <select
                        className="custom-select"
                        value={screenSettings.frameRate.toString()}
                        onChange={(e) => {
                            const frameRate = Number.parseInt(e.target.value, 10);
                            if (SCREEN_SHARING_FRAMERATES.includes(frameRate as any)) {
                                screenSharingSettings.setFrameRate(frameRate);
                            }
                        }}
                    >
                        {SCREEN_SHARING_FRAMERATES.map((fps) => (
                            <option key={fps} value={fps.toString()}>{fps} FPS</option>
                        ))}
                    </select>
                </div>

                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '12px' }}>
                    <div>
                        <div className="settings-label">Quality</div>
                        <div className="settings-description">
                            Balance between video quality and bandwidth usage
                        </div>
                    </div>
                    <select
                        className="custom-select"
                        value={screenSettings.quality}
                        onChange={(e) => {
                            const quality = e.target.value as QualityOption;
                            screenSharingSettings.setQuality(quality);
                        }}
                    >
                        {QUALITY_OPTIONS.map((q) => (
                            <option key={q} value={q}>{QUALITY_LABELS[q]}</option>
                        ))}
                    </select>
                </div>

                <div style={{ paddingTop: '16px' }}>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => screenSharingSettings.resetToDefaults()}
                    >
                        Reset to Defaults
                    </Button>
                </div>
            </div>
        </div>
    );
};

export default VoiceVideoSettings;
