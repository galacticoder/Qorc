import React from 'react';
import { AnimatedSwitch } from '../../ui/AnimatedSwitch';

interface AudioSettingsProps {
    audioSettings: { noiseSuppression: boolean; echoCancellation: boolean };
    setAudioSettings: (settings: { noiseSuppression: boolean; echoCancellation: boolean }) => void;
    saveSettings: (updates: any) => void;
    preferredMicId: string;
    setPreferredMicId: (id: string) => void;
    preferredSpeakerId: string;
    setPreferredSpeakerId: (id: string) => void;
    preferredCameraId: string;
    setPreferredCameraId: (id: string) => void;
    micDevices: MediaDeviceInfo[];
    speakerDevices: MediaDeviceInfo[];
    cameraDevices: MediaDeviceInfo[];
}

export const AudioSettings = ({
    audioSettings,
    setAudioSettings,
    saveSettings,
    preferredMicId,
    setPreferredMicId,
    preferredSpeakerId,
    setPreferredSpeakerId,
    preferredCameraId,
    setPreferredCameraId,
    micDevices,
    speakerDevices,
    cameraDevices
}: AudioSettingsProps) => {
    return (
        <div>
            <h2 className="settings-section-title">Audio</h2>

            <div className="settings-group">
                <div className="settings-group-title">Voice Processing</div>

                <div className="settings-row">
                    <div>
                        <div className="settings-label">Noise Suppression</div>
                        <div className="settings-description">
                            Filter out background noise during calls for clearer audio
                        </div>
                    </div>
                    <AnimatedSwitch
                        checked={audioSettings.noiseSuppression}
                        onCheckedChange={(checked) => {
                            const updated = { ...audioSettings, noiseSuppression: checked };
                            setAudioSettings(updated);
                            saveSettings({ audioSettings: updated });
                        }}
                    />
                </div>

                <div className="settings-row">
                    <div>
                        <div className="settings-label">Echo Cancellation</div>
                        <div className="settings-description">
                            Reduce echo and feedback during voice calls
                        </div>
                    </div>
                    <AnimatedSwitch
                        checked={audioSettings.echoCancellation}
                        onCheckedChange={(checked) => {
                            const updated = { ...audioSettings, echoCancellation: checked };
                            setAudioSettings(updated);
                            saveSettings({ audioSettings: updated });
                        }}
                    />
                </div>
            </div>

            <div className="settings-group">
                <div className="settings-group-title">Device Selection</div>

                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: '8px' }}>
                    <div>
                        <div className="settings-label">Microphone</div>
                        <div className="settings-description">Default microphone for calls and voice messages</div>
                    </div>
                    <select
                        value={preferredMicId}
                        onChange={(e) => {
                            setPreferredMicId(e.target.value);
                            saveSettings({ preferredMicId: e.target.value });
                        }}
                        className="settings-select"
                    >
                        <option value="">System Default</option>
                        {micDevices.map(d => (
                            <option key={d.deviceId} value={d.deviceId}>
                                {d.label || `Microphone ${d.deviceId.slice(0, 8)}`}
                            </option>
                        ))}
                    </select>
                </div>

                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: '8px' }}>
                    <div>
                        <div className="settings-label">Speaker</div>
                        <div className="settings-description">Default speaker for call audio output</div>
                    </div>
                    <select
                        value={preferredSpeakerId}
                        onChange={(e) => {
                            setPreferredSpeakerId(e.target.value);
                            saveSettings({ preferredSpeakerId: e.target.value });
                        }}
                        className="settings-select"
                    >
                        <option value="">System Default</option>
                        {speakerDevices.map(d => (
                            <option key={d.deviceId} value={d.deviceId}>
                                {d.label || `Speaker ${d.deviceId.slice(0, 8)}`}
                            </option>
                        ))}
                    </select>
                </div>

                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: '8px' }}>
                    <div>
                        <div className="settings-label">Camera</div>
                        <div className="settings-description">Default camera for video calls</div>
                    </div>
                    <select
                        value={preferredCameraId}
                        onChange={(e) => {
                            setPreferredCameraId(e.target.value);
                            saveSettings({ preferredCameraId: e.target.value });
                        }}
                        className="settings-select"
                    >
                        <option value="">System Default</option>
                        {cameraDevices.map(d => (
                            <option key={d.deviceId} value={d.deviceId}>
                                {d.label || `Camera ${d.deviceId.slice(0, 8)}`}
                            </option>
                        ))}
                    </select>
                </div>
            </div>
        </div>
    );
};

export default AudioSettings;
