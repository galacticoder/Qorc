import { Mic } from 'lucide-react';

interface VoiceRecorderButtonProps {
  readonly onClick: () => void;
  readonly disabled?: boolean;
}

export function VoiceRecorderButton({ onClick, disabled }: VoiceRecorderButtonProps) {
  return <button type="button" className="qorc-composer-icon-btn qorc-voice-button" onClick={onClick} disabled={disabled} title="Record voice message" aria-label="Record voice message"><Mic aria-hidden="true" /></button>;
}
