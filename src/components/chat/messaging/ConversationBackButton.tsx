import { ArrowLeft } from 'lucide-react';

export function ConversationBackButton({ onBack }: { onBack: () => void }) {
  return (
    <button type="button" className="qorc-chat-back" onClick={onBack} aria-label="Back to conversations">
      <ArrowLeft size={22} aria-hidden="true" />
    </button>
  );
}
