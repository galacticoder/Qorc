import type { ReactNode } from 'react';

interface ConversationWorkspaceProps {
  mobile: boolean;
  selectedConversation: string | null;
  panelWidth: number;
  list: ReactNode;
  children: ReactNode;
}

export function ConversationWorkspace({ mobile, selectedConversation, panelWidth, list, children }: ConversationWorkspaceProps) {
  return (
    <div className={`qorc-conversation-workspace${mobile ? ' is-mobile' : ''}`}>
      <div
        className={mobile && selectedConversation ? 'hidden' : 'qorc-conversations-panel flex flex-col relative'}
        style={mobile ? undefined : { width: `${panelWidth}px` }}
      >
        {list}
      </div>
      {(!mobile || selectedConversation) && <div className="qorc-pane">{children}</div>}
    </div>
  );
}
