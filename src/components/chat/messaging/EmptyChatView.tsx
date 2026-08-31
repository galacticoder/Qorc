import React from 'react';
import { ComposeIcon } from '../assets/icons';

interface EmptyChatViewProps {
  onCreateChat: () => void;
}

export const EmptyChatView: React.FC<EmptyChatViewProps> = ({ onCreateChat }) => {
  return (
    <div className="qorc-empty-chat">
      <div className="qorc-empty-chat-inner">
        <div className="qorc-empty-thread-preview" aria-hidden="true">
          <span className="qorc-empty-line long"></span>
          <span className="qorc-empty-line mid mine"></span>
          <span className="qorc-empty-line short"></span>
          <span className="qorc-empty-line long mine"></span>
        </div>
        <div className="qorc-empty-copy">
          <span className="qorc-empty-kicker">No chat selected</span>
          <h2>Your messages stay quiet here.</h2>
          <p>Select a conversation from the left, or start a new chat.</p>
        </div>
        <div className="qorc-empty-actions">
          <button className="qorc-empty-new-message" type="button" onClick={onCreateChat}>
            <ComposeIcon aria-hidden="true" />
            New message
          </button>
        </div>
      </div>
    </div>
  );
};
