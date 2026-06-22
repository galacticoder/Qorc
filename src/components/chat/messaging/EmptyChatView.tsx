import React from 'react';
import { ComposeIcon } from '../assets/icons';

interface EmptyChatViewProps {
  onCreateChat: () => void;
}

export const EmptyChatView: React.FC<EmptyChatViewProps> = ({ onCreateChat }) => {
  return (
    <div className="qor-empty-chat">
      <div className="qor-empty-chat-inner">
        <div className="qor-empty-thread-preview" aria-hidden="true">
          <span className="qor-empty-line long"></span>
          <span className="qor-empty-line mid mine"></span>
          <span className="qor-empty-line short"></span>
          <span className="qor-empty-line long mine"></span>
        </div>
        <div className="qor-empty-copy">
          <span className="qor-empty-kicker">No chat selected</span>
          <h2>Your messages stay quiet here.</h2>
          <p>Select a conversation from the left, or start a new chat.</p>
        </div>
        <div className="qor-empty-actions">
          <button className="qor-empty-new-message" type="button" onClick={onCreateChat}>
            <ComposeIcon aria-hidden="true" />
            New message
          </button>
        </div>
      </div>
    </div>
  );
};
