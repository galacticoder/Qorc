import React from 'react';
import { ComposeIcon } from '../assets/icons';
import { QorcBrandLogo } from '../../ui/QorcBrandLogo';

interface EmptyChatViewProps {
  onCreateChat: () => void;
}

export const EmptyChatView: React.FC<EmptyChatViewProps> = ({ onCreateChat }) => {
  return (
    <div className="qorc-empty-chat">
      <div className="qorc-empty-chat-inner">
        <div className="qorc-empty-bubbles" aria-hidden="true">
          <div className="qorc-empty-preview-message is-received">
            <span className="qorc-empty-preview-person" />
            <span className="qorc-empty-preview-bubble is-wide"><i /><i /></span>
          </div>
          <div className="qorc-empty-preview-message is-sent">
            <span className="qorc-empty-preview-bubble is-medium"><i /><i /></span>
          </div>
          <div className="qorc-empty-preview-message is-received">
            <span className="qorc-empty-preview-person is-alt" />
            <span className="qorc-empty-preview-bubble is-short"><i /><i /></span>
          </div>
        </div>

        <div className="qorc-empty-intro">
          <QorcBrandLogo className="qorc-empty-brand" imageClassName="qorc-empty-brand-image" />
          <div className="qorc-empty-copy">
            <h2>Select a conversation</h2>
            <p>Choose an existing chat or start a new conversation.</p>
          </div>
          <button className="qorc-empty-new-message" type="button" onClick={onCreateChat}>
            <ComposeIcon aria-hidden="true" />
            New conversation
          </button>
        </div>
      </div>
    </div>
  );
};
