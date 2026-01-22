import React from 'react';

interface EmptyChatViewProps {
  onCreateChat: () => void;
}

export const EmptyChatView: React.FC<EmptyChatViewProps> = ({ onCreateChat }) => {
  return (
    <div className="flex-1 flex items-center justify-center bg-background select-none">
      <div className="text-center px-6 max-w-md">
        <div
          className="flex items-center justify-center"
          style={{
            color: '#262626',
            fontSize: '4rem',
            marginBottom: '1.5rem'
          }}
        >
          <i className="fas fa-comments"></i>
        </div>
        <h2
          className="font-semibold tracking-tight"
          style={{
            fontSize: '1.5rem',
            marginBottom: '0.75rem',
            fontFamily: 'Inter, -apple-system, system-ui, sans-serif'
          }}
        >
          Your Messages
        </h2>
        <p
          style={{
            color: '#8e8e93',
            marginBottom: '1.5rem',
            fontFamily: 'Inter, -apple-system, system-ui, sans-serif'
          }}
        >
          Select a chat or start a new conversation
        </p>
        <button
          onClick={onCreateChat}
          style={{
            backgroundColor: '#0088cc',
            color: 'white',
            padding: '0.75rem 1.5rem',
            borderRadius: '10px',
            fontWeight: '600',
            border: 'none',
            transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
            cursor: 'pointer'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = '#0099e6';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = '#0088cc';
          }}
        >
          New Message
        </button>
      </div>
    </div>
  );
};
