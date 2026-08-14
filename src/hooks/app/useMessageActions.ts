import { useCallback } from 'react';
import { Message, MessageReply } from '../../components/chat/messaging/types';
import { SignalType } from '../../lib/types/signal-types';
import { toast } from 'sonner';
import type { UserWithKeys } from '../../lib/types/message-sending-types';

interface MessageActionsProps {
  selectedConversation: string | null;
  getOrCreateUser: (username: string) => UserWithKeys;
  messageSender: {
    handleSendMessage: (
      targetUser: UserWithKeys,
      content: string,
      replyTo?: string | { id: string; sender?: string; content?: string },
      messageSignalType?: string,
      originalMessageId?: string,
    ) => Promise<void>;
  };
  p2pMessaging: {
    isPeerConnected: (peer: string) => boolean;
    connectToPeer: (peer: string) => Promise<void>;
  };
}

export function useMessageActions({
  selectedConversation,
  getOrCreateUser,
  messageSender,
  p2pMessaging,
}: MessageActionsProps) {
  const onSendMessage = useCallback(async (
    messageId: string,
    content: string,
    messageSignalType: string,
    replyTo?: MessageReply | null,
  ) => {
    if (!selectedConversation) return;

    const targetUser = getOrCreateUser(selectedConversation);
    const replyToMessage = replyTo ? {
      id: replyTo.id,
      sender: replyTo.sender,
      content: replyTo.content,
      timestamp: new Date(),
      type: SignalType.TEXT as const,
      isCurrentUser: false,
    } as Message : undefined;

    if (!p2pMessaging.isPeerConnected(selectedConversation)) {
      void p2pMessaging.connectToPeer(selectedConversation).catch(() => {});
    }

    try {
      await messageSender.handleSendMessage(
        targetUser,
        content,
        replyToMessage,
        messageSignalType,
        messageId || undefined,
      );
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error || '');
      const retryable = /not ready|not connected|no p2p|connecting|establish|transport|not confirmed|session|encryption|account changed/i.test(detail);
      if (!retryable) toast.error(detail || 'Failed to send message', { duration: 5000 });
    }
  }, [selectedConversation, getOrCreateUser, messageSender, p2pMessaging]);

  return { onSendMessage };
}
