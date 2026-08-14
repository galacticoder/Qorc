import React from 'react';
import { Message } from '../../components/chat/messaging/types';

export type PeekableSetMessages =
  React.Dispatch<React.SetStateAction<Message[]>> & { __peek?: () => Message[] };

export function setMessagesWithResult<T>(
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  transform: (prev: Message[]) => { next: Message[]; result: T }
): Promise<T> {
  const peek = (setMessages as PeekableSetMessages).__peek;
  if (!peek) {
    return Promise.reject(new Error('Message state setter has no synchronous owner'));
  }
  const { next, result } = transform(peek());
  setMessages(next);
  return Promise.resolve(result);
}
