import { useEffect, useCallback } from 'react';
import { Message } from '@/components/chat/types';
import { SignalType } from '@/lib/signals';
import websocketClient from '@/lib/websocket';

export function useMessageReceipts(
	messages: Message[],
	setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
	currentUsername: string,
	sendEncryptedMessage: (messageId: string, content: string, messageSignalType: string, replyTo?: any) => Promise<void>
) {
	// Send read receipt when message is viewed (as encrypted message to hide from server)
	const sendReadReceipt = useCallback(async (messageId: string, sender: string) => {
		if (sender === currentUsername) return; // Don't send receipt for own messages

		try {
			// Send as encrypted message to hide read status from server
			await sendEncryptedMessage(
				crypto.randomUUID(),
				JSON.stringify({ type: 'read-receipt', messageId, timestamp: Date.now() }),
				'read-receipt'
			);
		} catch (error) {
			console.error('Failed to send read receipt:', error);
		}
	}, [currentUsername, sendEncryptedMessage]);

	// Mark message as read
	const markMessageAsRead = useCallback((messageId: string) => {
		setMessages(prev => prev.map(msg =>
			msg.id === messageId && !msg.receipt?.read && msg.sender !== currentUsername
				? {
					...msg,
					receipt: {
						...msg.receipt,
						read: true,
						readAt: new Date()
					}
				}
				: msg
		));
	}, [setMessages, currentUsername]);

	// Smart status management: show read status on most recent read message, delivery on latest message
	const getSmartReceiptStatus = useCallback((message: Message) => {
		// Only process messages sent by the current user (to show receipt status)
		if (!message.receipt || message.sender !== currentUsername) return message.receipt;

		// Find messages from this user
		const userMessages = messages.filter(m => m.sender === currentUsername);
		const latestMessage = userMessages[userMessages.length - 1];

		// Find the most recent read message from this user
		const mostRecentReadMessage = userMessages
			.filter(m => m.receipt?.read)
			.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0];

		// If this message is read and it's the most recent read message, show read status
		if (message.receipt?.read && message.id === mostRecentReadMessage?.id) {
			return message.receipt;
		}

		// If this is the latest message and it's not read, show delivery status
		if (message.id === latestMessage.id && !message.receipt?.read) {
			return message.receipt;
		}

		// For all other messages, don't show any receipt status
		return undefined;
	}, [messages, currentUsername]);

	// Handle delivery receipts from other users
	useEffect(() => {
		const handleDeliveryReceipt = (event: CustomEvent) => {
			const { messageId, from } = event.detail;
			console.debug('[Receipt] Received delivery receipt:', { messageId, from });

			setMessages(prev => {
				return prev.map(msg =>
					msg.id === messageId && msg.sender === currentUsername
						? {
							...msg,
							receipt: {
								...msg.receipt,
								delivered: true,
								deliveredAt: new Date()
							}
						}
						: msg
				);
			});
		};

		window.addEventListener('message-delivered', handleDeliveryReceipt as EventListener);

		return () => {
			window.removeEventListener('message-delivered', handleDeliveryReceipt as EventListener);
		};
	}, [currentUsername, setMessages]);

	// Handle read receipts from other users
	useEffect(() => {
		const handleReadReceipt = (event: CustomEvent) => {
			const { messageId, from } = event.detail;
			console.debug('[Receipt] Received read receipt:', { messageId, from });

			setMessages(prev => {
				return prev.map(msg =>
					msg.id === messageId && msg.sender === currentUsername
						? {
							...msg,
							receipt: {
								...msg.receipt,
								read: true,
								readAt: new Date()
							}
						}
						: msg
				);
			});
		};

		window.addEventListener('message-read', handleReadReceipt as EventListener);

		return () => {
			window.removeEventListener('message-read', handleReadReceipt as EventListener);
		};
	}, [currentUsername, setMessages]);

	return {
		sendReadReceipt,
		markMessageAsRead,
		getSmartReceiptStatus
	};
}
