import { useEffect, useCallback, useRef } from 'react';
import { Message } from '@/components/chat/types';
import { SignalType } from '@/lib/signals';
import websocketClient from '@/lib/websocket';

export function useMessageReceipts(
	messages: Message[],
	setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
	currentUsername: string,
	sendEncryptedMessage: (messageId: string, content: string, messageSignalType: string, replyTo?: any) => Promise<void>,
	saveMessageToLocalDB: (msg: Message) => Promise<void>
) {
	// Track which messages have already had read receipts sent to avoid duplicates
	const sentReadReceiptsRef = useRef<Set<string>>(new Set());

	// Load sent read receipts from localStorage on mount
	useEffect(() => {
		const stored = localStorage.getItem(`sentReadReceipts_${currentUsername}`);
		if (stored) {
			try {
				const receipts = JSON.parse(stored);
				sentReadReceiptsRef.current = new Set(receipts);
			} catch (error) {
				console.error('Failed to load sent read receipts:', error);
			}
		}
	}, [currentUsername]);

	// Save sent read receipts to localStorage
	const saveSentReadReceipts = useCallback(() => {
		try {
			localStorage.setItem(
				`sentReadReceipts_${currentUsername}`,
				JSON.stringify(Array.from(sentReadReceiptsRef.current))
			);
		} catch (error) {
			console.error('Failed to save sent read receipts:', error);
		}
	}, [currentUsername]);

	// Send read receipt when message is viewed (as encrypted message to hide from server)
	const sendReadReceipt = useCallback(async (messageId: string, sender: string) => {
		if (sender === currentUsername) return; // Don't send receipt for own messages

		// Check if we've already sent a read receipt for this message
		if (sentReadReceiptsRef.current.has(messageId)) {
			console.debug('[Receipt] Read receipt already sent for message:', messageId);
			return;
		}

		try {
			// Send as encrypted message to hide read status from server
			await sendEncryptedMessage(
				crypto.randomUUID(),
				JSON.stringify({ type: 'read-receipt', messageId, timestamp: Date.now() }),
				'read-receipt'
			);

			// Mark this message as having a read receipt sent
			sentReadReceiptsRef.current.add(messageId);
			saveSentReadReceipts();

			console.debug('[Receipt] Read receipt sent for message:', messageId);
		} catch (error) {
			console.error('Failed to send read receipt:', error);
		}
	}, [currentUsername, sendEncryptedMessage, saveSentReadReceipts]);

	// Mark message as read and persist to database
	const markMessageAsRead = useCallback(async (messageId: string) => {
		let updatedMessage: Message | null = null;

		setMessages(prev => prev.map(msg => {
			if (msg.id === messageId && !msg.receipt?.read && msg.sender !== currentUsername) {
				updatedMessage = {
					...msg,
					receipt: {
						...msg.receipt,
						read: true,
						readAt: new Date()
					}
				};
				return updatedMessage;
			}
			return msg;
		}));

		// Persist the updated message with read status to database
		if (updatedMessage) {
			try {
				await saveMessageToLocalDB(updatedMessage);
				console.debug('[Receipt] Message marked as read and persisted:', messageId);
			} catch (error) {
				console.error('[Receipt] Failed to persist read status:', error);
			}
		}
	}, [setMessages, currentUsername, saveMessageToLocalDB]);

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
		const handleDeliveryReceipt = async (event: CustomEvent) => {
			const { messageId, from } = event.detail;
			console.debug('[Receipt] Received delivery receipt:', { messageId, from });

			let updatedMessage: Message | null = null;

			setMessages(prev => {
				return prev.map(msg => {
					if (msg.id === messageId && msg.sender === currentUsername) {
						updatedMessage = {
							...msg,
							receipt: {
								...msg.receipt,
								delivered: true,
								deliveredAt: new Date()
							}
						};
						return updatedMessage;
					}
					return msg;
				});
			});

			// Persist the updated message with delivery status to database
			if (updatedMessage) {
				try {
					await saveMessageToLocalDB(updatedMessage);
					console.debug('[Receipt] Delivery status persisted for message:', messageId);
				} catch (error) {
					console.error('[Receipt] Failed to persist delivery status:', error);
				}
			}
		};

		window.addEventListener('message-delivered', handleDeliveryReceipt as EventListener);

		return () => {
			window.removeEventListener('message-delivered', handleDeliveryReceipt as EventListener);
		};
	}, [currentUsername, setMessages, saveMessageToLocalDB]);

	// Handle read receipts from other users
	useEffect(() => {
		const handleReadReceipt = async (event: CustomEvent) => {
			const { messageId, from } = event.detail;
			console.debug('[Receipt] Received read receipt:', { messageId, from });

			let updatedMessage: Message | null = null;

			setMessages(prev => {
				return prev.map(msg => {
					if (msg.id === messageId && msg.sender === currentUsername) {
						updatedMessage = {
							...msg,
							receipt: {
								...msg.receipt,
								read: true,
								readAt: new Date()
							}
						};
						return updatedMessage;
					}
					return msg;
				});
			});

			// Persist the updated message with read status to database
			if (updatedMessage) {
				try {
					await saveMessageToLocalDB(updatedMessage);
					console.debug('[Receipt] Read receipt status persisted for message:', messageId);
				} catch (error) {
					console.error('[Receipt] Failed to persist read receipt status:', error);
				}
			}
		};

		window.addEventListener('message-read', handleReadReceipt as EventListener);

		return () => {
			window.removeEventListener('message-read', handleReadReceipt as EventListener);
		};
	}, [currentUsername, setMessages, saveMessageToLocalDB]);

	// Clean up old read receipt tracking data (older than 30 days)
	useEffect(() => {
		const cleanupOldReceipts = () => {
			try {
				const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);

				// Get all messages older than 30 days
				const oldMessageIds = messages
					.filter(msg => new Date(msg.timestamp).getTime() < thirtyDaysAgo)
					.map(msg => msg.id);

				// Remove old message IDs from tracking
				let hasChanges = false;
				oldMessageIds.forEach(messageId => {
					if (sentReadReceiptsRef.current.has(messageId)) {
						sentReadReceiptsRef.current.delete(messageId);
						hasChanges = true;
					}
				});

				if (hasChanges) {
					saveSentReadReceipts();
					console.debug('[Receipt] Cleaned up old read receipt tracking data');
				}
			} catch (error) {
				console.error('Failed to cleanup old read receipts:', error);
			}
		};

		// Run cleanup on mount and then periodically
		cleanupOldReceipts();
		const cleanupInterval = setInterval(cleanupOldReceipts, 24 * 60 * 60 * 1000); // Daily

		return () => clearInterval(cleanupInterval);
	}, [messages, saveSentReadReceipts]);

	return {
		sendReadReceipt,
		markMessageAsRead,
		getSmartReceiptStatus
	};
}
