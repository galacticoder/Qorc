import { useEffect, useCallback, useRef } from 'react';
import { Message } from '@/components/chat/types';
import { SignalType } from '@/lib/signals';
import websocketClient from '@/lib/websocket';

export function useMessageReceipts(
	messages: Message[],
	setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
	currentUsername: string,
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

	// Send read receipt when message is viewed (as server signal to avoid appearing as chat message)
	const sendReadReceipt = useCallback(async (messageId: string, sender: string) => {
		console.log('[Receipt] sendReadReceipt called:', { messageId, sender, currentUsername });
		
		if (sender === currentUsername) {
			console.log('[Receipt] Skipping read receipt for own message');
			return; // Don't send receipt for own messages
		}

		// Check if we've already sent a read receipt for this message
		if (sentReadReceiptsRef.current.has(messageId)) {
			console.debug('[Receipt] Read receipt already sent for message:', messageId);
			return;
		}

		console.log('[Receipt] Sending read receipt for message:', messageId);

		try {
			// Send as server signal to avoid appearing as chat message
			const readReceiptPayload = {
				type: SignalType.MESSAGE_READ,
				messageId: messageId,
				to: sender
			};
			
			// Use websocketClient directly to send the read receipt signal
			websocketClient.send(JSON.stringify(readReceiptPayload));

			// Mark this message as having a read receipt sent
			sentReadReceiptsRef.current.add(messageId);
			saveSentReadReceipts();

			console.debug('[Receipt] Read receipt sent for message:', messageId);
		} catch (error) {
			console.error('Failed to send read receipt:', error);
		}
	}, [currentUsername, saveSentReadReceipts]);

	// Mark message as read and persist to database
	const markMessageAsRead = useCallback(async (messageId: string) => {
		console.log('[Receipt] markMessageAsRead called for message:', messageId);
		
		let updatedMessage: Message | null = null;

		setMessages(prev => prev.map(msg => {
			if (msg.id === messageId && !msg.receipt?.read && msg.sender !== currentUsername) {
				console.log('[Receipt] Marking message as read:', messageId);
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
		} else {
			console.log('[Receipt] Message already marked as read or not found:', messageId);
		}
	}, [setMessages, currentUsername, saveMessageToLocalDB]);

	// Smart status management: show receipt status only for latest read and latest delivered messages
	const getSmartReceiptStatus = useCallback((message: Message) => {
		// Only process messages sent by the current user (to show receipt status)
		if (!message.receipt || message.sender !== currentUsername) {
			return undefined; // No receipt status for other users' messages
		}

		// Find messages from this user
		const userMessages = messages.filter(m => m.sender === currentUsername);
		
		// Find the most recent read message from this user
		const mostRecentReadMessage = userMessages
			.filter(m => m.receipt?.read)
			.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0];

		// Find the most recent delivered message from this user
		const mostRecentDeliveredMessage = userMessages
			.filter(m => m.receipt?.delivered)
			.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0];

		// If this message is the most recent read message, show read status
		if (message.receipt?.read && message.id === mostRecentReadMessage?.id) {
			console.log('[Receipt] Showing READ status for latest read message:', message.id);
			return message.receipt;
		}

		// If this message is the most recent delivered message (and not the same as the latest read), show delivered status
		if (message.receipt?.delivered && message.id === mostRecentDeliveredMessage?.id && message.id !== mostRecentReadMessage?.id) {
			console.log('[Receipt] Showing DELIVERED status for latest delivered message:', message.id);
			return message.receipt;
		}

		// For all other messages, don't show any receipt status
		console.log('[Receipt] No receipt status shown for message:', message.id);
		return undefined;
	}, [messages, currentUsername]);

	// Handle delivery receipts from other users
	useEffect(() => {
		const handleDeliveryReceipt = async (event: CustomEvent) => {
			const { messageId, from } = event.detail;
			console.log('[Receipt] Received delivery receipt event:', { messageId, from, currentUsername });

			let updatedMessage: Message | null = null;

			setMessages(prev => {
				return prev.map(msg => {
					if (msg.id === messageId && msg.sender === currentUsername) {
						console.log('[Receipt] Updating message with delivery status:', messageId);
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
			} else {
				console.log('[Receipt] Message not found or not from current user for delivery receipt:', messageId);
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
			console.log('[Receipt] Received read receipt event:', { messageId, from, currentUsername });

			let updatedMessage: Message | null = null;

			setMessages(prev => {
				return prev.map(msg => {
					if (msg.id === messageId && msg.sender === currentUsername) {
						console.log('[Receipt] Updating message with read status:', messageId);
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
			} else {
				console.log('[Receipt] Message not found or not from current user for read receipt:', messageId);
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
