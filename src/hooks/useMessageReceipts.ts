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
	// Track which messages have already had read receipts sent in the current session only
	const sentReadReceiptsRef = useRef<Set<string>>(new Set());

	// Load sent read receipts from localStorage on mount, but only for recent messages
	useEffect(() => {
		const stored = localStorage.getItem(`sentReadReceipts_${currentUsername}`);
		if (stored) {
			try {
				const receipts = JSON.parse(stored);
				// Only load receipts from the last 24 hours to avoid permanent blocking
				const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
				const recentReceipts = receipts.filter((receipt: any) => {
					return receipt.timestamp && receipt.timestamp > oneDayAgo;
				});
				
				// Convert to Set of message IDs
				sentReadReceiptsRef.current = new Set(recentReceipts.map((r: any) => r.messageId));
			} catch (error) {
				console.error('Failed to load sent read receipts:', error);
			}
		}
	}, [currentUsername]);

	// Save sent read receipts to localStorage with timestamps
	const saveSentReadReceipts = useCallback(() => {
		try {
			// Convert Set to array with timestamps for better tracking
			const receiptsWithTimestamps = Array.from(sentReadReceiptsRef.current).map(messageId => ({
				messageId,
				timestamp: Date.now()
			}));
			
			localStorage.setItem(
				`sentReadReceipts_${currentUsername}`,
				JSON.stringify(receiptsWithTimestamps)
			);
		} catch (error) {
			console.error('Failed to save sent read receipts:', error);
		}
	}, [currentUsername]);

	// Send read receipt when message is viewed (as encrypted message)
	const sendReadReceipt = useCallback(async (messageId: string, sender: string) => {
		console.log('[Receipt] sendReadReceipt called:', { messageId, sender, currentUsername });
		
		if (sender === currentUsername) {
			console.log('[Receipt] Skipping read receipt for own message');
			return; // Don't send receipt for own messages
		}

		// Check if we've already sent a read receipt for this message in the current session
		if (sentReadReceiptsRef.current.has(messageId)) {
			console.debug('[Receipt] Read receipt already sent for message in current session:', messageId);
			return;
		}

		console.log('[Receipt] Sending read receipt for message:', messageId);

		try {
			// First, ensure we have a session with the sender for read receipts
			const sessionCheck = await (window as any).edgeApi?.hasSession?.({ 
				selfUsername: currentUsername, 
				peerUsername: sender, 
				deviceId: 1 
			});
			
			if (!sessionCheck?.hasSession) {
				console.log('[Receipt] No session with sender, requesting bundle for read receipt');
				// Request the sender's bundle so we can send read receipts
				websocketClient.send(JSON.stringify({ 
					type: SignalType.LIBSIGNAL_REQUEST_BUNDLE, 
					username: sender 
				}));
				
				// Wait a bit for the bundle to be processed
				await new Promise(resolve => setTimeout(resolve, 500));
			}
			
			// Create read receipt payload
			const readReceiptData = {
				messageId: `read-receipt-${messageId}`,
				from: currentUsername,
				to: sender,
				content: 'read-receipt',
				timestamp: Date.now(),
				messageType: 'signal-protocol',
				signalType: 'signal-protocol',
				protocolType: 'signal',
				type: 'read-receipt'
			};
			
			// Use the proper Signal Protocol encryption flow through edgeApi
			const encryptedMessage = await (window as any).edgeApi?.encrypt?.({
				fromUsername: currentUsername,
				toUsername: sender,
				plaintext: JSON.stringify(readReceiptData)
			});
			
			if (!encryptedMessage?.ciphertextBase64) {
				console.error('[Receipt] Failed to encrypt read receipt');
				return;
			}
			
			// Send the properly encrypted read receipt
			const readReceiptPayload = {
				type: SignalType.ENCRYPTED_MESSAGE,
				to: sender,
				encryptedPayload: {
					from: currentUsername,
					to: sender,
					content: encryptedMessage.ciphertextBase64,
					messageId: `read-receipt-${messageId}`,
					type: encryptedMessage.type,
					sessionId: encryptedMessage.sessionId
				}
			};
			
			// Use websocketClient to send the encrypted read receipt
			websocketClient.send(JSON.stringify(readReceiptPayload));

			// Mark this message as having a read receipt sent in this session
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

	// Smart status management: show receipt status for all messages that have receipts
	const getSmartReceiptStatus = useCallback((message: Message) => {
		// We only show status for messages sent by current user that are the latest read or delivered
		if (!message.receipt || message.sender !== currentUsername) return undefined;

		// Determine last read and last delivered (but not read) message IDs
		let lastReadId: string | undefined;
		let lastDeliveredId: string | undefined;

		for (let i = messages.length - 1; i >= 0; i--) {
			const msg = messages[i];
			if (msg.sender !== currentUsername) continue;
			if (!lastReadId && msg.receipt?.read) {
				lastReadId = msg.id;
			}
			if (!lastDeliveredId && msg.receipt?.delivered && !msg.receipt.read) {
				lastDeliveredId = msg.id;
			}
			if (lastReadId && lastDeliveredId) break;
		}

		if (message.id === lastReadId) {
			return { ...message.receipt, read: true };
		}

		if (message.id === lastDeliveredId) {
			return { ...message.receipt, delivered: true };
		}

		// otherwise, no status
		return undefined;
	}, [messages, currentUsername]);

	// Handle delivery receipts from other users
	useEffect(() => {
		const handleDeliveryReceipt = async (event: CustomEvent) => {
			const { messageId, from } = event.detail;
			console.log('[Receipt] Received delivery receipt event:', { messageId, from, currentUsername });

			// Extract the original message ID from the receipt message ID
			// Receipt message IDs are formatted as: "delivery-receipt-{originalMessageId}"
			const originalMessageId = messageId.replace(/^delivery-receipt-/, '');
			console.log('[Receipt] Extracted original message ID from delivery receipt:', { receiptMessageId: messageId, originalMessageId });

			let updatedMessage: Message | null = null;

			setMessages(prev => {
				console.log('[Receipt] Current messages before delivery receipt update:', prev.map(m => ({ id: m.id, sender: m.sender, receipt: m.receipt })));
				
				return prev.map(msg => {
					if (msg.id === originalMessageId && msg.sender === currentUsername) {
						console.log('[Receipt] Updating message with delivery status:', originalMessageId);
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
					console.debug('[Receipt] Delivery status persisted for message:', originalMessageId);
				} catch (error) {
					console.error('[Receipt] Failed to persist delivery status:', error);
				}
			} else {
				console.log('[Receipt] Message not found or not from current user for delivery receipt:', originalMessageId);
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

			// Extract the original message ID from the receipt message ID
			// Receipt message IDs are formatted as: "read-receipt-{originalMessageId}"
			const originalMessageId = messageId.replace(/^read-receipt-/, '');
			console.log('[Receipt] Extracted original message ID from receipt:', { receiptMessageId: messageId, originalMessageId });

			let updatedMessage: Message | null = null;

			setMessages(prev => {
				console.log('[Receipt] Current messages before read receipt update:', prev.map(m => ({ id: m.id, sender: m.sender, receipt: m.receipt })));
				
				return prev.map(msg => {
					if (msg.id === originalMessageId && msg.sender === currentUsername) {
						console.log('[Receipt] Updating message with read status:', originalMessageId);
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
					console.debug('[Receipt] Read receipt status persisted for message:', originalMessageId);
				} catch (error) {
					console.error('[Receipt] Failed to persist read receipt status:', error);
				}
			} else {
				console.log('[Receipt] Message not found or not from current user for read receipt:', originalMessageId);
			}
		};

		window.addEventListener('message-read', handleReadReceipt as EventListener);

		return () => {
			window.removeEventListener('message-read', handleReadReceipt as EventListener);
		};
	}, [currentUsername, setMessages, saveMessageToLocalDB]);

	// Clean up old read receipt tracking data (older than 24 hours)
	useEffect(() => {
		const cleanupOldReceipts = () => {
			try {
				const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);

				// Get all messages older than 24 hours
				const oldMessageIds = messages
					.filter(msg => new Date(msg.timestamp).getTime() < oneDayAgo)
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
