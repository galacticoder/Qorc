import { useCallback, useRef, useEffect } from 'react';

export function useTypingIndicator(
	currentUsername: string,
	selectedConversation?: string,
	sendEncryptedMessage?: (messageId: string, content: string, messageSignalType: string, replyTo?: any) => Promise<void>
) {
	const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);
	const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);
	const lastTypingTimeRef = useRef<number>(0);
	const isTypingRef = useRef<boolean>(false);
	const pendingTypingRef = useRef<boolean>(false);
	const lastTypingStartSentRef = useRef<number>(0);
	const isProcessingTypingRef = useRef<boolean>(false);
	const conversationChangeTimeoutRef = useRef<NodeJS.Timeout | null>(null);

	// Optimized timing for better UX and performance
	const TYPING_STOP_DELAY = 1500; // Reduced from 3000ms - more responsive
	const MIN_TYPING_INTERVAL = 3000; // Increased from 2000ms - less network traffic
	const DEBOUNCE_DELAY = 300; // Debounce keystrokes to prevent spam
	const CONVERSATION_CHANGE_DEBOUNCE = 100; // Debounce conversation changes

	// Send typing start signal with smart throttling
	const sendTypingStart = useCallback(async () => {
		console.log('[Typing] sendTypingStart called', {
			isTyping: isTypingRef.current,
			pendingTyping: pendingTypingRef.current,
			isProcessingTyping: isProcessingTypingRef.current,
			hasSendEncryptedMessage: !!sendEncryptedMessage
		});
		
		// Prevent concurrent typing start operations
		if (isProcessingTypingRef.current) {
			console.log('[Typing] Typing start already in progress, skipping');
			return;
		}

		const now = Date.now();
		// Only send if not already typing and enough time has passed since last typing start
		if (!isTypingRef.current && now - lastTypingStartSentRef.current > MIN_TYPING_INTERVAL) {
			try {
				isProcessingTypingRef.current = true;
				console.debug('[Typing] Sending typing-start signal');
				
				// Send typing indicator as encrypted message with unique ID
				if (sendEncryptedMessage) {
					console.debug('[Typing] Sending typing-start as encrypted message');
					// SECURITY: Use cryptographically secure random ID generation
					const randomBytes = crypto.getRandomValues(new Uint8Array(6));
					const secureId = Array.from(randomBytes, byte => byte.toString(36)).join('');
					const uniqueId = `typing-start-${now}-${secureId}`;
					await sendEncryptedMessage(
						uniqueId,
						JSON.stringify({ type: 'typing-start', timestamp: now }),
						'typing-start'
					);
				}
				lastTypingTimeRef.current = now;
				lastTypingStartSentRef.current = now;
				isTypingRef.current = true;
				pendingTypingRef.current = false;
				console.log('[Typing] Typing started successfully');
			} catch (error) {
				console.error('[Typing] Failed to send typing start:', error);
				isTypingRef.current = false;
			} finally {
				isProcessingTypingRef.current = false;
			}
		} else if (!isTypingRef.current) {
			// Mark that we want to send typing but are throttled
			console.log('[Typing] Typing start throttled, marking as pending', {
				timeSinceLastTypingStart: now - lastTypingStartSentRef.current,
				minInterval: MIN_TYPING_INTERVAL
			});
			pendingTypingRef.current = true;
		} else {
			console.log('[Typing] Typing start skipped - already typing');
		}
	}, [currentUsername, sendEncryptedMessage, selectedConversation]);

	// Send typing stop signal
	const sendTypingStop = useCallback(async () => {
		console.log('[Typing] sendTypingStop called', {
			isTyping: isTypingRef.current,
			pendingTyping: pendingTypingRef.current,
			hasSendEncryptedMessage: !!sendEncryptedMessage
		});
		
		// Only send if we were actually typing
		if (isTypingRef.current) {
			try {
				console.debug('[Typing] Sending typing-stop signal');
				
				// Send typing indicator as encrypted message with unique ID
				if (sendEncryptedMessage) {
					console.debug('[Typing] Sending typing-stop as encrypted message');
					// Use a more unique message ID for typing indicators to prevent duplicates
					// SECURITY: Use cryptographically secure random ID generation
					const randomBytes = crypto.getRandomValues(new Uint8Array(6));
					const secureId = Array.from(randomBytes, byte => byte.toString(36)).join('');
					const uniqueId = `typing-stop-${Date.now()}-${secureId}`;
					await sendEncryptedMessage(
						uniqueId,
						JSON.stringify({ type: 'typing-stop', timestamp: Date.now() }),
						'typing-stop'
					);
				}
				isTypingRef.current = false;
				pendingTypingRef.current = false;
				console.log('[Typing] Typing stopped successfully');
			} catch (error) {
				console.error('[Typing] Failed to send typing stop:', error);
				// Still mark as stopped locally even if network fails
				isTypingRef.current = false;
				pendingTypingRef.current = false;
			}
		} else {
			console.log('[Typing] sendTypingStop called but not currently typing, skipping');
		}
	}, [currentUsername, sendEncryptedMessage, selectedConversation]);

	// Debounced typing handler - much more efficient
	const handleLocalTyping = useCallback(() => {
		console.log('[Typing] handleLocalTyping called', {
			isTyping: isTypingRef.current,
			pendingTyping: pendingTypingRef.current,
			lastTypingStartSent: lastTypingStartSentRef.current,
			timeSinceLastTypingStart: Date.now() - lastTypingStartSentRef.current,
			minInterval: MIN_TYPING_INTERVAL,
			isProcessingTyping: isProcessingTypingRef.current
		});
		
		// Clear existing debounce timeout
		if (debounceTimeoutRef.current) {
			clearTimeout(debounceTimeoutRef.current);
		}

		// Only send typing start if not already typing, not processing, and enough time has passed
		const now = Date.now();
		if (!isTypingRef.current && !isProcessingTypingRef.current && now - lastTypingStartSentRef.current > MIN_TYPING_INTERVAL) {
			console.log('[Typing] Sending typing start - conditions met');
			sendTypingStart();
		} else {
			console.log('[Typing] Skipping typing start - conditions not met', {
				isTyping: isTypingRef.current,
				isProcessingTyping: isProcessingTypingRef.current,
				timeSinceLastTypingStart: now - lastTypingStartSentRef.current,
				minInterval: MIN_TYPING_INTERVAL
			});
		}

		// Set new debounce timeout for typing stop
		debounceTimeoutRef.current = setTimeout(() => {
			console.log('[Typing] Debounce timeout expired, sending typing stop', {
				isTyping: isTypingRef.current,
				pendingTyping: pendingTypingRef.current
			});
			sendTypingStop();
		}, TYPING_STOP_DELAY);
	}, [sendTypingStart, sendTypingStop]);

	// Handle conversation changes to stop typing indicators (debounced)
	const handleConversationChange = useCallback(() => {
		console.log('[Typing] handleConversationChange called', {
			isTyping: isTypingRef.current,
			pendingTyping: pendingTypingRef.current,
			hasDebounceTimeout: !!debounceTimeoutRef.current,
			hasTypingTimeout: !!typingTimeoutRef.current,
			hasConversationChangeTimeout: !!conversationChangeTimeoutRef.current
		});
		
		// Clear any existing conversation change timeout
		if (conversationChangeTimeoutRef.current) {
			clearTimeout(conversationChangeTimeoutRef.current);
		}
		
		// Debounce the conversation change handling
		conversationChangeTimeoutRef.current = setTimeout(() => {
			console.log('[Typing] Processing conversation change after debounce', {
				isTyping: isTypingRef.current,
				pendingTyping: pendingTypingRef.current,
				hasDebounceTimeout: !!debounceTimeoutRef.current,
				hasTypingTimeout: !!typingTimeoutRef.current
			});
			
			// Clear any pending debounce timeouts first
			if (debounceTimeoutRef.current) {
				console.log('[Typing] Clearing debounce timeout');
				clearTimeout(debounceTimeoutRef.current);
				debounceTimeoutRef.current = null;
			}
			
			// Clear any pending typing timeouts
			if (typingTimeoutRef.current) {
				console.log('[Typing] Clearing typing timeout');
				clearTimeout(typingTimeoutRef.current);
				typingTimeoutRef.current = null;
			}
			
			// Only send typing stop if we were actually typing
			if (isTypingRef.current) {
				console.log('[Typing] Sending typing stop due to conversation change');
				sendTypingStop();
			} else {
				console.log('[Typing] No typing stop needed - not currently typing');
			}
		}, CONVERSATION_CHANGE_DEBOUNCE);
	}, [sendTypingStop]);

	// Cleanup when component unmounts or conversation changes
	useEffect(() => {
		return () => {
			// Clear all timeouts
			if (debounceTimeoutRef.current) {
				clearTimeout(debounceTimeoutRef.current);
			}
			if (typingTimeoutRef.current) {
				clearTimeout(typingTimeoutRef.current);
			}
			if (conversationChangeTimeoutRef.current) {
				clearTimeout(conversationChangeTimeoutRef.current);
			}
			// Stop typing when leaving
			if (isTypingRef.current) {
				sendTypingStop();
			}
		};
	}, [sendTypingStop]);

	// Auto-retry pending typing signals when throttle period expires
	useEffect(() => {
		if (pendingTypingRef.current && !isTypingRef.current) {
			const now = Date.now();
			const timeUntilNextAllowed = MIN_TYPING_INTERVAL - (now - lastTypingStartSentRef.current);

			if (timeUntilNextAllowed > 0) {
				const retryTimeout = setTimeout(() => {
					if (pendingTypingRef.current && !isTypingRef.current) {
						sendTypingStart();
					}
				}, timeUntilNextAllowed);

				return () => clearTimeout(retryTimeout);
			}
		}
	}, [sendTypingStart]);

	return {
		handleLocalTyping,
		handleConversationChange,
		isTyping: isTypingRef.current
	};
}
