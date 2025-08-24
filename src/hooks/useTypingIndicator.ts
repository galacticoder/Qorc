import { useCallback, useRef, useEffect } from 'react';

export function useTypingIndicator(
	currentUsername: string,
	sendEncryptedMessage?: (messageId: string, content: string, messageSignalType: string, replyTo?: any) => Promise<void>
) {
	const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);
	const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);
	const lastTypingTimeRef = useRef<number>(0);
	const isTypingRef = useRef<boolean>(false);
	const pendingTypingRef = useRef<boolean>(false);

	// Optimized timing for better UX and performance
	const TYPING_STOP_DELAY = 1500; // Reduced from 3000ms - more responsive
	const MIN_TYPING_INTERVAL = 3000; // Increased from 2000ms - less network traffic
	const DEBOUNCE_DELAY = 300; // Debounce keystrokes to prevent spam

	// Send typing start signal with smart throttling
	const sendTypingStart = useCallback(async () => {
		const now = Date.now();
		// Only send if not already typing and enough time has passed
		if (!isTypingRef.current && now - lastTypingTimeRef.current > MIN_TYPING_INTERVAL) {
			try {
				console.debug('[Typing] Sending typing-start signal');
				console.debug('[Typing] edgeApi available:', !!window.edgeApi);
				console.debug('[Typing] sendTypingIndicator available:', !!window.edgeApi?.sendTypingIndicator);
				
				// Use the new direct typing indicator API to bypass Signal Protocol
				if (window.edgeApi?.sendTypingIndicator) {
					console.debug('[Typing] Using new direct typing indicator API');
					await window.edgeApi.sendTypingIndicator({
						fromUsername: currentUsername,
						toUsername: 'all', // Send to all users for now
						type: 'typing-start',
						timestamp: now
					});
				} else if (sendEncryptedMessage) {
					console.debug('[Typing] Falling back to encrypted message API');
					// Fallback to encrypted message if new API not available
					await sendEncryptedMessage(
						crypto.randomUUID(),
						JSON.stringify({ type: 'typing-start', timestamp: now }),
						'typing-start'
					);
				}
				lastTypingTimeRef.current = now;
				isTypingRef.current = true;
				pendingTypingRef.current = false;
			} catch (error) {
				console.error('[Typing] Failed to send typing start:', error);
				isTypingRef.current = false;
			}
		} else if (!isTypingRef.current) {
			// Mark that we want to send typing but are throttled
			pendingTypingRef.current = true;
		}
	}, [currentUsername, sendEncryptedMessage]);

	// Send typing stop signal
	const sendTypingStop = useCallback(async () => {
		// Only send if we were actually typing
		if (isTypingRef.current) {
			try {
				console.debug('[Typing] Sending typing-stop signal');
				console.debug('[Typing] edgeApi available:', !!window.edgeApi);
				console.debug('[Typing] sendTypingIndicator available:', !!window.edgeApi?.sendTypingIndicator);
				
				// Use the new direct typing indicator API to bypass Signal Protocol
				if (window.edgeApi?.sendTypingIndicator) {
					console.debug('[Typing] Using new direct typing indicator API for stop');
					await window.edgeApi.sendTypingIndicator({
						fromUsername: currentUsername,
						toUsername: 'all', // Send to all users for now
						type: 'typing-stop',
						timestamp: Date.now()
					});
				} else if (sendEncryptedMessage) {
					console.debug('[Typing] Falling back to encrypted message API for stop');
					// Fallback to encrypted message if new API not available
					await sendEncryptedMessage(
						crypto.randomUUID(),
						JSON.stringify({ type: 'typing-stop', timestamp: Date.now() }),
						'typing-stop'
					);
				}
				isTypingRef.current = false;
				pendingTypingRef.current = false;
			} catch (error) {
				console.error('[Typing] Failed to send typing stop:', error);
				// Still mark as stopped locally even if network fails
				isTypingRef.current = false;
				pendingTypingRef.current = false;
			}
		}
	}, [currentUsername, sendEncryptedMessage]);

	// Debounced typing handler - much more efficient
	const handleLocalTyping = useCallback(() => {
		// Clear existing debounce timeout
		if (debounceTimeoutRef.current) {
			clearTimeout(debounceTimeoutRef.current);
		}

		// Clear existing stop timeout
		if (typingTimeoutRef.current) {
			clearTimeout(typingTimeoutRef.current);
		}

		// Debounce the typing start signal to avoid spam
		debounceTimeoutRef.current = setTimeout(() => {
			sendTypingStart();
		}, DEBOUNCE_DELAY);

		// Always set the stop timeout
		typingTimeoutRef.current = setTimeout(() => {
			sendTypingStop();
		}, TYPING_STOP_DELAY);
	}, [sendTypingStart, sendTypingStop]);

	// Handle conversation changes - immediately stop typing
	const handleConversationChange = useCallback(() => {
		// Clear all timeouts
		if (debounceTimeoutRef.current) {
			clearTimeout(debounceTimeoutRef.current);
			debounceTimeoutRef.current = null;
		}
		if (typingTimeoutRef.current) {
			clearTimeout(typingTimeoutRef.current);
			typingTimeoutRef.current = null;
		}

		// Immediately send stop if we were typing
		if (isTypingRef.current) {
			sendTypingStop();
		}

		// Reset all state
		pendingTypingRef.current = false;
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
			const timeUntilNextAllowed = MIN_TYPING_INTERVAL - (now - lastTypingTimeRef.current);

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
