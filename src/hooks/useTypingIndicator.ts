import { useCallback, useRef, useEffect } from 'react';

export function useTypingIndicator(
	currentUsername: string,
	sendEncryptedMessage: (messageId: string, content: string, messageSignalType: string, replyTo?: any) => Promise<void>
) {
	const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);
	const lastTypingTimeRef = useRef<number>(0);
	const isTypingRef = useRef<boolean>(false);

	// Wait 3 seconds before stopping typing i'll change later to be lower for better accuracy
	const TYPING_STOP_DELAY = 3000;
	// Minimum time between typing start messages
	const MIN_TYPING_INTERVAL = 2000;

	// Send typing start signal
	const sendTypingStart = useCallback(async () => {
		const now = Date.now();
		// Only send if not already typing and not sent recently
		if (!isTypingRef.current && now - lastTypingTimeRef.current > MIN_TYPING_INTERVAL) {
			try {
				await sendEncryptedMessage(
					crypto.randomUUID(),
					JSON.stringify({ type: 'typing-start', timestamp: now }),
					'typing-start'
				);
				lastTypingTimeRef.current = now;
				isTypingRef.current = true;
			} catch (error) {
				console.error('Failed to send typing start:', error);
			}
		}
	}, [sendEncryptedMessage]);

	// Send typing stop signal
	const sendTypingStop = useCallback(async () => {
		// Only send if we were actually typing
		if (isTypingRef.current) {
			try {
				await sendEncryptedMessage(
					crypto.randomUUID(),
					JSON.stringify({ type: 'typing-stop', timestamp: Date.now() }),
					'typing-stop'
				);
				isTypingRef.current = false;
			} catch (error) {
				console.error('Failed to send typing stop:', error);
			}
		}
	}, [sendEncryptedMessage]);

	// Handle typing with delay
	const handleLocalTyping = useCallback(() => {
		// Clear old timeout
		if (typingTimeoutRef.current) {
			clearTimeout(typingTimeoutRef.current);
		}

		// Send typing start
		sendTypingStart();

		// Stop typing after delay
		typingTimeoutRef.current = setTimeout(() => {
			sendTypingStop();
		}, TYPING_STOP_DELAY);
	}, [sendTypingStart, sendTypingStop]);

	// Cleanup when component unmounts
	useEffect(() => {
		return () => {
			if (typingTimeoutRef.current) {
				clearTimeout(typingTimeoutRef.current);
			}
			// Stop typing when leaving
			sendTypingStop();
		};
	}, [sendTypingStop]);

	return {
		handleLocalTyping
	};
}
