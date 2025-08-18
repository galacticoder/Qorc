import { useCallback, useRef, useEffect } from 'react';

export function useTypingIndicator(
	currentUsername: string,
	sendEncryptedMessage: (messageId: string, content: string, messageSignalType: string, replyTo?: any) => Promise<void>
) {
	const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);
	const lastTypingTimeRef = useRef<number>(0);

	// Wait 2 seconds before stopping typing
	const TYPING_STOP_DELAY = 2000;

	// Send typing start signal
	const sendTypingStart = useCallback(async () => {
		const now = Date.now();
		// Only send if not sent recently (prevent spam)
		if (now - lastTypingTimeRef.current > 1000) {
			try {
				await sendEncryptedMessage(
					crypto.randomUUID(),
					JSON.stringify({ type: 'typing-start', timestamp: now }),
					'typing-start'
				);
				lastTypingTimeRef.current = now;
			} catch (error) {
				console.error('Failed to send typing start:', error);
			}
		}
	}, [sendEncryptedMessage]);

	// Send typing stop signal
	const sendTypingStop = useCallback(async () => {
		try {
			await sendEncryptedMessage(
				crypto.randomUUID(),
				JSON.stringify({ type: 'typing-stop', timestamp: Date.now() }),
				'typing-stop'
			);
		} catch (error) {
			console.error('Failed to send typing stop:', error);
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
