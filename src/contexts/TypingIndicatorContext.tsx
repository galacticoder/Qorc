import React, { createContext, useContext, useState, useCallback, ReactNode, useEffect, useRef } from 'react';

interface TypingIndicatorContextType {
	typingUsers: string[];
	setTypingUser: (username: string, isTyping: boolean) => void;
	clearTypingUser: (username: string) => void;
}

const TypingIndicatorContext = createContext<TypingIndicatorContextType | undefined>(undefined);

export function useTypingIndicatorContext() {
	const context = useContext(TypingIndicatorContext);
	if (!context) {
		throw new Error('useTypingIndicatorContext must be used within a TypingIndicatorProvider');
	}
	return context;
}

interface TypingIndicatorProviderProps {
	children: ReactNode;
	currentUsername?: string; // Add current username to filter out own typing indicators
}

export function TypingIndicatorProvider({ children, currentUsername }: TypingIndicatorProviderProps) {
	const [typingUsers, setTypingUsers] = useState<Set<string>>(new Set());
	const typingTimeoutsRef = useRef<Map<string, NodeJS.Timeout>>(new Map());

	const setTypingUser = useCallback((username: string, isTyping: boolean) => {
		setTypingUsers(prev => {
			const newSet = new Set(prev);
			const hasChanged = isTyping ? !prev.has(username) : prev.has(username);

			if (!hasChanged) return prev; // No change needed, prevent unnecessary re-renders

			if (isTyping) {
				newSet.add(username);
			} else {
				newSet.delete(username);
			}
			return newSet;
		});
	}, []);

	const clearTypingUser = useCallback((username: string) => {
		console.log('[TypingIndicator] clearTypingUser called for:', username);
		
		// Clear any existing timeout for this user
		const existingTimeout = typingTimeoutsRef.current.get(username);
		if (existingTimeout) {
			clearTimeout(existingTimeout);
			typingTimeoutsRef.current.delete(username);
		}

		setTypingUsers(prev => {
			const newSet = new Set(prev);
			if (!newSet.has(username)) {
				console.log('[TypingIndicator] User not in typing list, returning new reference:', username);
				return newSet; // No change needed, but return new reference
			}
			newSet.delete(username);
			console.log('[TypingIndicator] Removed user from typing list:', username, 'New list:', Array.from(newSet));
			return newSet;
		});
	}, []);

	// Listen for typing indicator events from encrypted messages
	useEffect(() => {
		const handleTypingIndicator = (event: CustomEvent) => {
			const { from, indicatorType } = event.detail;
			console.log('[TypingIndicator] Received typing indicator event:', event.detail);
			console.log('[TypingIndicator] Event details:', { from, indicatorType, currentUsername });

			// Handle typing indicators from encrypted messages
			if (from && indicatorType) {
				const username = from;
				
				// Skip if this is from the current user
				if (currentUsername && username === currentUsername) {
					console.log('[TypingIndicator] Skipping typing indicator from current user:', username);
					return;
				}
				
				console.log('[TypingIndicator] Processing typing indicator:', { indicatorType, username });
				
				if (indicatorType === 'typing-start') {
					// Clear any existing timeout for this user
					const existingTimeout = typingTimeoutsRef.current.get(username);
					if (existingTimeout) {
						clearTimeout(existingTimeout);
					}

					// Add user to typing list
					setTypingUsers(prev => {
						const newSet = new Set(prev);
						if (newSet.has(username)) {
							console.log('[TypingIndicator] User already typing, returning new reference:', username);
							return newSet; // Already typing, but return new reference
						}
						newSet.add(username);
						console.log('[TypingIndicator] Added user to typing list:', username, 'New list:', Array.from(newSet));
						return newSet;
					});

					// Set auto-clear timeout (fallback in case typing-stop is missed)
					const timeout = setTimeout(() => {
						clearTypingUser(username);
					}, 5000); // 5 second fallback timeout

					typingTimeoutsRef.current.set(username, timeout);

				} else if (indicatorType === 'typing-stop') {
					console.log('[TypingIndicator] Clearing typing user:', username);
					clearTypingUser(username);
				}
				return;
			}

			// Handle legacy encrypted message typing indicators (for backward compatibility)
			const { type, username, fromUsername } = event.detail;
			if (type === 'typing-start' && (username || fromUsername)) {
				const actualUsername = username || fromUsername;
				
				// Skip if this is from the current user
				if (currentUsername && actualUsername === currentUsername) {
					console.log('[TypingIndicator] Skipping legacy typing indicator from current user:', actualUsername);
					return;
				}
				
				console.log('[TypingIndicator] Processing legacy typing indicator:', { type, actualUsername });
				
				// Clear any existing timeout for this user
				const existingTimeout = typingTimeoutsRef.current.get(actualUsername);
				if (existingTimeout) {
					clearTimeout(existingTimeout);
				}

				// Add user to typing list
				setTypingUsers(prev => {
					const newSet = new Set(prev);
					if (newSet.has(actualUsername)) return newSet; // Already typing, but return new reference
					newSet.add(actualUsername);
					return newSet;
				});

				// Set auto-clear timeout (fallback in case typing-stop is missed)
				const timeout = setTimeout(() => {
					clearTypingUser(actualUsername);
				}, 5000); // 5 second fallback timeout

				typingTimeoutsRef.current.set(actualUsername, timeout);

			} else if (type === 'typing-stop' && (username || fromUsername)) {
				const actualUsername = username || fromUsername;
				clearTypingUser(actualUsername);
			}
		};

		// Listen for typing indicator events from encrypted messages
		window.addEventListener('typing-indicator', handleTypingIndicator as EventListener);

		return () => {
			window.removeEventListener('typing-indicator', handleTypingIndicator as EventListener);
			// Clear all timeouts on unmount
			typingTimeoutsRef.current.forEach(timeout => clearTimeout(timeout));
			typingTimeoutsRef.current.clear();
		};
	}, [clearTypingUser]);

	const value: TypingIndicatorContextType = {
		typingUsers: Array.from(typingUsers),
		setTypingUser,
		clearTypingUser,
	};

	// Log when typingUsers state changes
	useEffect(() => {
		console.log('[TypingIndicator] typingUsers state changed:', Array.from(typingUsers));
	}, [typingUsers]);

	return (
		<TypingIndicatorContext.Provider value={value}>
			{children}
		</TypingIndicatorContext.Provider>
	);
}