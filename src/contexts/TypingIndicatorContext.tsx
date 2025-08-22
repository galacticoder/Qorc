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
}

export function TypingIndicatorProvider({ children }: TypingIndicatorProviderProps) {
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
		// Clear any existing timeout for this user
		const existingTimeout = typingTimeoutsRef.current.get(username);
		if (existingTimeout) {
			clearTimeout(existingTimeout);
			typingTimeoutsRef.current.delete(username);
		}

		setTypingUsers(prev => {
			if (!prev.has(username)) return prev; // No change needed
			const newSet = new Set(prev);
			newSet.delete(username);
			return newSet;
		});
	}, []);

	// Listen for typing indicator events from encrypted messages
	useEffect(() => {
		const handleTypingIndicator = (event: CustomEvent) => {
			const { type, username } = event.detail;

			if (type === 'typing-start') {
				// Clear any existing timeout for this user
				const existingTimeout = typingTimeoutsRef.current.get(username);
				if (existingTimeout) {
					clearTimeout(existingTimeout);
				}

				// Add user to typing list
				setTypingUsers(prev => {
					if (prev.has(username)) return prev; // Already typing, no change
					const newSet = new Set(prev);
					newSet.add(username);
					return newSet;
				});

				// Set auto-clear timeout (fallback in case typing-stop is missed)
				const timeout = setTimeout(() => {
					clearTypingUser(username);
				}, 5000); // 5 second fallback timeout

				typingTimeoutsRef.current.set(username, timeout);

			} else if (type === 'typing-stop') {
				clearTypingUser(username);
			}
		};

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

	return (
		<TypingIndicatorContext.Provider value={value}>
			{children}
		</TypingIndicatorContext.Provider>
	);
}
