import React, { createContext, useContext, useState, useCallback, ReactNode, useEffect } from 'react';

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

	const setTypingUser = useCallback((username: string, isTyping: boolean) => {
		setTypingUsers(prev => {
			const newSet = new Set(prev);
			if (isTyping) {
				newSet.add(username);
			} else {
				newSet.delete(username);
			}
			return newSet;
		});
	}, []);

	const clearTypingUser = useCallback((username: string) => {
		setTypingUsers(prev => {
			const newSet = new Set(prev);
			newSet.delete(username);
			return newSet;
		});
	}, []);

	// Listen for typing indicator events from encrypted messages
	useEffect(() => {
		const handleTypingEvent = (event: CustomEvent) => {
			const { type, username } = event.detail;
			if (type === 'start') {
				setTypingUser(username, true);

				// Auto-remove typing indicator after 2 seconds
				setTimeout(() => {
					setTypingUser(username, false);
				}, 2000);
			} else if (type === 'stop') {
				setTypingUser(username, false);
			}
		};

		window.addEventListener('typing-indicator', handleTypingEvent as EventListener);

		return () => {
			window.removeEventListener('typing-indicator', handleTypingEvent as EventListener);
		};
	}, [setTypingUser]);

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
