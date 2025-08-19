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
		const handleTypingIndicator = (event: CustomEvent) => {
			const { type, username } = event.detail;

			if (type === 'typing-start') {
				setTypingUsers(prev => {
					const newSet = new Set(prev);
					newSet.add(username);
					return newSet;
				});
			} else if (type === 'typing-stop') {
				setTypingUsers(prev => {
					const newSet = new Set(prev);
					newSet.delete(username);
					return newSet;
				});
			}
		};

		window.addEventListener('typing-indicator', handleTypingIndicator as EventListener);

		return () => {
			window.removeEventListener('typing-indicator', handleTypingIndicator as EventListener);
		};
	}, []);

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
