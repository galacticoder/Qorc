import { createContext, useContext, useState, useCallback, ReactNode, useEffect, useRef, useMemo } from 'react';
import { EventType } from '../lib/types/event-types';
import { hasPrototypePollutionKeys, isCanonicalAuthUsername, isPlainObject } from '../lib/sanitizers';
import {
	DEFAULT_MAX_TYPING_USERS,
	DEFAULT_TYPING_TIMEOUT_MS,
	DEFAULT_RATE_LIMIT_PER_MINUTE,
	DEFAULT_TYPING_EVENT_RATE_WINDOW_MS
} from '../lib/constants';

type TypingAction = 'start' | 'stop';

interface TypingIndicatorContextType {
	readonly typingUsers: string[];
	readonly setTypingUser: (username: string, isTyping: boolean) => void;
	readonly clearTypingUser: (username: string) => void;
}

interface TypingIndicatorProviderProps {
	readonly children: ReactNode;
	readonly currentUsername?: string;
	readonly DEFAULT_MAX_TYPING_USERS?: number;
	readonly DEFAULT_TYPING_TIMEOUT_MS?: number;
	readonly DEFAULT_RATE_LIMIT_PER_MINUTE?: number;
}

interface SecureEventDetail {
    readonly username: string;
    readonly action: TypingAction;
}

class BoundedMap<K, V> extends Map<K, V> {
	constructor(private readonly maxSize: number) {
		super();
	}

	override set(key: K, value: V): this {
		if (!this.has(key) && this.size >= this.maxSize) {
			const firstKey = this.keys().next().value;
			if (firstKey !== undefined) {
				super.delete(firstKey);
			}
		}
		return super.set(key, value);
	}
}

class RateLimiter {
	private readonly permitMap = new BoundedMap<string, { count: number; resetAt: number }>(
		DEFAULT_MAX_TYPING_USERS
	);

	constructor(private readonly limit: number, private readonly windowMs: number) { }

	public tryConsume(key: string): boolean {
		const now = Date.now();
		const record = this.permitMap.get(key);
		if (!record || record.resetAt <= now) {
			this.permitMap.set(key, { count: 1, resetAt: now + this.windowMs });
			return true;
		}

		if (record.count >= this.limit) {
			return false;
		}

		record.count += 1;
		return true;
	}

	public reset(): void {
		this.permitMap.clear();
	}
}

const TypingIndicatorContext = createContext<TypingIndicatorContextType | undefined>(undefined);

export function useTypingIndicatorContext() {
	const context = useContext(TypingIndicatorContext);
	if (!context) {
		throw new Error('Context not available');
	}
	return context;
}

function validateTypingEvent(
    event: CustomEvent,
    rateLimiter: RateLimiter
): SecureEventDetail | null {
    try {
		if (!event?.detail || typeof event.detail !== 'object') {
			return null;
		}

		if (!isPlainObject(event.detail) || hasPrototypePollutionKeys(event.detail)) {
			return null;
		}

        const detail = event.detail as unknown as SecureEventDetail;
        const keys = Object.keys(detail);
        if (keys.length !== 2 || !keys.every(key => key === 'username' || key === 'action')) {
            return null;
        }

        const { username, action } = detail;

		if (!isCanonicalAuthUsername(username)) {
			return null;
		}

		if (action !== 'start' && action !== 'stop') {
			return null;
		}

		if (!rateLimiter.tryConsume(username)) {
			return null;
		}

        return detail;
	} catch {
		return null;
	}
}

export function TypingIndicatorProvider({
	children,
	currentUsername,
}: TypingIndicatorProviderProps) {
	const [typingUsers, setTypingUsers] = useState<Set<string>>(new Set());
	const typingTimeoutsRef = useRef(new BoundedMap<string, ReturnType<typeof setTimeout>>(DEFAULT_MAX_TYPING_USERS));

    const rateLimiterRef = useRef(new RateLimiter(DEFAULT_RATE_LIMIT_PER_MINUTE, DEFAULT_TYPING_EVENT_RATE_WINDOW_MS));

	const setTypingUser = useCallback((username: string, isTyping: boolean) => {
		if (!isCanonicalAuthUsername(username)) {
			return;
		}
		setTypingUsers(prev => {
			const hasChanged = isTyping ? !prev.has(username) : prev.has(username);
			if (!hasChanged) {
				return prev;
			}
			const newSet = new Set(prev);
			if (isTyping) {
				if (newSet.size >= DEFAULT_MAX_TYPING_USERS)
					return prev;
				newSet.add(username);
			} else {
				newSet.delete(username);
			}
			return newSet;
		});
	}, [DEFAULT_MAX_TYPING_USERS]);

	const clearTypingUser = useCallback((username: string) => {
		if (!isCanonicalAuthUsername(username)) {
			return;
		}
		const existingTimeout = typingTimeoutsRef.current.get(username);
		if (existingTimeout) {
			clearTimeout(existingTimeout);
			typingTimeoutsRef.current.delete(username);
		}
		setTypingUsers(prev => {
			if (!prev.has(username)) {
				return prev;
			}
			const newSet = new Set(prev);
			newSet.delete(username);
			return newSet;
		});
	}, []);

	useEffect(() => {
		setTypingUsers(new Set());
	}, [currentUsername]);

	useEffect(() => {
        const handleTypingIndicator = (event: Event) => {
            if (!(event instanceof CustomEvent)) {
                return;
            }

            const detail = validateTypingEvent(event, rateLimiterRef.current);
            if (!detail) {
                return;
            }
            const { username, action } = detail;

			if (currentUsername && username === currentUsername) {
				return;
			}

			if (action === 'start') {
				const existingTimeout = typingTimeoutsRef.current.get(username);
				if (existingTimeout) {
					clearTimeout(existingTimeout);
				}
				setTypingUser(username, true);
				const timeout = setTimeout(() => {
					clearTypingUser(username);
				}, DEFAULT_TYPING_TIMEOUT_MS);
				typingTimeoutsRef.current.set(username, timeout);
			} else {
				clearTypingUser(username);
			}
		};

        const windowListener = (event: Event) => {
            handleTypingIndicator(event);
        };

		window.addEventListener(EventType.TYPING_INDICATOR, windowListener as EventListener);

        return () => {
            window.removeEventListener(EventType.TYPING_INDICATOR, windowListener as EventListener);
            typingTimeoutsRef.current.forEach(timeout => clearTimeout(timeout));
            typingTimeoutsRef.current.clear();
            rateLimiterRef.current.reset();
        };
	}, [clearTypingUser, currentUsername, setTypingUser, DEFAULT_TYPING_TIMEOUT_MS]);

	const value = useMemo<TypingIndicatorContextType>(() => ({
		typingUsers: Array.from(typingUsers),
		setTypingUser,
		clearTypingUser,
	}), [typingUsers, setTypingUser, clearTypingUser]);

	return (
		<TypingIndicatorContext.Provider value={value}>
			{children}
		</TypingIndicatorContext.Provider>
	);
}
