import React, { createContext, useContext, useState, useCallback, ReactNode, useEffect, useRef, useMemo } from 'react';
import { CryptoUtils } from '../lib/unified-crypto';
import { SecureMemory } from '../lib/secure-memory';
import { SignalType } from '../lib/signal-types';
import { EventType } from '../lib/event-types';

type TypingAction = 'start' | 'stop';

interface TypingIndicatorContextType {
	readonly typingUsers: string[];
	readonly setTypingUser: (username: string, isTyping: boolean) => void;
	readonly clearTypingUser: (username: string) => void;
}

interface TypingIndicatorProviderProps {
	readonly children: ReactNode;
	readonly currentUsername?: string;
	readonly maxTypingUsers?: number;
	readonly typingTimeoutMs?: number;
	readonly rateLimitPerMinute?: number;
}

interface SecureEventDetail {
	readonly signature: string;
	readonly timestamp: number;
	readonly nonce: string;
	readonly payload: {
		readonly username: string;
		readonly action: TypingAction;
	};
}

const VALID_USERNAME = /^[a-z0-9@._-]{1,64}$/i;
const EVENT_RATE_LIMIT_WINDOW_MS = 60000;
const MAX_EVENT_QUEUE = 500;
const DEFAULT_MAX_TYPING_USERS = 200;
const DEFAULT_TYPING_TIMEOUT_MS = 5500;
const DEFAULT_RATE_LIMIT_PER_MINUTE = 240;

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
	if (typeof value !== 'object' || value === null) {
		return false;
	}
	const proto = Object.getPrototypeOf(value);
	return proto === Object.prototype || proto === null;
};

const hasPrototypePollutionKeys = (obj: Record<string, unknown>): boolean => {
	return ['__proto__', 'prototype', 'constructor'].some((key) => Object.prototype.hasOwnProperty.call(obj, key));
};

class BoundedMap<K, V> extends Map<K, V> {
	constructor(private readonly maxSize: number) {
		super();
	}

	override set(key: K, value: V): this {
		if (this.size >= this.maxSize) {
			const firstKey = this.keys().next().value;
			if (firstKey !== undefined) {
				super.delete(firstKey);
			}
		}
		return super.set(key, value);
	}
}

class RateLimiter {
	private readonly permitMap = new Map<string, { count: number; resetAt: number }>();

	constructor(private readonly limit: number, private readonly windowMs: number) {}

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

async function validateAndVerifyEvent(
	event: CustomEvent,
	nonceMap: Map<string, number>,
	rateLimiter: RateLimiter
): Promise<SecureEventDetail | null> {
	try {
		if (!event?.detail || typeof event.detail !== 'object') {
			return null;
		}

		if (!isPlainObject(event.detail) || hasPrototypePollutionKeys(event.detail)) {
			return null;
		}

		const detail = event.detail as unknown as SecureEventDetail;
		if (!detail.signature || typeof detail.signature !== 'string' || detail.signature.length < 32) {
			return null;
		}

		if (!Number.isSafeInteger(detail.timestamp) || Math.abs(Date.now() - detail.timestamp) > 15000) {
			return null;
		}

		if (!detail.nonce || typeof detail.nonce !== 'string' || detail.nonce.length < 32) {
			return null;
		}

		const nonceKey = `${detail.nonce}:${detail.timestamp}`;
		if (nonceMap.has(nonceKey)) {
			return null;
		}

		nonceMap.set(nonceKey, detail.timestamp);
		if (nonceMap.size > MAX_EVENT_QUEUE) {
			const oldestKey = nonceMap.keys().next().value;
			if (oldestKey) {
				nonceMap.delete(oldestKey);
			}
		}

		if (!detail.payload || typeof detail.payload !== 'object') {
			return null;
		}
		if (!isPlainObject(detail.payload) || hasPrototypePollutionKeys(detail.payload)) {
			return null;
		}

		const { username, action } = detail.payload;
		if (!username || typeof username !== 'string' || !VALID_USERNAME.test(username)) {
			return null;
		}

		if (action !== 'start' && action !== 'stop') {
			return null;
		}

		if (!rateLimiter.tryConsume(username)) {
			return null;
		}

		const encoder = new TextEncoder();
		const payloadBytes = encoder.encode(JSON.stringify(detail.payload));
		const expectedMac = CryptoUtils.Base64.base64ToUint8Array(detail.signature);
		const macKey = await CryptoUtils.Hash.generateBlake3Mac(encoder.encode(detail.nonce), encoder.encode(String(detail.timestamp)));
		const verified = await CryptoUtils.Hash.verifyBlake3Mac(payloadBytes, macKey, expectedMac);
		SecureMemory.zeroBuffer(payloadBytes);
		SecureMemory.zeroBuffer(expectedMac);
		SecureMemory.zeroBuffer(macKey);
		if (!verified) {
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
	maxTypingUsers = DEFAULT_MAX_TYPING_USERS,
	typingTimeoutMs = DEFAULT_TYPING_TIMEOUT_MS,
	rateLimitPerMinute = DEFAULT_RATE_LIMIT_PER_MINUTE,
}: TypingIndicatorProviderProps) {
	const [typingUsers, setTypingUsers] = useState<Set<string>>(new Set());
	const typingTimeoutsRef = useRef(new BoundedMap<string, ReturnType<typeof setTimeout>>(maxTypingUsers));
	const nonceMap = useRef(new BoundedMap<string, number>(MAX_EVENT_QUEUE));
	const rateLimiterRef = useRef(new RateLimiter(rateLimitPerMinute, EVENT_RATE_LIMIT_WINDOW_MS));

	const setTypingUser = useCallback((username: string, isTyping: boolean) => {
		if (!VALID_USERNAME.test(username)) {
			return;
		}
		setTypingUsers(prev => {
			const hasChanged = isTyping ? !prev.has(username) : prev.has(username);
			if (!hasChanged) {
				return prev;
			}
			const newSet = new Set(prev);
			if (isTyping) {
				if (newSet.size >= maxTypingUsers) {
					return prev;
				}
				newSet.add(username);
			} else {
				newSet.delete(username);
			}
			return newSet;
		});
	}, [maxTypingUsers]);

	const clearTypingUser = useCallback((username: string) => {
		if (!VALID_USERNAME.test(username)) {
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
		const handleTypingIndicator = async (event: Event) => {
			if (!(event instanceof CustomEvent)) {
				return;
			}

			const secureEvent = await validateAndVerifyEvent(event, nonceMap.current, rateLimiterRef.current);

			if (!secureEvent) {
				return;
			}

			const { payload } = secureEvent;
			const username = payload.username;
			const action = payload.action;

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
				}, typingTimeoutMs);
				typingTimeoutsRef.current.set(username, timeout);
			} else {
				clearTypingUser(username);
			}
		};

		const secureChannel = new MessageChannel();
		const listener = (event: MessageEvent) => {
			if (event.data?.type === EventType.TYPING_INDICATOR) {
				const customEvent = new CustomEvent(EventType.TYPING_INDICATOR, {
					detail: event.data.detail
				});
				handleTypingIndicator(customEvent);
			}
		};

		secureChannel.port1.onmessage = listener;

		const windowListener = (event: Event) => {
			try {
				if (!(event instanceof CustomEvent)) {
					return;
				}
				secureChannel.port2.postMessage({
					type: EventType.TYPING_INDICATOR,
					detail: event.detail
				});
			} catch {
				return;
			}
		};

		window.addEventListener(EventType.TYPING_INDICATOR, windowListener as EventListener);

		const handleP2PTypingIndicator = (event: Event) => {
			if (!(event instanceof CustomEvent)) return;
			const detail = event.detail;
			if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
			const from = detail.from;
			const content = detail.content;
			if (!from || typeof from !== 'string' || !VALID_USERNAME.test(from)) return;
			if (currentUsername && from === currentUsername) return;
			if (!rateLimiterRef.current.tryConsume(`p2p:${from}`)) return;

			const action = content === SignalType.TYPING_START ? 'start' : content === SignalType.TYPING_STOP ? 'stop' : null;
			if (!action) return;

			if (action === 'start') {
				const existingTimeout = typingTimeoutsRef.current.get(from);
				if (existingTimeout) {
					clearTimeout(existingTimeout);
				}
				setTypingUser(from, true);
				const timeout = setTimeout(() => {
					clearTypingUser(from);
				}, typingTimeoutMs);
				typingTimeoutsRef.current.set(from, timeout);
			} else {
				clearTypingUser(from);
			}
		};

		window.addEventListener('p2p-typing-indicator', handleP2PTypingIndicator as EventListener);

		return () => {
			window.removeEventListener(EventType.TYPING_INDICATOR, windowListener as EventListener);
			window.removeEventListener('p2p-typing-indicator', handleP2PTypingIndicator as EventListener);
			secureChannel.port1.onmessage = null;
			secureChannel.port1.close();
			secureChannel.port2.close();
			typingTimeoutsRef.current.forEach(timeout => clearTimeout(timeout));
			typingTimeoutsRef.current.clear();
			rateLimiterRef.current.reset();
			nonceMap.current.clear();
		};
	}, [clearTypingUser, currentUsername, setTypingUser, typingTimeoutMs]);

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