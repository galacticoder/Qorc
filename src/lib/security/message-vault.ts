/**
 * Secure storage for message content
 * - Message content is re-encrypted with a session-scoped AES-256-GCM key after Signal decryption
 * - Plaintext is ONLY retrieved at the moment of canvas painting, then immediately discarded
 * - The session key is generated fresh on each app launch and never saved
 */

// Session scoped encryption key
let sessionKey: CryptoKey | null = null;
let initPromise: Promise<void> | null = null;

// Store encrypted content indexed by message ID
const encryptedStore = new Map<string, { iv: Uint8Array; ciphertext: Uint8Array }>();

// Track which messages have been stored
const storedMessages = new Set<string>();

// Initialize session key
export async function initializeVault(): Promise<void> {
    if (sessionKey) return;
    if (initPromise) return initPromise;

    initPromise = (async () => {
        try {
            sessionKey = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
        } catch (err) {
            console.error('[MessageVault] Failed to generate session key:', err);
        } finally {
            initPromise = null;
        }
    })();

    return initPromise;
}

// Re-encrypt content for storage
export async function storeSecurely(messageId: string, plaintext: string): Promise<void> {
    if (!sessionKey) {
        await initializeVault();
    }

    if (storedMessages.has(messageId)) {
        return;
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        sessionKey!,
        data
    );

    encryptedStore.set(messageId, {
        iv,
        ciphertext: new Uint8Array(ciphertext)
    });

    storedMessages.add(messageId);
}

// Retrieve and decrypt content for canvas painting
export async function retrieveForPaint(messageId: string): Promise<string | null> {
    if (!sessionKey) {
        await initializeVault();
        if (!sessionKey) return null;
    }

    const stored = encryptedStore.get(messageId);
    if (!stored) {
        return null;
    }

    try {
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: new Uint8Array(stored.iv) },
            sessionKey,
            stored.ciphertext
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    } catch (err) {
        console.error('[MessageVault] Retrieval failed:', err);
        return null;
    }
}

// Remove a message from the vault
export function removeFromVault(messageId: string): void {
    encryptedStore.delete(messageId);
    storedMessages.delete(messageId);
}

// Clear all stored messages
export function clearVault(): void {
    encryptedStore.clear();
    storedMessages.clear();
}

// Check if a message has secure content stored
export function hasSecureContent(messageId: string): boolean {
    return storedMessages.has(messageId);
}

// Export singleton interface
export const messageVault = {
    initialize: initializeVault,
    store: storeSecurely,
    storeBatch: async (entries: { id: string; content: string }[]): Promise<void> => {
        // Process in parallel
        await Promise.all(entries.map(e => storeSecurely(e.id, e.content)));
    },
    retrieve: retrieveForPaint,
    remove: removeFromVault,
    clear: clearVault,
    has: hasSecureContent,
};

export default messageVault;
