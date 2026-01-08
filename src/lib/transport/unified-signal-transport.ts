import { SignalType } from '../types/signal-types';
import websocketClient from '../websocket';
import { quicTransport } from './quic-transport';

// Unified Signal Transport
class UnifiedSignalTransport {
    private encryptionProvider: ((to: string, payload: any, type: SignalType) => Promise<any>) | null = null;
    private p2pEncryptionProvider: ((to: string, payload: any, type: SignalType) => Promise<any>) | null = null;
    private p2pSender: ((to: string, payload: any, type: SignalType) => Promise<void>) | null = null;

    // Register a provider that can encrypt raw payloads for Signal Protocol fallback
    setEncryptionProvider(provider: (to: string, payload: any, type: SignalType) => Promise<any>): void {
        this.encryptionProvider = provider;
    }

    // Register a provider that can encrypt raw payloads for P2P delivery
    setP2PEncryptionProvider(provider: (to: string, payload: any, type: SignalType) => Promise<any>): void {
        this.p2pEncryptionProvider = provider;
    }

    // Register a sender that can sign and send P2P messages with route proofs
    setP2PSender(sender: (to: string, payload: any, type: SignalType) => Promise<void>): void {
        this.p2pSender = sender;
    }


    // Send a signal to a peer with mandatory P2P priority
    async send(
        to: string,
        payload: any,
        type: SignalType,
        options?: { fallbackEnvelope?: any }
    ): Promise<{ success: boolean; transport: 'p2p' | 'server'; error?: string }> {
        // Try P2P if connected
        if (quicTransport.isConnected(to)) {
            try {
                let attempts = 0;
                const maxAttempts = 2;
                while (attempts < maxAttempts) {
                    try {
                        attempts++;
                        let payloadToSend = payload;

                        if (this.p2pEncryptionProvider) {
                            payloadToSend = await this.p2pEncryptionProvider(to, payload, type);
                        }

                        if (this.p2pSender) {
                            await this.p2pSender(to, payloadToSend, type);
                        } else {
                            throw new Error('Encrypted P2P sender required');
                        }

                        return { success: true, transport: 'p2p' };
                    } catch (p2pErr: any) {
                        const msg = p2pErr?.message || String(p2pErr);
                        if (msg.includes('Not connected') || msg.includes('no P2P session')) {
                            break;
                        }
                        if (attempts < maxAttempts) await new Promise(r => setTimeout(r, 100));
                    }
                }
            } catch (err) {
                console.warn(`[UnifiedTransport] P2P send failed for ${to}, falling back to server:`, err);
            }
        }

        // Fallback to Server
        try {
            if (to === 'SERVER') {
                websocketClient.send(JSON.stringify({ type, ...payload }));
                return { success: true, transport: 'server' };
            }

            let envelopeToSend: any = null;

            let effectiveOptions = options;
            if (!effectiveOptions?.fallbackEnvelope && this.encryptionProvider) {
                try {
                    const fallback = await this.encryptionProvider(to, payload, type);
                    if (fallback) {
                        effectiveOptions = { ...options, fallbackEnvelope: fallback };
                    }
                } catch { }
            }

            if (type === SignalType.ENCRYPTED_MESSAGE && payload.encryptedPayload) {
                envelopeToSend = {
                    type: SignalType.ENCRYPTED_MESSAGE,
                    to,
                    messageId: payload.messageId,
                    encryptedPayload: payload.encryptedPayload
                };
            } else if (effectiveOptions?.fallbackEnvelope) {
                envelopeToSend = {
                    ...effectiveOptions.fallbackEnvelope,
                    type: SignalType.ENCRYPTED_MESSAGE,
                    to
                };
            }


            if (!envelopeToSend) {
                return { success: false, transport: 'server', error: 'Secure fallback envelope required' };
            }

            websocketClient.send(JSON.stringify(envelopeToSend));
            return { success: true, transport: 'server' };

        } catch (serverErr: any) {
            console.error(`[UnifiedTransport] Critical failure sending ${type} to ${to}:`, serverErr);
            return { success: false, transport: 'server', error: serverErr?.message || 'Server send failed' };
        }
    }

    // Profile picture requests
    async requestProfilePicture(to: string): Promise<void> {
        await this.send(to, { type: 'profile-picture-request' }, SignalType.SIGNAL);
    }

    // Send a typing indicator
    async sendTyping(to: string, payload: any, isStart: boolean): Promise<void> {
        await this.send(to, payload, isStart ? SignalType.TYPING_START : SignalType.TYPING_STOP);
    }

    // Send a read receipt
    async sendReadReceipt(to: string, payload: any): Promise<void> {
        await this.send(to, payload, SignalType.READ_RECEIPT);
    }
}

export const unifiedSignalTransport = new UnifiedSignalTransport();
