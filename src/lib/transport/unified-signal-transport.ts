import { SignalType } from '../types/signal-types';
import websocketClient from '../websocket/websocket';
import { quicTransport } from './quic-transport';
import { getBlindRoutingClient } from './blind-routing-client';
import { PostQuantumUtils } from '../utils/pq-utils';

// Unified Signal Transport
class UnifiedSignalTransport {
    private encryptionProvider: ((to: string, payload: any, type: SignalType) => Promise<any>) | null = null;
    private p2pSender: ((to: string, payload: any, type: SignalType) => Promise<void>) | null = null;

    // Register a provider that encrypts payloads
    setEncryptionProvider(provider: (to: string, payload: any, type: SignalType) => Promise<any>): void {
        this.encryptionProvider = provider;
    }

    // Register a sender that can sign and send P2P messages with route proofs
    setP2PSender(sender: (to: string, payload: any, type: SignalType) => Promise<void>): void {
        this.p2pSender = sender;
    }

    // Send a signal to a peer
    async send(
        to: string,
        payload: any,
        type: SignalType,
        options?: { destinationInbox?: string }
    ): Promise<{ success: boolean; transport: 'p2p' | 'server'; error?: string }> {
        // Check for active or pending connection to allow P2P queuing
        const isQuicConnected = quicTransport.hasActiveConnection(to);

        // Get encrypted envelope
        if (!this.encryptionProvider) {
            return { success: false, transport: 'server', error: 'Encryption provider not set' };
        }

        const encryptedResult = await this.encryptionProvider(to, payload, type);
        if (!encryptedResult) {
            return { success: false, transport: 'server', error: 'Encryption failed' };
        }

        const envelopeToSend = {
            type: SignalType.SEALED_ENVELOPE,
            destinationInbox: encryptedResult.destinationInbox || options?.destinationInbox,
            messageId: encryptedResult.messageId,
            envelope: encryptedResult.encryptedPayload,
            recipientKyberPublicBase64: encryptedResult.recipientKyberPublicBase64
        };

        if (isQuicConnected) {
            try {
                let attempts = 0;
                const maxAttempts = 2;
                while (attempts < maxAttempts) {
                    try {
                        attempts++;
                        if (this.p2pSender) {
                            await this.p2pSender(to, envelopeToSend, SignalType.SEALED_ENVELOPE);
                        } else {
                            throw new Error('P2P sender not configured');
                        }

                        return { success: true, transport: 'p2p' };
                    } catch (p2pErr: any) {
                        const msg = p2pErr?.message || String(p2pErr);
                        if (msg.includes('PEER_CERT_MISSING')) {
                            break;
                        }
                        if (msg.includes('Not connected') ||
                            msg.includes('no P2P session') ||
                            msg.includes('is not connected') ||
                            msg.includes('disconnected')) {
                            break;
                        }
                        if (attempts < maxAttempts) await new Promise(r => setTimeout(r, 200));
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

            if (!envelopeToSend.destinationInbox) {
                console.warn('[UnifiedTransport] Cannot route message without destinationInbox', to);
                return { success: false, transport: 'server', error: 'destinationInbox required' };
            }

            if (!envelopeToSend.recipientKyberPublicBase64) {
                console.warn('[UnifiedTransport] Cannot blind-route without recipient Kyber key', to);
                return { success: false, transport: 'server', error: 'recipientKyberPublicBase64 required' };
            }

            const blindClient = getBlindRoutingClient();
            const recipientKyber = PostQuantumUtils.base64ToUint8Array(envelopeToSend.recipientKyberPublicBase64);
            const sealedEnvelope = await blindClient.createSealedEnvelope(
                envelopeToSend.destinationInbox,
                recipientKyber,
                { envelope: envelopeToSend.envelope, messageId: envelopeToSend.messageId }
            );

            websocketClient.send(JSON.stringify({
                type: SignalType.BLIND_ROUTE,
                destinationInbox: envelopeToSend.destinationInbox,
                sealedEnvelope
            }));
           
            return { success: true, transport: 'server' };
        } catch (serverErr: any) {
            console.error(`[UnifiedTransport] Critical failure sending ${type} to ${to}:`, serverErr);
            return { success: false, transport: 'server', error: serverErr?.message || 'Server send failed' };
        }
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
