import { useCallback } from "react";
// websocketclient imported at top already
import { Message } from "@/components/chat/types";
import { SignalType } from "@/lib/signals";
import { User } from "@/components/chat/UserList";
import { CryptoUtils } from "@/lib/unified-crypto";
import { X3DH } from "@/lib/ratchet/x3dh";
import { SessionStore } from "@/lib/ratchet/session-store";
import { DoubleRatchet } from "@/lib/ratchet/double-ratchet";
import websocketClient from "@/lib/websocket";
import { ServerDatabase } from "./useSecureDB";

export function useMessageSender(
  users: User[],
  loginUsernameRef: React.MutableRefObject<string>,
  onNewMessage: (message: Message) => void,
  serverHybridPublic: { x25519PublicBase64: string; kyberPublicBase64: string } | null,
  getKeysOnDemand: () => Promise<{ x25519: { private: any; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  aesKeyRef: React.MutableRefObject<CryptoKey | null>,
  keyManagerRef?: React.MutableRefObject<any>,
  passphraseRef?: React.MutableRefObject<string>,
  isLoggedIn?: boolean
) {
  const pendingSendsRef = { current: [] as Array<() => Promise<void>> } as any;
  let flushTimer: any = null;

  function scheduleFlush(delayMs: number) {
    if (flushTimer) return;
    flushTimer = setTimeout(async () => {
      flushTimer = null;
      const tasks = pendingSendsRef.current.splice(0, pendingSendsRef.current.length);
      for (const task of tasks) {
        try { await task(); } catch { /* keep quiet */ }
      }
    }, delayMs);
  }
  async function waitForSessionAvailability(currentUser: string, peer: string, totalMs = 5000, intervalMs = 100): Promise<boolean> {
    const start = Date.now();
    let attempt = 0;
    while (Date.now() - start < totalMs) {
      const s = SessionStore.get(currentUser, peer);
      if (s) {
        try {
          console.debug("[Sender] Session became available", {
            peer,
            attempts: attempt,
            waitedMs: Date.now() - start,
            sendMessageNumber: s.sendMessageNumber,
            prevSendCount: s.previousSendMessageCount,
          });
        } catch { }
        return true;
      }
      attempt++;
      await new Promise(res => setTimeout(res, intervalMs));
    }
    console.warn("[Sender] Session did not become available in time", { peer, waitedMs: totalMs });
    return false;
  }
  async function getDeterministicMessageId(message: {
    content: string;
    timestamp: number;
    sender: string;
    replyToId?: string;
  }): Promise<string> {
    const encoder = new TextEncoder();
    const replyPart = message.replyToId ? `:${message.replyToId}` : '';
    const normalized = `${message.content.trim()}:${message.timestamp}:${message.sender.trim().toLowerCase()}${replyPart}`;
    try {
      console.debug("[Sender] Deterministic ID input:", { normalized });
    } catch { }

    const hashBuffer = await crypto.subtle.digest("SHA-512", encoder.encode(normalized));
    const idHex = Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    try {
      console.debug("[Sender] Deterministic ID computed:", idHex);
    } catch { }
    return idHex;
  }

  const handleSendMessage = useCallback(
    async ({
      messageId,
      replyTo,
      type,
      typeInside,
      content,
    }: {
      messageId?: string;
      replyTo?: Message | null;
      type?: string;
      typeInside?: string;
      content?: string;
    }) => {
      console.log("[Sender] handleSendMessage invoked", {
        messageId,
        replyToId: replyTo?.id,
        type,
        typeInside,
        contentPreview: (content || '').slice(0, 80),
      });
      if (!serverHybridPublic) {
        console.error("Server keys not available");
        return;
      }
      try {
        console.debug("[Sender] Server hybrid public keys", {
          x25519PublicBase64: serverHybridPublic.x25519PublicBase64?.slice(0, 24) + '...',
          kyberPublicBase64: serverHybridPublic.kyberPublicBase64?.slice(0, 24) + '...',
        });
      } catch { }

      const hybridKeys = await getKeysOnDemand();
      if (!hybridKeys) {
        console.error("Client keys not available");
        return;
      }
      try {
        console.debug("[Sender] Client hybrid keys", {
          x25519PublicBase64: hybridKeys.x25519.publicKeyBase64?.slice(0, 24) + '...',
          kyberPublicBase64: hybridKeys.kyber.publicKeyBase64?.slice(0, 24) + '...',
          x25519PrivateLen: (hybridKeys.x25519.private as Uint8Array)?.byteLength ?? 'n/a',
          kyberSecretLen: hybridKeys.kyber.secretKey?.byteLength ?? 'n/a',
          aesKeyPresent: !!aesKeyRef.current,
        });
      } catch { }

      const time = Date.now();
      const id = messageId || await getDeterministicMessageId({
        content: content || "",
        timestamp: time,
        sender: loginUsernameRef.current,
        replyToId: replyTo?.id
      });
      console.log("[Sender] Using messageId:", id, "timestamp:", time);

      const enqueueAndBackoff = (fn: () => Promise<void>, baseMs = 1000) => {
        pendingSendsRef.current.push(fn);
        scheduleFlush(baseMs);
      };

      try {
        console.debug("[Sender] Recipients count:", users.length, users.map(u => u.username));

        // Determine recipients; only send to online users
        const onlineRecipients = users.filter(u => u.username !== loginUsernameRef.current && u.isOnline);
        if (onlineRecipients.length === 0) {
          console.log("[Sender] No online recipients; not delivering");
        }

        await Promise.all(
          onlineRecipients.map(async (user) => {
            const currentUser = loginUsernameRef.current;
            // init persistent session context
            await SessionStore.initUserContext(currentUser, aesKeyRef.current);
            // build or fetch a session
            let session = SessionStore.get(currentUser, user.username);
            if (session) {
              console.debug("[Sender] Found existing session", {
                peer: user.username,
                hasValidRemoteKey: !session.remoteDhPublic.every(b => b === 0),
                remoteDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.remoteDhPublic).slice(0, 24) + '...',
              });
            }
            if (!session) {
              console.warn("[Sender] No session found, requesting X3DH bundle for", user.username);
              // request recipient bundle
              websocketClient.send(JSON.stringify({ type: SignalType.X3DH_REQUEST_BUNDLE, username: user.username }));
              // wait briefly for session creation and then proceed
              const available = await waitForSessionAvailability(currentUser, user.username, 5000, 100);
              session = SessionStore.get(currentUser, user.username);
              if (!available || !session) {
                console.warn("[Sender] Session still unavailable for", user.username, "after wait; skipping send");
                return;
              }
              // verify session has valid remote public key
              if (session.remoteDhPublic.every(b => b === 0)) {
                console.warn("[Sender] Session has invalid remote public key (all zeros); skipping send");
                return;
              }
            }
            try {
              console.debug("[Sender] Session state before encrypt", {
                to: user.username,
                from: currentUser,
                sendMessageNumber: session.sendMessageNumber,
                recvMessageNumber: session.recvMessageNumber,
                previousSendMessageCount: session.previousSendMessageCount,
                currentDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.currentDhPublic).slice(0, 24) + '...',
                remoteDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.remoteDhPublic).slice(0, 24) + '...',
              });
            } catch { }

            // check if session has valid remote public key
            if (session.remoteDhPublic.every(b => b === 0)) {
              console.warn("[Sender] Session has invalid remote public key (all zeros); clearing and requesting new bundle");
              SessionStore.clear(currentUser, user.username);
              websocketClient.send(JSON.stringify({ type: SignalType.X3DH_REQUEST_BUNDLE, username: user.username }));
              const available = await waitForSessionAvailability(currentUser, user.username, 5000, 100);
              session = SessionStore.get(currentUser, user.username);
              if (!available || !session || session.remoteDhPublic.every(b => b === 0)) {
                console.warn("[Sender] Session still invalid after retry; skipping send");
                return;
              }
            }

            const messagePayload = {
              id: id,
              from: currentUser,
              to: user.username,
              type: type,
              content: content,
              timestamp: time,
              typeInside: typeInside,
              ...(replyTo && {
                replyTo: {
                  id: replyTo.id,
                  sender: replyTo.sender,
                  content: replyTo.content,
                },
              }),
            };
            console.debug("[Sender] Built messagePayload", {
              id: messagePayload.id,
              from: messagePayload.from,
              to: messagePayload.to,
              type: messagePayload.type,
              typeInside: messagePayload.typeInside,
              hasReplyTo: !!replyTo,
              contentPreview: (messagePayload.content || '').slice(0, 120),
            });

            const includeX3dh = session.sendMessageNumber === 0 && session.previousSendMessageCount === 0;
            console.debug("[Sender] includeX3dh:", includeX3dh);
            console.debug("[Sender] Session before encrypt", {
              sendMessageNumber: session.sendMessageNumber,
              previousSendMessageCount: session.previousSendMessageCount,
              sendChainKeyAllZeros: session.sendChainKey.every(b => b === 0),
              sendChainKeyPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.sendChainKey).slice(0, 24) + '...',
              currentDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.currentDhPublic).slice(0, 24) + '...',
              remoteDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.remoteDhPublic).slice(0, 24) + '...',
            });

            // for the very first outbound message force refresh a proper sender session
            // to avoid using stale or receiver initialized state from persistence
            if (includeX3dh) {
              console.warn("[Sender] Forcing fresh sender session for first message");
              SessionStore.clear(currentUser, user.username);
              websocketClient.send(JSON.stringify({ type: SignalType.X3DH_REQUEST_BUNDLE, username: user.username }));
              const available = await waitForSessionAvailability(currentUser, user.username, 5000, 100);
              session = SessionStore.get(currentUser, user.username);
              if (!available || !session) {
                console.warn("[Sender] Sender session unavailable after forced refresh; skipping send", { peer: user.username });
                return;
              }
              try {
                console.debug("[Sender] Sender session ready after forced refresh", {
                  sendMessageNumber: session.sendMessageNumber,
                  recvMessageNumber: session.recvMessageNumber,
                  currentDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.currentDhPublic).slice(0, 24) + '...',
                  remoteDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.remoteDhPublic).slice(0, 24) + '...',
                });
              } catch { }
            }

            // additionally if the session was initialized as a receiver using our local signed prekey
            // refresh again to guarantee a proper sender session
            if (includeX3dh && keyManagerRef?.current?.getRatchetPrekeys) {
              try {
                const pre = await keyManagerRef.current.getRatchetPrekeys();
                const localSpkId = pre?.signedPreKey?.id;
                const localSpkPubB64 = pre?.signedPreKey?.publicBase64;
                const sessionSpkId = (session as any).usedSignedPreKeyId as string | undefined;
                const sessionDhPubB64 = CryptoUtils.Base64.arrayBufferToBase64(session.currentDhPublic);
                const looksReceiverInitialized =
                  // session was previously used to receive messages but never sent
                  session.recvMessageNumber > 0 ||
                  // sessions current dh pub equals our signed prekey pub receiver bootstrap signature
                  (localSpkPubB64 && sessionDhPubB64 === localSpkPubB64) ||
                  // session metadata indicates it was created referencing our own spk id
                  (localSpkId && sessionSpkId && localSpkId === sessionSpkId);
                if (looksReceiverInitialized) {
                  console.warn("[Sender] Existing session is receiver-initialized; requesting bundle to bootstrap sender session");
                  SessionStore.clear(currentUser, user.username);
                  websocketClient.send(JSON.stringify({ type: SignalType.X3DH_REQUEST_BUNDLE, username: user.username }));
                  const available = await waitForSessionAvailability(currentUser, user.username, 5000, 100);
                  session = SessionStore.get(currentUser, user.username);
                  if (!available || !session) {
                    console.warn("[Sender] Sender session unavailable after refresh; skipping send", { peer: user.username });
                    return;
                  }
                  try {
                    console.debug("[Sender] Sender session ready after refresh", {
                      sendMessageNumber: session.sendMessageNumber,
                      recvMessageNumber: session.recvMessageNumber,
                      currentDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.currentDhPublic).slice(0, 24) + '...',
                      remoteDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.remoteDhPublic).slice(0, 24) + '...',
                    });
                  } catch { }
                }
              } catch { }
            }
            const ratchetMessage = await DoubleRatchet.encrypt(session, JSON.stringify(messagePayload));
            try {
              console.debug("[Sender] Ratchet header", {
                dhPubPrefix: CryptoUtils.Base64.arrayBufferToBase64(ratchetMessage.header.dhPub).slice(0, 24) + '...',
                pn: ratchetMessage.header.pn,
                n: ratchetMessage.header.n,
                ciphertextLen: (ratchetMessage.ciphertext || '').length,
              });
            } catch { }

            const drPayload: any = {
              type: SignalType.DR_SEND,
              from: currentUser,
              to: user.username,
              payload: {
                header: {
                  dhPub: CryptoUtils.Base64.arrayBufferToBase64(ratchetMessage.header.dhPub),
                  pn: ratchetMessage.header.pn,
                  n: ratchetMessage.header.n,
                },
                ciphertext: ratchetMessage.ciphertext,
              },
            };
            // if first send on this session include x3dh envelope inside payload to help receiver
            if (includeX3dh) {
              const x3dhMeta: any = {
                ephX25519PublicBase64: CryptoUtils.Base64.arrayBufferToBase64(session.currentDhPublic),
              };
              if ((session as any).usedSignedPreKeyId) {
                x3dhMeta.usedSignedPreKeyId = (session as any).usedSignedPreKeyId;
              }
              if ((session as any).usedOneTimePreKeyId) {
                x3dhMeta.usedOneTimePreKeyId = (session as any).usedOneTimePreKeyId;
              }
              drPayload.payload.x3dh = x3dhMeta;
            }
            console.log("[Sender] Sending DR payload", {
              to: drPayload.to,
              from: drPayload.from,
              includeX3dh,
              header: drPayload.payload.header,
              ciphertextLen: (drPayload.payload.ciphertext || '').length,
            });
            const sendFn = async () => {
              // if globally rate limited, re-enqueue
              if ((websocketClient as any).isGloballyRateLimited?.()) {
                enqueueAndBackoff(sendFn, 1000);
                return;
              }
              websocketClient.send(
                JSON.stringify({
                  ...drPayload
                })
              );
            };
            await sendFn();

            console.log(`Sent DR message to user ${user.username}: `, drPayload);

            // Send to server db (skip typing)
            if (typeInside !== 'typing-start' && typeInside !== 'typing-stop' && serverHybridPublic && aesKeyRef.current) {
              const { iv, authTag, encrypted } = await CryptoUtils.AES.encryptWithAesGcmRaw(
                content,
                aesKeyRef.current
              );
              const encryptedContent = CryptoUtils.AES.serializeEncryptedData(iv, authTag, encrypted);
              try {
                console.debug("[Sender] Local AES-GCM for server payload", {
                  ivLen: iv.length,
                  authTagLen: authTag.length,
                  encryptedLen: encrypted.length,
                  serializedLen: encryptedContent.length,
                });
              } catch { }

              let encryptedReplyContent = "";
              if (replyTo) {
                const replyContent = replyTo.content || "";
                const { iv: replyIv, authTag: replyAuthTag, encrypted: replyEncrypted } = await CryptoUtils.AES.encryptWithAesGcmRaw(
                  replyContent,
                  aesKeyRef.current
                );
                encryptedReplyContent = CryptoUtils.AES.serializeEncryptedData(replyIv, replyAuthTag, replyEncrypted);
                try {
                  console.debug("[Sender] Reply content encrypted", {
                    replyIvLen: replyIv.length,
                    replyAuthTagLen: replyAuthTag.length,
                    replyEncryptedLen: replyEncrypted.length,
                    replySerializedLen: encryptedReplyContent.length,
                  });
                } catch { }
              }

              const serverPayload = {
                messageId: id,
                fromUsername: loginUsernameRef.current,
                toUsername: user.username,
                encryptedContent: encryptedContent,
                timestamp: time,
                typeInside: typeInside,
                ...(replyTo && {
                  replyTo: {
                    id: replyTo.id,
                    sender: replyTo.sender,
                    encryptedContent: encryptedReplyContent,
                  },
                }),
              };
              console.debug("[Sender] ServerPayload before hybrid encryption", {
                messageId: serverPayload.messageId,
                from: serverPayload.fromUsername,
                to: serverPayload.toUsername,
                typeInside: serverPayload.typeInside,
                payloadLen: JSON.stringify(serverPayload).length,
              });

              const serverEncrypted = await CryptoUtils.Hybrid.encryptHybridPayload(
                serverPayload,
                serverHybridPublic
              );
              try {
                console.debug("[Sender] Server payload encrypted (hybrid-v1)", {
                  hasEphemeralX25519Public: !!(serverEncrypted as any).ephemeralX25519Public,
                  kyberCiphertextLen: ((serverEncrypted as any).kyberCiphertext || '').length,
                  encryptedMessageLen: ((serverEncrypted as any).encryptedMessage || '').length,
                });
              } catch { }

              const dbPayload = {
                type: SignalType.UPDATE_DB,
                ...serverEncrypted
              };

              const sendDbFn = async () => {
                if ((websocketClient as any).isGloballyRateLimited?.()) {
                  enqueueAndBackoff(sendDbFn, 1000);
                  return;
                }
                websocketClient.send(JSON.stringify(dbPayload));
              }
              await sendDbFn();

              console.log(`Sent to server database:`, serverPayload.messageId);
            }
          })
        );

        // Save to local db (skip typing)
        if (typeInside !== 'typing-start' && typeInside !== 'typing-stop') {
          onNewMessage({
            id: id,
            content: content || "",
            sender: loginUsernameRef.current,
            timestamp: new Date(),
            isCurrentUser: true,
            isDeleted: typeInside === SignalType.DELETE_MESSAGE,
            ...(replyTo ? { replyTo } : {})
          });
        }
        try {
          console.debug("[Sender] Locally persisted outbound message", {
            id,
            sender: loginUsernameRef.current,
            typeInside,
            hasReply: !!replyTo,
          });
        } catch { }
      } catch (error) {
        console.error("handleMessage failed:", error);
      }
    },
    [users, loginUsernameRef, serverHybridPublic, getKeysOnDemand, aesKeyRef, onNewMessage]
  );

  const handleSendMessageType = useCallback(
    async (messageId: string, content: string, messageSignalType: string, replyTo?: Message | null) => {
      if (messageSignalType === "chat") {
        await handleSendMessage({
          replyTo: replyTo,
          type: SignalType.ENCRYPTED_MESSAGE,
          typeInside: "chat",
          content: content,
        });
      } else {
        await handleSendMessage({
          messageId: messageId,
          replyTo: replyTo,
          type: SignalType.ENCRYPTED_MESSAGE,
          typeInside: messageSignalType,
          content: content,
        });
      }
    },
    [handleSendMessage]
  );

  return {
    handleMessage: handleSendMessage,
    handleSendMessageType
  };
}