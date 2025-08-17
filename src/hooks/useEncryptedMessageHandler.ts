import { v4 as uuidv4 } from "uuid";
import { useCallback } from "react";
import { CryptoUtils } from "@/lib/unified-crypto";
import { SignalType } from "@/lib/signals";
import { Message } from "@/components/chat/types";
import { SessionStore } from "@/lib/ratchet/session-store";
import { DoubleRatchet } from "@/lib/ratchet/double-ratchet";
import { X3DH } from "@/lib/ratchet/x3dh";
import { SecureKeyManager } from "@/lib/secure-key-manager";
import websocketClient from "@/lib/websocket";
import { PinnedIdentities } from "@/lib/ratchet/pinned-identities";

async function fetchPeerBundleFor(currentUser: string, peer: string) {
  return null as any;
}

export function useEncryptedMessageHandler(
  getKeysOnDemand: () => Promise<{ x25519: { private: any; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  keyManagerRef: React.MutableRefObject<any>,
  loginUsernameRef: React.MutableRefObject<string>,
  setUsers: React.Dispatch<React.SetStateAction<any[]>>,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>
) {
  return useCallback(
    async (encryptedMessage: any) => {
      try {
        //skip nonobject stuff like raw strings from old server messages
        if (typeof encryptedMessage !== "object" || encryptedMessage === null) {
          return;
        }
        try {
          console.debug("[Recv] Incoming signal", {
            type: (encryptedMessage as any)?.type,
            keys: Object.keys(encryptedMessage || {}),
          });
        } catch { }

        let payload: any;
        if (encryptedMessage?.type === SignalType.DR_SEND) {
          const fromUser = encryptedMessage.from;
          const currentUser = loginUsernameRef.current;
          // only handle DR messages sent to us
          if (encryptedMessage.to && encryptedMessage.to !== currentUser) {
            console.debug("[Recv] DR message not for this user, ignoring", {
              to: encryptedMessage.to,
              currentUser,
            });
            return;
          }
          let session = SessionStore.get(currentUser, fromUser);
          console.debug("[Recv] Session lookup", {
            from: fromUser,
            to: currentUser,
            hasSession: !!session,
            sessionHasValidRemoteKey: session ? !session.remoteDhPublic.every(b => b === 0) : false,
          });
          //if we dont have a session yet but the message has x3dh data then create one
          const dr = encryptedMessage.payload || {};
          try {
            console.debug("[Recv] DR header", {
              from: fromUser,
              to: currentUser,
              hasX3dh: !!dr?.x3dh,
              header: dr?.header,
              ciphertextLen: (dr?.ciphertext || '').length,
              usedSpkId: dr?.x3dh?.usedSignedPreKeyId,
              usedOtkId: dr?.x3dh?.usedOneTimePreKeyId,
            });
          } catch { }
          console.debug("[Recv] Bootstrap condition check", {
            hasSession: !!session,
            hasX3dh: !!dr?.x3dh,
            hasEphPublic: !!dr?.x3dh?.ephX25519PublicBase64,
            shouldBootstrap: !session && !!dr?.x3dh?.ephX25519PublicBase64,
          });

          //if we have a session but the DH key doesnt match and this is the first message reset everything
          if (session && dr?.x3dh?.ephX25519PublicBase64 && dr.header.n === 0) {
            const messageDhPublic = CryptoUtils.Base64.base64ToUint8Array(dr.header.dhPub);
            const currentRemoteDhPublic = session.remoteDhPublic;
            const dhPublicsMatch = currentRemoteDhPublic.length === messageDhPublic.length &&
              currentRemoteDhPublic.every((b, i) => b === messageDhPublic[i]);

            console.debug("[Recv] Checking DH public key match", {
              currentRemoteDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(currentRemoteDhPublic).slice(0, 24) + '...',
              messageDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(messageDhPublic).slice(0, 24) + '...',
              dhPublicsMatch,
            });

            //always start fresh on first X3DH message to avoid old state
            console.warn("[Recv] Clearing existing session on first X3DH message and re-bootstrapping");
            SessionStore.clear(currentUser, fromUser);
            session = null;
          }

          if (!session && dr?.x3dh?.ephX25519PublicBase64) {
            const ratchetId = await keyManagerRef.current?.getRatchetIdentity?.();
            const prekeys = await keyManagerRef.current?.getRatchetPrekeys?.();
            if (ratchetId && prekeys?.signedPreKey) {
              //try to use the exact one-time key the sender said they used
              let oneTimePreKeySk: Uint8Array | undefined = undefined;
              if (dr.x3dh.usedOneTimePreKeyId && Array.isArray(prekeys.oneTimePreKeys)) {
                const match = prekeys.oneTimePreKeys.find(k => k.id === dr.x3dh.usedOneTimePreKeyId);
                if (match) oneTimePreKeySk = match.private;
              }
              const rootKey = await X3DH.deriveReceiverSecret(
                ratchetId.x25519Private,
                prekeys.signedPreKey.private,
                CryptoUtils.Base64.base64ToUint8Array(dr.x3dh.ephX25519PublicBase64),
                oneTimePreKeySk
              );
              session = {
                rootKey,
                //use our signed prekey as the ratchet key
                currentDhPrivate: prekeys.signedPreKey.private,
                currentDhPublic: CryptoUtils.Base64.base64ToUint8Array(prekeys.signedPreKey.publicBase64),
                //set to senders ephemeral key to match what they sent
                remoteDhPublic: CryptoUtils.Base64.base64ToUint8Array(dr.header?.dhPub || dr.x3dh.ephX25519PublicBase64),
                sendChainKey: new Uint8Array(32),
                recvChainKey: new Uint8Array(32),
                sendMessageNumber: 0,
                recvMessageNumber: 0,
                previousSendMessageCount: 0,
                skippedMessageKeys: new Map(),
                usedSignedPreKeyId: prekeys.signedPreKey.id,
                usedOneTimePreKeyId: dr.x3dh.usedOneTimePreKeyId,
              };
              SessionStore.set(currentUser, fromUser, session);
              console.debug("[Recv] Receiver bootstrap completed; session created", {
                currentDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.currentDhPublic).slice(0, 24) + '...',
                remoteDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.remoteDhPublic).slice(0, 24) + '...',
              });
              //wait to consume the one time key until we successfully decrypt
            } else {
              console.warn('[Recv] Missing ratchet identity or signed prekey; cannot bootstrap receiver session');
            }
          }
          if (!session) {
            console.warn('[Recv] No session available; cannot decrypt DR message yet');
            return;
          }
          const header = dr.header;
          const ratchetMsg = {
            header: {
              dhPub: CryptoUtils.Base64.base64ToUint8Array(header.dhPub),
              pn: header.pn,
              n: header.n,
            },
            ciphertext: dr.ciphertext,
          };
          console.debug("[Recv] Session before decrypt", {
            recvMessageNumber: session.recvMessageNumber,
            recvChainKeyAllZeros: session.recvChainKey.every(b => b === 0),
            recvChainKeyPrefix: CryptoUtils.Base64.arrayBufferToBase64(session.recvChainKey).slice(0, 24) + '...',
          });

          //save session state in case decrypt fails
          const snapshot = (() => {
            return {
              rootKey: new Uint8Array(session.rootKey),
              currentDhPrivate: new Uint8Array(session.currentDhPrivate),
              currentDhPublic: new Uint8Array(session.currentDhPublic),
              remoteDhPublic: new Uint8Array(session.remoteDhPublic),
              sendChainKey: new Uint8Array(session.sendChainKey),
              recvChainKey: new Uint8Array(session.recvChainKey),
              sendMessageNumber: session.sendMessageNumber,
              recvMessageNumber: session.recvMessageNumber,
              previousSendMessageCount: session.previousSendMessageCount,
              skippedMessageKeys: new Map(session.skippedMessageKeys),
              usedSignedPreKeyId: (session as any).usedSignedPreKeyId,
              usedOneTimePreKeyId: (session as any).usedOneTimePreKeyId,
            };
          })();
          const restore = (snap: any) => {
            session.rootKey = new Uint8Array(snap.rootKey);
            session.currentDhPrivate = new Uint8Array(snap.currentDhPrivate);
            session.currentDhPublic = new Uint8Array(snap.currentDhPublic);
            session.remoteDhPublic = new Uint8Array(snap.remoteDhPublic);
            session.sendChainKey = new Uint8Array(snap.sendChainKey);
            session.recvChainKey = new Uint8Array(snap.recvChainKey);
            session.sendMessageNumber = snap.sendMessageNumber;
            session.recvMessageNumber = snap.recvMessageNumber;
            session.previousSendMessageCount = snap.previousSendMessageCount;
            session.skippedMessageKeys = new Map(snap.skippedMessageKeys);
            (session as any).usedSignedPreKeyId = snap.usedSignedPreKeyId;
            (session as any).usedOneTimePreKeyId = snap.usedOneTimePreKeyId;
          };

          let plaintext: string;
          try {
            plaintext = await DoubleRatchet.decrypt(session, ratchetMsg);
            //save the updated session if decrypt worked
            SessionStore.set(currentUser, fromUser, session);
            //if we used a one time key mark it as used after successful decrypt
            if ((session as any).usedOneTimePreKeyId && keyManagerRef.current?.consumeOneTimePreKey) {
              try { await keyManagerRef.current.consumeOneTimePreKey((session as any).usedOneTimePreKeyId); } catch { }
            }
          } catch (e) {
            //put session back to how it was before trying to decrypt
            restore(snapshot);
            //if this is the first message try some other ways to decrypt
            if (dr?.x3dh && header.n === 0) {
              const ratchetId2 = await keyManagerRef.current?.getRatchetIdentity?.();
              const prekeys2 = await keyManagerRef.current?.getRatchetPrekeys?.();
              if (ratchetId2 && prekeys2?.signedPreKey) {
                const ephPub = CryptoUtils.Base64.base64ToUint8Array(dr.x3dh.ephX25519PublicBase64);
                const tryDecryptWith = async (oneTimeSk?: Uint8Array, otkId?: string): Promise<string | null> => {
                  const rootKey2 = await X3DH.deriveReceiverSecret(
                    ratchetId2.x25519Private,
                    prekeys2.signedPreKey.private,
                    ephPub,
                    oneTimeSk
                  );
                  const alt = {
                    rootKey: rootKey2,
                    currentDhPrivate: prekeys2.signedPreKey.private,
                    currentDhPublic: CryptoUtils.Base64.base64ToUint8Array(prekeys2.signedPreKey.publicBase64),
                    remoteDhPublic: CryptoUtils.Base64.base64ToUint8Array(dr.header?.dhPub || dr.x3dh.ephX25519PublicBase64),
                    sendChainKey: new Uint8Array(32),
                    recvChainKey: new Uint8Array(32),
                    sendMessageNumber: 0,
                    recvMessageNumber: 0,
                    previousSendMessageCount: 0,
                    skippedMessageKeys: new Map(),
                    usedSignedPreKeyId: prekeys2.signedPreKey.id,
                    ...(otkId ? { usedOneTimePreKeyId: otkId } : {}),
                  } as any;
                  try {
                    const out = await DoubleRatchet.decrypt(alt, ratchetMsg);
                    //save the session that worked
                    SessionStore.set(currentUser, fromUser, alt);
                    if (otkId && keyManagerRef.current?.consumeOneTimePreKey) {
                      try { await keyManagerRef.current.consumeOneTimePreKey(otkId); } catch { }
                    }
                    session = alt;
                    return out;
                  } catch { return null; }
                };

                //1) if message says it used a one time key first try without it //(maybe sender didnt actually use it)
                if (dr?.x3dh?.usedOneTimePreKeyId) {
                  const outNoOtk = await tryDecryptWith(undefined, undefined);
                  if (outNoOtk !== null) { plaintext = outNoOtk; }
                }

                //2) if that didnt work try all our one time keys
                if (!plaintext && Array.isArray(prekeys2.oneTimePreKeys) && prekeys2.oneTimePreKeys.length > 0) {
                  for (const k of prekeys2.oneTimePreKeys) {
                    const outWith = await tryDecryptWith(k.private, k.id);
                    if (outWith !== null) { plaintext = outWith; break; }
                  }
                }

                if (!plaintext) { throw e; }
              } else {
                throw e;
              }
            } else {
              throw e;
            }
          }
          console.debug("[Recv] DR decrypted plaintext length:", (plaintext || '').length);
          payload = JSON.parse(plaintext);
          console.debug("[Recv] Parsed DR payload", {
            id: payload?.id,
            from: payload?.from,
            to: payload?.to,
            type: payload?.type,
            typeInside: payload?.typeInside,
            ts: payload?.timestamp,
            hasReply: !!payload?.replyTo,
          });
        } else if (encryptedMessage?.type === SignalType.X3DH_DELIVER_BUNDLE) {
          //create a new session from the other users bundle because were sending to them
          const currentUser = loginUsernameRef.current;
          const targetUser = encryptedMessage.username;
          const bundle = encryptedMessage.bundle;
          const ratchetId = await keyManagerRef.current?.getRatchetIdentity?.();
          if (!ratchetId) return;
          const eph = await X3DH.generateEphemeralX25519KeyPair();
          const prekeyBundle = {
            username: targetUser,
            identityEd25519Public: CryptoUtils.Base64.base64ToUint8Array(bundle.identityEd25519PublicBase64),
            identityX25519Public: CryptoUtils.Base64.base64ToUint8Array(bundle.identityX25519PublicBase64),
            signedPreKey: {
              id: bundle.signedPreKey.id,
              publicKey: CryptoUtils.Base64.base64ToUint8Array(bundle.signedPreKey.publicKeyBase64),
              signature: CryptoUtils.Base64.base64ToUint8Array(bundle.signedPreKey.signatureBase64),
            },
            ratchetPublic: CryptoUtils.Base64.base64ToUint8Array(bundle.ratchetPublicBase64),
            oneTimePreKey: bundle.oneTimePreKey ? { id: bundle.oneTimePreKey.id, publicKey: CryptoUtils.Base64.base64ToUint8Array(bundle.oneTimePreKey.publicKeyBase64) } : undefined,
          } as any;

          //remember their identity and warn if it changes later
          const pinned = PinnedIdentities.get(currentUser, targetUser);
          if (!pinned) {
            PinnedIdentities.set(currentUser, targetUser, bundle.identityEd25519PublicBase64);
          } else if (pinned !== bundle.identityEd25519PublicBase64) {
            console.warn('[Recv] Remote identity changed for', targetUser);
            //for now just log 
          }

          //make sure the signed prekey is actually signed by their identity key
          const ok = await X3DH.verifyPreKeyBundle(prekeyBundle);
          if (!ok) {
            console.warn('[Recv] Invalid X3DH bundle signature for', targetUser);
            return;
          }

          const rootKey = await X3DH.deriveSenderSecret(
            ratchetId.x25519Private,
            eph.privateKey,
            prekeyBundle,
            prekeyBundle.oneTimePreKey
          );
          //set up basic session state
          const state = {
            rootKey,
            currentDhPrivate: eph.privateKey,
            currentDhPublic: eph.publicKey,
            remoteDhPublic: CryptoUtils.Base64.base64ToUint8Array(bundle.ratchetPublicBase64),
            sendChainKey: new Uint8Array(32),
            recvChainKey: new Uint8Array(32),
            sendMessageNumber: 0,
            recvMessageNumber: 0,
            previousSendMessageCount: 0,
            skippedMessageKeys: new Map(),
            usedSignedPreKeyId: bundle.signedPreKey.id,
            usedOneTimePreKeyId: bundle.oneTimePreKey?.id,
          };
          SessionStore.set(currentUser, targetUser, state);
          return;
        } else if (encryptedMessage?.version === "hybrid-v1") {
          //old hybrid encryption system messages
          const hybridKeys = await getKeysOnDemand();
          if (!hybridKeys) {
            console.error("Client hybrid keys not available for decryption");
            return;
          }

          payload = await CryptoUtils.Hybrid.decryptHybridPayload(
            encryptedMessage,
            {
              x25519: { private: hybridKeys.x25519.private },
              kyber: { secretKey: hybridKeys.kyber.secretKey }
            }
          );
          console.debug("[Recv] Hybrid decrypted payload", {
            id: payload?.id,
            from: payload?.from,
            to: payload?.to,
            type: payload?.type,
            typeInside: payload?.typeInside,
          });
        }

        if (payload.type === SignalType.USER_DISCONNECT) {
          const username = payload.content?.split(" ")[0];
          if (username) {
            setUsers(prevUsers =>
              prevUsers.filter(user => user.username !== username)
            );
          }
          return;
        }

        const isJoinLeave = payload.content?.includes("joined") ||
          payload.content?.includes("left");

        const messageId = payload.typeInside === "system"
          ? uuidv4()
          : payload.id ?? uuidv4();

        const payloadFull: Message = {
          id: messageId,
          content: payload.content || "",
          sender: payload.from || "system",
          timestamp: new Date(payload.timestamp || Date.now()),
          isCurrentUser: payload.from === loginUsernameRef.current,
          isSystemMessage: payload.typeInside === "system",
          isDeleted: payload.typeInside === SignalType.DELETE_MESSAGE,
          isEdited: payload.typeInside === SignalType.EDIT_MESSAGE,
          shouldPersist: isJoinLeave,
          ...(payload.replyTo && {
            replyTo: {
              id: payload.replyTo.id,
              sender: payload.replyTo.sender,
              content: payload.replyTo.content,
            },
          }),
        };

        console.debug("[Recv] Saving message to local DB", {
          id: payloadFull.id,
          from: payloadFull.sender,
          isSystem: payloadFull.isSystemMessage,
          isDeleted: payloadFull.isDeleted,
          isEdited: payloadFull.isEdited,
          ts: payloadFull.timestamp?.toISOString?.() ?? payloadFull.timestamp,
        });
        await saveMessageToLocalDB(payloadFull);

        console.log("[Recv] Received payload:", payload)

        setMessages(prev => {
          const exists = prev.some(msg => msg.id === payloadFull.id);
          if (exists) {
            return prev;
          }
          return [...prev, payloadFull];
        });

        if (payloadFull.isEdited || payloadFull.isDeleted) {
          setMessages(prev => prev.map(msg => {
            const updated = { ...msg };
            const content = payloadFull.isEdited
              ? payload.content
              : "Message Deleted";

            if (msg.replyTo?.id === payload.id) {
              updated.replyTo = { ...updated.replyTo, content: content };
              console.debug("[Recv] Updating replyTo content due to edit/delete", { id: updated.id });
              saveMessageToLocalDB(updated);
            }

            return updated;
          }));
        }
      } catch (error) {
        console.error("[Recv] Error handling encrypted message:", error);
      }
    },
    [saveMessageToLocalDB, getKeysOnDemand, setUsers, setMessages]
  );
}