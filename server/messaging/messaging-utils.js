import { SignalType } from "../signals.js";
import * as ServerConfig from "../config/config.js";
import { CryptoUtils } from "../crypto/unified-crypto.js";

export class MessagingUtils {
  static async broadcastUserJoin(clients, username) {
    console.log(`[MESSAGING] Broadcasting user join for: ${username}`);
    await this.broadcastEncryptedSystemMessage(
      `${username} has joined the chat.`,
      clients,
      { excludeUsername: username }
    );

    console.log(`[MESSAGING] Broadcasting public keys after user join`);
    this.broadcastPublicKeys(clients);
  }

  static async broadcastUserLeave(clients, username) {
    console.log(`[MESSAGING] Broadcasting user leave for: ${username}`);
    await this.broadcastEncryptedSystemMessage(
      `${username} has left the chat.`,
      clients,
      { signalType: SignalType.USER_DISCONNECT }
    );
  }

  static broadcastPublicKeys(clients) {
    console.log(`[MESSAGING] Broadcasting public keys to ${clients.size} clients`);
    const keyMap = {};

    for (const [uname, data] of clients.entries()) {
      if (data.hybridPublicKeys) {
        keyMap[uname] = data.hybridPublicKeys;
        console.log(`[MESSAGING] Added public keys for user: ${uname}`);
      } else {
        console.log(`[MESSAGING] No public keys available for user: ${uname}`);
      }
    }

    const keyUpdate = JSON.stringify({
      type: SignalType.PUBLICKEYS,
      message: JSON.stringify(keyMap),
    });

    console.log(`[MESSAGING] Sending public keys update to ${Object.keys(keyMap).length} users`);
    for (const [uname, client] of clients.entries()) {
      if (client.ws) {
        console.log(`[MESSAGING] Sending public keys to user: ${uname}`);
        client.ws.send(keyUpdate);
      } else {
        console.warn(`[MESSAGING] No WebSocket available for user: ${uname}`);
      }
    }
  }

  static async broadcastEncryptedSystemMessage(content, clientsMap, options = {}) {
    const {
      signalType = SignalType.ENCRYPTED_MESSAGE,
      excludeUsername = null,
    } = options;

    console.log(`[MESSAGING] Broadcasting encrypted system message: "${content}"`);
    console.log(`[MESSAGING] Signal type: ${signalType}, exclude username: ${excludeUsername || 'none'}`);

    const promises = [];

    for (const [clientUsername, client] of clientsMap.entries()) {
      if (clientUsername !== excludeUsername && client.hybridPublicKeys) {
        try {
          console.log(`[MESSAGING] Encrypting system message for user: ${clientUsername}`);
          const finalPayload = await CryptoUtils.Hybrid.encryptHybridPayload({
            from: ServerConfig.SERVER_ID,
            to: clientUsername,
            type: signalType,
            typeInside: "system",
            content: content,
            timestamp: Date.now()
          }, client.hybridPublicKeys);

          const messageToSend = {
            type: signalType,
            ...finalPayload
          };

          console.log(`[MESSAGING] Sending encrypted system message to user: ${clientUsername}`);
          promises.push(client.ws.send(JSON.stringify(messageToSend)));
        } catch (e) {
          console.error(`[MESSAGING] Failed to encrypt system message for ${clientUsername}:`, e);
        }
      } else if (clientUsername === excludeUsername) {
        console.log(`[MESSAGING] Skipping system message for excluded user: ${clientUsername}`);
      } else if (!client.hybridPublicKeys) {
        console.log(`[MESSAGING] Skipping system message for user without public keys: ${clientUsername}`);
      }
    }

    console.log(`[MESSAGING] Sending ${promises.length} encrypted system messages`);
    await Promise.allSettled(promises);
    console.log(`[MESSAGING] System message broadcast completed`);
  }
}