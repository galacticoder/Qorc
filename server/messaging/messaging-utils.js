import { SignalType } from "../signals.js";
import * as ServerConfig from "../config/config.js";
import { CryptoUtils } from "../crypto/unified-crypto.js";

export class MessagingUtils {
  static async broadcastUserJoin(clients, username) {
    await this.broadcastEncryptedSystemMessage(
      `${username} has joined the chat.`,
      clients,
      { excludeUsername: username }
    );
    
    this.broadcastPublicKeys(clients);
  }

  static async broadcastUserLeave(clients, username) {
    await this.broadcastEncryptedSystemMessage(
      `${username} has left the chat.`,
      clients,
      { signalType: SignalType.USER_DISCONNECT }
    );
  }

  static broadcastPublicKeys(clients) {
    const keyMap = {};
    for (const [uname, data] of clients.entries()) {
      if (data.publicKey) keyMap[uname] = data.publicKey;
    }
    
    const keyUpdate = JSON.stringify({
      type: SignalType.PUBLICKEYS,
      message: JSON.stringify(keyMap),
    });
    
    console.log("Broadcasting public keys: ", keyUpdate);
    
    for (const [, client] of clients.entries()) {
      if (client.publicKey) client.ws.send(keyUpdate);
    }
  }

  static async broadcastEncryptedSystemMessage(content, clientsMap, options = {}) {
    const {
      signalType = SignalType.ENCRYPTED_MESSAGE,
      excludeUsername = null,
    } = options;

    console.log(`Broadcasting system message: ${content}`);

    const promises = [];

    for (const [clientUsername, client] of clientsMap.entries()) {
      if (clientUsername !== excludeUsername && client.publicKey) {
      try {
        const finalPayload = await CryptoUtils.Encrypt.encryptAndFormatPayload({
          recipientPEM: client.publicKey,
          from: ServerConfig.SERVER_ID,
          to: clientUsername,
          type: signalType,
          typeInside: "system",
          content: content,
          timestamp: Date.now()
        });

        console.log(`finalPayload for ${clientUsername}: `, JSON.stringify(finalPayload));
        promises.push(client.ws.send(JSON.stringify(finalPayload)));
        console.log(`finalPayload for ${clientUsername} sent`);
      } catch (e) {
        console.error(`Failed to encrypt system message for ${clientUsername}:`, e);
      }
      }
    }

    await Promise.allSettled(promises);
  }
}