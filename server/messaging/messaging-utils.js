import { SignalType } from "../signals.js";
import * as ServerConfig from "../config/config.js";
import { CryptoUtils } from "../crypto/unified-crypto.js";

export class MessagingUtils {

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


}