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

          /*

          
          {
            "from": "SecureChat-Server",
            "to": "user1",
            "type": "user-disconnect",
            "encryptedAESKey": "pd/rgD+8R28Qr6kolrdipLby3QtpSjWcoCqPwW0KFgrVho9IWkmHSb/Z8GW4CgT5RLu5QzrSWvEX4bF8FyKJ/n1KMTuT/yuhl4aB3Lsv3NdjqCkiX6L1H3gngkbBOZZPr6Jd4YxL+Eb+NMefQyz/dStJ0jnYh2el2yBsunVoEe4LVxiqS1UmX7VDrWZF+EZ8ednzd3iFrcREjqRuB7qTKT5gBYn+BlVZm+PZlC8hDJKvEt9fGMgI6zw9f9ZMNI6vE/sNHKr1JQRVEgCLDiB/F7uBceRe8HpRiRpRQ5CuHuKZqw69igKF63vXfJNFBxT90U6bibxX2ZrmE1Kc6hxRUpMH8kYh7PasnmEswrnCeEdOMMmjOX+NyGFKEdSap+6uOu3wyl173POCEGnkxqYkYRlEWZZ1+zHSrp98dy3XS9hwsfYj5SIM74qnUX1OA4UFuSpG1uJ6PEhWIFVOyrx/u213+P+X0ss3F8AVDPN/a80uf1B3dvSVha3vH0rU3IDTY9Wb0hAgPPAcX/41HY1QJ2l8LmyYFPdWiJgxRAdG5Ukzj8UiThIpFe8rGfsb6OR1A++T2i+7g82nKDPPdqav45OKQ+/35yKZFyH/gbteIvtOyzK5PdzucBuR7Fx3fUK64ly6NdQG/4BUywh7cBaEUO5MLm70UerIY3WnEQKtSN4=",
            "encryptedMessage": "ARAgd6Dhyo/yNVS5L34Eb8eoEIfiMIw4JZ+SXTKqDY8q8UYAAABWDxsR2GrSH+AOddaqTjfFr4kN/CAAoRdGYo2JGLII4p16MCS8QFuLr0wNuvqPnIVA3aqIVT2AjRzQ1pdLvrf++7zEJM1i2j9kUobXlB+lWiJwghwq09g="
          }

          */
          
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