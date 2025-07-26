import { WebSocketServer } from 'ws';
import { SignalType } from './signals.js';
import * as crypto from './unified-crypto.js';

const PORT = 8080;
const SERVER_ID = 'SecureChat-Server';
const clients = new Map();

const wss = new WebSocketServer({ port: PORT });
console.log(`SecureChat relay server running on ws://localhost:${PORT}`);

wss.on('connection', (ws) => {
  let username = null;

  ws.on('message', async (message) => {
    try {
      const str = message.toString().trim();

      if (!username) {
        const validUsername = /^[a-zA-Z0-9_-]+$/;
        if (!validUsername.test(str)) {
          ws.send("Invalid username");
          return ws.close();
        }
        username = str;
        clients.set(username, { ws, publicKey: null });
        console.log(`User ${username} connected.`);
        return;
      }

      if (!clients.get(username).publicKey) {
        clients.get(username).publicKey = str;
        console.log(`Received public key from ${username}`);

        const keyMap = {};
        for (const [uname, data] of clients.entries()) {
          if (data.publicKey) keyMap[uname] = data.publicKey;
        }

        const keyUpdate = JSON.stringify({
          type: SignalType.PUBLICKEYS,
          message: JSON.stringify(keyMap)
        });

        console.log("Broadcasting public keys: ", keyUpdate);

        for (const [, client] of clients.entries()) {
          if (client.publicKey) client.ws.send(keyUpdate);
        }

        await broadcastEncryptedSystemMessage(`${username} has joined the chat.`, username);

        return;
      }

      try {
        const parsed = JSON.parse(str);
        console.log(`Received message from ${username}:`, parsed);

        if (parsed.type === SignalType.ENCRYPTED_MESSAGE && parsed.to && clients.has(parsed.to)) {
          const target = clients.get(parsed.to);
          target.ws.send(JSON.stringify(parsed));
          console.log(`Relayed message from ${parsed.from} to ${parsed.to}`);
        }

        if (parsed.type === SignalType.FILE_MESSAGE_CHUNK && parsed.to && clients.has(parsed.to)) {
          const target = clients.get(parsed.to);
          target.ws.send(JSON.stringify(parsed));
          console.log(`Relayed file chunk ${parsed.chunkIndex + 1}/${parsed.totalChunks} from ${parsed.from} to ${parsed.to}`);
        }

        // else if (parsed.type === SignalType.FILE_MESSAGE && parsed.to && clients.has(parsed.to)) {
        //   const target = clients.get(parsed.to);
        //   target.ws.send(JSON.stringify(parsed));
        //   console.log(`Relayed file from ${parsed.from} to ${parsed.to}`);
        // }
      } catch (e) {
        console.warn("Non-JSON message:", str);
      }
    } catch (err) {
      console.error("Message error:", err);
    }
  });

  ws.on('close', async () => {
    if (username) {
      clients.delete(username);
      console.log(`User '${username}' has disconnected.`);

      await broadcastEncryptedSystemMessage(`${username} has left the chat.`);
    }
  });
});

async function broadcastEncryptedSystemMessage(content, excludeUsername = null) {
  console.log(`Broadcasting system message: ${content}`);
  const systemPayload = {
    type: 'system',
    sender: SERVER_ID,
    content,
    timestamp: new Date().toISOString()
  };
  
  const promises = [];
  
  for (const [clientUsername, client] of clients.entries()) {
    if (clientUsername !== excludeUsername && client.publicKey) {
      try {
        const recipientKey = await crypto.importPublicKeyFromPEM(client.publicKey);
        
        const aesKey = await crypto.generateAESKey();
        
        const { iv, authTag, encrypted } = await crypto.encryptWithAES(
          JSON.stringify(systemPayload), 
          aesKey,
          true
        );
        
        const encryptedMessage = crypto.serializeEncryptedData(iv, authTag, encrypted);
        
        const rawKey = await crypto.exportAESKey(aesKey);
        const encryptedAESKey = await crypto.encryptWithRSA(rawKey, recipientKey);
        const encryptedAESKeyBase64 = crypto.arrayBufferToBase64(encryptedAESKey);
        
        const finalPayload = {
          type: SignalType.ENCRYPTED_MESSAGE,
          from: SERVER_ID,
          to: clientUsername,
          encryptedAESKey: encryptedAESKeyBase64,
          encryptedMessage
        };

        console.log(`finalPayload for ${clientUsername}:`, JSON.stringify(finalPayload));
        
        promises.push(client.ws.send(JSON.stringify(finalPayload)));
      } catch (e) {
        console.error(`Failed to encrypt system message for ${clientUsername}:`, e);
      }
    }
  }

  await Promise.allSettled(promises);
}