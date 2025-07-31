import https from 'https';
import { WebSocketServer } from 'ws';
import selfsigned from 'selfsigned';
import { SignalType } from './signals.js';
import  { CryptoUtils } from './crypto/unified-crypto.js';
import * as db from './database/database.js'
import * as ServerConfig from './config/config.js'
import { MessagingUtils } from './messaging/messaging-utils.js'
import * as authentication from './authentication/authentication.js'
import { setServerPasswordOnInput } from './authentication/auth-utils.js'

const clients = new Map();

const attrs = [{ name: 'commonName', value: 'localhost' }];
const pems = selfsigned.generate(attrs, { days: 365, keySize: 4096});

const server = https.createServer({
  key: pems.private,
  cert: pems.cert,
});

async function startServer() {
  await setServerPasswordOnInput();
  await db.loadUserDatabase();
  const serverKeyPair = await CryptoUtils.Keys.generateRSAKeyPair();

  const authHandler = new authentication.AccountAuthHandler(serverKeyPair, clients);
  const serverAuthHandler = new authentication.ServerAuthHandler(serverKeyPair, clients, ServerConfig);

  console.log("Server RSA key pair generated");
  console.log(`For self signed certificates allow here first https://localhost:${ServerConfig.PORT}`);

  server.listen(ServerConfig.PORT, () => {
    console.log(`SecureChat relay server running on wss://localhost:${ServerConfig.PORT}`);
  });

  const wss = new WebSocketServer({ server });

  wss.on('connection', async (ws) => {
    let clientState = {
      username: null,
      hasPassedAccountLogin: false,
      hasAuthenticated: false
    };

    ws.send(JSON.stringify({
      type: SignalType.SERVER_PUBLIC_KEY,
      publicKey: await CryptoUtils.Keys.exportPublicKeyToPEM(serverKeyPair.publicKey),
    }));

    ws.on('message', async (message) => {
      try {
        const str = message.toString().trim();

        if (!clientState.hasPassedAccountLogin) { //account logging in
          const authResult = await authHandler.processAuthRequest(ws, str);

          if (authResult) {
            console.log("Client has signed-in/signed-up")
            clientState.hasPassedAccountLogin = true;
            clientState.username = authResult.username;
          }
          
          return;
        }

        if (!clientState.hasAuthenticated && clientState.hasPassedAccountLogin){ //server password
            const result = await serverAuthHandler.handleServerAuthentication(ws, str, clientState);
            if (result) clientState.hasAuthenticated = true;
            else return;

            MessagingUtils.broadcastPublicKeys(clients);
            await MessagingUtils.broadcastUserJoin(clients,clientState.username)
            return;
        }
        
        try {
          const parsed = JSON.parse(str);
          console.log(`Received message from ${clientState.username}:`, parsed);
          
          if (parsed.to && clients.has(parsed.to)) {
            const target = clients.get(parsed.to);
            const isFileChunk = parsed.type === SignalType.FILE_MESSAGE_CHUNK;
            
            target.ws.send(JSON.stringify(parsed));
            
            console.log(
              isFileChunk 
                ? `Relayed file chunk ${parsed.chunkIndex + 1}/${parsed.totalChunks} from ${parsed.from} to ${parsed.to}`
                : `Relayed message from ${parsed.from} to ${parsed.to}`
            );
          }

        } catch (e) {
          console.warn("Caught exception: ", e);
        }
      } catch (err) {
        console.error("Message error: ", err);
      }
    });

    ws.on('close', async () => { 
      if (clientState.username && clientState.hasAuthenticated) {
        clients.delete(clientState.username);
        console.log(`User '${clientState.username}' has disconnected.`);
        await MessagingUtils.broadcastUserLeave(clients, clientState.username);
      }
    });
  });
}

startServer();