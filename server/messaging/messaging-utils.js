import { SignalType } from "../signals.js";
import * as ServerConfig from "../config/config.js";
import { CryptoUtils } from "../crypto/unified-crypto.js";

export class MessagingUtils {

  static broadcastPublicKeys(/* clients */) {
    // Removed in-memory broadcast; keys are fetched on-demand via bundle APIs
    console.log(`[MESSAGING] broadcastPublicKeys skipped (no global client map)`);
    return;
  }

  // sendPublicKeyUpdate removed - clients now request key bundles on-demand via REST APIs
  // This method has been deprecated as the system no longer maintains in-memory client maps
}