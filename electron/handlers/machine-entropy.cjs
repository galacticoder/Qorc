/**
 * Machine Entropy Collector
 * Gathers machine-specific identifiers and derives stable entropy context
 */

const fs = require('fs').promises;
const os = require('os');

let noble = null;

async function loadNoble() {
  if (!noble) {
    const sha3m = await import('@noble/hashes/sha3.js');
    noble = { sha3_512: sha3m.sha3_512 };
  }
}

function sha3(buf) {
  return Buffer.from(noble.sha3_512(buf));
}

/**
 * Read file safely, return empty buffer on error
 */
async function readFileSafe(filePath) {
  try {
    return await fs.readFile(filePath, 'utf8');
  } catch (_) {
    return '';
  }
}

/**
 * Gather machine-specific identifiers and derive 64-byte context
 */
async function getMachineContext(installPath) {
  await loadNoble();
  
  // Gather machine-specific data (best-effort, async, Linux-safe)
  const sources = await Promise.all([
    readFileSafe('/etc/machine-id'),
    readFileSafe('/sys/class/dmi/id/product_uuid'),
    Promise.resolve(os.hostname()),
    Promise.resolve(process.env.HOME || ''),
    Promise.resolve(installPath || '')
  ]);
  
  // Hash each source individually with domain separation
  const hashedParts = sources.map((source, idx) => {
    const prefix = Buffer.from(`QSSv1/machine-entropy/${idx}`, 'utf8');
    const data = Buffer.from(String(source).trim(), 'utf8');
    return sha3(Buffer.concat([prefix, data]));
  });
  
  // Final hash of all parts
  const combined = Buffer.concat(hashedParts);
  const final = sha3(Buffer.concat([Buffer.from('QSSv1/machine-context', 'utf8'), combined]));
  
  // Clear intermediate buffers
  hashedParts.forEach(buf => buf.fill(0));
  combined.fill(0);
  
  return final;
}

module.exports = { getMachineContext };
