export { DEFAULT_BRIDGE_TRANSPORT_PATH } from "../constants/transport";

export { DEFAULT_SNOWFLAKE_BRIDGE } from "../constants/transport";

export function isValidBridgeLine(line: string): boolean {
  const bridgeLine = line.trim().startsWith('Bridge ') ? line.trim() : `Bridge ${line.trim()}`;
  const endpoint = String.raw`(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+):\d{1,5}`;
  const fingerprint = String.raw`[A-F0-9]{40}`;
  const obfs4Pattern = new RegExp(
    String.raw`^Bridge\s+(?:obfs4|vanilla)\s+${endpoint}\s+${fingerprint}(?:\s+\S+=\S+)*$`,
    'i'
  );
  const snowflakePattern = new RegExp(
    String.raw`^Bridge\s+snowflake\s+${endpoint}(?:\s+${fingerprint})?(?:\s+\S+=\S+)*$`,
    'i'
  );
  const webtunnelPattern = new RegExp(
    String.raw`^Bridge\s+webtunnel\s+${endpoint}\s+${fingerprint}(?:\s+\S+=\S+)*$`,
    'i'
  );

  return obfs4Pattern.test(bridgeLine)
    || snowflakePattern.test(bridgeLine)
    || webtunnelPattern.test(bridgeLine);
}
