export const DEFAULT_BRIDGE_TRANSPORT_PATH = './pluggable_transports/lyrebird';

export const DEFAULT_SNOWFLAKE_BRIDGE =
  'snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org front=www.phpmyadmin.net,cdn.zk.mk ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn';

export function sanitizeBinaryPath(path: string): string {
  const sanitized = path.replace(/[^a-zA-Z0-9_\-./:\\]/g, '');
  return sanitized || DEFAULT_BRIDGE_TRANSPORT_PATH;
}

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
