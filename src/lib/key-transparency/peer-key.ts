export function keyTransparencyPeerKey(account: string, peer: string): string {
  return `${account}\0${peer}`;
}
