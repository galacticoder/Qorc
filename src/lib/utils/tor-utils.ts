export function sanitizeBinaryPath(path: string): string {
  const sanitized = path.replace(/[^a-zA-Z0-9_\-./]/g, '');
  return sanitized || 'obfs4proxy';
}

export function isValidBridgeLine(line: string): boolean {
  const startsWithBridge = line.startsWith('Bridge ') ? line : `Bridge ${line}`;
  const obfs4Pattern = /^Bridge\s+(obfs4|vanilla)\s+[\d.]+:\d+\s+[A-F0-9]{40}(\s+.+)?$/i;
  const snowflakePattern = /^Bridge\s+snowflake(\s+.+)?$/i;

  return obfs4Pattern.test(startsWithBridge) || snowflakePattern.test(startsWithBridge);
}
