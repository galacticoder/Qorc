export function isAndroidPlatform(
  userAgent = typeof navigator === 'undefined' ? '' : navigator.userAgent,
): boolean {
  return /\bAndroid\b/i.test(userAgent);
}
