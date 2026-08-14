import { ACCOUNT_AUTH_PURPOSE, SERVER_ENTRY_PURPOSE } from '../config/audiences';

export function normalizePrivacyPassPurpose(purpose?: string): string {
  const value = typeof purpose === 'string' ? purpose.trim().toLowerCase() : '';
  if (value !== ACCOUNT_AUTH_PURPOSE && value !== SERVER_ENTRY_PURPOSE) {
    throw new Error('Invalid Privacy Pass purpose');
  }
  return value;
}
