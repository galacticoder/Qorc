import { ACCOUNT_AUTH_PURPOSE, SERVER_ENTRY_PURPOSE } from '../config/audiences';

export function normalizePrivacyPassPurpose(purpose: string): string {
  if (purpose !== ACCOUNT_AUTH_PURPOSE && purpose !== SERVER_ENTRY_PURPOSE) {
    throw new Error('Invalid Privacy Pass purpose');
  }
  return purpose;
}
