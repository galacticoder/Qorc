import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Truncates long hexadecimal usernames (32+ characters) to first 8 characters.
 */
export function truncateUsername(username: string): string {
  if (typeof username !== 'string' || username.length === 0) return '';
  return username.length > 32 ? `${username.slice(0, 8)}...` : username;
}