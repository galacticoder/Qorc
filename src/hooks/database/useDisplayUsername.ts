import { useMemo } from 'react';
import { sanitizeDbUsername } from '../../lib/utils/database-utils';

export interface UseDisplayUsernameProps {
  username: string;
}

/**
 * Hook for resolving display names
 */
export function useDisplayUsername({ username }: UseDisplayUsernameProps): string {
  return useMemo(() => sanitizeDbUsername(username) ?? '', [username]);
}
