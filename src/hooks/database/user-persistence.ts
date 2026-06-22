import type { User } from '../../components/chat/messaging/UserList';
import type { SecureDB } from '../../lib/database/secureDB';

// Load users from database
export const loadUsers = async (secureDB: SecureDB): Promise<User[]> => {
  const savedUsers = await secureDB.loadUsers();
  if (!savedUsers || savedUsers.length === 0) return [];

  return savedUsers.map((su: any) => ({
    id: su.id || '',
    username: su.username || '',
    isOnline: su.isOnline ?? false,
    isTyping: su.isTyping,
    peerCertificateFingerprint: su.peerCertificateFingerprint,
    peerCertificatePinnedAt: su.peerCertificatePinnedAt,
    identityRootFingerprint: su.identityRootFingerprint,
    identityBundleFingerprint: su.identityBundleFingerprint,
    hybridPublicKeys: su.hybridPublicKeys,
    inboxId: su.inboxId,
    routeId: su.routeId,
    mailboxLookupId: su.mailboxLookupId,
    bundleLookupId: su.bundleLookupId,
  }));
};

// Save users to database
export const saveUsers = async (secureDB: SecureDB, users: User[]): Promise<void> => {
  const storedUsers = users.map(u => ({ ...u } as any));
  await secureDB.saveUsers(storedUsers);
};

// Update user hybrid keys in state
export const updateUserHybridKeys = (
  users: User[],
  username: string,
  hybridKeys: User['hybridPublicKeys']
): User[] | null => {
  const idx = users.findIndex(u => u.username === username);
  if (idx === -1) return null;

  if (JSON.stringify(users[idx].hybridPublicKeys) === JSON.stringify(hybridKeys)) {
    return null;
  }

  const newUsers = [...users];
  newUsers[idx] = { ...users[idx], hybridPublicKeys: hybridKeys };
  return newUsers;
};
