import type { User } from '../../components/chat/messaging/UserList';
import type { SecureDB } from '../../lib/database/secureDB';

// Load users from database
export const loadUsers = async (secureDB: SecureDB): Promise<User[]> => {
  return secureDB.loadUsers();
};

// Save users to database
export const saveUsers = async (secureDB: SecureDB, users: User[]): Promise<void> => {
  await secureDB.saveUsers(users);
};
