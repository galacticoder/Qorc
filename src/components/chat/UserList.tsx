import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";

export interface User {
  id: string;
  username: string;
  isOnline: boolean;
  isTyping?: boolean;
  hybridPublicKeys?: {
    x25519PublicBase64: string;
    kyberPublicBase64: string;
  };
}

interface UserListProps {
  users: User[];
  currentUser?: string;
  className?: string;
}

export function UserList({ users, currentUser, className }: UserListProps) {
  const [sortedUsers, setSortedUsers] = useState<User[]>([]);

  useEffect(() => {
    // sort users: current user first, then online users, then alphabetically
    const sorted = [...users].sort((a, b) => {
      if (a.username === currentUser) return -1;
      if (b.username === currentUser) return 1;
      if (a.isOnline && !b.isOnline) return -1;
      if (!a.isOnline && b.isOnline) return 1;
      return a.username.localeCompare(b.username);
    });

    setSortedUsers(sorted);
  }, [users, currentUser]);

  return (
    <Card className={cn("w-full h-full", className)}>
      <CardHeader className="py-3">
        <CardTitle className="text-sm font-medium">
          Users ({users.filter((u) => u.isOnline).length}/{users.length})
        </CardTitle>
      </CardHeader>
      <CardContent className="px-2">
        <ScrollArea className="h-[calc(100%-3rem)] pr-2">
          <div className="space-y-1 py-1">
            {sortedUsers.map((user) => (
              <div
                key={user.id}
                className={cn(
                  "flex items-center justify-between rounded-md px-3 py-2",
                  user.username === currentUser
                    ? "bg-muted"
                    : "hover:bg-muted/50"
                )}
              >
                <div className="flex items-center gap-2">
                  <div
                    className={cn(
                      "h-2 w-2 rounded-full",
                      user.isOnline ? "bg-green-500" : "bg-gray-300"
                    )}
                  />
                  <span
                    className={cn(
                      "text-sm",
                      user.username === currentUser && "font-medium"
                    )}
                  >
                    {user.username}
                    {user.username === currentUser && " (you)"}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
