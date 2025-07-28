import { useState } from "react";
import { Button } from "../ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "../ui/card";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { LockClosedIcon, CheckIcon } from "@radix-ui/react-icons";
import { Alert, AlertDescription } from "../ui/alert";
import { KeyRing, EncryptionIcon } from "./icons";

interface LoginProps {
  onLogin: (username: string, password: string) => Promise<void>;
  isGeneratingKeys: boolean;
  error?: string;
}

export function Login({ onLogin, isGeneratingKeys, error }: LoginProps) {
  const [username, setUsername] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [password, setPassword] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || isSubmitting || isGeneratingKeys) return;

    setIsSubmitting(true);
    try {
      await onLogin(username.trim(), password);
    } catch (err) {
      console.error("Login failed", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-md mx-auto">
      <Card className="w-full">
        <CardHeader className="space-y-4">
          <div className="mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
            <EncryptionIcon className="h-8 w-8 text-primary" />
          </div>
          <CardTitle className="text-2xl text-center">SecureChat</CardTitle>
          <CardDescription className="text-center">
            End-to-end encrypted messaging using 4096-bit RSA and AES-GCM
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              placeholder="Enter your username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={isSubmitting || isGeneratingKeys}
              required
              minLength={3}
              maxLength={16}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">Server Password</Label>
            <Input
              id="password"
              type="password"
              placeholder="Enter server password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isSubmitting || isGeneratingKeys}
              required
            />
          </div>
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <LockClosedIcon className="h-3 w-3" />
              <span>
                Your messages are secured with end-to-end encryption
              </span>
            </div>
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <CheckIcon className="h-3 w-3" />
              <span>
                Only the intended recipients can read your messages
              </span>
            </div>
          </div>
        </CardContent>
        <CardFooter>
          <Button
            type="submit"
            className="w-full"
            disabled={!username.trim() || !password.trim() || isSubmitting || isGeneratingKeys}
          >
            {isGeneratingKeys ? (
              <span className="flex items-center gap-2">
                <KeyRing className="animate-spin h-4 w-4" />
                Generating encryption keys...
              </span>
            ) : isSubmitting ? (
              "Connecting..."
            ) : (
              "Join Secure Chat"
            )}
          </Button>
        </CardFooter>
      </Card>
    </form>
  );
}
