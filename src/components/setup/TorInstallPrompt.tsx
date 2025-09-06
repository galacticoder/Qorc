import React, { useState } from 'react';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Alert, AlertDescription } from '../ui/alert';
import { Badge } from '../ui/badge';
import { Terminal, Download, Shield, ExternalLink, Copy } from 'lucide-react';

interface TorInstallPromptProps {
  onContinue?: () => void;
  onCancel?: () => void;
}

export const TorInstallPrompt: React.FC<TorInstallPromptProps> = ({ onContinue, onCancel }) => {
  const [copied, setCopied] = useState(false);

  const installCommands = {
    ubuntu: 'sudo apt-get update && sudo apt-get install tor',
    fedora: 'sudo dnf install tor',
    arch: 'sudo pacman -S tor',
    mac: 'brew install tor',
    windows: 'Download from https://www.torproject.org/download/'
  };

  const copyCommand = (command: string) => {
    navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Card className="w-full max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle className="flex items-center">
          <Shield className="w-5 h-5 mr-2" />
          Tor Installation Required
        </CardTitle>
        <CardDescription>
          To enable automatic Tor setup, we need to install Tor on your system
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Alert>
          <Terminal className="h-4 w-4" />
          <AlertDescription>
            <strong>Why do we need Tor?</strong> Tor provides network-level anonymity by routing your 
            connections through multiple encrypted relays, making it impossible to trace your real IP address.
          </AlertDescription>
        </Alert>

        <div className="space-y-3">
          <h3 className="font-semibold">Installation Commands by Platform:</h3>
          
          <div className="space-y-2">
            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <div>
                <Badge variant="outline" className="mr-2">Ubuntu/Debian</Badge>
                <code className="text-sm">{installCommands.ubuntu}</code>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => copyCommand(installCommands.ubuntu)}
              >
                <Copy className="w-3 h-3" />
              </Button>
            </div>

            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <div>
                <Badge variant="outline" className="mr-2">Fedora/RHEL</Badge>
                <code className="text-sm">{installCommands.fedora}</code>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => copyCommand(installCommands.fedora)}
              >
                <Copy className="w-3 h-3" />
              </Button>
            </div>

            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <div>
                <Badge variant="outline" className="mr-2">Arch Linux</Badge>
                <code className="text-sm">{installCommands.arch}</code>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => copyCommand(installCommands.arch)}
              >
                <Copy className="w-3 h-3" />
              </Button>
            </div>

            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <div>
                <Badge variant="outline" className="mr-2">macOS</Badge>
                <code className="text-sm">{installCommands.mac}</code>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => copyCommand(installCommands.mac)}
              >
                <Copy className="w-3 h-3" />
              </Button>
            </div>

            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <div>
                <Badge variant="outline" className="mr-2">Windows</Badge>
                <span className="text-sm">Download from Tor Project</span>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={async () => {
                  // Always open in external browser
                  if (typeof window !== 'undefined' && (window as any).electronAPI?.openExternal) {
                    try {
                      await (window as any).electronAPI.openExternal('https://www.torproject.org/download/');
                    } catch {
                      // Fallback to system default browser
                      window.open('https://www.torproject.org/download/', '_blank');
                    }
                  } else {
                    // Fallback to system default browser
                    window.open('https://www.torproject.org/download/', '_blank');
                  }
                }}
              >
                <ExternalLink className="w-3 h-3" />
              </Button>
            </div>
          </div>

          {copied && (
            <div className="text-sm text-green-600">✓ Command copied to clipboard!</div>
          )}
        </div>

        <Alert>
          <Download className="h-4 w-4" />
          <AlertDescription>
            <strong>Installation Steps:</strong>
            <ol className="list-decimal list-inside mt-2 space-y-1">
              <li>Copy the command for your operating system</li>
              <li>Open a terminal and paste the command</li>
              <li>Enter your password when prompted (this is normal for system installation)</li>
              <li>Wait for installation to complete</li>
              <li>Click "Continue" below to proceed with Tor setup</li>
            </ol>
          </AlertDescription>
        </Alert>

        <div className="flex gap-3 pt-4">
          <Button onClick={onContinue} className="flex-1">
            <Shield className="w-4 h-4 mr-2" />
            Continue with Tor Setup
          </Button>
          <Button onClick={onCancel} variant="outline">
            Skip Tor Setup
          </Button>
        </div>

        <div className="text-xs text-gray-500">
          <strong>Note:</strong> Tor installation requires administrator privileges to install system packages. 
          This is standard for any system-level software installation and ensures Tor is properly integrated 
          with your system's security features.
        </div>
      </CardContent>
    </Card>
  );
};