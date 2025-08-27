import React from 'react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Shield, Download, ExternalLink } from 'lucide-react';

export function BrowserTorNotice() {
  // Only show in browser environment (not Electron)
  if (typeof window !== 'undefined' && (window as any).electronAPI) {
    return null;
  }

  return (
    <Alert className="border-blue-200 bg-blue-50">
      <Shield className="h-4 w-4 text-blue-600" />
      <div className="flex items-center justify-between">
        <AlertDescription className="flex-1">
          <strong className="text-blue-800">Enhanced Privacy Available</strong>
          <br />
          <span className="text-blue-700">
            For automatic Tor network setup and maximum anonymity, download our desktop application.
            The web version provides end-to-end encryption but not network-level anonymity.
          </span>
        </AlertDescription>
        <div className="flex gap-2 ml-4">
          <Button
            variant="outline"
            size="sm"
            onClick={() => window.open('https://www.torproject.org/', '_blank')}
            className="border-blue-300 text-blue-700 hover:bg-blue-100"
          >
            <ExternalLink className="h-3 w-3 mr-1" />
            Tor Browser
          </Button>
          <Button
            size="sm"
            className="bg-blue-600 hover:bg-blue-700 text-white"
            onClick={() => {
              // This would link to your desktop app download
              console.log('Download desktop app');
            }}
          >
            <Download className="h-3 w-3 mr-1" />
            Desktop App
          </Button>
        </div>
      </div>
    </Alert>
  );
}
