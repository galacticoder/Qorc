import React, { useState } from 'react';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';

interface TorInfo {
  isRunning: boolean;
  processId?: number | string;
  configExists: boolean;
  configSize: number;
  configPath?: string;
  binaryExists: boolean;
  binaryPath?: string;
  dataDirExists: boolean;
  dataDirectory?: string;
  torDirectory: string;
  platform: string;
  arch: string;
  hasProcess: boolean;
  processKilled?: boolean;
  uptime: number;
  systemTorRunning?: boolean;
  systemTorVersion?: string;
  usingSystemTor?: boolean;
  error?: string;
}

interface TorVerificationProps {
  onClose?: () => void;
}

export const TorVerification: React.FC<TorVerificationProps> = ({ onClose }) => {
  const [torInfo, setTorInfo] = useState<TorInfo | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [connectionTest, setConnectionTest] = useState<{ success: boolean; isTor?: boolean; ip?: string; error?: string } | null>(null);

  const checkTorStatus = async () => {
    if (isLoading) return;
    setIsLoading(true);
    try {
      const api = (typeof window !== 'undefined' && (window as any).electronAPI) || null;
      if (!api || typeof api.getTorInfo !== 'function') return;
      const info = await api.getTorInfo();
      setTorInfo(info);
    } catch (error) {
      console.error('[TOR-VERIFICATION] getTorInfo failed:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const testTorConnection = async () => {
    if (isLoading) return;
    setIsLoading(true);
    try {
      const api = (typeof window !== 'undefined' && (window as any).electronAPI) || null;
      if (!api || typeof api.verifyTorConnection !== 'function') return;
      const result = await api.verifyTorConnection();
      setConnectionTest({
        success: Boolean(result?.success),
        isTor: Boolean(result?.isTor),
        ip: typeof result?.ip === 'string' ? result.ip : undefined,
        error: typeof result?.error === 'string' ? result.error : undefined,
      });
    } catch (error) {
      setConnectionTest({ success: false, error: error instanceof Error ? error.message : 'Unknown error' });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Card className="w-full max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle>Tor Verification</CardTitle>
        <CardDescription>Verify Tor status and connectivity.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Button onClick={checkTorStatus} disabled={isLoading}>Check Status</Button>
          <Button onClick={testTorConnection} disabled={isLoading} variant="outline">Test Connection</Button>
          {onClose && (
            <Button onClick={onClose} variant="ghost">Close</Button>
          )}
        </div>

        {torInfo && (
          <div className="space-y-2 p-4 bg-gray-50 rounded-lg">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
              <div>Process Running: <span className="font-mono">{torInfo.isRunning ? 'Yes' : 'No'}</span></div>
              <div>Process ID: <span className="font-mono">{torInfo.processId === 'system' ? 'System Service' : (torInfo.processId || 'N/A')}</span></div>
              <div>Config File: <span className="font-mono">{torInfo.configExists ? 'Exists' : 'Missing'}</span></div>
              <div>Config Size: <span className="font-mono">{torInfo.configSize} bytes</span></div>
              <div>Tor Binary: <span className="font-mono">{torInfo.binaryExists ? 'Found' : (torInfo.usingSystemTor ? 'System' : 'Missing')}</span></div>
              <div>Data Directory: <span className="font-mono">{torInfo.dataDirExists ? 'Exists' : 'Missing'}</span></div>
              <div>Platform: <span className="font-mono">{torInfo.platform}</span></div>
              <div>Architecture: <span className="font-mono">{torInfo.arch}</span></div>
              {torInfo.uptime > 0 && (
                <div>Uptime: <span className="font-mono">{Math.floor(torInfo.uptime / 1000)}s</span></div>
              )}
            </div>
            <div className="text-xs text-gray-600 space-y-1">
              <div><strong>Tor Directory:</strong> {torInfo.torDirectory}</div>
              {torInfo.configPath && (<div><strong>Config File:</strong> {torInfo.configPath}</div>)}
              {torInfo.binaryPath && (<div><strong>Binary Path:</strong> {torInfo.binaryPath === 'system' ? 'System Tor (PATH)' : torInfo.binaryPath}</div>)}
              {torInfo.dataDirectory && (<div><strong>Data Directory:</strong> {torInfo.dataDirectory}</div>)}
            </div>
          </div>
        )}

        {connectionTest && (
          <div className="space-y-2 p-4 bg-gray-50 rounded-lg border">
            <div>Status: <span className="font-mono">{connectionTest.success ? (connectionTest.isTor ? 'Tor' : 'Direct') : 'Failed'}</span></div>
            {connectionTest.ip && (<div>Reported IP: <span className="font-mono">{connectionTest.ip}</span></div>)}
            {connectionTest.error && (<div className="text-red-600 text-sm">{connectionTest.error}</div>)}
          </div>
        )}

        <div className="text-xs text-gray-500 space-y-1">
          <p><strong>Verification checklist:</strong></p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>Process Running is Yes with a valid Process ID</li>
            <li>Config File exists and has content</li>
            <li>Connection test shows Tor path when enabled</li>
            <li>Reported IP differs from your real IP when using Tor</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
};