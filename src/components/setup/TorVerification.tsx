import React, { useState } from 'react';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { CheckCircle, XCircle, Info, RefreshCw } from 'lucide-react';

interface TorInfo {
  isRunning: boolean;
  processId?: number;
  configExists: boolean;
  configSize: number;
  binaryExists: boolean;
  dataDirExists: boolean;
  torDirectory: string;
  platform: string;
  arch: string;
  hasProcess: boolean;
  processKilled?: boolean;
  uptime: number;
  error?: string;
}

interface TorVerificationProps {
  onClose?: () => void;
}

export const TorVerification: React.FC<TorVerificationProps> = ({ onClose }) => {
  const [torInfo, setTorInfo] = useState<TorInfo | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [connectionTest, setConnectionTest] = useState<any>(null);

  const checkTorStatus = async () => {
    setIsLoading(true);
    try {
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        const info = await (window as any).electronAPI.getTorInfo();
        setTorInfo(info);
        console.log('[TOR-VERIFICATION] Tor info:', info);
      }
    } catch (error) {
      console.error('[TOR-VERIFICATION] Failed to get Tor info:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const testTorConnection = async () => {
    setIsLoading(true);
    try {
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        const result = await (window as any).electronAPI.verifyTorConnection();
        setConnectionTest(result);
        console.log('[TOR-VERIFICATION] Connection test:', result);
      }
    } catch (error) {
      console.error('[TOR-VERIFICATION] Failed to test connection:', error);
      setConnectionTest({ success: false, error: error.message });
    } finally {
      setIsLoading(false);
    }
  };

  const StatusBadge = ({ condition, trueText, falseText }: { condition: boolean; trueText: string; falseText: string }) => (
    <Badge variant={condition ? "default" : "destructive"} className="ml-2">
      {condition ? (
        <>
          <CheckCircle className="w-3 h-3 mr-1" />
          {trueText}
        </>
      ) : (
        <>
          <XCircle className="w-3 h-3 mr-1" />
          {falseText}
        </>
      )}
    </Badge>
  );

  return (
    <Card className="w-full max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle className="flex items-center">
          <Info className="w-5 h-5 mr-2" />
          Tor Verification
        </CardTitle>
        <CardDescription>
          Verify that Tor is actually running and working properly
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Button onClick={checkTorStatus} disabled={isLoading}>
            {isLoading ? (
              <>
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                Checking...
              </>
            ) : (
              'Check Tor Status'
            )}
          </Button>
          <Button onClick={testTorConnection} disabled={isLoading} variant="outline">
            Test Connection
          </Button>
          {onClose && (
            <Button onClick={onClose} variant="ghost">
              Close
            </Button>
          )}
        </div>

        {torInfo && (
          <div className="space-y-3 p-4 bg-gray-50 rounded-lg">
            <h3 className="font-semibold">Tor Process Status</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
              <div className="flex items-center">
                Process Running:
                <StatusBadge condition={torInfo.isRunning} trueText="Yes" falseText="No" />
              </div>
              <div className="flex items-center">
                Process ID: <span className="ml-2 font-mono">{torInfo.processId || 'N/A'}</span>
              </div>
              <div className="flex items-center">
                Config File:
                <StatusBadge condition={torInfo.configExists} trueText="Exists" falseText="Missing" />
              </div>
              <div className="flex items-center">
                Config Size: <span className="ml-2 font-mono">{torInfo.configSize} bytes</span>
              </div>
              <div className="flex items-center">
                Tor Binary:
                <StatusBadge condition={torInfo.binaryExists} trueText="Found" falseText="Missing" />
              </div>
              <div className="flex items-center">
                Data Directory:
                <StatusBadge condition={torInfo.dataDirExists} trueText="Exists" falseText="Missing" />
              </div>
              <div className="flex items-center">
                Platform: <span className="ml-2 font-mono">{torInfo.platform}</span>
              </div>
              <div className="flex items-center">
                Architecture: <span className="ml-2 font-mono">{torInfo.arch}</span>
              </div>
              {torInfo.uptime > 0 && (
                <div className="flex items-center">
                  Uptime: <span className="ml-2 font-mono">{Math.floor(torInfo.uptime / 1000)}s</span>
                </div>
              )}
            </div>
            <div className="text-xs text-gray-600">
              <strong>Tor Directory:</strong> {torInfo.torDirectory}
            </div>
          </div>
        )}

        {connectionTest && (
          <div className="space-y-3 p-4 bg-blue-50 rounded-lg">
            <h3 className="font-semibold">Connection Test Results</h3>
            <div className="text-sm">
              {connectionTest.success ? (
                <div className="flex items-center text-green-700">
                  <CheckCircle className="w-4 h-4 mr-2" />
                  {connectionTest.isTor ? (
                    <>
                      <strong>SUCCESS:</strong> You are connected through Tor!
                      <br />
                      <span className="text-xs">Your IP: {connectionTest.ip}</span>
                    </>
                  ) : (
                    <>
                      <strong>WARNING:</strong> Connected but not through Tor
                      <br />
                      <span className="text-xs">Your real IP: {connectionTest.ip}</span>
                    </>
                  )}
                </div>
              ) : (
                <div className="flex items-center text-red-700">
                  <XCircle className="w-4 h-4 mr-2" />
                  <strong>FAILED:</strong> {connectionTest.error}
                </div>
              )}
            </div>
          </div>
        )}

        <div className="text-xs text-gray-500 space-y-1">
          <p><strong>How to verify Tor is really working:</strong></p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>Process Running should be "Yes" with a real Process ID</li>
            <li>Config File should exist with content (&gt;400 bytes)</li>
            <li>Connection test should show "You are connected through Tor!"</li>
            <li>Your IP should be different from your real IP</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
};
