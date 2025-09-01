import React, { useState } from 'react';
import { Button } from '@/components/ui/button';

export function MediaDebug() {
  const [logs, setLogs] = useState<string[]>([]);
  
  const addLog = (message: string) => {
    console.log(message);
    setLogs(prev => [...prev, `${new Date().toLocaleTimeString()}: ${message}`]);
  };

  const testMicrophone = async () => {
    addLog('Testing microphone access...');
    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        addLog('❌ MediaDevices not supported');
        return;
      }
      
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      addLog('✅ Microphone access granted');
      addLog(`Stream tracks: ${stream.getAudioTracks().length}`);
      
      // Test MediaRecorder
      const supportedTypes = [
        'audio/webm;codecs=opus',
        'audio/webm',
        'audio/ogg;codecs=opus',
        'audio/mp4'
      ];
      
      for (const type of supportedTypes) {
        const supported = MediaRecorder.isTypeSupported(type);
        addLog(`${supported ? '✅' : '❌'} ${type}`);
      }
      
      stream.getTracks().forEach(track => track.stop());
    } catch (error) {
      addLog(`❌ Microphone error: ${error}`);
    }
  };

  const testScreenSharing = async () => {
    addLog('Testing screen sharing...');
    
    // Test Electron API
    const electronAPI = (window as any).electronAPI;
    if (electronAPI) {
      addLog('✅ ElectronAPI available');
      addLog(`Available functions: ${Object.keys(electronAPI).join(', ')}`);
      
      if (electronAPI.getScreenSources) {
        addLog('✅ getScreenSources available');
        try {
          const sources = await electronAPI.getScreenSources();
          addLog(`✅ Got ${sources?.length || 0} screen sources`);
        } catch (error) {
          addLog(`❌ getScreenSources error: ${error}`);
        }
      } else {
        addLog('❌ getScreenSources NOT available');
      }
    } else {
      addLog('❌ ElectronAPI not available');
    }
    
    // Test browser API
    if (navigator.mediaDevices?.getDisplayMedia) {
      addLog('✅ getDisplayMedia available');
      try {
        const stream = await navigator.mediaDevices.getDisplayMedia({ video: true });
        addLog('✅ Screen sharing works via browser API');
        stream.getTracks().forEach(track => track.stop());
      } catch (error) {
        addLog(`❌ getDisplayMedia error: ${error}`);
      }
    } else {
      addLog('❌ getDisplayMedia not available');
    }
  };

  const clearLogs = () => setLogs([]);

  return (
    <div className="p-4 border rounded-lg bg-gray-50">
      <h3 className="text-lg font-semibold mb-4">Media Debug Panel</h3>
      
      <div className="flex gap-2 mb-4">
        <Button onClick={testMicrophone} size="sm">Test Microphone</Button>
        <Button onClick={testScreenSharing} size="sm">Test Screen Sharing</Button>
        <Button onClick={clearLogs} variant="outline" size="sm">Clear Logs</Button>
      </div>
      
      <div className="bg-black text-green-400 p-3 rounded font-mono text-sm max-h-64 overflow-y-auto">
        {logs.length === 0 ? (
          <div className="text-gray-500">Click buttons above to run tests...</div>
        ) : (
          logs.map((log, i) => (
            <div key={i}>{log}</div>
          ))
        )}
      </div>
    </div>
  );
}
