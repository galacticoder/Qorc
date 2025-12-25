import React from 'react';
import ChatApp from './pages/Index.tsx';

import { CallHistoryProvider } from './contexts/CallHistoryContext';

function App() {
  return (
    <div className="App">
      <CallHistoryProvider>
        <ChatApp />
      </CallHistoryProvider>
    </div>
  );
}

export default App;