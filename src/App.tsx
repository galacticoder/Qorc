import ChatApp from './pages/Index.tsx';

import { CallHistoryProvider } from './contexts/CallHistoryContext';
import { FirstRunGate } from './components/setup/FirstRunGate';

function App() {
  return (
    <div className="App">
      <FirstRunGate>
        <CallHistoryProvider>
          <ChatApp />
        </CallHistoryProvider>
      </FirstRunGate>
    </div>
  );
}

export default App;
