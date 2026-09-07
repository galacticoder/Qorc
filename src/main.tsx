import './lib/runtime/client-log-forwarding';
import './trusted-types.ts';
import { createRoot } from 'react-dom/client';
import { ThemeProvider } from './contexts/ThemeContext';
import App from './App.tsx';
import './index.css';
import { installNativeContextMenuGuard } from './lib/runtime/native-context-menu';

const root = document.getElementById('root');
if (!(root instanceof HTMLElement) || !root.isConnected) {
  throw new Error('Application root is unavailable');
}

installNativeContextMenuGuard(document);
createRoot(root).render(
  <ThemeProvider>
    <App />
  </ThemeProvider>
);
