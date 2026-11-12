import './lib/runtime/android-timers';
import './lib/runtime/client-log-forwarding';
import './trusted-types.ts';
import { createRoot } from 'react-dom/client';
import { ThemeProvider } from './contexts/ThemeContext';
import App from './App.tsx';
import './index.css';
import { installNativeContextMenuGuard } from './lib/runtime/native-context-menu';
import { installAndroidBackNavigation } from './lib/runtime/android-back';
import { installMobileInteractions } from './lib/runtime/mobile-interactions';
import { installPressFeedback } from './lib/runtime/press-feedback';

const root = document.getElementById('root');
if (!(root instanceof HTMLElement) || !root.isConnected) {
  throw new Error('Application root is unavailable');
}

installNativeContextMenuGuard(document);
installAndroidBackNavigation();
installMobileInteractions();
installPressFeedback();
createRoot(root).render(
  <ThemeProvider>
    <App />
  </ThemeProvider>
);
