import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';

// Notify Electron main that renderer is ready to receive cached server events
try { (window as any)?.edgeApi?.rendererReady?.(); } catch {}

createRoot(document.getElementById('root')!).render(<App />);
