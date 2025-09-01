import React from 'react';
import { createRoot } from 'react-dom/client';
import { ThemeProvider } from 'next-themes';
import App from './App.tsx';
import './index.css';

// Notify Electron main that renderer is ready to receive cached server events
try { (window as any)?.edgeApi?.rendererReady?.(); } catch {}

createRoot(document.getElementById('root')!).render(
  <ThemeProvider attribute="class" defaultTheme="light" enableSystem>
    <App />
  </ThemeProvider>
);
