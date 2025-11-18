import './trusted-types.ts';
import React from 'react';
import { createRoot } from 'react-dom/client';
import { ThemeProvider } from 'next-themes';
import App from './App.tsx';
import './index.css';

function bootstrap() {
  const isElectron = typeof (window as any).electronAPI !== 'undefined';

  if (!isElectron) {
    const body = document.body || document.documentElement;
    const el = document.getElementById('root') || body;
    const container = document.createElement('div');
    container.setAttribute('role', 'dialog');
    container.setAttribute('aria-live', 'assertive');
    container.style.position = 'fixed';
    container.style.inset = '0';
    container.style.display = 'flex';
    container.style.alignItems = 'center';
    container.style.justifyContent = 'center';
    container.style.background = 'rgba(0,0,0,0.5)';
    container.style.zIndex = '9999';

    const box = document.createElement('div');
    box.style.maxWidth = '460px';
    box.style.margin = '16px';
    box.style.padding = '16px 20px';
    box.style.borderRadius = '10px';
    box.style.background = '#111827';
    box.style.color = '#e5e7eb';
    box.style.boxShadow = '0 10px 30px rgba(0,0,0,0.3)';
    box.style.fontFamily = 'system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, sans-serif';
    box.innerHTML = `
      <div style="font-size:16px; font-weight:600; margin-bottom:6px;">Desktop app required</div>
      <div style="font-size:14px; line-height:1.45; opacity:0.9;">
        This application runs as a desktop app (Electron). Please use the packaged app instead of opening it directly in a web browser.
      </div>
    `;
    container.appendChild(box);

    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = 'OK';
    close.style.marginTop = '12px';
    close.style.padding = '6px 12px';
    close.style.borderRadius = '6px';
    close.style.border = '1px solid #374151';
    close.style.background = '#1f2937';
    close.style.color = '#e5e7eb';
    close.style.cursor = 'pointer';
    close.addEventListener('click', () => container.remove());
    box.appendChild(close);

    el.appendChild(container);
    return;
  }

  try { (window as any)?.edgeApi?.rendererReady?.(); } catch {}

  const waitForBody = (callback: () => void) => {
    if (document.body) {
      callback();
    } else {
      const observer = new MutationObserver(() => {
        if (document.body) {
          observer.disconnect();
          callback();
        }
      });
      observer.observe(document.documentElement, { childList: true });
    }
  };

  waitForBody(() => {
    let root = document.getElementById('root');
    if (!root) {
      root = document.createElement('div');
      root.id = 'root';
      document.body.appendChild(root);
    }

    // Ensure root is attached to the document before React mounts
    if (!root.isConnected || !document.body.contains(root)) {
      console.error('[React Mount] Root element is not properly attached to DOM');
      // Re-attach if needed
      if (!document.body.contains(root)) {
        document.body.appendChild(root);
      }
    }

    createRoot(root as HTMLElement).render(
      <ThemeProvider attribute="class" defaultTheme="light" forcedTheme="light">
        <App />
      </ThemeProvider>
    );
  });
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    window.addEventListener('DOMContentLoaded', bootstrap, { once: true });
  } else {
    bootstrap();
  }
}
