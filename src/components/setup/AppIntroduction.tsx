import { useEffect, useRef, useState } from 'react';
import { QorcBrandLogo } from '../ui/QorcBrandLogo';
import { ThemeToggleButton } from '../ui/ThemeToggleButton';
import { useAppBack } from '../../hooks/useAppBack';
import { useDesktopZoom } from '../../hooks/useDesktopZoom';
import './app-introduction.css';

const steps = [
  {
    label: 'Welcome to Qorc',
    title: 'Keep your identity private',
    description: 'Qorc is designed to keep your account, contact searches, and conversations from becoming a server-side profile.',
    items: [
      { title: 'Anonymous account access', description: 'Sign in without giving the server your username. One-time anonymous tokens authorize account operations.' },
      { title: 'Private discovery and delivery', description: 'Contact searches hide the username you look up. Sealed delivery keeps sender and recipient identities out of server-visible routing.' },
      { title: 'Tor on every network path', description: 'Connections run through Tor to keep your IP address hidden from servers and contacts.' },
    ],
  },
  {
    label: 'Servers',
    title: 'Choose your server',
    description: 'Qorc lets you choose the infrastructure you use. Connect to a community’s server or one you host yourself.',
    privacy: {
      statement: 'Your account privacy is enforced by the protocol.',
      explanation: 'Anonymous account access, private contact discovery, encrypted profiles, and protected messages, files, and calls are built into Qorc’s protocol. Your username, password, and passphrase are never sent to the server in plaintext.',
    },
    items: [
      { title: 'Use the same server as your contacts', description: 'Ask for their server address. Enter it when you connect, before creating or signing in to your account.' },
      { title: 'Verify the server you connect to', description: 'Saved servers shows the address and identity fingerprint. Compare the fingerprint with the owner through a trusted channel; names and pictures can be copied.' },
    ],
  },
  {
    label: 'Your account',
    title: 'Keep your account safe',
    description: 'Your account belongs to the server you choose. Create one there, or sign in with your existing details.',
    items: [
      { title: 'Password and passphrase', description: 'Choose different values and store both safely. Together they protect the encrypted account vault holding your identity keys and local data.' },
      { title: 'Your username is for your contacts', description: 'Share it with the people you want to talk to. Keep your password and passphrase to yourself.' },
    ],
  },
  {
    label: 'Conversations',
    title: 'Start a conversation',
    description: 'Once you’re signed in, open New conversation from the compose button in Chats and search for a contact’s username.',
    items: [
      { title: 'Messages, files, and voice notes', description: 'Write in the message box, attach a file with the file button, or record a voice note with the microphone.' },
      { title: 'Voice and video calls', description: 'Use the call buttons at the top of a conversation. Your call history is in Calls, notification and privacy controls are in Settings.' },
    ],
  },
] as const;

interface AppIntroductionProps {
  readonly onComplete: () => Promise<void>;
}

export function AppIntroduction({ onComplete }: AppIntroductionProps) {
  const [index, setIndex] = useState(0);
  const [finishing, setFinishing] = useState(false);
  const finishingRef = useRef(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const step = steps[index];
  const lastStep = index === steps.length - 1;

  useDesktopZoom(false);
  useAppBack(index > 0 && !finishing, () => setIndex(value => value - 1), 20);

  useEffect(() => {
    headingRef.current?.focus({ preventScroll: true });
    headingRef.current?.closest('.screen-intro')?.scrollTo({ top: 0, behavior: 'instant' });
  }, [index]);

  const finish = async () => {
    if (finishingRef.current) return;
    finishingRef.current = true;
    setFinishing(true);
    await onComplete();
  };

  return (
    <section className="screen screen-welcome screen-intro" aria-label="Getting started with Qorc">
      <div className="welcome-scene">
        <header className="welcome-topbar intro-topbar">
          <div className="login-screen-brand" aria-label="Qorc">
            <QorcBrandLogo className="login-brand-mark" />
            <span className="login-brand-name">Qorc</span>
          </div>
          <div className="intro-topbar-actions">
            <button type="button" className="intro-skip" onClick={finish} disabled={finishing}>Skip introduction</button>
            <ThemeToggleButton className="intro-theme-toggle" />
          </div>
        </header>

        <main className="intro-main">
          <div className="intro-content">
            <div className="intro-step-heading">
              <p className="intro-step-label">{step.label}</p>
              <span className="intro-step-count" aria-label={`Step ${index + 1} of ${steps.length}`}>{index + 1} of {steps.length}</span>
            </div>
            <h1 className="intro-heading" ref={headingRef} tabIndex={-1}>{step.title}</h1>
            <p className="intro-description">{step.description}</p>
            {'privacy' in step && (
              <aside className="intro-privacy" aria-label="Server privacy">
                <strong>{step.privacy.statement}</strong>
                <p>{step.privacy.explanation}</p>
              </aside>
            )}
            <dl className="intro-facts">
              {step.items.map(item => (
                <div className="intro-fact" key={item.title}>
                  <dt>{item.title}</dt>
                  <dd>{item.description}</dd>
                </div>
              ))}
            </dl>
          </div>

          <footer className="intro-footer">
            <div className="intro-progress" role="progressbar" aria-label="Introduction progress" aria-valuemin={1} aria-valuemax={steps.length} aria-valuenow={index + 1}>
              {steps.map((item, position) => <span key={item.title} className={position <= index ? 'is-complete' : ''} />)}
            </div>
            <div className={`intro-actions${index === 0 ? ' is-first' : ''}`}>
              {index > 0 && <button type="button" className="intro-back" onClick={() => setIndex(value => value - 1)} disabled={finishing}>Back</button>}
              <button type="button" className="login-simple-submit" disabled={finishing} onClick={lastStep ? finish : () => setIndex(value => value + 1)}>
                {lastStep ? 'Connect to a server' : 'Continue'}
              </button>
            </div>
          </footer>
        </main>
      </div>
    </section>
  );
}
