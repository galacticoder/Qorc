import { toast } from 'sonner';
import { createElement } from 'react';
import { SaveServerPrompt } from '../../components/servers/SaveServerPrompt';
import { savedServers, type ServerProfile } from './saved-servers';
import { normalizeToWss } from './server-address';
import { validateServerProfile } from '../../../shared/server-profile.js';

export async function offerToSaveServer(address: string, profile: ServerProfile | null): Promise<void> {
  const url = normalizeToWss(address);
  if (!url || !profile || !validateServerProfile(profile)) return;
  try {
    await savedServers.load();
    if (savedServers.getSnapshot().servers.some((server) => server.url === url)) {
      await savedServers.updateIcon(url, profile.icon);
      return;
    }
    const id = `save-server:${url}`;
    const options = {
      id,
      unstyled: true,
      className: 'server-save-toast',
      style: { width: 'min(440px, calc(100vw - 32px))', maxWidth: 'calc(100vw - 32px)', fontFamily: 'var(--qorc-ui-font)' },
      duration: 10_000,
    };
    const props = {
      url,
      profile,
      onSaveStart: () => { toast.custom(render, { ...options, duration: Infinity, dismissible: false }); },
      onDismiss: () => { toast.dismiss(id); },
    };
    const render = () => createElement(SaveServerPrompt, props);
    toast.custom(render, options);
  } catch (error) {
    toast.error(error instanceof Error ? error.message : 'Saved servers could not be loaded');
  }
}
