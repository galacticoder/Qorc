const APP_SETTINGS_CSS = `
    .qor-settings-host {
      --bg: #040405;
      --nav: #08080a;
      --content: #050506;
      --surface: #0c0c10;
      --surface-2: #121218;
      --surface-3: #181820;
      --line: rgba(255,255,255,.085);
      --line-soft: rgba(255,255,255,.055);
      --text: #f4f4f6;
      --muted: #a0a0aa;
      --quiet: #70707b;
      --purple: #7057c8;
      --purple-2: #a994ff;
      --danger: #e05260;
      --green: #22c55e;
      color-scheme: dark;
      height: 100%;
      min-height: 0;
      background: var(--content);
      color: var(--text);
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
      font-size: 14px;
      user-select: none;
      -webkit-user-select: none;
    }

    .qor-settings-host input,
    .qor-settings-host textarea {
      user-select: text;
      -webkit-user-select: text;
    }

    .qor-settings-host.light {
      --bg: #ffffff;
      --nav: #ffffff;
      --content: #ffffff;
      --surface: #f6f7f9;
      --surface-2: #eef0f3;
      --surface-3: #e5e7eb;
      --line: rgba(15,23,42,.12);
      --line-soft: rgba(15,23,42,.075);
      --text: #111116;
      --muted: #666675;
      --quiet: #8c8c98;
      --purple: #7057c8;
      --purple-2: #5c46b1;
      --danger: #dc2626;
      --green: #16a34a;
      color-scheme: light;
    }

    .qor-settings-host *,
    .qor-settings-host *::before,
    .qor-settings-host *::after { box-sizing: border-box; }
    .qor-settings-host button,
    .qor-settings-host input,
    .qor-settings-host select { font: inherit; }
    .qor-settings-host button { cursor: pointer; }
    .qor-settings-host button:disabled { cursor: not-allowed; opacity: .55; }
    .qor-settings-host svg { display: block; }
    .hidden-symbols { position: absolute; width: 0; height: 0; overflow: hidden; }

    .settings-screen {
      position: relative;
      height: 100%;
      min-height: 0;
      display: block;
      background: var(--content);
      isolation: isolate;
    }

    .settings-content::-webkit-scrollbar { width: 8px; }
    .settings-content::-webkit-scrollbar-thumb { background: color-mix(in srgb, var(--muted) 22%, transparent); border-radius: 999px; }

    .settings-brand {
      width: min(100%, 930px);
      margin: 0 auto 44px;
      padding: 0 0 24px;
      border-bottom: 1px solid var(--line);
    }

    .settings-brand strong {
      display: block;
      color: var(--text);
      font-size: clamp(34px, 4.4vw, 52px);
      line-height: 1;
      font-weight: 950;
      letter-spacing: 0;
    }

    .settings-content {
      min-width: 0;
      height: 100%;
      overflow-y: auto;
      padding: 54px clamp(32px, 7vw, 96px) 84px;
      background: var(--content);
    }

    .pane {
      display: block;
      width: min(100%, 930px);
      margin-inline: auto;
    }

    .pane + .pane {
      margin-top: 52px;
      padding-top: 46px;
      border-top: 1px solid var(--line);
    }

    .pane-head {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 24px;
      margin-bottom: 30px;
      padding-bottom: 0;
      border-bottom: 0;
    }

    .pane-title {
      margin: 0;
      color: var(--text);
      font-size: clamp(23px, 2.5vw, 30px);
      line-height: 1.1;
      font-weight: 950;
      letter-spacing: 0;
    }

    .pane-subtitle {
      max-width: 520px;
      margin: 13px 0 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.55;
    }

    .settings-section {
      display: block;
      margin-bottom: 26px;
    }

    .settings-list {
      display: grid;
      gap: 7px;
      border-bottom: 0;
    }

    .setting-row {
      min-height: 62px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(190px, auto);
      align-items: center;
      gap: 22px;
      padding: 13px 14px;
      border: 0;
      border-radius: 12px;
      background: color-mix(in srgb, var(--surface) 34%, transparent);
    }

    .setting-row:last-child {
      border-bottom: 0;
    }

    .setting-row:hover {
      background: color-mix(in srgb, var(--surface-2) 52%, transparent);
    }

    .setting-label {
      margin: 0 0 4px;
      color: var(--text);
      font-size: 14px;
      font-weight: 850;
      letter-spacing: 0;
    }

    .setting-description {
      max-width: 540px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
    }

    .account-editor {
      border-bottom: 0;
    }

    .account-pane {
      position: relative;
      isolation: isolate;
    }

    .account-pane > * {
      position: relative;
      z-index: 1;
    }

    .account-pane .pane-head {
      margin-bottom: 18px;
    }

    .account-pane .pane-subtitle {
      display: none;
    }

    .account-pane .settings-section {
      display: block;
    }

    .account-preview {
      position: relative;
      display: grid;
      place-items: center;
      justify-items: center;
      min-height: 470px;
      padding: 44px 0 54px;
      border-bottom: 0;
      isolation: isolate;
    }

    .avatar-preview {
      position: relative;
      width: min(350px, 62vw);
      aspect-ratio: 1;
      overflow: hidden;
      border: 0;
      border-radius: 50%;
      background:
        radial-gradient(circle at 36% 26%, rgba(255,255,255,.18), transparent 30%),
        linear-gradient(135deg, rgba(112,87,200,.98), rgba(20,20,27,1));
      color: white;
    }

    .avatar-preview::before {
      content: "";
      position: absolute;
      inset: 28%;
      border: 9px solid rgba(255,255,255,.9);
      border-radius: 22px;
      transform: rotate(45deg);
    }

    .avatar-preview.has-image::before {
      display: none;
    }

    .avatar-preview::after {
      content: "";
      position: absolute;
      inset: 0;
      background:
        linear-gradient(180deg, transparent 54%, rgba(0,0,0,.38));
      pointer-events: none;
    }

    .avatar-preview img {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      object-fit: cover;
      transition: filter .15s ease;
    }

    .avatar-preview-button {
      position: relative;
      z-index: 1;
      border: 0;
      padding: 0;
      background: transparent;
      display: block;
      border-radius: 50%;
    }

    .avatar-hover-overlay {
      position: absolute;
      inset: 0;
      z-index: 3;
      display: grid;
      place-items: center;
      background: rgba(0,0,0,.46);
      color: white;
      opacity: 0;
      transition: opacity .15s ease;
    }

    .avatar-hover-overlay svg {
      width: 44px;
      height: 44px;
      filter: drop-shadow(0 8px 20px rgba(0,0,0,.35));
    }

    .avatar-preview-button:hover .avatar-hover-overlay,
    .avatar-preview-button:focus-visible .avatar-hover-overlay {
      opacity: 1;
    }

    .avatar-preview-button:hover .avatar-preview img,
    .avatar-preview-button:focus-visible .avatar-preview img {
      filter: brightness(.62);
    }

    .avatar-upload-input {
      display: none;
    }

    .account-name-row {
      max-width: min(720px, 100%);
      margin-top: -42px;
      display: flex;
      align-items: flex-start;
      justify-content: center;
      position: relative;
      z-index: 2;
    }

    .account-username {
      max-width: min(640px, 100%);
      padding: 0 18px;
      color: var(--text);
      font-size: clamp(44px, 6.6vw, 76px);
      line-height: .88;
      font-weight: 950;
      letter-spacing: 0;
      text-align: center;
      overflow-wrap: anywhere;
    }

    .copy-username {
      position: absolute;
      left: calc(100% + 8px);
      top: 50%;
      width: 42px;
      height: 42px;
      display: grid;
      place-items: center;
      border: 0;
      border-radius: 12px;
      background: rgba(255,255,255,.1);
      color: white;
      transform: translateY(-50%);
      transition: background .15s ease, transform .15s ease;
    }

    .copy-username:hover {
      background: rgba(255,255,255,.18);
    }

    .copy-username.copied {
      background: rgba(34,197,94,.22);
      color: #d7ffe5;
    }

    .copy-username svg {
      width: 19px;
      height: 19px;
    }

    .qor-settings-host.light .copy-username {
      background: rgba(17,24,39,.08);
      color: #111116;
    }

    .qor-settings-host.light .copy-username:hover {
      background: rgba(112,87,200,.14);
      color: var(--purple-2);
    }

    .qor-settings-host.light .copy-username.copied {
      background: rgba(22,163,74,.14);
      color: #15803d;
    }

    .account-share-row {
      min-height: 66px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 22px;
      margin-top: 10px;
      padding: 14px 16px;
      border-radius: 12px;
      background: color-mix(in srgb, var(--surface) 34%, transparent);
      border: 0;
    }

    .account-actions {
      display: grid;
      gap: 7px;
      margin-top: 7px;
    }

    .account-action-row {
      min-height: 64px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 22px;
      padding: 14px 16px;
      border: 0;
      border-radius: 12px;
      background: color-mix(in srgb, var(--surface) 34%, transparent);
    }

    .account-danger-row {
      background: color-mix(in srgb, var(--danger) 6%, var(--surface));
    }

    .logout-row {
      display: flex;
      justify-content: center;
      padding: 20px 0 2px;
    }

    .action,
    .danger-action {
      min-height: 34px;
      border: 0;
      border-radius: 9px;
      padding: 0 13px;
      background: var(--surface-2);
      color: var(--text);
      font-size: 12px;
      font-weight: 880;
      white-space: nowrap;
      transition: background .15s ease, color .15s ease;
    }

    .action:hover {
      background: color-mix(in srgb, var(--purple) 36%, var(--surface-2));
      color: white;
    }

    .danger-action {
      background: color-mix(in srgb, var(--danger) 14%, var(--surface-2));
      color: color-mix(in srgb, var(--danger) 78%, white);
    }

    .danger-action:hover {
      background: var(--danger);
      color: white;
    }

    .confirm-inline {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .danger-action.is-armed {
      background: var(--danger);
      color: #fff;
      box-shadow: 0 0 0 3px color-mix(in srgb, var(--danger) 26%, transparent);
    }

    .danger-action.is-armed:hover {
      background: color-mix(in srgb, var(--danger) 88%, black);
    }

    .account-danger-row .danger-action {
      background: var(--danger);
      color: white;
    }

    .account-danger-row .danger-action:hover {
      background: color-mix(in srgb, var(--danger) 82%, black);
      color: white;
    }

    .switch {
      width: 42px;
      height: 24px;
      justify-self: end;
      display: inline-flex;
      align-items: center;
      border: 0;
      border-radius: 999px;
      padding: 3px;
      background: #393942;
      transition: background .16s ease;
    }

    .switch::before {
      content: "";
      width: 18px;
      height: 18px;
      display: block;
      border-radius: 50%;
      background: white;
      transition: transform .16s ease;
    }

    .switch.on {
      background: var(--purple);
    }

    .switch.on::before {
      transform: translateX(18px);
    }

    .select,
    .text-input {
      width: 100%;
      height: 38px;
      border: 1px solid var(--line-soft);
      border-radius: 9px;
      padding: 0 12px;
      background: color-mix(in srgb, var(--bg) 70%, transparent);
      color: var(--text);
      outline: none;
      font-size: 12px;
      font-weight: 750;
    }

    .select:focus,
    .text-input:focus {
      border-color: color-mix(in srgb, var(--purple) 72%, white);
      box-shadow: 0 0 0 3px rgba(112,87,200,.14);
    }

    .input-line {
      width: min(100%, 540px);
      justify-self: end;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 10px;
    }

    .blocked-spinner {
      animation: qor-blocked-spin 0.7s linear infinite;
      color: var(--muted);
    }

    @keyframes qor-blocked-spin {
      to { transform: rotate(360deg); }
    }

    .blocked-empty {
      min-height: 96px;
      display: grid;
      place-items: center;
      border-bottom: 0;
      color: var(--muted);
      text-align: center;
    }

    .blocked-empty strong {
      display: block;
      margin-bottom: 6px;
      color: var(--text);
      font-size: 15px;
      font-weight: 900;
    }

    .blocked-user-list {
      display: grid;
      gap: 7px;
      margin-top: 7px;
    }

    .blocked-user-row {
      grid-template-columns: minmax(0, 1fr) auto;
    }

    .blocked-user-name {
      color: var(--text);
      font-size: 14px;
      font-weight: 850;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .settings-error {
      margin: 9px 0 0;
      padding: 10px 12px;
      border-radius: 10px;
      background: color-mix(in srgb, var(--danger) 11%, var(--surface));
      color: color-mix(in srgb, var(--danger) 80%, white);
      font-size: 12px;
      font-weight: 760;
    }

    .blocked-head {
      display: flex;
      align-items: flex-start;
      justify-content: flex-end;
      gap: 18px;
      margin-bottom: 12px;
    }

    .blocked-head .action {
      flex: 0 0 auto;
    }

    /* Custom settings modal (block / unblock) */
    .qor-modal-overlay {
      position: fixed;
      inset: 0;
      z-index: 60;
      display: grid;
      place-items: center;
      padding: 24px;
      background: rgba(0,0,0,.55);
      animation: qorModalOverlayIn .16s ease;
    }

    .qor-settings-host.light .qor-modal-overlay {
      background: rgba(15,23,42,.34);
    }

    .qor-modal {
      width: min(420px, 100%);
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: var(--nav);
      box-shadow: 0 30px 90px rgba(0,0,0,.5);
      animation: qorModalIn .18s cubic-bezier(0.16, 1, 0.3, 1);
    }

    @keyframes qorModalOverlayIn { from { opacity: 0; } to { opacity: 1; } }
    @keyframes qorModalIn {
      from { opacity: 0; transform: scale(.96); }
      to { opacity: 1; transform: scale(1); }
    }

    .qor-modal-head {
      padding: 22px 22px 4px;
    }

    .qor-modal-head h3 {
      margin: 0 0 7px;
      color: var(--text);
      font-size: 18px;
      font-weight: 900;
      letter-spacing: -.01em;
    }

    .qor-modal-head p {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }

    .qor-modal-head p strong {
      color: var(--text);
      font-weight: 850;
    }

    .qor-modal-body {
      padding: 16px 22px 4px;
    }

    .qor-modal-field {
      display: block;
    }

    .qor-modal-field .field-label {
      display: block;
      margin: 0 0 7px;
      color: var(--quiet);
      font-size: 10px;
      font-weight: 950;
      letter-spacing: .12em;
      text-transform: uppercase;
    }

    .qor-modal-field .text-input {
      height: 44px;
      font-size: 14px;
      font-weight: 650;
    }

    .qor-modal-error {
      margin: 11px 0 0;
      padding: 9px 11px;
      border-radius: 9px;
      background: color-mix(in srgb, var(--danger) 13%, var(--surface));
      color: color-mix(in srgb, var(--danger) 82%, white);
      font-size: 12px;
      font-weight: 750;
      line-height: 1.4;
    }

    .qor-modal-actions {
      display: grid;
      grid-template-columns: 1fr 1.3fr;
      gap: 10px;
      padding: 20px 22px 22px;
    }

    .qor-modal-btn {
      height: 44px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: 0;
      border-radius: 11px;
      background: var(--surface-2);
      color: var(--text);
      font-size: 13px;
      font-weight: 850;
      transition: background .15s ease, opacity .15s ease;
    }

    .qor-modal-btn:hover {
      background: var(--surface-3);
    }

    .qor-modal-btn.primary {
      background: var(--purple);
      color: #fff;
    }

    .qor-modal-btn.primary:hover {
      background: color-mix(in srgb, var(--purple) 86%, white);
    }

    .qor-modal-btn:disabled {
      opacity: .55;
      cursor: not-allowed;
    }

    .danger-zone {
      border-top: 1px solid color-mix(in srgb, var(--danger) 38%, transparent);
      border-bottom: 1px solid color-mix(in srgb, var(--danger) 38%, transparent);
    }

    @media (max-width: 980px) {
      .settings-screen {
        min-height: 100%;
        height: auto;
        display: block;
      }

      .settings-brand {
        margin-bottom: 28px;
        padding-bottom: 18px;
      }

      .settings-content {
        height: auto;
        padding: 32px 18px 70px;
      }

      .settings-section {
        display: block;
      }

      .pane-head,
      .setting-row,
      .account-share-row,
      .account-action-row {
        display: flex;
        align-items: flex-start;
        flex-direction: column;
      }

      .account-name-row {
        padding-right: 50px;
        padding-left: 50px;
      }

      .copy-username {
        left: auto;
        right: 0;
      }

      .switch {
        justify-self: start;
      }

      .input-line {
        justify-self: start;
        width: 100%;
        grid-template-columns: 1fr;
      }
    }
`;

let installed = false;

export function installAppSettingsStyles(): void {
  if (installed || typeof document === 'undefined') return;
  installed = true;
  const style = document.createElement('style');
  style.setAttribute('data-qor-app-settings', '');
  style.textContent = APP_SETTINGS_CSS;
  document.head.appendChild(style);
}
