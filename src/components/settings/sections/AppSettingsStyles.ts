const APP_SETTINGS_CSS = `
    .qorc-settings-host {
      --settings-bg: var(--qorc-bg, #050507);
      --settings-panel: #0d0d0e;
      --settings-card: rgb(10, 10, 10);
      --settings-hover: rgb(11, 11, 11);
      --settings-control: #111114;
      --settings-input: #111114;
      --settings-text: #f4f4f6;
      --settings-muted: #96969f;
      --settings-soft: #707078;
      --settings-danger: #ef4444;
      --settings-danger-hover: #dc2626;
      --settings-success: #4b9568;
      --text: var(--settings-text);
      --muted: var(--settings-muted);
      --quiet: var(--settings-soft);
      --danger: var(--settings-danger);
      color-scheme: dark;
      width: 100%;
      height: 100%;
      min-height: 0;
      overflow: hidden;
      background: var(--settings-bg);
      color: var(--settings-text);
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
      font-size: 14px;
      user-select: none;
      -webkit-user-select: none;
    }

    .qorc-settings-host.light {
      --settings-bg: #ffffff;
      --settings-panel: #f6f7f9;
      --settings-card: #ffffff;
      --settings-hover: #eef0f3;
      --settings-control: #e9e9e9;
      --settings-input: #f7f7f7;
      --settings-text: #17131f;
      --settings-muted: #6f6475;
      --settings-soft: #8a818f;
      --settings-danger: #ef4444;
      --settings-danger-hover: #dc2626;
      --settings-success: #3d8a5a;
      color-scheme: light;
    }

    .qorc-settings-host *,
    .qorc-settings-host *::before,
    .qorc-settings-host *::after {
      box-sizing: border-box;
    }

    .qorc-settings-host button,
    .qorc-settings-host input,
    .qorc-settings-host select {
      font: inherit;
    }

    .qorc-settings-host button {
      cursor: pointer;
    }

    .qorc-settings-host button:disabled,
    .qorc-settings-host input:disabled,
    .qorc-settings-host select:disabled {
      cursor: not-allowed;
      opacity: .5;
    }

    .qorc-settings-host input {
      user-select: text;
      -webkit-user-select: text;
    }

    .qorc-settings-host svg {
      display: block;
    }

    .settings-screen {
      width: 100%;
      height: 100%;
      min-height: 0;
      overflow: hidden;
      background: var(--settings-bg);
    }

    .settings-content {
      width: 100%;
      height: 100%;
      min-width: 0;
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      grid-template-areas:
        "title"
        "account"
        "general"
        "devices"
        "privacy";
      align-content: start;
      align-items: start;
      gap: 44px;
      overflow-y: auto;
      padding: 30px 18px 72px;
      background: var(--settings-bg);
      scrollbar-width: thin;
    }

    .settings-content::-webkit-scrollbar {
      width: 6px;
    }

    .settings-content::-webkit-scrollbar-track {
      background: transparent;
    }

    .settings-content::-webkit-scrollbar-thumb {
      border-radius: 999px;
      background: color-mix(in srgb, var(--settings-muted) 24%, transparent);
    }

    .settings-brand {
      grid-area: title;
      margin: 0;
      padding: 0 4px 8px;
    }

    .settings-brand strong {
      display: block;
      color: var(--settings-text);
      font-size: 30px;
      line-height: 1.15;
      font-weight: 800;
      letter-spacing: -.025em;
    }

    .pane {
      width: 100%;
      min-width: 0;
      overflow: visible;
      border: 0;
      border-radius: 0;
      background: transparent;
    }

    .pane[data-settings-pane="account"] {
      grid-area: account;
    }

    .pane[data-settings-pane="general"] {
      grid-area: general;
    }

    .pane[data-settings-pane="devices"] {
      grid-area: devices;
    }

    .pane[data-settings-pane="privacy"] {
      grid-area: privacy;
    }

    .pane-head {
      min-height: 62px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      margin: 0;
      padding: 0 8px 16px;
    }

    .pane-head > div {
      min-width: 0;
    }

    .pane-title {
      margin: 0;
      color: var(--settings-text);
      font-size: 20px;
      line-height: 1.2;
      font-weight: 650;
      letter-spacing: -.01em;
    }

    .pane-subtitle {
      margin: 7px 0 0;
      color: var(--settings-muted);
      font-size: 13px;
      line-height: 1.45;
      font-weight: 450;
    }

    .settings-section {
      margin: 0;
      padding: 0;
    }

    .settings-list,
    .account-actions,
    .blocked-user-list {
      display: grid;
      gap: 9px;
    }

    .setting-row,
    .account-action-row {
      min-width: 0;
      min-height: 82px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(180px, auto);
      align-items: center;
      gap: 24px;
      border: 0;
      border-radius: 8px;
      padding: 17px 18px;
      background: transparent;
      transition: background .15s ease;
    }

    .setting-row:hover,
    .setting-row:focus-within,
    .account-action-row:hover,
    .account-action-row:focus-within {
      background: var(--settings-hover);
    }

    .setting-row > div,
    .account-action-row > div {
      min-width: 0;
    }

    .setting-label {
      margin: 0 0 6px;
      color: var(--settings-text);
      font-size: 15px;
      line-height: 1.3;
      font-weight: 600;
    }

    .setting-description {
      max-width: 560px;
      color: var(--settings-muted);
      font-size: 13px;
      line-height: 1.5;
      font-weight: 430;
    }

    .navigation-layout-picker {
      width: 164px;
      height: 38px;
      justify-self: end;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      align-items: center;
      gap: 0;
      padding: 0;
      overflow: hidden;
      border-radius: 9px;
      background: var(--settings-control);
    }

    .navigation-layout-picker button {
      width: 100%;
      min-width: 0;
      height: 38px;
      border: 0;
      border-radius: 0;
      padding: 0 8px;
      background: transparent;
      color: var(--settings-muted);
      font-size: 12px;
      font-weight: 600;
    }

    .navigation-layout-picker button:hover {
      background: var(--settings-hover);
      color: var(--settings-text);
    }

    .navigation-layout-picker button.is-active,
    .navigation-layout-picker button.is-active:hover {
      background: var(--qorc-accent, #7057c8);
      color: #fff;
    }

    .navigation-layout-picker button:first-child {
      border-radius: 9px 7px 7px 9px;
    }

    .navigation-layout-picker button:last-child {
      border-radius: 7px 9px 9px 7px;
    }

    .settings-icon-action,
    .settings-head-action,
    .action,
    .danger-action,
    .copy-username,
    .qorc-modal-btn {
      border: 0;
      box-shadow: none;
      transition: background .15s ease, color .15s ease, opacity .15s ease;
    }

    .settings-icon-action {
      width: 40px;
      height: 40px;
      flex: 0 0 40px;
      display: grid;
      place-items: center;
      border-radius: 9px;
      padding: 0;
      background: var(--settings-card);
      color: var(--settings-muted);
    }

    .settings-icon-action:hover,
    .settings-icon-action:focus-visible {
      outline: none;
      background: var(--settings-hover);
      color: var(--settings-text);
    }

    .settings-icon-action svg {
      width: 18px;
      height: 18px;
    }

    .settings-head-action {
      min-height: 40px;
      flex: 0 0 auto;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      border-radius: 9px;
      padding: 0 14px;
      background: var(--settings-card);
      color: var(--settings-danger);
      font-size: 13px;
      line-height: 1;
      font-weight: 550;
    }

    .settings-head-action:hover,
    .settings-head-action:focus-visible {
      outline: none;
      background: var(--settings-hover);
    }

    .settings-head-action svg {
      width: 17px;
      height: 17px;
    }

    .account-editor {
      min-width: 0;
    }

    .account-preview {
      min-width: 0;
      display: flex;
      flex-direction: row;
      align-items: center;
      justify-content: flex-start;
      gap: 18px;
      margin-bottom: 10px;
      padding: 20px 18px;
      border-radius: 8px;
      background: transparent;
    }

    .avatar-preview-button {
      display: block;
      border: 0;
      border-radius: 50%;
      padding: 0;
      background: transparent;
    }

    .avatar-preview-button:focus-visible {
      outline: 1px solid var(--settings-muted);
      outline-offset: 3px;
    }

    .avatar-preview {
      position: relative;
      width: 104px;
      height: 104px;
      overflow: hidden;
      display: grid;
      place-items: center;
      border: 0;
      border-radius: 50%;
      background: var(--settings-control);
      color: var(--settings-text);
    }

    .avatar-preview img {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      object-fit: cover;
    }

    .avatar-preview-fallback {
      font-size: 36px;
      line-height: 1;
      font-weight: 650;
      text-transform: uppercase;
    }

    .avatar-hover-overlay {
      position: absolute;
      inset: 0;
      z-index: 2;
      display: grid;
      place-items: center;
      background: rgba(0, 0, 0, .52);
      color: #fff;
      opacity: 0;
      transition: opacity .15s ease;
    }

    .avatar-preview-button:hover .avatar-hover-overlay,
    .avatar-preview-button:focus-visible .avatar-hover-overlay {
      opacity: 1;
    }

    .avatar-hover-overlay svg {
      width: 25px;
      height: 25px;
    }

    .avatar-upload-input {
      display: none;
    }

    .account-name-row {
      max-width: 100%;
      display: flex;
      align-items: center;
      justify-content: flex-start;
      gap: 10px;
      margin-top: 0;
    }

    .account-username {
      min-width: 0;
      max-width: min(520px, 60vw);
      overflow: hidden;
      color: var(--settings-text);
      font-size: 21px;
      line-height: 1.25;
      font-weight: 650;
      text-align: left;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .copy-username {
      width: 38px;
      height: 38px;
      flex: 0 0 38px;
      display: grid;
      place-items: center;
      border-radius: 8px;
      padding: 0;
      background: var(--settings-control);
      color: var(--settings-muted);
    }

    .copy-username:hover,
    .copy-username:focus-visible {
      outline: none;
      background: var(--settings-hover);
      color: var(--settings-text);
    }

    .copy-username.copied {
      color: var(--settings-success);
    }

    .copy-username svg {
      width: 17px;
      height: 17px;
    }

    .account-actions {
      margin-top: 4px;
    }

    .account-action-row {
      grid-template-columns: minmax(0, 1fr) auto;
    }

    .account-danger-row {
      background: transparent;
    }

    .action,
    .danger-action {
      min-height: 40px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      border-radius: 8px;
      padding: 0 15px;
      font-size: 12.5px;
      line-height: 1;
      font-weight: 600;
      white-space: nowrap;
    }

    .action {
      background: var(--settings-control);
      color: var(--settings-text);
    }

    .action:hover,
    .action:focus-visible {
      outline: none;
      background: var(--settings-hover);
    }

    .danger-action {
      background: var(--settings-danger);
      color: #fff;
    }

    .danger-action:hover,
    .danger-action:focus-visible,
    .danger-action.is-armed:hover,
    .danger-action.is-armed:focus-visible {
      outline: none;
      background: var(--settings-danger-hover);
    }

    .danger-action.is-armed {
      background: var(--settings-danger);
      color: #fff;
    }

    .action svg,
    .danger-action svg {
      width: 14px;
      height: 14px;
    }

    .confirm-inline {
      min-width: 0;
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 6px;
    }

    .switch {
      position: relative;
      width: 40px;
      height: 24px;
      justify-self: end;
      display: inline-flex;
      align-items: center;
      border: 0;
      border-radius: 999px;
      padding: 3px;
      background: #303034;
      transition: background .16s ease;
    }

    .qorc-settings-host.light .switch {
      background: #cacbd0;
    }

    .switch::before {
      content: "";
      width: 18px;
      height: 18px;
      display: block;
      border-radius: 50%;
      background: #fff;
      transition: transform .16s ease;
    }

    .switch.on {
      background: var(--settings-success);
    }

    .switch.on::before {
      transform: translateX(16px);
    }

    .switch:focus-visible {
      outline: 1px solid var(--settings-muted);
      outline-offset: 2px;
    }

    .select,
    .text-input {
      width: min(100%, 300px);
      height: 42px;
      border: 0;
      border-radius: 9px;
      padding: 0 12px;
      background: var(--settings-input);
      color: var(--settings-text);
      outline: none;
      box-shadow: none;
      font-size: 13px;
      line-height: 1;
      font-weight: 500;
    }

    .select {
      justify-self: end;
      cursor: pointer;
    }

    .select:hover,
    .select:focus,
    .text-input:hover,
    .text-input:focus {
      background: var(--settings-hover);
    }

    .select option {
      background: var(--settings-panel);
      color: var(--settings-text);
    }

    .blocked-spinner {
      animation: qorc-blocked-spin .7s linear infinite;
      color: var(--settings-muted);
    }

    @keyframes qorc-blocked-spin {
      to { transform: rotate(360deg); }
    }

    .blocked-empty {
      min-height: 132px;
      display: grid;
      place-items: center;
      border-radius: 0;
      background: transparent;
      color: var(--settings-muted);
      text-align: center;
    }

    .blocked-empty strong {
      display: block;
      margin-bottom: 4px;
      color: var(--settings-text);
      font-size: 15px;
      line-height: 1.3;
      font-weight: 600;
    }

    .blocked-empty span {
      font-size: 13px;
      line-height: 1.35;
    }

    .blocked-user-list {
      margin: 0;
    }

    .blocked-user-row {
      grid-template-columns: minmax(0, 1fr) auto;
    }

    .blocked-user-identity {
      min-width: 0;
      display: flex;
      align-items: center;
      gap: 9px;
    }

    .blocked-user-name {
      overflow: hidden;
      color: var(--settings-text);
      font-size: 15px;
      line-height: 1.3;
      font-weight: 600;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .settings-error {
      margin: 0 0 5px;
      padding: 9px 11px;
      border-radius: 9px;
      background: color-mix(in srgb, var(--settings-danger) 12%, var(--settings-card));
      color: var(--settings-danger);
      font-size: 11.5px;
      line-height: 1.4;
      font-weight: 550;
    }

    .qorc-modal-overlay {
      position: fixed;
      inset: 0;
      z-index: 60;
      display: grid;
      place-items: center;
      padding: 18px;
      background: rgba(0, 0, 0, .58);
    }

    .qorc-settings-host.light .qorc-modal-overlay {
      background: rgba(17, 24, 39, .32);
    }

    .qorc-modal {
      width: min(400px, 100%);
      overflow: hidden;
      border: 0;
      border-radius: 12px;
      background: var(--settings-panel);
      color: var(--settings-text);
      box-shadow: 0 18px 46px rgba(0, 0, 0, .34);
    }

    .qorc-settings-host.light .qorc-modal {
      box-shadow: 0 18px 46px rgba(17, 24, 39, .18);
    }

    .qorc-modal-head {
      padding: 16px 16px 5px;
    }

    .qorc-modal-head h3 {
      margin: 0 0 5px;
      color: var(--settings-text);
      font-size: 16px;
      line-height: 1.25;
      font-weight: 650;
      letter-spacing: -.01em;
    }

    .qorc-modal-head p {
      margin: 0;
      color: var(--settings-muted);
      font-size: 12px;
      line-height: 1.45;
    }

    .qorc-modal-head p strong {
      color: var(--settings-text);
      font-weight: 600;
    }

    .qorc-modal-body {
      padding: 13px 16px 3px;
    }

    .qorc-modal-field {
      display: block;
    }

    .qorc-modal-field .field-label {
      display: block;
      margin: 0 0 6px;
      color: var(--settings-muted);
      font-size: 11px;
      line-height: 1.2;
      font-weight: 550;
    }

    .qorc-modal-field .text-input {
      width: 100%;
      height: 40px;
      background: var(--settings-input);
      font-size: 13px;
    }

    .qorc-modal-error {
      margin: 8px 0 0;
      padding: 8px 10px;
      border-radius: 8px;
      background: color-mix(in srgb, var(--settings-danger) 12%, var(--settings-card));
      color: var(--settings-danger);
      font-size: 11.5px;
      line-height: 1.4;
      font-weight: 550;
    }

    .qorc-modal-actions {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 7px;
      padding: 16px;
    }

    .qorc-modal-btn {
      height: 38px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 9px;
      background: var(--settings-card);
      color: var(--settings-text);
      font-size: 12px;
      line-height: 1;
      font-weight: 600;
    }

    .qorc-modal-btn:hover,
    .qorc-modal-btn:focus-visible {
      outline: none;
      background: var(--settings-hover);
    }

    .qorc-modal-btn.primary {
      background: #e9e9e9;
      color: #101014;
    }

    .qorc-settings-host.light .qorc-modal-btn.primary {
      background: #101014;
      color: #fff;
    }

    .qorc-modal-btn.primary:hover,
    .qorc-modal-btn.primary:focus-visible {
      background: #dcdce0;
    }

    .qorc-settings-host.light .qorc-modal-btn.primary:hover,
    .qorc-settings-host.light .qorc-modal-btn.primary:focus-visible {
      background: #24242a;
    }

    .qorc-modal-btn.danger {
      background: var(--settings-danger);
      color: #fff;
    }

    .qorc-modal-btn.danger:hover,
    .qorc-modal-btn.danger:focus-visible {
      background: var(--settings-danger-hover);
    }

    @media (max-width: 900px) {
      .settings-content {
        gap: 36px;
        padding: 24px 12px 60px;
      }

      .account-preview {
        padding-block: 18px;
      }
    }

    @media (max-width: 580px) {
      .settings-brand strong {
        font-size: 22px;
      }

      .pane-head {
        padding: 11px 12px;
      }

      .settings-section {
        padding: 0 6px 6px;
      }

      .setting-row,
      .account-action-row {
        grid-template-columns: minmax(0, 1fr);
        gap: 9px;
      }

      .select {
        width: 100%;
        justify-self: stretch;
      }

      .switch {
        justify-self: start;
      }

      .account-action-row .confirm-inline {
        width: 100%;
      }

      .account-action-row .confirm-inline > button {
        flex: 1 1 0;
      }
    }
`;

let installed = false;

export function installAppSettingsStyles(): void {
  if (installed || typeof document === 'undefined') return;
  installed = true;
  const style = document.createElement('style');
  style.setAttribute('data-qorc-app-settings', '');
  style.textContent = APP_SETTINGS_CSS;
  document.head.appendChild(style);
}
