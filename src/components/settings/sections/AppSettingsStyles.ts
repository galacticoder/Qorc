const APP_SETTINGS_CSS = `
    .qorc-settings-host {
      --settings-bg: var(--qorc-app-bg, #050507);
      --settings-panel: #0d0d0e;
      --settings-card: rgb(10, 10, 10);
      --settings-hover: rgb(11, 11, 11);
      --settings-control: #111114;
      --settings-layout-hover: #0d0d10;
      --settings-link-bg: var(--qorc-option-bg);
      --settings-link-hover: var(--qorc-option-hover);
      --settings-text: #f4f4f6;
      --settings-muted: #aaa8b5;
      --settings-title-size: 24px;
      --settings-label-size: 16px;
      --settings-caption-size: 14px;
      --settings-section-link-gap: 8px;
      --settings-danger: var(--qorc-danger);
      --settings-danger-hover: var(--qorc-danger-hover);
      --settings-success: #4b9568;
      --muted: var(--settings-muted);
      --danger: var(--settings-danger);
      color-scheme: dark;
      width: 100%;
      height: 100%;
      min-height: 0;
      overflow: hidden;
      background: var(--settings-bg);
      color: var(--settings-text);
      font-family: var(--qorc-ui-font, "Google Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif);
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
      --settings-layout-hover: #dedede;
      --settings-link-bg: var(--qorc-option-bg);
      --settings-link-hover: var(--qorc-option-hover);
      --settings-text: #17131f;
      --settings-muted: #625c6e;
      --settings-danger: var(--qorc-danger);
      --settings-danger-hover: var(--qorc-danger-hover);
      --settings-success: #3d8a5a;
      color-scheme: light;
      -webkit-font-smoothing: antialiased;
      font-synthesis: none;
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
      container-type: size;
      display: flex;
      flex-direction: column;
      width: 100%;
      height: 100%;
      min-height: 0;
      overflow: hidden;
      background: var(--settings-bg);
    }

    .settings-content {
      container: settings-panel / inline-size;
      --settings-avatar-size: 288px;
      width: 100%;
      flex: 1;
      min-height: 0;
      min-width: 0;
      overflow-x: hidden;
      overflow-y: auto;
      overscroll-behavior-y: contain;
      max-width: none;
      margin-inline: 0;
      padding: 16px var(--qorc-page-gutter) 36px;
      background: var(--settings-bg);
      scrollbar-width: none;
    }

    .settings-content::-webkit-scrollbar { display: none; }

    .settings-header {
      box-sizing: border-box;
      height: var(--qorc-header-height);
      min-height: var(--qorc-header-height);
      max-height: var(--qorc-header-height);
      flex-shrink: 0;
      min-width: 0;
      display: flex;
      align-items: center;
      gap: 8px;
      width: 100%;
      max-width: none;
      margin-inline: 0;
      padding: 0 var(--qorc-header-gutter);
      box-shadow: var(--qorc-header-divider);
      background: var(--qorc-header-bg);
    }

    .settings-brand {
      min-width: 0;
      margin: 0;
      min-height: 40px;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .settings-brand-icon {
      width: 22px;
      height: 22px;
      flex: 0 0 22px;
      margin-inline: 6px;
      color: var(--settings-text);
      transform: translateY(-1px);
    }

    .settings-brand strong {
      display: block;
      color: var(--settings-text);
      font-size: var(--settings-title-size);
      line-height: 1.25;
      font-weight: 700;
      letter-spacing: -.02em;
      overflow-wrap: anywhere;
    }

    .settings-brand:focus { outline: none; }

    .settings-section-link:focus-visible { outline: 2px solid var(--qorc-accent); outline-offset: -2px; }

    .settings-section-menu {
      display: grid;
      gap: var(--settings-section-link-gap);
      border: 0;
      margin-top: 28px;
    }

    .settings-legal-links { display: grid; gap: 8px; margin-top: 28px; }

    .settings-section-link {
      display: flex;
      align-items: center;
      gap: 14px;
      width: 100%;
      min-width: 0;
      min-height: 72px;
      padding: 14px 12px;
      border: 0;
      border-radius: 12px;
      background: var(--settings-link-bg);
      color: var(--settings-text);
      text-align: left;
    }

    .settings-section-link:is(:hover, :active, [data-qorc-pressed]) { background: var(--settings-link-hover); }
    .settings-section-link > svg { flex: 0 0 auto; color: var(--settings-muted); }
    .settings-section-copy { display: grid; gap: 4px; min-width: 0; flex: 1; }
    .settings-section-copy strong { font-size: var(--settings-label-size); line-height: 1.35; font-weight: 600; }
    .settings-section-copy > span { font-size: var(--settings-caption-size); line-height: 1.5; color: var(--settings-muted); }

    .pane {
      width: 100%;
      min-width: 0;
      padding: 0;
      overflow: visible;
      border: 0;
      border-radius: 0;
      background: transparent;
    }

    .pane + .pane {
      border-top: 0;
      margin-top: 36px;
    }

    .settings-section {
      margin: 0;
      padding: 0;
    }

    .settings-subsection-title {
      margin: 0 0 10px;
      padding-inline: 12px;
      color: var(--settings-muted);
      font-size: 15px;
      line-height: 1.4;
      font-weight: 650;
      letter-spacing: .015em;
    }

    .settings-list > .settings-subsection-title { margin: 22px 0 2px; }
    .settings-list > .settings-subsection-title:first-child { margin-top: 0; }
    .settings-legal-links > .settings-subsection-title { margin-bottom: 2px; }
    .settings-local-data { margin-top: 36px; }
    .setting-row.setting-row-destructive { grid-template-columns: minmax(0, 1fr); gap: 14px; }
    .settings-clear-controls, .settings-account-action-copy { min-width: 0; }
    .settings-refresh-row .settings-refresh-button { min-height: 44px; justify-self: start; }

    .settings-list,
    .blocked-user-list {
      display: grid;
      gap: 8px;
    }

    .setting-row {
      --settings-control: color-mix(in srgb, var(--settings-text) 5%, var(--settings-link-bg));
      min-width: 0;
      min-height: 68px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 24px;
      border: 0;
      border-radius: 12px;
      padding: 14px 12px;
      background: var(--settings-link-bg);
    }

    .setting-row:is(:hover, :active, [data-qorc-pressed]),
    .setting-row:focus-within {
      background: var(--settings-link-hover);
    }

    .setting-row > div {
      min-width: 0;
    }

    .setting-copy { min-width: 0; }
    .setting-copy-text { min-width: 0; }

    .setting-label {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 6px 10px;
      margin: 0 0 4px;
      color: var(--settings-text);
      font-size: var(--settings-label-size);
      line-height: 1.35;
      font-weight: 550;
    }

    .setting-feedback {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      max-width: 100%;
      color: var(--settings-muted);
      font-size: 12px;
      font-weight: 500;
      line-height: 1.4;
      animation: qorc-setting-feedback-in 120ms ease-out;
    }
    .setting-feedback svg { flex: 0 0 auto; }
    .setting-feedback.is-error { color: var(--settings-danger); }
    .setting-label > .setting-feedback.is-error { flex-basis: 100%; }
    @keyframes qorc-setting-feedback-in { from { opacity: 0; } to { opacity: 1; } }
    @media (prefers-reduced-motion: reduce) {
      .setting-feedback { animation: none; }
      .qorc-settings-host .switch,
      .qorc-settings-host .switch::before { transition: none; }
      .qorc-unblock-overlay,
      .qorc-unblock-dialog { animation: none; }
    }

    .setting-description {
      max-width: 560px;
      color: var(--settings-muted);
      font-size: var(--settings-caption-size);
      line-height: 1.5;
      font-weight: 400;
    }

    .navigation-layout-picker {
      position: relative;
      isolation: isolate;
      width: 176px;
      height: 44px;
      justify-self: end;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      align-items: center;
      padding: 0;
      border: 0;
      border-radius: 8px;
      background: var(--settings-control);
    }
    .navigation-layout-picker::before {
      content: "";
      position: absolute;
      z-index: -1;
      inset: 0 auto 0 0;
      width: 50%;
      border-radius: 8px;
      background: var(--qorc-accent);
      transition: transform 180ms cubic-bezier(.2,.8,.2,1);
    }
    .navigation-layout-picker[data-layout="top"]::before { transform: translateX(100%); }
    .navigation-layout-picker span { padding: 0 8px; color: var(--settings-muted); font-size: 14px; font-weight: 600; }
    .navigation-layout-picker[data-layout="sidebar"] [data-choice="sidebar"],
    .navigation-layout-picker[data-layout="top"] [data-choice="top"] { color: #fff; }
    .navigation-layout-picker:focus-visible { outline: 2px solid var(--settings-muted); outline-offset: 3px; }
    .qorc-settings-host .navigation-layout-picker:disabled { opacity: 1; cursor: progress; }
    @media (prefers-reduced-motion: reduce) {
      .navigation-layout-picker::before { transition: none; }
    }

    .action,
    .danger-action,
    .copy-username {
      border: 0;
      box-shadow: none;
      transition: background .15s ease, color .15s ease, opacity .15s ease;
    }

    .account-editor {
      min-width: 0;
    }

    .account-preview {
      min-width: 0;
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      grid-template-areas: "avatar" "name";
      align-items: center;
      justify-items: center;
      gap: 16px;
      margin-bottom: 0;
      padding: 16px 0 8px;
      border-radius: 8px;
      background: transparent;
    }

    .avatar-preview-button {
      grid-area: avatar;
      display: block;
      width: var(--settings-avatar-size);
      max-width: 100%;
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
      width: 100%;
      height: auto;
      aspect-ratio: 1;
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

    .avatar-preview-placeholder {
      font-size: calc(var(--settings-avatar-size) * .35);
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

    .avatar-preview-button:is(:hover, :active, [data-qorc-pressed]) .avatar-hover-overlay,
    .avatar-preview-button:focus-visible .avatar-hover-overlay {
      opacity: 1;
    }

    .avatar-hover-overlay svg {
      width: 32px;
      height: 32px;
    }

    .avatar-upload-input {
      display: none;
    }

    .account-name-row {
      grid-area: name;
      align-self: center;
      flex: 0 1 auto;
      width: fit-content;
      max-width: 100%;
      display: grid;
      grid-template-columns: 38px minmax(0, auto) 38px;
      align-items: center;
      justify-content: center;
      gap: 10px;
      margin-top: 0;
    }

    .account-name-row > .setting-feedback { grid-column: 1 / -1; justify-self: center; }

    .account-username {
      grid-column: 2;
      min-width: 0;
      max-width: 520px;
      overflow: hidden;
      color: var(--settings-text);
      font-size: 32px;
      line-height: 1.25;
      font-weight: 650;
      text-align: center;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .copy-username { grid-column: 3; }

    .account-actions {
      width: 100%;
      flex: 0 0 auto;
      display: flex;
      justify-content: flex-start;
      margin: 40px 0 0;
      padding: 16px 12px 0;
    }

    .account-action-controls {
      min-width: 0;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: flex-start;
      gap: 12px;
    }

    .qorc-settings-host .settings-account-footer {
      margin-top: calc(var(--settings-section-link-gap) * 2.5);
      padding: 0;
    }
    .settings-account-footer .settings-account-action-copy,
    .settings-account-footer .account-action-controls,
    .settings-account-footer .danger-action { width: 100%; }

    .action,
    .danger-action {
      min-height: 40px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      border-radius: 8px;
      padding: 0 15px;
      font-size: var(--settings-caption-size);
      line-height: 1;
      font-weight: 600;
      white-space: nowrap;
    }

    .settings-account-footer .action,
    .settings-account-footer .danger-action { min-height: 44px; }

    .qorc-settings-host :is(.action, .danger-action) {
      font-size: var(--settings-caption-size);
      font-weight: 600;
      line-height: 1;
    }

    .action {
      background: var(--qorc-accent);
      color: #fff;
    }
    .action.is-secondary {
      background: var(--qorc-button-secondary-bg);
      color: var(--qorc-button-secondary-text);
    }
    .action.is-secondary:is(:hover, :active, [data-qorc-pressed]),
    .action.is-secondary:focus-visible { background: var(--qorc-button-secondary-hover); }

    .action:not(.is-secondary):is(:hover, :active, [data-qorc-pressed]),
    .action:not(.is-secondary):focus-visible {
      background: color-mix(in srgb, var(--qorc-accent) 86%, black);
    }
    .action:focus-visible { outline: 2px solid var(--settings-muted); outline-offset: 3px; }

    .danger-action {
      background: var(--settings-danger);
      color: #fff;
    }

    .danger-action:is(:hover, :active, [data-qorc-pressed]),
    .danger-action:focus-visible {
      outline: none;
      background: var(--settings-danger-hover);
    }

    .action svg,
    .danger-action svg {
      width: 16px;
      height: 16px;
    }

    .switch {
      position: relative;
      width: 48px;
      height: 44px;
      justify-self: end;
      display: inline-flex;
      align-items: center;
      border: 0;
      border-radius: 8px;
      padding: 0 7px;
      background: transparent;
    }

    .qorc-settings-host .switch.is-saving:disabled { opacity: 1; cursor: progress; }

    .switch::after {
      content: "";
      position: absolute;
      left: 4px;
      top: 10px;
      width: 40px;
      height: 24px;
      border-radius: 999px;
      background: #303034;
      transition: background .16s ease;
    }

    .qorc-settings-host.light .switch::after { background: #cacbd0; }
    .switch.on::after { background: var(--qorc-accent, #7057c8); }
    .qorc-settings-host.light .switch.on::after { background: var(--qorc-accent, #7057c8); }

    .switch::before {
      content: "";
      position: relative;
      z-index: 1;
      width: 18px;
      height: 18px;
      display: block;
      border-radius: 50%;
      background: #fff;
      transition: transform .16s ease;
    }

    .switch.on::before { transform: translateX(16px); }
    .switch:focus-visible { outline: 1px solid var(--settings-muted); outline-offset: 2px; }
    .qorc-settings-host .qorc-select { min-height: 44px; }

    .device-select {
      width: 240px;
      max-width: 100%;
      justify-self: end;
    }

    .theme-select {
      width: 128px;
      max-width: 100%;
      justify-self: end;
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

    .blocked-users-screen .settings-content > .settings-section-link { margin-bottom: 16px; }


    .blocked-users-header .settings-brand { flex: 1; }

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

    .qorc-unblock-overlay {
      position: fixed;
      inset: 0;
      z-index: 140;
      display: grid;
      place-items: center;
      padding: 18px;
      background: rgba(0, 0, 0, .58);
      animation: qorc-unblock-overlay-in 200ms cubic-bezier(.16, 1, .3, 1);
    }

    .qorc-settings-host.light .qorc-unblock-overlay,
    .qorc-settings-host.light.qorc-unblock-overlay {
      background: rgba(17, 24, 39, .32);
    }

    @keyframes qorc-unblock-overlay-in {
      from { opacity: 0; }
      to { opacity: 1; }
    }

    .qorc-unblock-dialog {
      --unblock-bg: var(--settings-panel);
      --unblock-card: var(--settings-card);
      width: min(420px, 100%);
      overflow: hidden;
      border: 0;
      border-radius: 12px;
      background: var(--unblock-bg);
      color: var(--settings-text);
      box-shadow: 0 18px 46px rgba(0, 0, 0, .34);
      animation: qorc-unblock-dialog-in 200ms cubic-bezier(.16, 1, .3, 1);
    }

    .settings-action-dialog { max-height: calc(100dvh - 36px); overflow-y: auto; outline: none; }
    .settings-action-dialog-copy { padding: 24px; }
    .settings-action-dialog h2 { margin: 0; font-size: 22px; line-height: 1.25; font-weight: 700; }
    .settings-action-dialog p { margin: 12px 0 0; color: var(--settings-muted); font-size: 14px; line-height: 1.55; overflow-wrap: anywhere; }
    .settings-action-dialog .settings-action-dialog-error { color: var(--settings-danger); }
    .settings-action-dialog .settings-action-dialog-status { color: var(--settings-text); }
    .settings-action-dialog-buttons { display: flex; justify-content: flex-end; gap: 8px; padding: 0 24px 24px; }
    .settings-action-dialog-buttons > button { min-height: 44px; min-width: 88px; white-space: normal; }
    .settings-action-dialog-buttons > button:focus-visible { outline: 2px solid var(--qorc-accent); outline-offset: 3px; }
    @media (max-width: 420px) {
      .settings-action-dialog-copy { padding: 20px; }
      .settings-action-dialog-buttons { padding: 0 20px 20px; }
      .settings-action-dialog-buttons > button { flex: 1 1 0; min-width: 0; }
    }

    @keyframes qorc-unblock-dialog-in {
      from { opacity: 0; transform: scale(.96); }
      to { opacity: 1; transform: scale(1); }
    }

    .qorc-settings-host.light .qorc-unblock-dialog {
      --unblock-bg: var(--settings-card);
      --unblock-card: var(--settings-panel);
      box-shadow: 0 18px 46px rgba(17, 24, 39, .18);
    }

    .qorc-unblock-head {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 16px 14px 12px 16px;
    }

    .qorc-unblock-head-copy {
      min-width: 0;
      flex: 1 1 auto;
    }

    .qorc-unblock-head h3 {
      margin: 0;
      color: var(--settings-text);
      font-size: 18px;
      line-height: 1.15;
      font-weight: 850;
      letter-spacing: -.01em;
    }

    .qorc-unblock-head p {
      max-width: 340px;
      margin: 6px 0 0;
      color: var(--settings-muted);
      font-size: 12px;
      line-height: 1.45;
    }

    .qorc-unblock-close {
      width: 32px;
      height: 32px;
      flex: 0 0 32px;
      display: grid;
      place-items: center;
      border: 0;
      border-radius: 8px;
      padding: 0;
      background: transparent;
      color: var(--settings-muted);
      cursor: pointer;
      transition: background .15s ease, color .15s ease;
    }

    .qorc-unblock-close:is(:hover, :active, [data-qorc-pressed]),
    .qorc-unblock-close:focus-visible {
      outline: none;
      background: var(--settings-hover);
      color: var(--settings-text);
    }

    .qorc-unblock-close svg {
      width: 17px;
      height: 17px;
    }

    .qorc-unblock-target {
      min-width: 0;
      min-height: 58px;
      display: flex;
      align-items: center;
      gap: 10px;
      margin: 0 8px 8px;
      padding: 7px 8px;
      border-radius: 10px;
      background: var(--unblock-card);
    }

    .qorc-unblock-avatar {
      flex: 0 0 auto;
    }

    .qorc-unblock-user-copy {
      min-width: 0;
      flex: 1 1 auto;
      display: grid;
      gap: 2px;
    }

    .qorc-unblock-name,
    .qorc-unblock-username {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .qorc-unblock-name {
      color: var(--settings-text);
      font-size: 13.5px;
      font-weight: 550;
    }

    .qorc-unblock-username {
      color: var(--settings-muted);
      font-size: 11.5px;
      font-weight: 500;
    }

    .qorc-unblock-confirm {
      height: 34px;
      flex: 0 0 auto;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 7px;
      border: 0;
      border-radius: 8px;
      padding: 0 14px;
      background: var(--qorc-accent);
      color: #fff;
      font-size: 12.5px;
      font-weight: 650;
      cursor: pointer;
      transition: background .15s ease, color .15s ease, opacity .15s ease;
    }

    .qorc-unblock-confirm:is(:hover, :active, [data-qorc-pressed]),
    .qorc-unblock-confirm:focus-visible {
      background: color-mix(in srgb, var(--qorc-accent) 86%, black);
    }
    .qorc-unblock-confirm:focus-visible { outline: 2px solid var(--settings-muted); outline-offset: 3px; }

    .qorc-unblock-close:disabled,
    .qorc-unblock-confirm:disabled {
      cursor: not-allowed;
      opacity: .55;
    }

    .qorc-unblock-spinner {
      width: 15px;
      height: 15px;
      animation: qorc-blocked-spin .7s linear infinite;
    }

    @container settings-panel (min-width: 581px) {
      .setting-row.setting-row-destructive { grid-template-columns: minmax(240px, 1fr) auto; gap: 24px; }
      .settings-clear-controls { justify-self: end; }
    }

    @container settings-panel (max-width: 580px) {
      .account-preview {
        --settings-avatar-size: 256px;
        padding: 8px 0;
      }

      .account-username { font-size: 28px; }
      .account-name-row { grid-template-columns: 44px minmax(0, auto) 44px; }
      .setting-row { gap: 16px; padding: 14px 12px; }
      .setting-row:has(.settings-refresh-button),
      .setting-row:has(.navigation-layout-picker) { grid-template-columns: minmax(0, 1fr); gap: 10px; }
      .setting-row:has(.qorc-select) { grid-template-columns: minmax(0, 1fr) auto; gap: 4px 14px; }
      .setting-row:has(.qorc-select) > .setting-copy,
      .setting-row:has(.qorc-select) .setting-copy-text { display: contents; }
      .setting-row:has(.qorc-select) .setting-label { grid-column: 1; grid-row: 1; min-width: 0; margin: 0; overflow-wrap: anywhere; }
      .setting-row:has(.qorc-select) .setting-description { grid-column: 1 / -1; grid-row: 2; }
      .device-select, .theme-select { grid-column: 2; grid-row: 1; width: clamp(104px, 34cqw, 128px); justify-self: end; }
      .setting-description { line-height: 1.5; }
      .action, .danger-action { min-height: 44px; }
      .account-actions { justify-content: stretch; padding-inline: 0; }
      .account-action-controls { width: 100%; }
      .account-action-controls > button { flex: 1 1 0; }
      .blocked-user-row { grid-template-columns: minmax(0, 1fr) auto; }
    }

    @media (max-width: 760px) {
      .settings-content { padding-bottom: 24px; }
    }

`;

let installed = false;

export function installAppSettingsStyles(): void {
  if (installed) return;
  installed = true;
  const style = document.createElement('style');
  style.setAttribute('data-qorc-app-settings', '');
  style.textContent = APP_SETTINGS_CSS;
  document.head.appendChild(style);
}
