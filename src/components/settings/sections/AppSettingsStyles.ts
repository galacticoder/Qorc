const APP_SETTINGS_CSS = `
    .qorc-settings-host {
      --settings-bg: var(--qorc-bg, #050507);
      --settings-panel: #0d0d0e;
      --settings-card: rgb(10, 10, 10);
      --settings-section-bg: #030305;
      --settings-hover: rgb(11, 11, 11);
      --settings-control: #111114;
      --settings-layout-hover: #0d0d10;
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
      font-family: var(--qorc-ui-font, "Google Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif);
      font-size: 14px;
      user-select: none;
      -webkit-user-select: none;
    }

    .qorc-settings-host.light {
      --settings-bg: #ffffff;
      --settings-panel: #f6f7f9;
      --settings-card: #ffffff;
      --settings-section-bg: #fafafa;
      --settings-hover: #eef0f3;
      --settings-control: #e9e9e9;
      --settings-layout-hover: #dedede;
      --settings-input: #f7f7f7;
      --settings-text: #17131f;
      --settings-muted: #6f6475;
      --settings-soft: #8a818f;
      --settings-danger: #ef4444;
      --settings-danger-hover: #dc2626;
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
      --settings-section-gap: 44px;
      --settings-avatar-size: max(64px, min(220px, calc(50cqh - 130px), calc(50cqw - 48px)));
      width: 100%;
      flex: 1;
      min-height: 0;
      min-width: 0;
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      grid-template-areas:
        "account"
        "general"
        "devices"
        "privacy";
      align-content: start;
      align-items: start;
      gap: var(--settings-section-gap);
      overflow-y: auto;
      padding: var(--settings-section-gap) 18px 72px;
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
      flex-shrink: 0;
      margin: 0;
      min-height: 56px;
      padding: 16px 18px 0;
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
      font-size: 24px;
      line-height: 1;
      font-weight: 800;
      letter-spacing: -.025em;
    }

    .pane {
      width: 100%;
      min-width: 0;
      overflow: visible;
      border: 0;
      border-radius: 10px;
      background: var(--settings-section-bg);
    }

    .pane[data-settings-pane="account"] {
      grid-area: account;
      display: grid;
      align-content: center;
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
      padding: 17px 18px 12px;
    }

    .pane-head > div {
      min-width: 0;
    }

    .pane-heading {
      display: grid;
      align-items: start;
      gap: 7px;
    }

    .pane-heading > div {
      min-width: 0;
    }

    .pane-title-row {
      display: flex;
      align-items: center;
      gap: 11px;
    }

    .pane-title-icon {
      width: 20px;
      height: 20px;
      flex: 0 0 auto;
      margin: 0;
      color: var(--settings-muted);
      stroke-width: 2;
      transform: translateY(-1px);
    }

    .pane-title {
      margin: 0;
      color: var(--settings-text);
      font-size: 20px;
      line-height: 1;
      font-weight: 650;
      letter-spacing: -.01em;
    }

    .pane-subtitle {
      margin: 0;
      color: var(--settings-soft);
      font-size: 13px;
      line-height: 1.45;
      font-weight: 450;
    }

    .settings-section {
      margin: 0;
      padding: 0;
    }

    .settings-list,
    .blocked-user-list {
      display: grid;
      gap: 9px;
    }

    .setting-row {
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
    .setting-row:focus-within {
      background: var(--settings-hover);
    }

    .setting-row > div {
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
      background: var(--settings-layout-hover);
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
    .copy-username {
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
      display: grid;
      grid-template-columns: auto minmax(0, 1fr) auto;
      grid-template-areas: "avatar name actions";
      align-items: center;
      gap: 12px 18px;
      margin-bottom: 0;
      padding: 20px 18px;
      border-radius: 8px;
      background: transparent;
    }

    .avatar-preview-button {
      grid-area: avatar;
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
      width: var(--settings-avatar-size);
      height: var(--settings-avatar-size);
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

    .avatar-preview-button:hover .avatar-hover-overlay,
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
      max-width: 100%;
      display: grid;
      grid-template-columns: minmax(0, auto) 38px;
      align-items: center;
      justify-content: start;
      gap: 10px;
      margin-top: 0;
    }

    .account-username {
      grid-column: 1;
      min-width: 0;
      max-width: min(520px, 60vw);
      overflow: hidden;
      color: var(--settings-text);
      font-size: 24px;
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
      grid-area: actions;
      width: 100%;
      max-width: 240px;
      flex: 0 0 auto;
      align-self: center;
      display: flex;
      justify-content: flex-end;
      margin: 0;
    }

    .account-action-controls {
      min-width: 0;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: flex-end;
      gap: 8px;
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
      background: var(--qorc-accent, #7057c8);
    }

    .qorc-settings-host.light .switch.on {
      background: var(--qorc-accent, #7057c8);
    }

    .switch.on::before {
      transform: translateX(16px);
    }

    .switch:focus-visible {
      outline: 1px solid var(--settings-muted);
      outline-offset: 2px;
    }

    .select {
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

    .device-select {
      position: relative;
      width: min(100%, 340px);
      height: 44px;
      justify-self: end;
      overflow: hidden;
      border-radius: 10px;
      background: var(--settings-input);
      transition: background .15s ease, box-shadow .15s ease;
    }

    .device-select:hover {
      background: var(--settings-layout-hover);
    }

    .device-select:focus-within {
      background: var(--settings-layout-hover);
      box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--settings-muted) 28%, transparent);
    }

    .device-select > svg {
      position: absolute;
      top: 50%;
      right: 14px;
      width: 17px;
      height: 17px;
      pointer-events: none;
      color: var(--settings-muted);
      transform: translateY(-50%);
      stroke-width: 2;
    }

    .select {
      width: 100%;
      height: 100%;
      appearance: none;
      -webkit-appearance: none;
      border-radius: inherit;
      padding: 0 44px 0 15px;
      background: transparent;
      cursor: pointer;
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

    .blocked-user-row .action:hover,
    .blocked-user-row .action:focus-visible {
      background: var(--settings-layout-hover);
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
      z-index: 60;
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

    .qorc-unblock-close:hover,
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
      background: var(--settings-control);
      color: var(--settings-text);
      font-size: 12.5px;
      font-weight: 650;
      cursor: pointer;
      transition: background .15s ease, color .15s ease, opacity .15s ease;
    }

    .qorc-unblock-confirm:hover,
    .qorc-unblock-confirm:focus-visible {
      outline: none;
      background: var(--settings-layout-hover);
    }

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

    @media (max-width: 900px) {
      .settings-content {
        --settings-section-gap: 36px;
        padding: var(--settings-section-gap) 18px 60px;
      }

      .account-preview {
        padding-block: 18px;
      }
    }

    @media (max-width: 580px) {
      .account-preview {
        --settings-avatar-size: min(96px, max(64px, calc(30cqw - 24px)));
        grid-template-columns: auto minmax(0, 1fr) minmax(100px, auto);
        gap: 12px;
      }

      .pane-head {
        padding: 15px 14px 10px;
      }

      .settings-section {
        padding: 0 6px 6px;
      }

      .setting-row {
        grid-template-columns: minmax(0, 1fr);
        gap: 9px;
      }

      .select {
        width: 100%;
      }

      .device-select {
        width: 100%;
        justify-self: stretch;
      }

      .switch {
        justify-self: start;
      }

      .account-actions .confirm-inline {
        width: 100%;
        flex-direction: column;
        align-items: stretch;
      }

      .account-action-controls {
        flex-direction: column;
        align-items: stretch;
      }

      .account-action-controls > button,
      .account-actions .confirm-inline > button {
        flex: 1 1 0;
      }
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
