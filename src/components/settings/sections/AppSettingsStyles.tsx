import React from 'react';

export const AppSettingsStyles = () => (
    <style>{`
    .settings-layout {
      display: flex;
      height: 80vh;
      width: 100%;
      overflow: hidden;
    }
    .settings-sidebar {
      width: 220px;
      flex-shrink: 0;
      background: hsl(var(--secondary) / 0.3);
      overflow-y: auto;
      scrollbar-width: thin;
      scrollbar-color: hsl(var(--muted-foreground) / 0.2) transparent;
    }
    .settings-sidebar::-webkit-scrollbar { width: 4px; }
    .settings-sidebar::-webkit-scrollbar-track { background: transparent; }
    .settings-sidebar::-webkit-scrollbar-thumb { 
      background: hsl(var(--muted-foreground) / 0.2); 
      border-radius: 2px;
    }
    .settings-content {
      flex: 1;
      overflow-y: auto;
      padding: 40px;
      scrollbar-width: thin;
      scrollbar-color: hsl(var(--muted-foreground) / 0.2) transparent;
    }
    .settings-content::-webkit-scrollbar { width: 8px; }
    .settings-content::-webkit-scrollbar-track { background: transparent; }
    .settings-content::-webkit-scrollbar-thumb { 
      background: hsl(var(--muted-foreground) / 0.2); 
      border-radius: 4px;
    }
    .settings-nav-item {
      display: flex;
      align-items: center;
      gap: 10px;
      width: 100%;
      padding: 8px 12px;
      margin: 2px 8px;
      border-radius: 4px;
      font-size: 14px;
      font-weight: 500;
      color: hsl(var(--muted-foreground));
      background: transparent;
      border: none;
      cursor: pointer;
      transition: all 0.1s ease;
      text-align: left;
    }
    .settings-nav-item:hover {
      background: hsl(var(--secondary) / 0.8);
      color: hsl(var(--foreground));
    }
    .settings-nav-item.active {
      background: hsl(var(--secondary));
      color: hsl(var(--foreground));
    }
    .settings-category {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.02em;
      text-transform: uppercase;
      color: hsl(var(--muted-foreground));
      padding: 16px 20px 8px;
    }
    .settings-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 0;
      border-bottom: 1px solid hsl(var(--border) / 0.5);
    }
    .settings-row:last-child {
      border-bottom: none;
    }
    .settings-label {
      font-size: 15px;
      font-weight: 500;
      color: hsl(var(--foreground));
      margin-bottom: 4px;
    }
    .settings-description {
      font-size: 13px;
      color: hsl(var(--muted-foreground));
      line-height: 1.4;
    }
    .settings-section-title {
      font-size: 20px;
      font-weight: 600;
      color: hsl(var(--foreground));
      margin-bottom: 20px;
    }
    .settings-group {
      margin-bottom: 32px;
    }
    .settings-group-title {
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.02em;
      text-transform: uppercase;
      color: hsl(var(--muted-foreground));
      margin-bottom: 12px;
    }
    .avatar-container {
      position: relative;
      width: 80px;
      height: 80px;
      border-radius: 50%;
      overflow: hidden;
      cursor: pointer;
      background: linear-gradient(135deg, #5865F2 0%, #4752C4 100%);
    }
    .avatar-container:hover .avatar-overlay {
      opacity: 1;
    }
    .avatar-overlay {
      position: absolute;
      inset: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      background: rgba(0, 0, 0, 0.6);
      opacity: 0;
      transition: opacity 0.2s ease;
    }
    .avatar-image {
      width: 100%;
      height: 100%;
      object-fit: cover;
    }
    .avatar-placeholder {
      width: 100%;
      height: 100%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 32px;
      font-weight: 600;
      color: white;
    }
    .account-card {
      background: hsl(var(--secondary) / 0.5);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .theme-option {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 16px;
      border-radius: 8px;
      border: 2px solid transparent;
      cursor: pointer;
      transition: all 0.2s ease;
      background: hsl(var(--secondary) / 0.3);
      min-width: 80px;
    }
    .theme-option:hover {
      background: hsl(var(--secondary) / 0.6);
    }
    .theme-option.active {
      border-color: #5865F2;
      background: hsl(var(--secondary) / 0.8);
    }
    .theme-icon {
      width: 40px;
      height: 40px;
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .custom-select {
      width: 100%;
      padding: 10px 12px;
      border-radius: 4px;
      border: 1px solid hsl(var(--border));
      background: hsl(var(--background));
      color: hsl(var(--foreground));
      font-size: 14px;
      cursor: pointer;
      outline: none;
      transition: border-color 0.2s ease;
    }
    .custom-select:hover {
      border-color: rgba(88, 101, 242, 0.5);
    }
    .custom-select:focus {
      border-color: #5865F2;
    }
    .danger-zone {
      background: hsl(0 70% 50% / 0.1);
      border: 1px solid hsl(0 70% 50% / 0.3);
      border-radius: 8px;
      padding: 20px;
    }
    .settings-select {
      width: 100%;
      padding: 8px 12px;
      border-radius: 6px;
      border: 1px solid hsl(var(--border));
      background: hsl(var(--background));
      color: hsl(var(--foreground));
      font-size: 14px;
      outline: none;
    }
    .settings-select:focus {
      border-color: #5865F2;
    }
  `}</style>
);
