import React, { useId } from 'react';
import { useTheme } from 'next-themes';

interface ThemeToggleButtonProps {
  className?: string;
}

export function ThemeToggleButton({ className }: ThemeToggleButtonProps) {
  const { theme, resolvedTheme, setTheme } = useTheme();
  const activeTheme = theme === 'system' ? resolvedTheme : theme;
  const maskId = `moon-mask-${useId().replace(/:/g, '')}`;

  return (
    <button
      type="button"
      className={className ? `theme-toggle-btn ${className}` : 'theme-toggle-btn'}
      onClick={() => setTheme(activeTheme === 'dark' ? 'light' : 'dark')}
      aria-label={activeTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
    >
      <span className="themeToggle st-sunMoonThemeToggleBtn" aria-hidden="true">
        <input
          type="checkbox"
          className="themeToggleInput"
          checked={activeTheme === 'light'}
          readOnly
        />
        <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor" stroke="none">
          <mask id={maskId}>
            <rect x="0" y="0" width="20" height="20" fill="white"></rect>
            <circle cx="11" cy="3" r="8" fill="black"></circle>
          </mask>
          <circle className="sunMoon" cx="10" cy="10" r="8" mask={`url(#${maskId})`}></circle>
          <g>
            <circle className="sunRay sunRay1" cx="18" cy="10" r="1.5"></circle>
            <circle className="sunRay sunRay2" cx="14" cy="16.928" r="1.5"></circle>
            <circle className="sunRay sunRay3" cx="6" cy="16.928" r="1.5"></circle>
            <circle className="sunRay sunRay4" cx="2" cy="10" r="1.5"></circle>
            <circle className="sunRay sunRay5" cx="6" cy="3.1718" r="1.5"></circle>
            <circle className="sunRay sunRay6" cx="14" cy="3.1718" r="1.5"></circle>
          </g>
        </svg>
      </span>
    </button>
  );
}
