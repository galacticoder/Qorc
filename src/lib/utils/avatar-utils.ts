// Generates a deterministic color based on the username
export const getAvatarColor = (username: string): string => {
    const normalized = (username || '').toLowerCase().trim();
    const colors = [
        '#5865F2',
        '#57F287',
        '#FEE75C',
        '#EB459E',
        '#ED4245',
        '#3BA55C',
        '#FAA61A',
        '#9B59B6',
        '#1ABC9C',
        '#E91E63'
    ];

    let hash = 0;
    for (let i = 0; i < normalized.length; i++) {
        hash = normalized.charCodeAt(i) + ((hash << 5) - hash);
    }

    return colors[Math.abs(hash) % colors.length];
};

// Generates initials from the username
export const getAvatarInitials = (username: string): string => {
    if (!username) return '?';

    const isHash = /^[a-f0-9]{32,}$/i.test(username);

    if (isHash) {
        return username.slice(0, 2).toUpperCase();
    }

    const clean = username.replace(/[^a-zA-Z0-9]/g, '');
    if (!clean) return username.charAt(0).toUpperCase();

    return clean.slice(0, 2).toUpperCase();
};

// Truncates long hexadecimal usernames (32+ characters) to first 8 characters
export function truncateUsername(username: string): string {
  if (typeof username !== 'string' || username.length === 0) return '';
  return username.length > 32 ? `${username.slice(0, 8)}...` : username;
}

// Generates a deterministic default avatar SVG for a username
export function generateDefaultAvatar(username: string): string {
  const normalized = (username || '').toLowerCase().trim();
  const colors = [
    '#5865F2', '#57F287', '#FEE75C', '#EB459E', '#ED4245',
    '#3BA55C', '#FAA61A', '#9B59B6', '#1ABC9C', '#E91E63'
  ];
  let hash = 0;
  for (let i = 0; i < normalized.length; i++) {
    hash = normalized.charCodeAt(i) + ((hash << 5) - hash);
  }
  const color = colors[Math.abs(hash) % colors.length];

  let initials = '?';
  const isHash = /^[a-f0-9]{32,}$/i.test(username);
  if (isHash) {
    initials = username.slice(0, 2).toUpperCase();
  } else {
    const clean = username.replace(/[^a-zA-Z0-9]/g, '');
    initials = (clean || username).slice(0, 2).toUpperCase();
  }

  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">
      <rect width="512" height="512" fill="${color}"/>
      <text x="50%" y="50%" font-family="Arial, sans-serif" font-weight="bold" font-size="256" fill="#FFFFFF" text-anchor="middle" dy=".35em">${initials}</text>
    </svg>`;

  return `data:image/svg+xml;base64,${btoa(svg)}`;
}