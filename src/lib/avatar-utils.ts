/**
 * Utility functions for generating standardized default avatars and colors.
 */

/**
 * Generates a deterministic color based on the username.
 */
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

/**
 * Generates  initials from the username.
 */
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
