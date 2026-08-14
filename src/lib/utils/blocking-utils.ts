// Validate username format
export const validateUsername = (username: string): void => {
  if (typeof username !== 'string' || username.length < 3 || username.length > 128) {
    throw new Error('Invalid username');
  }

  if (/[\x00-\x1F\x7F]/.test(username)) {
    throw new Error('Username contains invalid control characters');
  }

  const isPseudonym = /^[a-f0-9]{32,}$/i.test(username);

  if (isPseudonym) {
    if (username.length > 128) {
      throw new Error('Invalid pseudonymized username length');
    }
    return;
  }

  if (!/^(?!__)[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])$/.test(username)) {
    throw new Error('Username contains invalid characters');
  }
  if (['__proto__', 'constructor', 'prototype'].includes(username)) {
    throw new Error('Username contains reserved identifier');
  }
};
