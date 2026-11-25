import {
  CONTROL_CHARS_REGEX,
  HEX_PATTERN,
  BLOCKING_UTILS_USERNAME_LENGTH_MINIMUM,
  BLOCKING_UTILS_USERNAME_LENGTH_LIMIT,
} from '../constants';
// Validate username format
export const validateUsername = (username: string): void => {
  if (typeof username !== 'string' || username.length < BLOCKING_UTILS_USERNAME_LENGTH_MINIMUM || username.length > BLOCKING_UTILS_USERNAME_LENGTH_LIMIT) {
    throw new Error('Invalid username');
  }

  if (username.search(CONTROL_CHARS_REGEX) !== -1) {
    throw new Error('Username contains invalid control characters');
  }

  const isPseudonym = HEX_PATTERN.test(username);

  if (isPseudonym) {
    if (username.length > BLOCKING_UTILS_USERNAME_LENGTH_LIMIT) {
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
