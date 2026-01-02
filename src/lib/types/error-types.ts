export const ErrorType = {
  SIGNAL_BUNDLE_FAILURE: 'signal-bundle-failure',
} as const;

export type ErrorTypeValue = (typeof ErrorType)[keyof typeof ErrorType];
