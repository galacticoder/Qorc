export interface PseudonymizationConfig {
  cacheSize?: number;
  cacheTTL?: number;
  defaultMemoryCost?: number;
  maxUsernameLength?: number;
  slowOperationThreshold?: number;
  enableAuditLogging?: boolean;
}

export interface UsernameDisplayConfig {
  cacheSize?: number;
  cacheTTL?: number;
  maxUsernameLength?: number;
  concurrentResolutionLimit?: number;
  hashPreviewLength?: number;
}

export type UsernameResolutionOperation =
  | 'resolve-single'
  | 'batch-resolve'
  | 'resolver-cache'
  | 'context-resolve'
  | 'context-batch'
  | 'validate-resolver'
  | 'ensure-mapping';

export const DEFAULT_USERNAME_DISPLAY_CONFIG: Required<UsernameDisplayConfig> = {
  cacheSize: 1000,
  cacheTTL: 30 * 60 * 1000,
  maxUsernameLength: 50,
  concurrentResolutionLimit: 10,
  hashPreviewLength: 16
};

export const DEFAULT_PSEUDONYMIZATION_CONFIG: Required<PseudonymizationConfig> = {
  cacheSize: 10000,
  cacheTTL: 24 * 60 * 60 * 1000,
  defaultMemoryCost: 1 << 16,
  maxUsernameLength: 100,
  slowOperationThreshold: 5000,
  enableAuditLogging: true
};