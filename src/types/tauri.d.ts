/**
 * Tauri Type Definitions
 */

// Re-export types from tauri-bindings
export * from '../lib/tauri-bindings';

// Extend Window interface for Tauri global access
declare global {
    interface Window {
        __TAURI__?: {
            core: {
                invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
            };
            event: {
                listen: (event: string, callback: (evt: { payload: unknown }) => void) => Promise<() => void>;
                emit: (event: string, payload?: unknown) => Promise<void>;
            };
        };
    }
}

export { };
