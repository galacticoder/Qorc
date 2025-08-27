declare module 'tor-request' {
  interface TorRequestOptions {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    json?: boolean;
    timeout?: number;
    torControlPort?: number;
    torHost?: string;
    torPort?: number;
  }

  interface TorRequestCallback {
    (error: Error | null, response?: any, body?: string): void;
  }

  interface TorRequest {
    (options: TorRequestOptions | string, callback: TorRequestCallback): void;
    get(url: string, callback: TorRequestCallback): void;
    post(options: TorRequestOptions, callback: TorRequestCallback): void;
    setTorAddress(host: string, port: number): void;
    newTorSession(callback: (error: Error | null) => void): void;
  }

  const torRequest: TorRequest;
  export = torRequest;
}
