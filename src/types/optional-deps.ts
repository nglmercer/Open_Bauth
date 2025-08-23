// src/types/optional-deps.ts
// Type declarations for optional dependencies

// Express types - only used if express adapter is imported
export interface ExpressRequest {
  headers: Record<string, string | string[] | undefined>;
  path: string;
  method: string;
  body?: any;
  query?: any;
  params?: any;
  auth?: any;
}

export interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(data: any): ExpressResponse;
  send(data: any): ExpressResponse;
  setHeader(name: string, value: string): ExpressResponse;
  end(): void;
}

export interface ExpressNextFunction {
  (error?: any): void;
}

// WebSocket types - only used if websocket adapter is imported
export interface WSWebSocket {
  send(data: string | Buffer): void;
  close(code?: number, reason?: string): void;
  on(event: string, listener: (...args: any[]) => void): void;
  off(event: string, listener: (...args: any[]) => void): void;
  readyState: number;
  CONNECTING: number;
  OPEN: number;
  CLOSING: number;
  CLOSED: number;
}

// Conditional type helpers
export type ConditionalExpress<T> = T extends { express: true } ? {
  Request: ExpressRequest;
  Response: ExpressResponse;
  NextFunction: ExpressNextFunction;
} : never;

export type ConditionalWebSocket<T> = T extends { websocket: true } ? {
  WebSocket: WSWebSocket;
} : never;