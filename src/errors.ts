import type { ApiErrorBody, ApiErrorEnvelope, FoilFieldError } from './types.js';

export class FoilConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FoilConfigurationError';
  }
}

export class FoilTokenVerificationError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = 'FoilTokenVerificationError';
    if (options?.cause !== undefined) {
      (this as Error & { cause?: unknown }).cause = options.cause;
    }
  }
}

export class FoilApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly request_id: string | null;
  readonly field_errors: FoilFieldError[];
  readonly docs_url: string | null;
  readonly body: ApiErrorBody | ApiErrorEnvelope | unknown;

  constructor(options: {
    status: number;
    code: string;
    message: string;
    request_id?: string | null;
    field_errors?: FoilFieldError[];
    docs_url?: string | null;
    body?: ApiErrorBody | ApiErrorEnvelope | unknown;
  }) {
    super(options.message);
    this.name = 'FoilApiError';
    this.status = options.status;
    this.code = options.code;
    this.request_id = options.request_id ?? null;
    this.field_errors = options.field_errors ?? [];
    this.docs_url = options.docs_url ?? null;
    this.body = options.body;
  }
}
