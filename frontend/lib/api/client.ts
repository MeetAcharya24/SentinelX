export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"
).replace(/\/+$/, "");

export type ApiErrorDetail = { field: string; message: string };

export class ApiError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number | null = null,
    readonly details: ApiErrorDetail[] | null = null,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type Envelope<T> =
  | { success: true; data: T; error: null }
  | {
      success: false;
      data: null;
      error: { code: string; message: string; details: ApiErrorDetail[] | null };
    };

function isEnvelope(value: unknown): value is Envelope<unknown> {
  if (typeof value !== "object" || value === null) return false;
  const { success, error } = value as { success?: unknown; error?: unknown };
  if (success === true) return true;
  if (success !== false || typeof error !== "object" || error === null) return false;
  const { code, message } = error as { code?: unknown; message?: unknown };
  return typeof code === "string" && typeof message === "string";
}

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  return new ApiError("unknown_error", "Something went wrong.");
}

async function request<T>(path: string, init: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: { Accept: "application/json", ...init.headers },
    });
  } catch (error) {
    if (init.signal?.aborted) throw error;
    throw new ApiError(
      "network_error",
      "Cannot reach the SentinelX API. Check that the backend is running.",
    );
  }

  const body: unknown = await response.json().catch(() => null);
  if (!isEnvelope(body)) {
    throw new ApiError(
      "invalid_response",
      "The API returned an unexpected response.",
      response.status,
    );
  }
  if (!body.success) {
    const { code, message, details } = body.error;
    throw new ApiError(code, message, response.status, details);
  }
  return body.data as T;
}

/** GETs a backend path and unwraps the response envelope, or throws `ApiError`. */
export function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  return request<T>(path, { signal });
}

/** PATCHes JSON to a backend path and unwraps the envelope. */
export function apiPatch<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** POSTs a raw body (for example a CSV file) and unwraps the envelope. */
export function apiPostRaw<T>(path: string, body: BodyInit, contentType: string): Promise<T> {
  return request<T>(path, { method: "POST", headers: { "Content-Type": contentType }, body });
}
