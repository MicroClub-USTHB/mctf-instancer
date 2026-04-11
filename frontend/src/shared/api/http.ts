import type { ApiRecord } from "../types/common";

function isRecord(value: unknown): value is ApiRecord {
  return typeof value === "object" && value !== null;
}

export class HttpError extends Error {
  status: number;
  payload: unknown;

  constructor(status: number, message: string, payload: unknown) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.payload = payload;
  }
}

async function parseResponseBody(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    try {
      return await response.json();
    } catch {
      return {};
    }
  }

  try {
    const text = await response.text();
    return text ? { detail: text } : {};
  } catch {
    return {};
  }
}

function getErrorMessage(status: number, payload: unknown): string {
  if (isRecord(payload) && typeof payload.detail === "string" && payload.detail.trim()) {
    return payload.detail;
  }

  if (isRecord(payload) && typeof payload.message === "string" && payload.message.trim()) {
    return payload.message;
  }

  return `Request failed (${status})`;
}

export async function requestJson<T>(url: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(url, {
    ...init,
    credentials: "same-origin",
  });

  const payload = await parseResponseBody(response);

  if (!response.ok) {
    throw new HttpError(response.status, getErrorMessage(response.status, payload), payload);
  }

  return payload as T;
}

export function jsonRequestInit(method: string, body?: unknown, init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers || {});

  if (!headers.has("Content-Type") && body !== undefined) {
    headers.set("Content-Type", "application/json");
  }

  return {
    ...init,
    method,
    headers,
    body: body === undefined ? init.body : JSON.stringify(body),
  };
}
