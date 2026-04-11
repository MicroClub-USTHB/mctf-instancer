import { HttpError, jsonRequestInit, requestJson } from "./http";
import type {
  ChallengeInfo,
  ChallengeListResponse,
  HealthResponse,
  InstanceInfo,
  InstanceListResponse,
  PublicConfig,
  SpawnResponse,
  TeamResponse,
  UserMeResponse,
} from "../../user/types";

const API_BASE = "";

function buildHeaders(token?: string): Headers {
  const headers = new Headers();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  return headers;
}

export interface ApiRootResponse {
  status: string;
  auth_mode: string;
}

export async function getApiRoot(): Promise<ApiRootResponse> {
  return requestJson<ApiRootResponse>(`${API_BASE}/api`);
}

export async function getHealth(token?: string): Promise<HealthResponse> {
  return requestJson<HealthResponse>(`${API_BASE}/health`, { headers: buildHeaders(token) });
}

export async function getConfig(): Promise<PublicConfig> {
  return requestJson<PublicConfig>(`${API_BASE}/config`);
}

export async function getMe(token?: string): Promise<UserMeResponse> {
  return requestJson<UserMeResponse>(`${API_BASE}/me`, { headers: buildHeaders(token) });
}

export async function getTeam(token?: string): Promise<TeamResponse> {
  return requestJson<TeamResponse>(`${API_BASE}/me/team`, { headers: buildHeaders(token) });
}

export async function getChallenges(token?: string): Promise<ChallengeInfo[]> {
  const payload = await requestJson<ChallengeListResponse>(`${API_BASE}/challenges`, { headers: buildHeaders(token) });
  return payload.challenges || [];
}

export async function getInstances(token?: string): Promise<InstanceInfo[]> {
  const payload = await requestJson<InstanceListResponse>(`${API_BASE}/instances`, { headers: buildHeaders(token) });
  return payload.instances || [];
}

export async function spawnInstance(challengeId: string, token?: string): Promise<SpawnResponse> {
  return requestJson<SpawnResponse>(
    `${API_BASE}/instances/spawn`,
    jsonRequestInit("POST", { challenge_id: challengeId }, { headers: buildHeaders(token) }),
  );
}

export async function stopInstance(instanceId: string, token?: string): Promise<{ success: boolean; message: string }> {
  return requestJson<{ success: boolean; message: string }>(
    `${API_BASE}/instances/${encodeURIComponent(instanceId)}`,
    {
      method: "DELETE",
      headers: buildHeaders(token),
    },
  );
}

export async function extendInstance(instanceId: string, token?: string): Promise<{ success: boolean; message: string; extended_seconds: number }> {
  return requestJson<{ success: boolean; message: string; extended_seconds: number }>(
    `${API_BASE}/instances/${encodeURIComponent(instanceId)}/extend`,
    {
      method: "POST",
      headers: buildHeaders(token),
    },
  );
}

export function getErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof HttpError && error.message) {
    return error.message;
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return fallback;
}

export function summarizeConnection(instance?: InstanceInfo): string {
  if (!instance) {
    return "Instance deployed";
  }

  if (instance.connection_hint) {
    return instance.connection_hint;
  }

  if (instance.public_urls && instance.public_urls.length > 0) {
    return instance.public_urls.join(", ");
  }

  if (instance.public_url) {
    return instance.public_url;
  }

  return "Instance deployed";
}
