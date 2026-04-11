import { jsonRequestInit, requestJson } from "./http";
import { encodePathSegments } from "../utils/format";
import type {
  AdminInstance,
  AdminLogsResponse,
  AdminStats,
  ChallengeFilesResponse,
  ChallengeItem,
  ChallengeSettingsResponse,
  CtfdChallengesResponse,
  FlagsData,
  ForensicsLog,
  ForensicsStats,
  MonitoringInstancesResponse,
  MonitoringSystem,
  SettingsResponse,
  UserPortsResponse,
} from "../../admin/types";

function toQuery(params: Record<string, string | number | boolean | undefined>): string {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== "") {
      query.set(key, String(value));
    }
  });
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

export function createAdminClient(getAdminKey: () => string) {
  async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers || {});
    headers.set("X-Admin-Key", getAdminKey());

    return requestJson<T>(path, {
      ...init,
      headers,
    });
  }

  return {
    request,

    getStats: () => request<AdminStats>("/admin/api/stats"),
    getPortStats: () => request<Record<string, unknown>>("/admin/api/port-stats"),
    getInstances: async () => {
      const payload = await request<{ instances: AdminInstance[] }>("/admin/api/instances");
      return payload.instances || [];
    },
    forceStopInstance: (instanceId: string) =>
      request<{ success: boolean; message: string }>(`/admin/api/instances/${encodeURIComponent(instanceId)}`, {
        method: "DELETE",
      }),

    testSpawnInstance: (challengeId: string, userId: number) =>
      request<{ success: boolean; message: string; instance: AdminInstance }>(
        "/admin/api/instances/spawn",
        jsonRequestInit("POST", { challenge_id: challengeId, user_id: userId }),
      ),

    resolveCtfdUser: (userId: number) =>
      request<{ success: boolean; user: { id: number; name: string; team_id?: string | null; team_name?: string | null } }>(
        `/admin/api/ctfd/users/${userId}`,
      ),

    getLogs: (params: { limit: number; offset: number; event_type?: string; username?: string }) =>
      request<AdminLogsResponse>(`/admin/api/logs${toQuery(params)}`),

    getUserPorts: () => request<UserPortsResponse>("/admin/api/user-ports"),
    clearAllUserPorts: () => request<{ success: boolean; message: string }>("/admin/api/user-ports", { method: "DELETE" }),
    deleteUserPorts: (userId: string, challengeId: string) =>
      request<{ success: boolean; message: string }>(
        `/admin/api/user-ports/${encodeURIComponent(userId)}${toQuery({ challenge_id: challengeId })}`,
        { method: "DELETE" },
      ),

    getFlagsData: () => request<FlagsData>("/admin/api/flags"),
    checkSubmissions: () => request<{ success: boolean; new_suspicious_count: number }>("/admin/api/flags/check-submissions", { method: "POST" }),
    clearSuspicious: () => request<{ success: boolean; cleared: number }>("/admin/api/flags/suspicious", { method: "DELETE" }),
    deleteFlag: (flagId: number) => request<{ success: boolean; message: string }>(`/admin/api/flags/${flagId}`, { method: "DELETE" }),
    syncChallenge: (localChallengeId: string, ctfdChallengeId: number) =>
      request<{ success: boolean; message: string }>(
        `/admin/api/flags/sync-challenge${toQuery({ local_challenge_id: localChallengeId, ctfd_challenge_id: ctfdChallengeId })}`,
        { method: "POST" },
      ),
    removeChallengeMapping: (localChallengeId: string) =>
      request<{ success: boolean; message: string }>(`/admin/api/flags/mapping/${encodePathSegments(localChallengeId)}`, { method: "DELETE" }),
    getCtfdChallenges: () => request<CtfdChallengesResponse>("/admin/api/ctfd/challenges"),

    getForensicsStats: () => request<ForensicsStats>("/admin/api/forensics/stats"),
    getForensicsLogs: async (limit = 200) => {
      const payload = await request<{ logs: ForensicsLog[] }>(`/admin/api/forensics/logs${toQuery({ limit })}`);
      return payload.logs || [];
    },
    toggleForensics: (enabled: boolean) =>
      request<{ success: boolean; message: string }>(`/admin/api/forensics/toggle${toQuery({ enabled })}`, {
        method: "POST",
      }),
    liveCapture: (instanceId: string) =>
      request<{ success: boolean; message: string }>(`/admin/api/forensics/live-capture/${encodeURIComponent(instanceId)}`, {
        method: "POST",
      }),
    getForensicsLogContent: (logId: string) => request<{ log_id: string; content: string }>(`/admin/api/forensics/logs/${encodeURIComponent(logId)}`),
    deleteForensicsLog: (logId: string) => request<{ success: boolean; message: string }>(`/admin/api/forensics/logs/${encodeURIComponent(logId)}`, { method: "DELETE" }),
    clearForensicsLogs: () => request<{ success: boolean; message: string }>("/admin/api/forensics/logs", { method: "DELETE" }),

    getChallenges: async () => {
      const payload = await request<{ challenges: ChallengeItem[] }>("/admin/api/challenges/list");
      return payload.challenges || [];
    },
    getChallengeSettings: () => request<ChallengeSettingsResponse>("/admin/api/challenges/settings"),
    uploadChallenge: (file: File) => {
      const formData = new FormData();
      formData.append("file", file);
      return request<{ success: boolean; message: string; challenge_id?: string }>("/admin/api/challenges/upload", {
        method: "POST",
        body: formData,
      });
    },
    deleteChallenge: (challengeId: string) => request<{ success: boolean; message: string }>(`/admin/api/challenges/${encodeURIComponent(challengeId)}`, { method: "DELETE" }),
    reloadChallenge: (challengeId: string) => request<{ success: boolean; message: string }>(`/admin/api/challenges/${encodeURIComponent(challengeId)}/reload`, { method: "POST" }),
    toggleChallenge: (challengeId: string, isActive: boolean) =>
      request<{ success: boolean; message: string }>(
        `/admin/api/challenges/${encodeURIComponent(challengeId)}/toggle`,
        jsonRequestInit("POST", { is_active: isActive }),
      ),
    getChallengeFiles: (challengeId: string) =>
      request<ChallengeFilesResponse>(`/admin/api/challenges/${encodeURIComponent(challengeId)}/files`),
    readChallengeFile: (challengeId: string, filePath: string) =>
      request<{ path: string; content: string; size: number }>(
        `/admin/api/challenges/${encodeURIComponent(challengeId)}/files/${encodePathSegments(filePath)}`,
      ),
    writeChallengeFile: (challengeId: string, filePath: string, content: string) =>
      request<{ success: boolean; message: string }>(
        `/admin/api/challenges/${encodeURIComponent(challengeId)}/files/${encodePathSegments(filePath)}`,
        jsonRequestInit("PUT", { content }),
      ),
    deleteChallengeFile: (challengeId: string, filePath: string) =>
      request<{ success: boolean; message: string }>(
        `/admin/api/challenges/${encodeURIComponent(challengeId)}/files/${encodePathSegments(filePath)}`,
        { method: "DELETE" },
      ),

    getMonitoringSystem: () => request<MonitoringSystem>("/admin/api/monitoring/system"),
    getMonitoringInstances: () => request<MonitoringInstancesResponse>("/admin/api/monitoring/instances"),

    getSettings: () => request<SettingsResponse>("/admin/api/settings"),
    saveSettings: (settings: Record<string, unknown>) =>
      request<{ success: boolean; applied: Record<string, string>; errors: Record<string, string>; message: string }>(
        "/admin/api/settings",
        jsonRequestInit("PUT", { settings }),
      ),
    resetSetting: (key: string) => request<{ success: boolean; default_value?: string }>(`/admin/api/settings/${encodeURIComponent(key)}`, { method: "DELETE" }),
  };
}
