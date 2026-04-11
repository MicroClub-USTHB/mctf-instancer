export interface AdminStats {
  active_instances?: number;
  challenges_loaded?: number;
  ports_allocated?: number;
  unique_users?: number;
  last_24h_events?: number;
  event_counts?: Record<string, number>;
  [key: string]: unknown;
}

export interface AdminInstance {
  instance_id: string;
  challenge_id: string;
  status: string;
  user_id: string;
  username?: string | null;
  team_id?: string | null;
  team_name?: string | null;
  public_url?: string | null;
  ports: Record<string, number>;
  routing_type?: string | null;
  created_at?: string;
  expires_at?: string;
  error_message?: string | null;
}

export interface AdminLogEntry {
  timestamp: string;
  event_type: string;
  username?: string | null;
  user_id?: string | null;
  challenge_id?: string | null;
  instance_id?: string | null;
  ports?: Record<string, number>;
  public_url?: string | null;
  ip_address?: string | null;
  message?: string | null;
}

export interface AdminLogsResponse {
  logs: AdminLogEntry[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface UserPortRow {
  user_id: string;
  username: string;
  challenge_id: string;
  ports: Record<string, number>;
}

export interface UserPortsResponse {
  user_ports: Record<string, Record<string, unknown>>;
  mappings: UserPortRow[];
  total_users: number;
  total_mappings: number;
}

export interface ForensicsStats {
  auto_capture_enabled: boolean;
  total_logs: number;
  auto_capture_count: number;
  live_capture_count: number;
  total_size_mb: number;
  retention_hours?: number;
}

export interface ForensicsLog {
  log_id: string;
  instance_id: string;
  challenge_id: string;
  challenge_name: string;
  owner_id: string;
  owner_name: string;
  spawned_by: string;
  capture_type: "auto" | "live";
  capture_time: string;
  terminate_reason: string;
  file_size_bytes: number;
  compressed: boolean;
  container_count: number;
  container_names: string[];
  team_id?: string | null;
  team_name?: string | null;
}

export interface SuspiciousSubmission {
  submission_id?: number;
  submitter_user_id?: number;
  submitter_username: string;
  submitter_team_id?: string;
  submitter_team_name?: string;
  flag_owner_user_id?: string;
  flag_owner_username: string;
  flag_owner_team_id?: string;
  flag_owner_team_name?: string;
  challenge_id?: number;
  local_challenge_id: string;
  provided_flag?: string;
  submission_time: string;
  ip_address: string;
}

export interface FlagMapping {
  flag_id: number;
  ctfd_challenge_id?: number;
  local_challenge_id: string;
  user_id: string;
  username: string;
  team_id?: string;
  team_name?: string;
  flag_content: string;
  created_at: string;
  instance_id?: string;
}

export interface FlagsData {
  dynamic_flags_enabled: boolean;
  ctfd_configured: boolean;
  total_flags: number;
  total_users: number;
  suspicious_submissions: SuspiciousSubmission[];
  suspicious_total?: number;
  last_submission_id?: number;
  flag_mappings: FlagMapping[];
  challenge_mapping: Record<string, number>;
}

export interface CtfdChallenge {
  id: number;
  name: string;
  category: string;
  value: number;
  type: string;
  mapped_local_id?: string | null;
  suggested_local_id?: string | null;
  name_match_score?: number;
}

export interface CtfdChallengesResponse {
  success: boolean;
  challenges: CtfdChallenge[];
  categories: string[];
  total: number;
}

export interface ChallengeItem {
  id: string;
  folder: string;
  path: string;
  has_config: boolean;
  has_compose: boolean;
  loaded: boolean;
  is_active: boolean;
  disable_dynamic_flags: boolean;
}

export interface ChallengeSettingsItem {
  is_active?: boolean;
  max_memory?: string | null;
  max_cpu?: string | null;
}

export interface ChallengeSettingsResponse {
  settings: Record<string, ChallengeSettingsItem>;
}

export interface ChallengeFileNode {
  name: string;
  path: string;
  type: "directory" | "file";
  size?: number;
  editable?: boolean;
  children?: ChallengeFileNode[];
}

export interface ChallengeFilesResponse {
  challenge_id: string;
  files: ChallengeFileNode[];
}

export interface MonitoringSystem {
  total_containers: number;
  running_containers: number;
  total_cpu_percent: number;
  total_memory_mb: number;
  host_cpu_cores: number;
  host_memory_total_mb: number;
  host_memory_used_mb: number;
  host_memory_percent: number;
  timestamp: string;
}

export interface MonitoringContainer {
  container_id: string;
  container_name: string;
  cpu_percent: number;
  memory_usage_mb: number;
  memory_limit_mb: number;
  memory_percent: number;
  pids: number;
}

export interface MonitoringInstance {
  instance_id: string;
  challenge_id: string;
  challenge_name: string;
  owner_id: string;
  owner_name: string;
  container_count: number;
  total_cpu_percent: number;
  total_memory_mb: number;
  containers: MonitoringContainer[];
  timestamp: string;
}

export interface MonitoringInstancesResponse {
  instances: MonitoringInstance[];
  total_instances: number;
}

export interface SettingMeta {
  value: unknown;
  db_override?: string | null;
  has_override: boolean;
  type: "int" | "float" | "bool" | "str" | "select";
  options?: string[];
  min?: number;
  max?: number;
  label: string;
}

export interface SettingsResponse {
  settings: Record<string, SettingMeta>;
}
