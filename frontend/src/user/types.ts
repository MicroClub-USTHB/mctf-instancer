export interface UserProfile {
  username: string;
}

export interface TeamMember {
  name: string;
  is_current?: boolean;
}

export interface UserMeResponse {
  user: UserProfile;
  instances: number;
  max_instances: number;
  team_mode: boolean;
}

export interface TeamResponse {
  team_mode: boolean;
  team_name?: string;
  members?: TeamMember[];
  message?: string;
}

export interface ChallengeInfo {
  id: string;
  name: string;
  category: string;
  routing_type?: string;
  tls_enabled?: boolean | null;
  description?: string | null;
}

export interface ChallengeListResponse {
  challenges: ChallengeInfo[];
}

export interface InstanceInfo {
  instance_id: string;
  challenge_id: string;
  username?: string | null;
  team_name?: string | null;
  routing_type?: string | null;
  connection_hint?: string | null;
  status: string;
  created_at?: string;
  expires_at?: string;
  public_url?: string | null;
  public_urls?: string[];
}

export interface InstanceListResponse {
  instances: InstanceInfo[];
}

export interface SpawnResponse {
  success: boolean;
  message: string;
  instance?: InstanceInfo;
}

export interface HealthResponse {
  status: string;
  active_instances: number;
}

export interface PublicConfig {
  team_mode: boolean;
  max_instances_per_user: number;
  max_instances_per_team: number;
  instance_timeout: number;
  auth_mode: string;
  ctfd_url?: string | null;
}
