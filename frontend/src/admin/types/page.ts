import type { createAdminClient } from "../../shared/api/adminApi";

export type AdminClient = ReturnType<typeof createAdminClient>;

export interface AdminPageProps {
  client: AdminClient;
  isActive: boolean;
}
