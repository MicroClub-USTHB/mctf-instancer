import { useCallback, useEffect, useMemo, useState } from "react";
import { Badge } from "../../shared/components/ui/Badge";
import { Button } from "../../shared/components/ui/Button";
import { Card } from "../../shared/components/ui/Card";
import { Input } from "../../shared/components/ui/Input";
import { Loader } from "../../shared/components/ui/Loader";
import { Pagination } from "../../shared/components/ui/Pagination";
import { Select } from "../../shared/components/ui/Select";
import { Table, type Column } from "../../shared/components/ui/Table";
import { useConfirm } from "../../shared/hooks/useConfirm";
import { useToast } from "../../shared/hooks/useToast";
import { useWebSocket } from "../../shared/hooks/useWebSocket";
import type { AdminInstance, AdminStats, ChallengeItem } from "../types";
import type { AdminPageProps } from "../types/page";
import { formatDateTime, formatRelativeRemaining } from "../../shared/utils/time";
import { safeString } from "../../shared/utils/format";

const INSTANCES_PER_PAGE = 15;

interface DashboardPageProps extends AdminPageProps {}

export function DashboardPage({ client, isActive }: DashboardPageProps) {
  const { pushToast } = useToast();
  const { confirm } = useConfirm();

  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [portStats, setPortStats] = useState<Record<string, unknown>>({});
  const [config, setConfig] = useState<{ team_mode?: boolean }>({});
  const [instances, setInstances] = useState<AdminInstance[]>([]);
  const [challenges, setChallenges] = useState<ChallengeItem[]>([]);

  const [testChallengeId, setTestChallengeId] = useState("");
  const [testUserId, setTestUserId] = useState("");
  const [testSpawning, setTestSpawning] = useState(false);

  const [instancePage, setInstancePage] = useState(1);
  const [instanceChallengeFilter, setInstanceChallengeFilter] = useState("");
  const [instanceUserFilter, setInstanceUserFilter] = useState("");
  const [instanceStatusFilter, setInstanceStatusFilter] = useState("");

  const load = useCallback(async () => {
    if (!isActive) return;
    setLoading(true);
    try {
      const [statsData, portStatsData, instancesData, challengeList] = await Promise.all([
        client.getStats(),
        client.getPortStats(),
        client.getInstances(),
        client.getChallenges(),
      ]);
      setStats(statsData);
      setPortStats(portStatsData);
      setInstances(instancesData);
      setChallenges(challengeList || []);
      try {
        const publicConfig = await fetch("/config").then((r) => r.json());
        setConfig(publicConfig || {});
      } catch {
        setConfig({});
      }
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to load dashboard", "error");
    } finally {
      setLoading(false);
    }
  }, [client, isActive, pushToast]);

  useEffect(() => {
    if (!isActive) return;
    void load();
  }, [isActive, load]);

  // ── WebSocket real-time updates ──────────────────────────────────────

  const adminKey = useMemo(() => localStorage.getItem("admin_key") || "", []);
  const wsUrl = useMemo(() => {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${window.location.host}/ws/admin?admin_key=${encodeURIComponent(adminKey)}`;
  }, [adminKey]);

  const [wsConnected, setWsConnected] = useState(false);
  const { onEvent } = useWebSocket({ url: wsUrl, enabled: isActive && !!adminKey });

  useEffect(() => {
    onEvent((event, data) => {
      const payload = data as AdminInstance | { instance_id: string };
      switch (event) {
        case "instance_spawned": {
          const inst = data as AdminInstance;
          setInstances((prev) => {
            const exists = prev.some((i) => i.instance_id === inst.instance_id);
            if (exists) return prev.map((i) => i.instance_id === inst.instance_id ? inst : i);
            return [inst, ...prev];
          });
          setStats((prev) => prev ? { ...prev, active_instances: (prev.active_instances || 0) + 1 } : prev);
          break;
        }
        case "instance_stopped": {
          const { instance_id } = data as { instance_id: string };
          setInstances((prev) => prev.filter((i) => i.instance_id !== instance_id));
          setStats((prev) => prev ? { ...prev, active_instances: Math.max(0, (prev.active_instances || 0) - 1) } : prev);
          break;
        }
        case "instance_extended": {
          const inst = data as AdminInstance;
          setInstances((prev) => prev.map((i) => i.instance_id === inst.instance_id ? { ...i, expires_at: inst.expires_at } : i));
          break;
        }
        case "challenges_updated": {
          void client.getChallenges().then((list) => setChallenges(list || []));
          break;
        }
      }
      setWsConnected(true);
    });

    return () => setWsConnected(false);
  }, [onEvent, client]);

  // ── Live countdown tick ─────────────────────────────────────────────

  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const totalSpawns = stats?.event_counts?.instance_spawn || 0;
  const activeInstances = stats?.active_instances || 0;
  const uniqueUsers = Number(stats?.unique_users || 0);
  const last24hEvents = Number(stats?.last_24h_events || 0);
  const portsUsed = Number(portStats.currently_allocated || 0);
  const portsAvailable = Number(portStats.available || 0);
  const modeLabel = useMemo(() => (config.team_mode ? "Team mode" : "User mode"), [config.team_mode]);

  // ── Filtered instances ─────────────────────────────────────────────

  const filteredInstances = useMemo(() => {
    return instances
      .filter((i) => {
        if (instanceChallengeFilter && !i.challenge_id.toLowerCase().includes(instanceChallengeFilter.toLowerCase())) return false;
        if (instanceStatusFilter && i.status !== instanceStatusFilter) return false;
        if (instanceUserFilter) {
          const q = instanceUserFilter.toLowerCase();
          const userMatch = (i.username || "").toLowerCase().includes(q) || i.user_id.toLowerCase().includes(q);
          const teamMatch = (i.team_name || "").toLowerCase().includes(q) || (i.team_id || "").toLowerCase().includes(q);
          if (!userMatch && !teamMatch) return false;
        }
        return true;
      })
      .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());
  }, [instances, instanceChallengeFilter, instanceStatusFilter, instanceUserFilter]);

  const instancePageCount = Math.max(1, Math.ceil(filteredInstances.length / INSTANCES_PER_PAGE));
  const pageInstances = useMemo(() => {
    const start = (instancePage - 1) * INSTANCES_PER_PAGE;
    return filteredInstances.slice(start, start + INSTANCES_PER_PAGE);
  }, [filteredInstances, instancePage]);

  // ── Actions ─────────────────────────────────────────────────────────

  async function forceStop(instanceId: string) {
    const approved = await confirm({
      title: "Force stop this instance?",
      message: `Instance ${instanceId} will be terminated immediately.`,
      confirmText: "Force stop",
      danger: true,
    });
    if (!approved) return;
    try {
      const response = await client.forceStopInstance(instanceId);
      pushToast(response.message || "Instance stopped", "success");
      await load();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to stop instance", "error");
    }
  }

  function copyUrl(url: string | null | undefined) {
    if (!url) return;
    void navigator.clipboard.writeText(url);
    pushToast("URL copied", "success");
  }

  async function testSpawn() {
    const challengeId = testChallengeId.trim();
    const rawId = testUserId.trim();

    if (!challengeId) { pushToast("Select a challenge first", "warning"); return; }
    if (!rawId) { pushToast("Enter a CTFd user ID", "warning"); return; }

    const userId = Number(rawId);
    if (!Number.isInteger(userId) || userId < 1) { pushToast("User ID must be a positive integer", "warning"); return; }

    let userName = `#${userId}`;
    try {
      const resolved = await client.resolveCtfdUser(userId);
      userName = resolved.user.name;
    } catch {
      pushToast(`CTFd user #${userId} not found`, "error");
      return;
    }

    const challengeName = challenges.find((c) => c.id === challengeId)?.id || challengeId;
    const approved = await confirm({
      title: "Test spawn instance?",
      message: `Spawn "${challengeName}" for CTFd user "${userName}" (ID ${userId})?`,
      confirmText: "Spawn",
    });
    if (!approved) return;

    setTestSpawning(true);
    try {
      const result = await client.testSpawnInstance(challengeId, userId);
      pushToast(`Instance ${result.instance.instance_id} spawned for ${userName}`, "success");
      setTestUserId("");
      await load();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Test spawn failed", "error");
    } finally {
      setTestSpawning(false);
    }
  }

  const testableChallenges = useMemo(() => challenges.filter((c) => c.loaded), [challenges]);

  // ── Instance columns ────────────────────────────────────────────────

  const instanceColumns: Column<AdminInstance>[] = useMemo(() => [
    {
      key: "challenge",
      header: "Challenge",
      className: "min-w-[120px]",
      render: (i) => (
        <div>
          <p className="font-semibold text-slate-100">{i.challenge_id}</p>
          {i.routing_type ? <p className="font-mono text-[10px] text-slate-400">{i.routing_type}</p> : null}
        </div>
      ),
    },
    {
      key: "owner",
      header: "Owner",
      className: "min-w-[130px]",
      render: (i) => (
        <div>
          <p className="text-slate-200">{safeString(i.username || i.user_id)}</p>
          {i.team_name ? <p className="text-[11px] text-violet-300/80">{i.team_name}</p> : null}
          {i.user_id !== (i.username || i.user_id) ? (
            <p className="font-mono text-[10px] text-slate-500">ID {i.user_id}</p>
          ) : null}
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      className: "w-[90px]",
      render: (i) => (
        <Badge
          tone={i.status === "running" ? "success" : i.status === "error" ? "danger" : "warning"}
        >
          {i.status}
        </Badge>
      ),
    },
    {
      key: "url",
      header: "Endpoint",
      className: "max-w-[240px]",
      render: (i) => {
        if (!i.public_url) return <span className="text-slate-500">—</span>;
        return (
          <button
            type="button"
            className="max-w-full text-left font-mono text-[11px] text-violet-200/80 hover:text-violet-100 truncate block transition-colors"
            title={i.public_url}
            onClick={() => copyUrl(i.public_url)}
          >
            {i.public_url}
          </button>
        );
      },
    },
    {
      key: "ports",
      header: "Ports",
      className: "w-[120px]",
      render: (i) => (
        <span className="font-mono text-[11px] whitespace-nowrap">
          {Object.entries(i.ports || {}).map(([k, v]) => `${k}→${v}`).join(", ") || "—"}
        </span>
      ),
    },
    {
      key: "expires",
      header: "Expires",
      className: "w-[120px]",
      render: (i) => (
        <span className="font-mono text-[11px] whitespace-nowrap">
          {formatRelativeRemaining(i.expires_at, now)}
        </span>
      ),
    },
    {
      key: "created",
      header: "Created",
      className: "w-[150px] hidden xl:table-cell",
      render: (i) => (
        <span className="font-mono text-[11px] text-slate-400 whitespace-nowrap">
          {formatDateTime(i.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      className: "w-[100px]",
      render: (i) => (
        <Button variant="danger" size="sm" onClick={() => void forceStop(i.instance_id)}>
          Stop
        </Button>
      ),
    },
  ], [now]);

  // ── Render ──────────────────────────────────────────────────────────

  const statCards = [
    { label: "Total spawns", value: String(totalSpawns) },
    { label: "Active instances", value: String(activeInstances) },
    { label: "Unique users", value: String(uniqueUsers) },
    { label: "Events (24h)", value: String(last24hEvents) },
    { label: "Ports in use", value: `${portsUsed} / ${portsAvailable}` },
    { label: "Mode", value: modeLabel },
    { label: "Challenges loaded", value: String(stats?.challenges_loaded || 0) },
  ];

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="text-xs uppercase tracking-[0.15em] text-slate-400">Overview</p>
            <h3 className="mt-1 text-xl text-slate-100">Runtime statistics</h3>
          </div>
          <div className="flex items-center gap-2">
            <Badge tone={wsConnected ? "success" : "neutral"}>
              {wsConnected ? "Live" : "Polling"}
            </Badge>
            <Button variant="secondary" size="sm" onClick={() => void load()}>Refresh</Button>
          </div>
        </div>

        {loading ? <Loader label="Loading dashboard metrics..." /> : null}

        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {statCards.map(({ label, value }) => (
            <div key={label} className="rounded-xl border border-white/10 bg-black/25 p-3 hover:border-violet-300/20 transition-colors">
              <p className="text-[11px] uppercase tracking-[0.14em] text-slate-400">{label}</p>
              <p className="mt-1 text-lg text-slate-100 font-semibold">{value}</p>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="text-xs uppercase tracking-[0.15em] text-slate-400">Test spawn</p>
            <h3 className="mt-1 text-xl text-slate-100">
              Spawn a challenge for a CTFd user (bypasses active/inactive gate)
            </h3>
          </div>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <Select label="Challenge" value={testChallengeId} onChange={(event) => setTestChallengeId(event.target.value)}>
            <option value="">Select challenge</option>
            {testableChallenges.map((c) => (
              <option key={c.id} value={c.id}>{c.id}{c.is_active ? "" : " (inactive)"}</option>
            ))}
          </Select>
          <Input
            label="CTFd user ID"
            type="number"
            placeholder="e.g. 1"
            min={1} step={1}
            value={testUserId}
            onChange={(event) => setTestUserId(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Enter") void testSpawn(); }}
          />
          <div className="flex items-end">
            <Button variant="primary" className="w-full" disabled={testSpawning || !testChallengeId || !testUserId.trim()} onClick={() => void testSpawn()}>
              {testSpawning ? "Spawning..." : "Spawn test instance"}
            </Button>
          </div>
        </div>
        <p className="mt-2 text-xs text-slate-400">
          Enter a CTFd user ID. You will be asked to confirm before the instance is created.
        </p>
      </Card>

      <Card>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="text-xs uppercase tracking-[0.15em] text-slate-400">Active instances</p>
            <h3 className="mt-1 text-xl text-slate-100">Running instances with full detail</h3>
          </div>
          <Badge tone={instances.length > 0 ? "info" : "neutral"}>{instances.length} total</Badge>
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          <Input
            label="Filter by challenge"
            placeholder="challenge id..."
            value={instanceChallengeFilter}
            onChange={(event) => { setInstanceChallengeFilter(event.target.value); setInstancePage(1); }}
          />
          <Input
            label="Filter by user / team"
            placeholder="username, team..."
            value={instanceUserFilter}
            onChange={(event) => { setInstanceUserFilter(event.target.value); setInstancePage(1); }}
          />
          <Select
            label="Status"
            value={instanceStatusFilter}
            onChange={(event) => { setInstanceStatusFilter(event.target.value); setInstancePage(1); }}
          >
            <option value="">All statuses</option>
            <option value="running">Running</option>
            <option value="starting">Starting</option>
            <option value="error">Error</option>
          </Select>
        </div>

        <div className="mt-3">
          <Table
            columns={instanceColumns}
            data={pageInstances}
            keyExtractor={(i) => i.instance_id}
            loading={loading}
            emptyTitle="No active instances"
            emptyHint={
              filteredInstances.length === 0 && instances.length > 0
                ? "Try adjusting filters."
                : "All challenge containers are currently stopped."
            }
            rowClassName={(i) => i.status === "error" ? "bg-rose-500/6 hover:bg-rose-500/12" : ""}
          />
          <Pagination
            page={instancePage}
            pageCount={instancePageCount}
            total={filteredInstances.length}
            onPageChange={setInstancePage}
          />
        </div>
      </Card>
    </div>
  );
}
