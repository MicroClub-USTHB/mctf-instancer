import { useCallback, useEffect, useMemo, useState } from "react";
import { Badge } from "../../shared/components/ui/Badge";
import { Button } from "../../shared/components/ui/Button";
import { Card } from "../../shared/components/ui/Card";
import { EmptyState } from "../../shared/components/ui/EmptyState";
import { Input } from "../../shared/components/ui/Input";
import { Loader } from "../../shared/components/ui/Loader";
import { Modal } from "../../shared/components/ui/Modal";
import { Pagination } from "../../shared/components/ui/Pagination";
import { Select } from "../../shared/components/ui/Select";
import { Table, type Column } from "../../shared/components/ui/Table";
import { Tabs } from "../../shared/components/ui/Tabs";
import { useConfirm } from "../../shared/hooks/useConfirm";
import { useToast } from "../../shared/hooks/useToast";
import { downloadBlob } from "../../shared/utils/download";
import { formatBytes, safeString } from "../../shared/utils/format";
import { formatDateTime } from "../../shared/utils/time";
import type { AdminInstance, AdminLogEntry, ForensicsLog, ForensicsStats, UserPortRow } from "../types";
import type { AdminPageProps } from "../types/page";

type LogsTab = "events" | "ports" | "forensics";

const EVENTS_PER_PAGE_OPTIONS = [50, 100, 200, 500];
const FORENSICS_PAGE_SIZE = 10;

interface LogsPageProps extends AdminPageProps {}

export function LogsPage({ client, isActive }: LogsPageProps) {
  const { pushToast } = useToast();
  const { confirm } = useConfirm();

  const [activeTab, setActiveTab] = useState<LogsTab>("events");

  const [events, setEvents] = useState<AdminLogEntry[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventType, setEventType] = useState("");
  const [eventUsername, setEventUsername] = useState("");
  const [eventPage, setEventPage] = useState(0);
  const [eventLimit, setEventLimit] = useState(50);

  const [portsRows, setPortsRows] = useState<UserPortRow[]>([]);
  const [portsLoading, setPortsLoading] = useState(false);
  const [portsUserFilter, setPortsUserFilter] = useState("");
  const [portsChallengeFilter, setPortsChallengeFilter] = useState("");

  const [forensicsStats, setForensicsStats] = useState<ForensicsStats | null>(null);
  const [forensicsLogs, setForensicsLogs] = useState<ForensicsLog[]>([]);
  const [forensicsLoading, setForensicsLoading] = useState(false);
  const [forensicsTypeFilter, setForensicsTypeFilter] = useState("");
  const [forensicsChallengeFilter, setForensicsChallengeFilter] = useState("");
  const [forensicsOwnerFilter, setForensicsOwnerFilter] = useState("");
  const [forensicsPage, setForensicsPage] = useState(1);
  const [runningInstances, setRunningInstances] = useState<AdminInstance[]>([]);
  const [selectedLiveCaptureInstance, setSelectedLiveCaptureInstance] = useState("");

  const [viewLogId, setViewLogId] = useState("");
  const [viewLogContent, setViewLogContent] = useState("");
  const [viewLogOpen, setViewLogOpen] = useState(false);

  const loadEvents = useCallback(async () => {
    if (!isActive) return;
    setEventsLoading(true);
    try {
      const result = await client.getLogs({
        limit: eventLimit,
        offset: eventPage * eventLimit,
        event_type: eventType || undefined,
        username: eventUsername || undefined,
      });
      setEvents(result.logs || []);
      setEventsTotal(result.total || 0);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to load logs", "error");
    } finally {
      setEventsLoading(false);
    }
  }, [client, eventLimit, eventPage, eventType, eventUsername, isActive, pushToast]);

  const loadUserPorts = useCallback(async () => {
    if (!isActive) return;
    setPortsLoading(true);
    try {
      const result = await client.getUserPorts();
      setPortsRows(result.mappings || []);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to load user ports", "error");
    } finally {
      setPortsLoading(false);
    }
  }, [client, isActive, pushToast]);

  const loadForensics = useCallback(async () => {
    if (!isActive) return;
    setForensicsLoading(true);
    try {
      const [statsData, logsData, instancesData] = await Promise.all([
        client.getForensicsStats(),
        client.getForensicsLogs(200),
        client.getInstances(),
      ]);
      setForensicsStats(statsData);
      setForensicsLogs(logsData || []);
      setRunningInstances((instancesData || []).filter((instance) => instance.status === "running"));
      setForensicsPage(1);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to load forensics", "error");
    } finally {
      setForensicsLoading(false);
    }
  }, [client, isActive, pushToast]);

  useEffect(() => {
    if (!isActive) return;
    if (activeTab === "events") void loadEvents();
    if (activeTab === "ports") void loadUserPorts();
    if (activeTab === "forensics") void loadForensics();
  }, [activeTab, isActive, loadEvents, loadForensics, loadUserPorts]);

  useEffect(() => {
    if (activeTab === "events" && isActive) void loadEvents();
  }, [eventPage, eventLimit, eventType, eventUsername, activeTab, isActive, loadEvents]);

  const filteredPorts = useMemo(() => {
    return portsRows.filter((row) => {
      const userHit =
        !portsUserFilter ||
        row.username.toLowerCase().includes(portsUserFilter.toLowerCase()) ||
        row.user_id.toLowerCase().includes(portsUserFilter.toLowerCase());
      const challengeHit =
        !portsChallengeFilter ||
        row.challenge_id.toLowerCase().includes(portsChallengeFilter.toLowerCase());
      return userHit && challengeHit;
    });
  }, [portsChallengeFilter, portsRows, portsUserFilter]);

  const filteredForensics = useMemo(() => {
    return forensicsLogs.filter((log) => {
      const typeHit = !forensicsTypeFilter || log.capture_type === forensicsTypeFilter;
      const challengeHit =
        !forensicsChallengeFilter ||
        log.challenge_id.toLowerCase().includes(forensicsChallengeFilter.toLowerCase()) ||
        log.challenge_name.toLowerCase().includes(forensicsChallengeFilter.toLowerCase());
      const ownerHit =
        !forensicsOwnerFilter ||
        log.owner_name.toLowerCase().includes(forensicsOwnerFilter.toLowerCase()) ||
        log.spawned_by.toLowerCase().includes(forensicsOwnerFilter.toLowerCase()) ||
        (log.team_name || "").toLowerCase().includes(forensicsOwnerFilter.toLowerCase());
      return typeHit && challengeHit && ownerHit;
    });
  }, [forensicsChallengeFilter, forensicsLogs, forensicsOwnerFilter, forensicsTypeFilter]);

  const forensicsPageCount = Math.max(1, Math.ceil(filteredForensics.length / FORENSICS_PAGE_SIZE));
  const forensicsPageRows = useMemo(() => {
    const boundedPage = Math.min(forensicsPage, forensicsPageCount);
    const start = (boundedPage - 1) * FORENSICS_PAGE_SIZE;
    return filteredForensics.slice(start, start + FORENSICS_PAGE_SIZE);
  }, [filteredForensics, forensicsPage, forensicsPageCount]);

  async function exportLogs(format: "json" | "csv") {
    try {
      pushToast("Fetching logs for export...", "info");
      const data = await client.getLogs({
        limit: 10000,
        offset: 0,
        event_type: eventType || undefined,
        username: eventUsername || undefined,
      });

      if (!data.logs || data.logs.length === 0) {
        pushToast("No logs available for export", "warning");
        return;
      }

      const datePart = new Date().toISOString().slice(0, 10);
      if (format === "json") {
        const blob = new Blob([JSON.stringify(data.logs, null, 2)], { type: "application/json" });
        downloadBlob(blob, `mctf-logs-${datePart}.json`);
        pushToast(`Exported ${data.logs.length} logs`, "success");
        return;
      }

      const headers = ["timestamp", "event_type", "username", "user_id", "challenge_id", "instance_id", "ports", "public_url", "ip_address", "message"];
      const rows = data.logs.map((log) => {
        return headers.map((header) => {
          const value = (log as unknown as Record<string, unknown>)[header];
          let serialized = "";
          if (header === "ports" && value && typeof value === "object") {
            serialized = Object.entries(value as Record<string, unknown>)
              .map(([key, mapped]) => `${key}:${mapped}`)
              .join(";");
          } else {
            serialized = safeString(value, "");
          }
          if (serialized.includes(",") || serialized.includes("\n") || serialized.includes('"')) {
            return `"${serialized.replace(/"/g, '""')}"`;
          }
          return serialized;
        });
      });

      const csv = [headers.join(","), ...rows.map((row) => row.join(","))].join("\n");
      const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
      downloadBlob(blob, `mctf-logs-${datePart}.csv`);
      pushToast(`Exported ${data.logs.length} logs`, "success");
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to export logs", "error");
    }
  }

  async function removeUserPorts(userId: string, challengeId: string) {
    const approved = await confirm({
      title: "Delete user port mapping?",
      message: `User: ${userId}\nChallenge: ${challengeId}\n\nThe next spawn will allocate a new random mapping.`,
      confirmText: "Delete mapping",
      danger: true,
    });
    if (!approved) return;
    try {
      await client.deleteUserPorts(userId, challengeId);
      pushToast("Port mapping deleted", "success");
      await loadUserPorts();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to delete mapping", "error");
    }
  }

  async function clearAllPorts() {
    const approved = await confirm({
      title: "Clear all user port mappings?",
      message: "All persisted mappings will be removed for every user and challenge.",
      confirmText: "Clear all",
      danger: true,
    });
    if (!approved) return;
    try {
      const result = await client.clearAllUserPorts();
      pushToast(result.message || "Mappings cleared", "success");
      await loadUserPorts();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to clear mappings", "error");
    }
  }

  async function toggleAutoCapture(enabled: boolean) {
    if (enabled) {
      const approved = await confirm({
        title: "Enable forensics auto-capture?",
        message: `This may increase disk and I/O usage.\nRetention: ${forensicsStats?.retention_hours || 168} hours.\n\nUse this only when full evidence capture is required.`,
        confirmText: "Enable",
      });
      if (!approved) return;
    }
    try {
      const response = await client.toggleForensics(enabled);
      pushToast(response.message || "Forensics updated", "success");
      await loadForensics();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to update auto-capture", "error");
    }
  }

  async function startLiveCapture() {
    if (!selectedLiveCaptureInstance) {
      pushToast("Select a running instance first", "warning");
      return;
    }
    try {
      pushToast("Capturing container logs...", "info");
      const response = await client.liveCapture(selectedLiveCaptureInstance);
      pushToast(response.message || "Capture complete", "success");
      await loadForensics();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Live capture failed", "error");
    }
  }

  async function openForensicsLog(logId: string) {
    try {
      const payload = await client.getForensicsLogContent(logId);
      setViewLogId(logId);
      setViewLogContent(payload.content || "");
      setViewLogOpen(true);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to load log", "error");
    }
  }

  async function deleteForensicsLog(logId: string) {
    const approved = await confirm({
      title: "Delete forensics log?",
      message: `Log ${logId} will be permanently deleted.`,
      confirmText: "Delete",
      danger: true,
    });
    if (!approved) return;
    try {
      await client.deleteForensicsLog(logId);
      pushToast("Log deleted", "success");
      await loadForensics();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to delete log", "error");
    }
  }

  async function clearForensics() {
    const approved = await confirm({
      title: "Delete all forensics logs?",
      message: "This action is irreversible.",
      confirmText: "Delete all",
      danger: true,
    });
    if (!approved) return;
    try {
      const response = await client.clearForensicsLogs();
      pushToast(response.message || "Logs cleared", "success");
      await loadForensics();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to clear logs", "error");
    }
  }

  const eventsPageCount = Math.max(1, Math.ceil(eventsTotal / eventLimit));

  // ── Column definitions ──────────────────────────────────────────────

  const eventColumns: Column<AdminLogEntry>[] = useMemo(() => [
    { key: "time", header: "Time", className: "w-[140px]", render: (log) => <span className="font-mono text-[11px] whitespace-nowrap">{formatDateTime(log.timestamp)}</span> },
    { key: "event", header: "Event", className: "w-[140px]", render: (log) => <Badge tone="info">{log.event_type}</Badge> },
    { key: "user", header: "User", className: "max-w-[120px]", render: (log) => <span className="truncate block">{safeString(log.username)}</span> },
    { key: "challenge", header: "Challenge", className: "max-w-[120px]", render: (log) => <span className="truncate block">{safeString(log.challenge_id)}</span> },
    { key: "ports", header: "Ports", className: "whitespace-nowrap font-mono text-[11px]", render: (log) => Object.entries(log.ports || {}).map(([k, v]) => `${k}→${v}`).join(", ") || "—" },
    { key: "url", header: "URL", className: "max-w-[160px]", render: (log) => <span className="font-mono text-[11px] truncate block">{safeString(log.public_url)}</span> },
    { key: "ip", header: "IP", className: "w-[110px]", render: (log) => <span className="font-mono text-[11px]">{safeString(log.ip_address)}</span> },
    { key: "message", header: "Message", className: "max-w-[200px]", render: (log) => <span className="truncate block">{safeString(log.message)}</span> },
  ], []);

  const portColumns: Column<UserPortRow>[] = useMemo(() => [
    { key: "user", header: "User", className: "min-w-[160px]", render: (row) => (
      <div>
        <p className="text-slate-200">{row.username}</p>
        <p className="font-mono text-[11px] text-slate-400">{row.user_id}</p>
      </div>
    )},
    { key: "challenge", header: "Challenge", render: (row) => <span className="font-medium">{row.challenge_id}</span> },
    { key: "mappings", header: "Port mappings", className: "font-mono text-[11px]", render: (row) => Object.entries(row.ports || {}).map(([k, v]) => `${k}→${v}`).join(", ") || "—" },
    { key: "actions", header: "Actions", className: "w-[100px]", render: (row) => (
      <Button variant="danger" size="sm" onClick={() => void removeUserPorts(row.user_id, row.challenge_id)}>Delete</Button>
    )},
  ], []);

  const forensicsColumns: Column<ForensicsLog>[] = useMemo(() => [
    { key: "time", header: "Time", className: "w-[140px]", render: (log) => <span className="font-mono text-[11px] whitespace-nowrap">{formatDateTime(log.capture_time)}</span> },
    { key: "type", header: "Type", className: "w-[80px]", render: (log) => <Badge tone={log.capture_type === "auto" ? "warning" : "info"}>{log.capture_type}</Badge> },
    { key: "challenge", header: "Challenge", render: (log) => (
      <div>
        <p className="text-slate-200">{log.challenge_name}</p>
        <p className="font-mono text-[11px] text-slate-400">{log.challenge_id}</p>
      </div>
    )},
    { key: "owner", header: "Owner", render: (log) => safeString(log.team_name || log.owner_name) },
    { key: "spawner", header: "Spawner", render: (log) => safeString(log.spawned_by) },
    { key: "reason", header: "Reason", render: (log) => safeString(log.terminate_reason) },
    { key: "size", header: "Size", className: "w-[80px]", render: (log) => formatBytes(log.file_size_bytes) },
    { key: "actions", header: "Actions", className: "w-[140px]", render: (log) => (
      <div className="flex gap-1.5 flex-nowrap">
        <Button variant="secondary" size="sm" onClick={() => void openForensicsLog(log.log_id)}>View</Button>
        <Button variant="danger" size="sm" onClick={() => void deleteForensicsLog(log.log_id)}>Del</Button>
      </div>
    )},
  ], []);

  return (
    <div className="space-y-4">
      <Tabs
        tabs={[
          { id: "events", label: "Event logs", icon: "📜" },
          { id: "ports", label: "User ports", icon: "🔌" },
          { id: "forensics", label: "Forensics", icon: "🔍" },
        ]}
        activeTab={activeTab}
        onChange={(nextTab) => setActiveTab(nextTab as LogsTab)}
      />

      {activeTab === "events" ? (
        <Card>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-xs uppercase tracking-[0.15em] text-slate-400">Event telemetry</p>
              <h3 className="mt-1 text-xl text-slate-100">Search, page, and export runtime events</h3>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="secondary" size="sm" onClick={() => void exportLogs("json")}>JSON</Button>
              <Button variant="secondary" size="sm" onClick={() => void exportLogs("csv")}>CSV</Button>
              <Button variant="secondary" size="sm" onClick={() => void loadEvents()}>Refresh</Button>
            </div>
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Select label="Event type" value={eventType} onChange={(event) => { setEventType(event.target.value); setEventPage(0); }}>
              <option value="">All events</option>
              <option value="instance_spawn">instance_spawn</option>
              <option value="instance_spawn_failed">instance_spawn_failed</option>
              <option value="instance_stop">instance_stop</option>
              <option value="instance_extend">instance_extend</option>
              <option value="flag_created">flag_created</option>
              <option value="suspicious_submission">suspicious_submission</option>
            </Select>
            <Input label="Username filter" placeholder="search by username" value={eventUsername} onChange={(event) => { setEventUsername(event.target.value); setEventPage(0); }} />
            <Select label="Entries per page" value={String(eventLimit)} onChange={(event) => { setEventLimit(Number(event.target.value)); setEventPage(0); }}>
              {EVENTS_PER_PAGE_OPTIONS.map((size) => (<option key={size} value={size}>{size}</option>))}
            </Select>
            <div className="rounded-xl border border-white/10 bg-black/25 p-3">
              <p className="text-[11px] uppercase tracking-[0.14em] text-slate-400">Total matching events</p>
              <p className="mt-1 text-lg text-slate-100">{eventsTotal}</p>
            </div>
          </div>

          {eventsLoading ? <Loader label="Loading logs..." /> : null}

          {!eventsLoading ? (
            <div className="mt-4">
              <Table
                columns={eventColumns}
                data={events}
                keyExtractor={(_, i) => `event-${i}`}
                loading={false}
                emptyTitle="No logs found"
                emptyHint="Adjust filters or wait for new events."
              />
              <Pagination page={eventPage + 1} pageCount={eventsPageCount} total={eventsTotal} onPageChange={(p) => setEventPage(p - 1)} />
            </div>
          ) : null}
        </Card>
      ) : null}

      {activeTab === "ports" ? (
        <Card>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-xs uppercase tracking-[0.15em] text-slate-400">Persistent mappings</p>
              <h3 className="mt-1 text-xl text-slate-100">User challenge port assignments</h3>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="danger" size="sm" onClick={() => void clearAllPorts()}>Clear all</Button>
              <Button variant="secondary" size="sm" onClick={() => void loadUserPorts()}>Refresh</Button>
            </div>
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <Input label="Filter by user" value={portsUserFilter} onChange={(event) => setPortsUserFilter(event.target.value)} />
            <Input label="Filter by challenge" value={portsChallengeFilter} onChange={(event) => setPortsChallengeFilter(event.target.value)} />
          </div>

          {portsLoading ? <Loader label="Loading user port mappings..." /> : (
            <div className="mt-4">
              <Table
                columns={portColumns}
                data={filteredPorts}
                keyExtractor={(row) => `${row.user_id}-${row.challenge_id}`}
                emptyTitle="No port mappings found"
                emptyHint="Try changing the filters or wait for new instance spawns."
              />
            </div>
          )}
        </Card>
      ) : null}

      {activeTab === "forensics" ? (
        <Card>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-xs uppercase tracking-[0.15em] text-slate-400">Container evidence capture</p>
              <h3 className="mt-1 text-xl text-slate-100">Forensics logs and live capture operations</h3>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="danger" size="sm" onClick={() => void clearForensics()}>Clear all logs</Button>
              <Button variant="secondary" size="sm" onClick={() => void loadForensics()}>Refresh</Button>
            </div>
          </div>

          {forensicsLoading ? <Loader label="Loading forensics data..." /> : null}

          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <StatValue label="Auto capture" value={forensicsStats?.auto_capture_enabled ? "ON" : "OFF"} />
            <StatValue label="Total logs" value={String(forensicsStats?.total_logs || 0)} />
            <StatValue label="Auto captures" value={String(forensicsStats?.auto_capture_count || 0)} />
            <StatValue label="Live captures" value={String(forensicsStats?.live_capture_count || 0)} />
            <StatValue label="Total size" value={`${forensicsStats?.total_size_mb || 0} MB`} />
          </div>

          <div className="mt-3 rounded-xl border border-white/10 bg-black/20 p-3">
            <div className="flex flex-wrap items-end gap-3">
              <label className="inline-flex items-center gap-2 rounded-lg border border-white/15 px-3 py-2 text-sm text-slate-200 cursor-pointer hover:border-violet-300/40 transition-colors">
                <input
                  type="checkbox"
                  checked={Boolean(forensicsStats?.auto_capture_enabled)}
                  onChange={(event) => { void toggleAutoCapture(event.target.checked); }}
                />
                Auto capture on terminate
              </label>
              <Select label="Live capture instance" value={selectedLiveCaptureInstance} onChange={(event) => setSelectedLiveCaptureInstance(event.target.value)} className="min-w-[280px]">
                <option value="">Select running instance</option>
                {runningInstances.map((instance) => (
                  <option key={instance.instance_id} value={instance.instance_id}>
                    {instance.challenge_id} — {safeString(instance.team_name || instance.username)} ({instance.instance_id.slice(-8)})
                  </option>
                ))}
              </Select>
              <Button variant="primary" size="sm" onClick={() => void startLiveCapture()}>Capture now</Button>
            </div>
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            <Select label="Capture type" value={forensicsTypeFilter} onChange={(event) => { setForensicsTypeFilter(event.target.value); setForensicsPage(1); }}>
              <option value="">All captures</option>
              <option value="auto">Auto</option>
              <option value="live">Live</option>
            </Select>
            <Input label="Challenge filter" value={forensicsChallengeFilter} onChange={(event) => { setForensicsChallengeFilter(event.target.value); setForensicsPage(1); }} />
            <Input label="Owner/spawner filter" value={forensicsOwnerFilter} onChange={(event) => { setForensicsOwnerFilter(event.target.value); setForensicsPage(1); }} />
          </div>

          <div className="mt-4">
            <Table
              columns={forensicsColumns}
              data={forensicsPageRows}
              keyExtractor={(log) => log.log_id}
              emptyTitle="No forensics logs"
              emptyHint="No logs match current filter criteria."
            />
            <Pagination page={forensicsPage} pageCount={forensicsPageCount} total={filteredForensics.length} onPageChange={setForensicsPage} />
          </div>
        </Card>
      ) : null}

      <Modal
        open={viewLogOpen}
        title={`Forensics Log: ${viewLogId}`}
        onClose={() => setViewLogOpen(false)}
        footer={
          <>
            <Button variant="secondary" size="sm" onClick={() => { if (!viewLogContent) return; void navigator.clipboard.writeText(viewLogContent); pushToast("Log copied to clipboard", "success"); }}>Copy</Button>
            <Button variant="secondary" size="sm" onClick={() => { const blob = new Blob([viewLogContent], { type: "text/plain" }); downloadBlob(blob, `forensics_${viewLogId}.log`); }}>Download</Button>
            <Button variant="primary" size="sm" onClick={() => setViewLogOpen(false)}>Done</Button>
          </>
        }
      >
        <pre className="max-h-[60vh] overflow-auto rounded-lg border border-white/10 bg-black/30 p-3 text-xs text-slate-100">{viewLogContent || "(empty)"}</pre>
      </Modal>
    </div>
  );
}

function StatValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/20 p-3">
      <p className="text-[11px] uppercase tracking-[0.14em] text-slate-400">{label}</p>
      <p className="mt-1 text-base text-slate-100">{value}</p>
    </div>
  );
}
