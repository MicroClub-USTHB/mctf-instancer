import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "../shared/components/ui/Button";
import { Card } from "../shared/components/ui/Card";
import { Badge } from "../shared/components/ui/Badge";
import { Input } from "../shared/components/ui/Input";
import { Select } from "../shared/components/ui/Select";
import { Loader } from "../shared/components/ui/Loader";
import { EmptyState } from "../shared/components/ui/EmptyState";
import { Toggle } from "../shared/components/ui/Toggle";
import { PageShell } from "../shared/components/layout/PageShell";
import { useConfirm } from "../shared/hooks/useConfirm";
import { useToast } from "../shared/hooks/useToast";
import { useWebSocket } from "../shared/hooks/useWebSocket";
import {
  extendInstance,
  getApiRoot,
  getChallenges,
  getConfig,
  getErrorMessage,
  getHealth,
  getInstances,
  getMe,
  getTeam,
  spawnInstance,
  stopInstance,
  summarizeConnection,
} from "../shared/api/userApi";
import type { ChallengeInfo, InstanceInfo, PublicConfig, TeamMember, UserMeResponse } from "./types";
import { formatDateTime, formatRelativeRemaining } from "../shared/utils/time";
import { classNames, safeString } from "../shared/utils/format";

const REFRESH_MS = 10000;

type AuthMode = "ctfd" | "none";

const categoryTone: Record<string, "info" | "warning" | "neutral" | "success"> = {
  web: "info",
  pwn: "warning",
  reverse: "neutral",
  crypto: "success",
  misc: "neutral",
  forensics: "warning",
};

const statusTone: Record<string, "success" | "warning" | "danger" | "info" | "neutral"> = {
  running: "success",
  starting: "info",
  stopping: "warning",
  stopped: "neutral",
  error: "danger",
};

function getCategoryTone(category?: string): "info" | "warning" | "neutral" | "success" {
  return categoryTone[(category || "").toLowerCase()] || "neutral";
}

function getStatusTone(status?: string): "success" | "warning" | "danger" | "info" | "neutral" {
  return statusTone[(status || "").toLowerCase()] || "neutral";
}

export function UserApp() {
  const savedToken = sessionStorage.getItem("ctfd_token") || "";

  const { pushToast } = useToast();
  const { confirm } = useConfirm();

  const [booting, setBooting] = useState(true);
  const [authMode, setAuthMode] = useState<AuthMode>("none");
  const [token, setToken] = useState(savedToken);
  const [tokenInput, setTokenInput] = useState("");
  const [authenticated, setAuthenticated] = useState(false);
  const [authError, setAuthError] = useState("");

  const [health, setHealth] = useState({
    online: false,
    activeInstances: 0,
  });

  const [config, setConfig] = useState<PublicConfig | null>(null);
  const [me, setMe] = useState<UserMeResponse | null>(null);
  const [teamName, setTeamName] = useState("");
  const [teamMembers, setTeamMembers] = useState<TeamMember[]>([]);
  const [challenges, setChallenges] = useState<ChallengeInfo[]>([]);
  const [instances, setInstances] = useState<InstanceInfo[]>([]);

  const [loadingChallenges, setLoadingChallenges] = useState(false);
  const [loadingInstances, setLoadingInstances] = useState(false);
  const [spawningChallengeId, setSpawningChallengeId] = useState("");
  const [busyInstanceId, setBusyInstanceId] = useState("");

  const [tableView, setTableView] = useState(() => localStorage.getItem("whaley_challenge_view") === "table");
  const [challengeSearch, setChallengeSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");

  const [now, setNow] = useState(Date.now());

  const isTeamMode = Boolean(me?.team_mode);
  const maxInstances = me?.max_instances || 0;
  const currentInstanceCount = me?.instances ?? instances.length;
  const limitReached = maxInstances > 0 && currentInstanceCount >= maxInstances;

  const refreshHealth = useCallback(
    async (tokenOverride?: string) => {
      try {
        const result = await getHealth(tokenOverride);
        setHealth({
          online: true,
          activeInstances: result.active_instances || 0,
        });
      } catch {
        setHealth({ online: false, activeInstances: 0 });
      }
    },
    [],
  );

  const loadSession = useCallback(
    async (tokenOverride?: string, silent = false) => {
      try {
        const meData = await getMe(tokenOverride);
        setMe(meData);
        setAuthError("");

        if (meData.team_mode) {
          try {
            const teamData = await getTeam(tokenOverride);
            setTeamMembers(teamData.members || []);
            setTeamName(teamData.team_name || "");
          } catch {
            setTeamMembers([]);
            setTeamName("");
          }
        } else {
          setTeamMembers([]);
          setTeamName("");
        }

        return true;
      } catch (error) {
        setMe(null);
        setTeamMembers([]);
        setTeamName("");
        const message = getErrorMessage(error, "Authentication failed");
        setAuthError(message);
        if (!silent) {
          pushToast(message, "error", "Session error");
        }
        return false;
      }
    },
    [pushToast],
  );

  const loadChallengesData = useCallback(
    async (tokenOverride?: string, silent = false) => {
      setLoadingChallenges(true);
      try {
        const list = await getChallenges(tokenOverride);
        setChallenges(list);
      } catch (error) {
        setChallenges([]);
        if (!silent) {
          pushToast(getErrorMessage(error, "Failed to load challenges"), "error", "Challenge error");
        }
      } finally {
        setLoadingChallenges(false);
      }
    },
    [pushToast],
  );

  const loadInstancesData = useCallback(
    async (tokenOverride?: string, silent = false) => {
      setLoadingInstances(true);
      try {
        const list = await getInstances(tokenOverride);
        setInstances(list);
      } catch (error) {
        setInstances([]);
        if (!silent) {
          pushToast(getErrorMessage(error, "Failed to load instances"), "error", "Instance error");
        }
      } finally {
        setLoadingInstances(false);
      }
    },
    [pushToast],
  );

  const refreshAll = useCallback(
    async (tokenOverride?: string, silent = false) => {
      await Promise.all([
        refreshHealth(tokenOverride),
        loadSession(tokenOverride, silent),
        loadChallengesData(tokenOverride, silent),
        loadInstancesData(tokenOverride, silent),
      ]);
    },
    [loadChallengesData, loadInstancesData, loadSession, refreshHealth],
  );

  const bootstrap = useCallback(async () => {
    setBooting(true);

    try {
      const [apiRoot, publicConfig] = await Promise.all([getApiRoot(), getConfig()]);
      const mode = (apiRoot.auth_mode || publicConfig.auth_mode || "none") as AuthMode;
      setAuthMode(mode);
      setConfig(publicConfig);

      if (mode === "none") {
        setAuthenticated(true);
        await refreshAll(undefined, true);
        setBooting(false);
        return;
      }

      if (savedToken) {
        setToken(savedToken);
        const ok = await loadSession(savedToken, true);
        if (ok) {
          setAuthenticated(true);
          await Promise.all([
            refreshHealth(savedToken),
            loadChallengesData(savedToken, true),
            loadInstancesData(savedToken, true),
          ]);
        } else {
          sessionStorage.removeItem("ctfd_token");
          setToken("");
          setAuthenticated(false);
        }
      } else {
        setAuthenticated(false);
      }
    } catch {
      setAuthError("Failed to initialize the dashboard");
      setAuthenticated(false);
    } finally {
      setBooting(false);
    }
  }, [loadChallengesData, loadInstancesData, loadSession, refreshAll, refreshHealth, savedToken]);

  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(Date.now());
    }, 1000);

    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!authenticated) {
      return;
    }

    const timer = window.setInterval(() => {
      void loadInstancesData(token || undefined, true);
      void refreshHealth(token || undefined);
    }, REFRESH_MS);

    return () => window.clearInterval(timer);
  }, [authenticated, loadInstancesData, refreshHealth, token]);

  // ── WebSocket real-time updates ──────────────────────────────────────

  const wsUrl = useMemo(() => {
    if (!token || authMode !== "ctfd") return "";
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${window.location.host}/ws?token=${encodeURIComponent(token)}`;
  }, [token, authMode]);

  const { onEvent } = useWebSocket({ url: wsUrl, enabled: authenticated && authMode === "ctfd" });

  useEffect(() => {
    if (!authenticated) return;
    onEvent((event, data) => {
      switch (event) {
        case "instance_spawned": {
          const inst = data as InstanceInfo;
          setInstances((prev) => {
            if (prev.some((i) => i.instance_id === inst.instance_id)) return prev;
            return [...prev, inst];
          });
          break;
        }
        case "instance_stopped": {
          const { instance_id } = data as { instance_id: string };
          setInstances((prev) => prev.filter((i) => i.instance_id !== instance_id));
          break;
        }
        case "instance_extended": {
          const inst = data as InstanceInfo;
          setInstances((prev) =>
            prev.map((i) => (i.instance_id === inst.instance_id ? { ...i, expires_at: inst.expires_at } : i)),
          );
          break;
        }
        case "challenges_updated": {
          void loadChallengesData(token || undefined);
          break;
        }
      }
    });
  }, [authenticated, onEvent, loadChallengesData, token]);

  async function authenticate() {
    const candidate = tokenInput.trim();

    if (!candidate) {
      pushToast("Please enter your CTFd access token", "warning", "Token required");
      return;
    }

    setToken(candidate);
    const ok = await loadSession(candidate);

    if (!ok) {
      setToken("");
      return;
    }

    sessionStorage.setItem("ctfd_token", candidate);
    setAuthenticated(true);
    setTokenInput("");
    pushToast("Authentication successful", "success", "Welcome");
    await Promise.all([
      refreshHealth(candidate),
      loadChallengesData(candidate, true),
      loadInstancesData(candidate, true),
    ]);
  }

  function logout() {
    sessionStorage.removeItem("ctfd_token");
    setToken("");
    setTokenInput("");
    setAuthenticated(false);
    setMe(null);
    setTeamName("");
    setTeamMembers([]);
    setChallenges([]);
    setInstances([]);
    setAuthError("");
    pushToast("Session closed", "info");
  }

  async function handleSpawn(challengeId: string) {
    setSpawningChallengeId(challengeId);

    try {
      const response = await spawnInstance(challengeId, token || undefined);
      if (!response.success) {
        throw new Error(response.message || "Failed to spawn instance");
      }

      pushToast(summarizeConnection(response.instance), "success", "Instance deployed");
      await refreshAll(token || undefined, true);
    } catch (error) {
      pushToast(getErrorMessage(error, "Failed to deploy instance"), "error", "Spawn error");
    } finally {
      setSpawningChallengeId("");
    }
  }

  async function handleStop(instanceId: string) {
    const approved = await confirm({
      title: "Stop this instance?",
      message: "The container and its ephemeral state will be removed immediately.",
      confirmText: "Stop instance",
      danger: true,
    });

    if (!approved) {
      return;
    }

    setBusyInstanceId(instanceId);

    try {
      const response = await stopInstance(instanceId, token || undefined);
      pushToast(response.message || "Instance stopped", "success");
      await refreshAll(token || undefined, true);
    } catch (error) {
      pushToast(getErrorMessage(error, "Failed to stop instance"), "error");
    } finally {
      setBusyInstanceId("");
    }
  }

  async function handleExtend(instanceId: string) {
    setBusyInstanceId(instanceId);

    try {
      const response = await extendInstance(instanceId, token || undefined);
      pushToast(response.message || "Instance extended", "success");
      await loadInstancesData(token || undefined, true);
    } catch (error) {
      pushToast(getErrorMessage(error, "Failed to extend instance"), "error");
    } finally {
      setBusyInstanceId("");
    }
  }

  async function copyToClipboard(value: string) {
    if (!value || value === "-") {
      return;
    }

    try {
      await navigator.clipboard.writeText(value);
      pushToast(value, "info", "Copied");
    } catch {
      const input = document.createElement("input");
      input.value = value;
      document.body.appendChild(input);
      input.select();
      document.execCommand("copy");
      document.body.removeChild(input);
      pushToast(value, "info", "Copied");
    }
  }

  const showAuthPanel = !booting && authMode === "ctfd" && !authenticated;
  const showDashboard = !booting && (authMode === "none" || authenticated);

  const challengeCountLabel = useMemo(() => `${challenges.length} loaded`, [challenges.length]);

  const categoryOptions = useMemo(() => {
    const cats = new Set(challenges.map((c) => (c.category || "misc").toLowerCase()));
    return Array.from(cats).sort();
  }, [challenges]);

  const toggleView = useCallback((enabled: boolean) => {
    setTableView(enabled);
    localStorage.setItem("whaley_challenge_view", enabled ? "table" : "card");
  }, []);

  const filteredChallenges = useMemo(() => {
    const search = challengeSearch.toLowerCase().trim();
    const cat = categoryFilter.toLowerCase();
    return challenges.filter((c) => {
      if (search && !c.name.toLowerCase().includes(search) && !c.id.toLowerCase().includes(search)) {
        return false;
      }
      if (cat && (c.category || "misc").toLowerCase() !== cat) {
        return false;
      }
      return true;
    });
  }, [challenges, challengeSearch, categoryFilter]);

  return (
    <PageShell
      title="MCTF 5.0 Challenges Instancer"
      subtitle="Deploy instances of CTF challenges on demand for your team."
      actions={
        <>
          <Badge tone="info">{challengeCountLabel}</Badge>
          <Badge tone="neutral">{health.activeInstances} active</Badge>
          <Button variant="secondary" onClick={() => void refreshAll(token || undefined)}>
            Refresh all
          </Button>
        </>
      }
    >
      {booting ? <Loader label="Bootstrapping user dashboard..." /> : null}

      {showAuthPanel ? (
        <Card className="mx-auto w-full max-w-3xl">
          <div className="grid gap-4 sm:grid-cols-[1fr_auto] sm:items-end">
            <Input
              label="CTFd Access Token"
              placeholder="ctfd_xxxxxxxxx"
              type="password"
              value={tokenInput}
              onChange={(event) => setTokenInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  void authenticate();
                }
              }}
            />
            <Button variant="primary" size="md" onClick={() => void authenticate()}>
              Authenticate
            </Button>
          </div>

          {config?.ctfd_url ? (
            <div className="mt-3 flex flex-wrap gap-3 text-sm text-slate-300">
              <a className="underline decoration-slate-500 underline-offset-4 transition hover:text-white" href={`${config.ctfd_url}/settings`} target="_blank" rel="noreferrer noopener">
                Get access token
              </a>
            </div>
          ) : null}

          {authError ? <p className="mt-3 rounded-lg border border-rose-300/45 bg-rose-500/15 px-3 py-2 text-sm text-rose-100">{authError}</p> : null}
        </Card>
      ) : null}

      {!booting && !showAuthPanel && !showDashboard ? (
        <Card>
          <EmptyState title="Unable to start session" hint={authError || "Try refreshing the page."}>
            <Button variant="secondary" onClick={() => void bootstrap()}>
              Retry
            </Button>
          </EmptyState>
        </Card>
      ) : null}

      {showDashboard ? (
        <>
          <Card>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Operator session</p>
                <h2 className="mt-1 text-2xl text-slate-100">{safeString(me?.user.username, "Unknown user")}</h2>
              </div>
              {authMode === "ctfd" ? (
                <Button variant="danger" onClick={logout}>
                  Sign out
                </Button>
              ) : (
                <Badge tone="neutral">No external auth</Badge>
              )}
            </div>

            <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-xl border border-white/10 bg-black/25 p-3">
                <p className="text-[11px] uppercase tracking-[0.15em] text-slate-400">Session user</p>
                <p className="mt-1 font-mono text-sm text-slate-100">{safeString(me?.user.username)}</p>
              </div>
              <div className="rounded-xl border border-white/10 bg-black/25 p-3">
                <p className="text-[11px] uppercase tracking-[0.15em] text-slate-400">Team</p>
                <p className="mt-1 text-sm text-slate-100">{safeString(teamName, isTeamMode ? "Team" : "Solo")}</p>
              </div>
              <div className="rounded-xl border border-white/10 bg-black/25 p-3">
                <p className="text-[11px] uppercase tracking-[0.15em] text-slate-400">Instances</p>
                <p className="mt-1 font-mono text-sm text-slate-100">
                  {currentInstanceCount} / {maxInstances || "-"}
                </p>
              </div>
              <div className="rounded-xl border border-white/10 bg-black/25 p-3">
                <p className="text-[11px] uppercase tracking-[0.15em] text-slate-400">Instance timeout</p>
                <p className="mt-1 text-sm text-slate-100">{config?.instance_timeout ? `${config.instance_timeout}s` : "-"}</p>
              </div>
            </div>

            {isTeamMode && teamMembers.length > 0 ? (
              <div className="mt-4 rounded-xl border border-white/10 bg-black/20 p-3">
                <p className="text-[11px] uppercase tracking-[0.15em] text-slate-400">Team members</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {teamMembers.map((member, index) => {
                    const isCurrent = Boolean(member.is_current) || String(member.name).toLowerCase() === String(me?.user.username || "").toLowerCase();
                    return (
                      <span
                        key={`${member.name}-${index}`}
                        className={classNames(
                          "rounded-full border px-3 py-1 text-xs",
                          isCurrent
                            ? "border-violet-300/40 bg-violet-950/35 text-violet-100"
                            : "border-white/15 bg-white/6 text-slate-200",
                        )}
                      >
                        {member.name}
                        {isCurrent ? " (you)" : ""}
                      </span>
                    );
                  })}
                </div>
              </div>
            ) : null}
          </Card>

          <Card>
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Challenge deck</p>
                <h3 className="mt-1 text-xl text-slate-100">Select a challenge to deploy</h3>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <Toggle enabled={tableView} onChange={toggleView} label="Table view" />
                <Button variant="secondary" onClick={() => void loadChallengesData(token || undefined)}>
                  Refresh deck
                </Button>
              </div>
            </div>

            {tableView ? (
              <div className="mb-4 grid gap-3 sm:grid-cols-2">
                <Input
                  placeholder="Search by name or ID..."
                  value={challengeSearch}
                  onChange={(event) => setChallengeSearch(event.target.value)}
                />
                <Select value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)}>
                  <option value="">All categories</option>
                  {categoryOptions.map((cat) => (
                    <option key={cat} value={cat}>{cat}</option>
                  ))}
                </Select>
              </div>
            ) : null}

            {loadingChallenges ? <Loader label="Loading challenges..." /> : null}

            {!loadingChallenges && challenges.length === 0 ? (
              <EmptyState title="No active challenges" hint="Ask an administrator to upload or activate challenge definitions." />
            ) : null}

            {!loadingChallenges && !tableView ? (
              <div className="grid gap-3 lg:grid-cols-2">
                {challenges.map((challenge) => {
                  const deploying = spawningChallengeId === challenge.id;
                  const disabled = deploying || Boolean(busyInstanceId) || limitReached;

                  return (
                    <article key={challenge.id} className="rounded-xl border border-white/12 bg-black/25 p-4 transition hover:border-white/20">
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div>
                          <h4 className="text-lg text-slate-100">{challenge.name}</h4>
                          <p className="font-mono text-xs text-slate-400">ID: {challenge.id}</p>
                        </div>
                        <Badge tone={getCategoryTone(challenge.category)}>{challenge.category || "misc"}</Badge>
                      </div>

                      <p className="mt-2 text-sm text-slate-300">{safeString(challenge.description, "No description available.")}</p>

                      <div className="mt-3 grid gap-2 text-xs text-slate-300 sm:grid-cols-2">
                        <p>
                          Routing: <strong>{safeString(challenge.routing_type, "unknown")}</strong>
                        </p>
                        <p>
                          TLS: <strong>{challenge.tls_enabled ? "Enabled" : "Disabled"}</strong>
                        </p>
                      </div>

                      {limitReached ? <p className="mt-3 text-xs text-zinc-300">Instance limit reached for your current owner scope.</p> : null}

                      <Button className="mt-4 w-full" variant="primary" disabled={disabled} onClick={() => void handleSpawn(challenge.id)}>
                        {deploying ? "Deploying..." : "Deploy challenge"}
                      </Button>
                    </article>
                  );
                })}
              </div>
            ) : null}

            {!loadingChallenges && tableView ? (
              <>
                {filteredChallenges.length === 0 ? (
                  <EmptyState title="No matching challenges" hint="Try adjusting the search or category filter." />
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead>
                        <tr className="border-b border-white/12 text-xs uppercase tracking-[0.12em] text-slate-400">
                          <th className="px-3 py-2 font-medium">Challenge</th>
                          <th className="px-3 py-2 font-medium hidden sm:table-cell">Category</th>
                          <th className="px-3 py-2 font-medium hidden md:table-cell">Routing</th>
                          <th className="px-3 py-2 font-medium hidden md:table-cell">TLS</th>
                          <th className="px-3 py-2 font-medium hidden lg:table-cell">Description</th>
                          <th className="px-3 py-2 font-medium w-36"></th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/8">
                        {filteredChallenges.map((challenge) => {
                          const deploying = spawningChallengeId === challenge.id;
                          const disabled = deploying || Boolean(busyInstanceId) || limitReached;

                          return (
                            <tr key={challenge.id} className="transition hover:bg-white/[0.03]">
                              <td className="px-3 py-2.5">
                                <p className="text-slate-100">{challenge.name}</p>
                                <p className="font-mono text-[11px] text-slate-500">{challenge.id}</p>
                              </td>
                              <td className="px-3 py-2.5 hidden sm:table-cell">
                                <Badge tone={getCategoryTone(challenge.category)}>{challenge.category || "misc"}</Badge>
                              </td>
                              <td className="px-3 py-2.5 font-mono text-xs text-slate-300 hidden md:table-cell">
                                {safeString(challenge.routing_type, "unknown")}
                              </td>
                              <td className="px-3 py-2.5 hidden md:table-cell">
                                <Badge tone={challenge.tls_enabled ? "success" : "neutral"}>
                                  {challenge.tls_enabled ? "On" : "Off"}
                                </Badge>
                              </td>
                              <td className="px-3 py-2.5 text-xs text-slate-400 hidden lg:table-cell max-w-48 truncate">
                                {safeString(challenge.description, "-")}
                              </td>
                              <td className="px-3 py-2.5">
                                <Button variant="primary" disabled={disabled} onClick={() => void handleSpawn(challenge.id)}>
                                  {deploying ? "..." : "Deploy"}
                                </Button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
                {limitReached && filteredChallenges.length > 0 ? (
                  <p className="mt-3 text-xs text-zinc-300">Instance limit reached for your current owner scope.</p>
                ) : null}
              </>
            ) : null}
          </Card>

          <Card>
            <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Active instances</p>
                <h3 className="mt-1 text-xl text-slate-100">Runtime lifecycles and connection details</h3>
              </div>
              <Button variant="secondary" onClick={() => void loadInstancesData(token || undefined)}>
                Refresh instances
              </Button>
            </div>

            {loadingInstances ? <Loader label="Loading active instances..." /> : null}

            {!loadingInstances && instances.length === 0 ? (
              <EmptyState title="No active instances" hint="Deploy a challenge to create a runtime environment." />
            ) : null}

            <div className="space-y-3">
              {instances.map((instance) => {
                const urls = instance.public_urls && instance.public_urls.length > 0
                  ? instance.public_urls
                  : instance.public_url
                    ? [instance.public_url]
                    : [];

                const isBusy = busyInstanceId === instance.instance_id;
                const showSpawner = Boolean(instance.team_name) && Boolean(instance.username) && instance.username !== me?.user.username;

                return (
                  <article key={instance.instance_id} className="rounded-xl border border-white/12 bg-black/25 p-4">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <h4 className="text-lg text-slate-100">{instance.challenge_id}</h4>
                          <Badge tone={getStatusTone(instance.status)}>{instance.status}</Badge>
                          <Badge tone="neutral">{safeString(instance.routing_type, "unknown")}</Badge>
                        </div>
                        <p className="mt-1 font-mono text-xs text-slate-400">Instance ID: {instance.instance_id}</p>
                        <p className="mt-1 text-xs text-slate-300">
                          Owner: {safeString(instance.team_name || instance.username)}
                          {showSpawner ? ` (spawned by ${instance.username})` : ""}
                        </p>
                      </div>

                      <div className="flex gap-2">
                        <Button variant="secondary" disabled={isBusy} onClick={() => void handleExtend(instance.instance_id)}>
                          Extend
                        </Button>
                        <Button variant="danger" disabled={isBusy} onClick={() => void handleStop(instance.instance_id)}>
                          Stop
                        </Button>
                      </div>
                    </div>

                    <div className="mt-3 grid gap-3 lg:grid-cols-2">
                      <div className="rounded-xl border border-white/10 bg-black/25 p-3">
                        <p className="text-[11px] uppercase tracking-[0.15em] text-slate-400">Public endpoints</p>
                        {urls.length === 0 ? (
                          <p className="mt-2 text-sm text-slate-300">No public endpoint available.</p>
                        ) : (
                          <div className="mt-2 space-y-2">
                            {urls.map((url, index) => (
                              <button
                                key={`${instance.instance_id}-${index}-${url}`}
                                type="button"
                                onClick={() => void copyToClipboard(url)}
                                className="w-full rounded-lg border border-white/12 bg-black/35 px-3 py-2 text-left font-mono text-xs text-slate-100 transition hover:border-white/30"
                                title="Copy endpoint"
                              >
                                {url}
                              </button>
                            ))}
                          </div>
                        )}

                        {instance.connection_hint ? (
                          <button
                            type="button"
                            onClick={() => void copyToClipboard(instance.connection_hint || "")}
                            className="mt-2 w-full rounded-lg border border-violet-300/35 bg-violet-950/40 px-3 py-2 text-left font-mono text-xs text-violet-100 transition hover:border-violet-200/60"
                            title="Copy connection command"
                          >
                            {instance.connection_hint}
                          </button>
                        ) : null}
                      </div>

                      <div className="rounded-xl border border-white/10 bg-black/25 p-3">
                        <p className="text-[11px] uppercase tracking-[0.15em] text-slate-400">Runtime metadata</p>
                        <div className="mt-2 space-y-1 text-sm text-slate-200">
                          <p>
                            Created: <span className="font-mono text-xs text-slate-300">{formatDateTime(instance.created_at)}</span>
                          </p>
                          <p>
                            Expires in: <span className="font-mono text-xs text-slate-200">{formatRelativeRemaining(instance.expires_at, now)}</span>
                          </p>
                          <p>
                            Expires at: <span className="font-mono text-xs text-slate-300">{formatDateTime(instance.expires_at)}</span>
                          </p>
                        </div>
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          </Card>
        </>
      ) : null}

      <footer className="border-t border-white/12 pt-4 text-center text-xs uppercase tracking-[0.16em] text-slate-500">
        MCTF 5.0 Instancer
      </footer>
    </PageShell>
  );
}
