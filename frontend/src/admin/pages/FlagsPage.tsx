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
import { useConfirm } from "../../shared/hooks/useConfirm";
import { useToast } from "../../shared/hooks/useToast";
import { formatDateTime } from "../../shared/utils/time";
import { safeString } from "../../shared/utils/format";
import type { ChallengeItem, CtfdChallenge, FlagMapping, FlagsData, SuspiciousSubmission } from "../types";
import type { AdminPageProps } from "../types/page";

interface FlagsPageProps extends AdminPageProps {}

const ITEMS_PER_PAGE = 6;

export function FlagsPage({ client, isActive }: FlagsPageProps) {
  const { pushToast } = useToast();
  const { confirm } = useConfirm();

  const [loading, setLoading] = useState(false);
  const [flagsData, setFlagsData] = useState<FlagsData | null>(null);
  const [localChallenges, setLocalChallenges] = useState<ChallengeItem[]>([]);

  const [flagUserFilter, setFlagUserFilter] = useState("");
  const [flagChallengeFilter, setFlagChallengeFilter] = useState("");

  const [suspiciousPage, setSuspiciousPage] = useState(1);
  const [mappingPage, setMappingPage] = useState(1);
  const [challengeMapPage, setChallengeMapPage] = useState(1);

  const [localChallengeToMap, setLocalChallengeToMap] = useState("");
  const [ctfdChallengeToMap, setCtfdChallengeToMap] = useState("");

  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardLoading, setWizardLoading] = useState(false);
  const [ctfdChallenges, setCtfdChallenges] = useState<CtfdChallenge[]>([]);
  const [ctfdCategories, setCtfdCategories] = useState<string[]>([]);
  const [wizardSearch, setWizardSearch] = useState("");
  const [wizardCategory, setWizardCategory] = useState("");
  const [wizardSelection, setWizardSelection] = useState<Record<number, string>>({});

  const load = useCallback(async () => {
    if (!isActive) return;
    setLoading(true);
    try {
      const [flagPayload, challenges] = await Promise.all([client.getFlagsData(), client.getChallenges()]);
      setFlagsData(flagPayload);
      setLocalChallenges(challenges || []);
      setSuspiciousPage(1);
      setMappingPage(1);
      setChallengeMapPage(1);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to load flag data", "error");
    } finally {
      setLoading(false);
    }
  }, [client, isActive, pushToast]);

  useEffect(() => {
    if (!isActive) return;
    void load();
  }, [isActive, load]);

  const suspiciousRows = useMemo(() => {
    return [...(flagsData?.suspicious_submissions || [])].sort((a, b) => {
      return new Date(b.submission_time || 0).getTime() - new Date(a.submission_time || 0).getTime();
    });
  }, [flagsData?.suspicious_submissions]);

  const filteredMappings = useMemo(() => {
    return [...(flagsData?.flag_mappings || [])]
      .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime())
      .filter((mapping) => {
        const userHit =
          !flagUserFilter ||
          mapping.username.toLowerCase().includes(flagUserFilter.toLowerCase()) ||
          mapping.user_id.toLowerCase().includes(flagUserFilter.toLowerCase()) ||
          (mapping.team_name || "").toLowerCase().includes(flagUserFilter.toLowerCase());
        const challengeHit =
          !flagChallengeFilter ||
          mapping.local_challenge_id.toLowerCase().includes(flagChallengeFilter.toLowerCase());
        return userHit && challengeHit;
      });
  }, [flagChallengeFilter, flagUserFilter, flagsData?.flag_mappings]);

  const challengeMappingRows = useMemo(() => {
    const mapping = flagsData?.challenge_mapping || {};
    const challengeSet = new Set<string>([...Object.keys(mapping), ...localChallenges.map((c) => c.id)]);
    const localMap = new Map(localChallenges.map((c) => [c.id, c]));
    return Array.from(challengeSet)
      .sort((a, b) => a.localeCompare(b))
      .map((localId) => {
        const challenge = localMap.get(localId);
        return {
          localId,
          ctfdId: mapping[localId],
          mapped: mapping[localId] !== undefined,
          flagsDisabled: challenge?.disable_dynamic_flags ?? false,
        };
      });
  }, [flagsData?.challenge_mapping, localChallenges]);

  const suspiciousPageRows = useMemo(() => {
    const start = (suspiciousPage - 1) * ITEMS_PER_PAGE;
    return suspiciousRows.slice(start, start + ITEMS_PER_PAGE);
  }, [suspiciousPage, suspiciousRows]);

  const mappingPageRows = useMemo(() => {
    const start = (mappingPage - 1) * ITEMS_PER_PAGE;
    return filteredMappings.slice(start, start + ITEMS_PER_PAGE);
  }, [filteredMappings, mappingPage]);

  const challengePageRows = useMemo(() => {
    const start = (challengeMapPage - 1) * ITEMS_PER_PAGE;
    return challengeMappingRows.slice(start, start + ITEMS_PER_PAGE);
  }, [challengeMapPage, challengeMappingRows]);

  const suspiciousTotal = flagsData?.suspicious_total ?? suspiciousRows.length;
  const suspiciousPageCount = Math.max(1, Math.ceil(suspiciousRows.length / ITEMS_PER_PAGE));
  const mappingPageCount = Math.max(1, Math.ceil(filteredMappings.length / ITEMS_PER_PAGE));
  const challengePageCount = Math.max(1, Math.ceil(challengeMappingRows.length / ITEMS_PER_PAGE));

  async function checkSubmissions() {
    try {
      const result = await client.checkSubmissions();
      if (result.new_suspicious_count > 0) {
        pushToast(`Detected ${result.new_suspicious_count} new suspicious submissions`, "warning");
      } else {
        pushToast("No new suspicious submissions", "success");
      }
      await load();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to check submissions", "error");
    }
  }

  async function clearSuspicious() {
    const approved = await confirm({
      title: "Clear suspicious submission history?",
      message: "All suspicious submission records will be removed.",
      confirmText: "Clear history",
      danger: true,
    });
    if (!approved) return;
    try {
      await client.clearSuspicious();
      pushToast("Suspicious history cleared", "success");
      await load();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to clear suspicious list", "error");
    }
  }

  async function deleteFlag(mapping: FlagMapping) {
    const owner = mapping.team_name || mapping.username;
    const approved = await confirm({
      title: "Delete flag mapping?",
      message: `Owner: ${owner}\nChallenge: ${mapping.local_challenge_id}\n\nThis also attempts CTFd deletion.`,
      confirmText: "Delete mapping",
      danger: true,
    });
    if (!approved) return;
    try {
      const result = await client.deleteFlag(mapping.flag_id);
      pushToast(result.message || "Flag mapping deleted", "success");
      await load();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to delete flag mapping", "error");
    }
  }

  async function addChallengeMapping() {
    const localId = localChallengeToMap.trim();
    const ctfdId = Number(ctfdChallengeToMap);
    if (!localId) { pushToast("Select a local challenge", "warning"); return; }
    if (!ctfdId || Number.isNaN(ctfdId) || ctfdId < 1) { pushToast("Enter a valid CTFd challenge ID", "warning"); return; }
    try {
      const result = await client.syncChallenge(localId, ctfdId);
      pushToast(result.message || "Mapping created", "success");
      setCtfdChallengeToMap("");
      await load();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to add mapping", "error");
    }
  }

  async function removeChallengeMapping(localId: string) {
    const approved = await confirm({
      title: "Remove challenge mapping?",
      message: `Mapping for ${localId} will be removed.`,
      confirmText: "Remove",
      danger: true,
    });
    if (!approved) return;
    try {
      const result = await client.removeChallengeMapping(localId);
      pushToast(result.message || "Mapping removed", "success");
      await load();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to remove mapping", "error");
    }
  }

  async function openWizard() {
    setWizardOpen(true);
    setWizardLoading(true);
    try {
      const response = await client.getCtfdChallenges();
      setCtfdChallenges(response.challenges || []);
      setCtfdCategories(response.categories || []);
      const preselect: Record<number, string> = {};
      (response.challenges || []).forEach((challenge) => {
        if (challenge.suggested_local_id) preselect[challenge.id] = challenge.suggested_local_id;
      });
      setWizardSelection(preselect);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to fetch CTFd challenges", "error");
    } finally {
      setWizardLoading(false);
    }
  }

  const wizardRows = useMemo(() => {
    let rows = [...ctfdChallenges];
    if (wizardSearch) rows = rows.filter((c) => c.name.toLowerCase().includes(wizardSearch.toLowerCase()));
    if (wizardCategory) rows = rows.filter((c) => c.category === wizardCategory);
    return rows.sort((a, b) => {
      if (a.suggested_local_id && !b.suggested_local_id) return -1;
      if (!a.suggested_local_id && b.suggested_local_id) return 1;
      if (!a.mapped_local_id && b.mapped_local_id) return -1;
      if (a.mapped_local_id && !b.mapped_local_id) return 1;
      return a.name.localeCompare(b.name);
    });
  }, [ctfdChallenges, wizardCategory, wizardSearch]);

  async function mapFromWizard(challenge: CtfdChallenge) {
    const localId = wizardSelection[challenge.id];
    if (!localId) { pushToast("Select a local challenge first", "warning"); return; }
    try {
      const result = await client.syncChallenge(localId, challenge.id);
      pushToast(result.message || "Mapping created", "success");
      await Promise.all([load(), openWizard()]);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to create mapping", "error");
    }
  }

  async function unmapFromWizard(localId: string) {
    const approved = await confirm({
      title: "Remove mapping?",
      message: `Mapping for ${localId} will be deleted.`,
      confirmText: "Unmap",
      danger: true,
    });
    if (!approved) return;
    try {
      await client.removeChallengeMapping(localId);
      pushToast("Mapping removed", "success");
      await Promise.all([load(), openWizard()]);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to remove mapping", "error");
    }
  }

  // ── Column definitions ──────────────────────────────────────────────

  const suspiciousColumns: Column<SuspiciousSubmission>[] = useMemo(() => [
    { key: "time", header: "Time", className: "w-[140px]", render: (entry) => <span className="text-xs whitespace-nowrap">{formatDateTime(entry.submission_time)}</span> },
    { key: "submitter", header: "Submitter", render: (entry) => {
      const isTeam = Boolean(entry.submitter_team_id || entry.flag_owner_team_id);
      return (
        <div>
          <p className="text-slate-200">{isTeam ? safeString(entry.submitter_team_name, "Unknown team") : entry.submitter_username}</p>
          <p className="text-[11px] text-slate-400">{isTeam ? `by ${entry.submitter_username}` : "submitter"}</p>
        </div>
      );
    }},
    { key: "owner", header: "Flag owner", render: (entry) => {
      const isTeam = Boolean(entry.submitter_team_id || entry.flag_owner_team_id);
      return (
        <div>
          <p className="text-slate-200">{isTeam ? safeString(entry.flag_owner_team_name, "Unknown team") : entry.flag_owner_username}</p>
          <p className="text-[11px] text-slate-400">{isTeam ? "team flag owner" : "flag owner"}</p>
        </div>
      );
    }},
    { key: "challenge", header: "Challenge", render: (entry) => entry.local_challenge_id },
    { key: "ip", header: "IP", className: "w-[110px]", render: (entry) => <span className="font-mono text-[11px]">{entry.ip_address}</span> },
  ], []);

  const mappingColumns: Column<FlagMapping>[] = useMemo(() => [
    { key: "owner", header: "Owner", className: "min-w-[140px]", render: (mapping) => (
      <div>
        <p className="text-slate-200">{mapping.team_name || mapping.username}</p>
        <p className="font-mono text-[11px] text-slate-400">{mapping.user_id}</p>
      </div>
    )},
    { key: "challenge", header: "Challenge", render: (mapping) => <span className="font-medium">{mapping.local_challenge_id}</span> },
    { key: "flag", header: "Flag preview", className: "max-w-[280px]", render: (mapping) => (
      <span className="font-mono text-[11px] text-slate-300 break-all">{mapping.flag_content}</span>
    )},
    { key: "created", header: "Created", className: "w-[150px]", render: (mapping) => <span className="whitespace-nowrap text-[11px]">{formatDateTime(mapping.created_at)}</span> },
    { key: "actions", header: "Actions", className: "w-[90px]", render: (mapping) => (
      <Button variant="danger" size="sm" onClick={() => void deleteFlag(mapping)}>Delete</Button>
    )},
  ], []);

  const challengeColumns: Column<{ localId: string; ctfdId?: number; mapped: boolean; flagsDisabled: boolean }>[] = useMemo(() => [
    { key: "local", header: "Local challenge ID", render: (row) => (
      <span className="font-semibold text-slate-200">{row.localId}</span>
    )},
    { key: "ctfd", header: "CTFd ID", render: (row) => <span className="font-mono">{row.mapped ? `#${row.ctfdId}` : "Not mapped"}</span> },
    { key: "status", header: "Status", className: "w-[180px]", render: (row) => {
      if (row.flagsDisabled) return <Badge tone="danger">Dynamic flags disabled</Badge>;
      return <Badge tone={row.mapped ? "success" : "warning"}>{row.mapped ? "Configured" : "Needs mapping"}</Badge>;
    }},
    { key: "actions", header: "Actions", className: "w-[100px]", render: (row) => {
      if (row.flagsDisabled) return <span className="text-xs text-slate-500">N/A</span>;
      return row.mapped
        ? <Button variant="danger" size="sm" onClick={() => void removeChallengeMapping(row.localId)}>Remove</Button>
        : <span className="text-slate-500">—</span>;
    }},
  ], []);

  const suspiciousRowClass = () => "bg-rose-500/8 hover:bg-rose-500/14";

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="text-xs uppercase tracking-[0.15em] text-slate-400">Dynamic flag system</p>
            <h3 className="mt-1 text-xl text-slate-100">Flag integrity, suspicious submissions, and challenge mapping</h3>
          </div>
          <Button variant="secondary" size="sm" onClick={() => void load()}>Refresh</Button>
        </div>

        {loading ? <Loader label="Loading flag data..." /> : null}

        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard label="Status" value={flagsData?.dynamic_flags_enabled ? "Enabled" : "Disabled"} tone={flagsData?.dynamic_flags_enabled ? "success" : "danger"} />
          <StatCard label="Total flags" value={String(flagsData?.total_flags || 0)} />
          <StatCard label="Users with flags" value={String(flagsData?.total_users || 0)} />
          <StatCard label="Suspicious" value={String(flagsData?.suspicious_total ?? flagsData?.suspicious_submissions?.length ?? 0)} tone="warning" />
        </div>
      </Card>

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-lg text-slate-100">Suspicious submissions</h3>
          <div className="flex gap-2">
            <Button variant="primary" size="sm" onClick={() => void checkSubmissions()}>Check now</Button>
            <Button variant="danger" size="sm" onClick={() => void clearSuspicious()}>Clear history</Button>
          </div>
        </div>

        {suspiciousRows.length === 0 ? (
          <EmptyState title="No suspicious submissions" hint="Automatic detection has not found mismatched flag ownership." />
        ) : (
          <div className="mt-4">
            <Table
              columns={suspiciousColumns}
              data={suspiciousPageRows}
              keyExtractor={(_, i) => `suspicious-${i}`}
              rowClassName={suspiciousRowClass}
              emptyTitle="No suspicious submissions"
            />
            <Pagination page={suspiciousPage} pageCount={suspiciousPageCount} total={suspiciousTotal} onPageChange={setSuspiciousPage} />
          </div>
        )}
      </Card>

      <Card>
        <h3 className="text-lg text-slate-100">Flag mappings</h3>

        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <Input label="Filter by owner" value={flagUserFilter} onChange={(event) => { setFlagUserFilter(event.target.value); setMappingPage(1); }} />
          <Input label="Filter by challenge" value={flagChallengeFilter} onChange={(event) => { setFlagChallengeFilter(event.target.value); setMappingPage(1); }} />
        </div>

        {filteredMappings.length === 0 ? (
          <EmptyState title="No flag mappings" hint="Spawn challenge instances to generate per-owner dynamic flags." />
        ) : (
          <div className="mt-4">
            <Table
              columns={mappingColumns}
              data={mappingPageRows}
              keyExtractor={(mapping) => String(mapping.flag_id)}
              emptyTitle="No flag mappings"
            />
            <Pagination page={mappingPage} pageCount={mappingPageCount} total={filteredMappings.length} onPageChange={setMappingPage} />
          </div>
        )}
      </Card>

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-lg text-slate-100">Challenge ID mapping</h3>
          <Button variant="primary" size="sm" onClick={() => void openWizard()}>Sync wizard</Button>
        </div>

        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <Select label="Local challenge" value={localChallengeToMap} onChange={(event) => setLocalChallengeToMap(event.target.value)}>
            <option value="">Select challenge</option>
            {localChallenges.filter((c) => c.loaded).map((c) => (
              <option key={c.id} value={c.id} disabled={c.disable_dynamic_flags}>
                {c.id}{c.disable_dynamic_flags ? " (flags disabled)" : ""}
              </option>
            ))}
          </Select>
          <Input label="CTFd challenge ID" type="number" min={1} value={ctfdChallengeToMap} onChange={(event) => setCtfdChallengeToMap(event.target.value)} />
          <div className="flex items-end">
            <Button variant="primary" size="sm" className="w-full" onClick={() => void addChallengeMapping()}>Add mapping</Button>
          </div>
        </div>

        {challengeMappingRows.length === 0 ? (
          <EmptyState title="No challenge IDs found" hint="Upload or load challenges first." />
        ) : (
          <div className="mt-4">
            <Table
              columns={challengeColumns}
              data={challengePageRows}
              keyExtractor={(row) => row.localId}
              emptyTitle="No challenge IDs found"
            />
            <Pagination page={challengeMapPage} pageCount={challengePageCount} total={challengeMappingRows.length} onPageChange={setChallengeMapPage} />
          </div>
        )}
      </Card>

      <Modal open={wizardOpen} onClose={() => setWizardOpen(false)} title="CTFd sync wizard" maxWidthClass="max-w-5xl">
        {wizardLoading ? (
          <Loader label="Fetching CTFd challenge catalog..." />
        ) : (
          <>
            <div className="grid gap-3 md:grid-cols-2">
              <Input label="Search CTFd challenges" value={wizardSearch} onChange={(event) => setWizardSearch(event.target.value)} />
              <Select label="Category" value={wizardCategory} onChange={(event) => setWizardCategory(event.target.value)}>
                <option value="">All categories</option>
                {ctfdCategories.map((category) => (<option key={category} value={category}>{category}</option>))}
              </Select>
            </div>

            <p className="mt-3 text-xs text-slate-300">
              {ctfdChallenges.length} CTFd challenge(s) total, {ctfdChallenges.filter((c) => c.mapped_local_id).length} mapped.
            </p>

            {wizardRows.length === 0 ? (
              <EmptyState title="No challenges match the filter" />
            ) : (
              <div className="mt-3 space-y-2">
                {wizardRows.map((challenge) => {
                  const mapped = Boolean(challenge.mapped_local_id);
                  const suggested = Boolean(challenge.suggested_local_id) && !mapped;
                  return (
                    <div key={challenge.id} className="rounded-xl border border-white/10 bg-black/20 p-3 hover:border-violet-300/30 transition-colors">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <p className="text-sm text-slate-100">
                            {challenge.name}
                            {suggested ? <span className="ml-2"><Badge tone="info">Suggested match</Badge></span> : null}
                            {mapped ? <span className="ml-2"><Badge tone="success">Mapped</Badge></span> : null}
                          </p>
                          <p className="mt-1 text-xs text-slate-400">
                            CTFd #{challenge.id} &bull; {safeString(challenge.category, "No category")} &bull; {challenge.value} points
                          </p>
                        </div>
                        {mapped ? (
                          <div className="flex items-center gap-2">
                            <Badge tone="success">Mapped to {challenge.mapped_local_id}</Badge>
                            <Button variant="danger" size="sm" onClick={() => void unmapFromWizard(challenge.mapped_local_id || "")}>Unmap</Button>
                          </div>
                        ) : (
                          <div className="flex flex-wrap items-center gap-2">
                            <select
                              className="rounded-lg border border-white/20 bg-black/35 px-3 py-2 text-xs text-slate-100"
                              value={wizardSelection[challenge.id] || ""}
                              onChange={(event) => setWizardSelection((current) => ({ ...current, [challenge.id]: event.target.value }))}
                            >
                              <option value="">Select local challenge</option>
                              {localChallenges.filter((item) => item.loaded).map((item) => (
                                <option key={item.id} value={item.id} disabled={item.disable_dynamic_flags}>
                                  {item.id}{item.disable_dynamic_flags ? " (flags disabled)" : ""}
                                </option>
                              ))}
                            </select>
                            <Button variant="primary" size="sm" onClick={() => void mapFromWizard(challenge)}>Map</Button>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}
      </Modal>
    </div>
  );
}

function StatCard({ label, value, tone = "neutral" }: { label: string; value: string; tone?: "neutral" | "success" | "warning" | "danger" }) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/20 p-3">
      <p className="text-[11px] uppercase tracking-[0.14em] text-slate-400">{label}</p>
      <p className="mt-1 text-base text-slate-100">{value}</p>
      <div className="mt-2">
        <Badge tone={tone}>{tone}</Badge>
      </div>
    </div>
  );
}
