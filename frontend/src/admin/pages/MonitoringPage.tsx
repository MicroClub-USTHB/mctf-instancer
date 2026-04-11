import { useCallback, useEffect, useMemo, useState } from "react";
import { Badge } from "../../shared/components/ui/Badge";
import { Button } from "../../shared/components/ui/Button";
import { Card } from "../../shared/components/ui/Card";
import { EmptyState } from "../../shared/components/ui/EmptyState";
import { Loader } from "../../shared/components/ui/Loader";
import { useToast } from "../../shared/hooks/useToast";
import { formatDateTime } from "../../shared/utils/time";
import type { MonitoringContainer, MonitoringInstance, MonitoringSystem } from "../types";
import type { AdminPageProps } from "../types/page";

interface MonitoringPageProps extends AdminPageProps {}

export function MonitoringPage({ client, isActive }: MonitoringPageProps) {
  const { pushToast } = useToast();

  const [loading, setLoading] = useState(false);
  const [system, setSystem] = useState<MonitoringSystem | null>(null);
  const [instances, setInstances] = useState<MonitoringInstance[]>([]);
  const [highUsageOnly, setHighUsageOnly] = useState(false);
  const [expandedInstances, setExpandedInstances] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    if (!isActive) return;
    setLoading(true);
    try {
      const [systemData, instancesData] = await Promise.all([
        client.getMonitoringSystem(),
        client.getMonitoringInstances(),
      ]);
      setSystem(systemData);
      setInstances(instancesData.instances || []);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to load monitoring metrics", "error");
    } finally {
      setLoading(false);
    }
  }, [client, isActive, pushToast]);

  useEffect(() => {
    if (!isActive) return;
    void load();
  }, [isActive, load]);

  const visibleInstances = useMemo(() => {
    const sorted = [...instances].sort((a, b) => b.total_cpu_percent - a.total_cpu_percent);
    if (!highUsageOnly) return sorted;
    return sorted.filter((instance) => {
      const highCpu = instance.total_cpu_percent > 50;
      const highRam = (instance.containers || []).some((c) => c.memory_percent > 80);
      return highCpu || highRam;
    });
  }, [highUsageOnly, instances]);

  function toggleExpand(instanceId: string) {
    setExpandedInstances((prev) => {
      const next = new Set(prev);
      if (next.has(instanceId)) next.delete(instanceId);
      else next.add(instanceId);
      return next;
    });
  }

  const systemMetrics = [
    { label: "Total containers", value: String(system?.total_containers || 0) },
    { label: "Running containers", value: String(system?.running_containers || 0) },
    { label: "Total CPU", value: `${(system?.total_cpu_percent || 0).toFixed(1)}%` },
    { label: "Total memory", value: `${(system?.total_memory_mb || 0).toFixed(0)} MB` },
    { label: "Host CPU cores", value: String(system?.host_cpu_cores || 0) },
    { label: "Host RAM used", value: `${(system?.host_memory_used_mb || 0).toFixed(0)} / ${(system?.host_memory_total_mb || 0).toFixed(0)} MB` },
    { label: "Host RAM %", value: `${(system?.host_memory_percent || 0).toFixed(1)}%` },
    { label: "Last sample", value: formatDateTime(system?.timestamp) },
  ];

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="text-xs uppercase tracking-[0.15em] text-slate-400">Host and container metrics</p>
            <h3 className="mt-1 text-xl text-slate-100">System resource overview</h3>
          </div>
          <Button variant="secondary" size="sm" onClick={() => void load()}>Refresh</Button>
        </div>

        {loading ? <Loader label="Loading monitoring metrics..." /> : null}

        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {systemMetrics.map(({ label, value }) => (
            <div key={label} className="rounded-xl border border-white/10 bg-black/20 p-3 hover:border-violet-300/20 transition-colors">
              <p className="text-[11px] uppercase tracking-[0.14em] text-slate-400">{label}</p>
              <p className="mt-1 text-base text-slate-100 font-semibold">{value}</p>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-lg text-slate-100">Instance resource usage</h3>
            <p className="text-xs text-slate-400">CPU and memory at instance and container granularity</p>
          </div>
          <div className="flex items-center gap-3">
            <label className="inline-flex items-center gap-2 rounded-lg border border-white/15 px-3 py-2 text-xs text-slate-200 cursor-pointer hover:border-violet-300/40 transition-colors">
              <input type="checkbox" checked={highUsageOnly} onChange={(event) => setHighUsageOnly(event.target.checked)} />
              High usage only
            </label>
            {visibleInstances.length > 0 ? (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  if (expandedInstances.size === visibleInstances.length) {
                    setExpandedInstances(new Set());
                  } else {
                    setExpandedInstances(new Set(visibleInstances.map((i) => i.instance_id)));
                  }
                }}
              >
                {expandedInstances.size === visibleInstances.length ? "Collapse all" : "Expand all"}
              </Button>
            ) : null}
          </div>
        </div>

        {visibleInstances.length === 0 ? (
          <EmptyState
            title={instances.length === 0 ? "No running instances" : "No high-usage instances"}
            hint={instances.length === 0 ? "Spawn instances to collect runtime metrics." : "Try disabling the high-usage filter."}
          />
        ) : (
          <div className="space-y-2">
            {visibleInstances.map((instance) => {
              const avgMemoryPercent =
                instance.containers.length > 0
                  ? instance.containers.reduce((sum, c) => sum + c.memory_percent, 0) / instance.containers.length
                  : 0;
              const isExpanded = expandedInstances.has(instance.instance_id);

              return (
                <article
                  key={instance.instance_id}
                  className="rounded-xl border border-white/10 bg-black/20 hover:border-violet-300/30 transition-colors"
                >
                  <button
                    type="button"
                    className="w-full p-3 text-left"
                    onClick={() => toggleExpand(instance.instance_id)}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0 flex-1">
                        <h4 className="text-sm font-semibold text-slate-100">{instance.challenge_name}</h4>
                        <p className="mt-0.5 font-mono text-[11px] text-slate-400 truncate">
                          {instance.owner_name} &bull; {instance.instance_id}
                        </p>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <CpuBadge percent={instance.total_cpu_percent} />
                        <MemoryBadge percent={avgMemoryPercent} mb={instance.total_memory_mb} />
                        <span className="text-[11px] text-slate-400 font-mono">
                          {instance.container_count} container(s)
                          <span className="ml-1 text-slate-500">{isExpanded ? "▾" : "▸"}</span>
                        </span>
                      </div>
                    </div>
                  </button>

                  {isExpanded ? (
                    <div className="border-t border-white/8 px-3 pb-3 space-y-2">
                      {instance.containers.map((container) => (
                        <ContainerDetail key={container.container_id} container={container} />
                      ))}
                    </div>
                  ) : null}
                </article>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
}

function CpuBadge({ percent }: { percent: number }) {
  return (
    <Badge tone={percent > 80 ? "danger" : percent > 50 ? "warning" : "success"}>
      CPU {percent.toFixed(1)}%
    </Badge>
  );
}

function MemoryBadge({ percent, mb }: { percent: number; mb: number }) {
  return (
    <Badge tone={percent > 80 ? "danger" : percent > 60 ? "warning" : "info"}>
      RAM {mb.toFixed(0)} MB
    </Badge>
  );
}

function ContainerDetail({ container }: { container: MonitoringContainer }) {
  return (
    <div className="rounded-lg border border-white/8 bg-black/15 p-2.5 text-xs hover:border-white/15 transition-colors">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm text-slate-100 truncate">{container.container_name}</p>
          <p className="font-mono text-[11px] text-slate-400 truncate">{container.container_id}</p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge tone={container.cpu_percent > 80 ? "danger" : container.cpu_percent > 50 ? "warning" : "success"}>
            CPU {container.cpu_percent.toFixed(1)}%
          </Badge>
          <Badge tone={container.memory_percent > 80 ? "danger" : container.memory_percent > 60 ? "warning" : "info"}>
            RAM {container.memory_usage_mb.toFixed(0)} MB ({container.memory_percent.toFixed(1)}%)
          </Badge>
          <Badge tone="neutral">PIDs {container.pids}</Badge>
        </div>
      </div>
    </div>
  );
}
