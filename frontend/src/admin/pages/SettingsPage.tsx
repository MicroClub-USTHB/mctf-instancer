import { useCallback, useEffect, useMemo, useState } from "react";
import { Badge } from "../../shared/components/ui/Badge";
import { Button } from "../../shared/components/ui/Button";
import { Card } from "../../shared/components/ui/Card";
import { EmptyState } from "../../shared/components/ui/EmptyState";
import { Input } from "../../shared/components/ui/Input";
import { Loader } from "../../shared/components/ui/Loader";
import { Select } from "../../shared/components/ui/Select";
import { useConfirm } from "../../shared/hooks/useConfirm";
import { useToast } from "../../shared/hooks/useToast";
import type { SettingMeta } from "../types";
import type { AdminPageProps } from "../types/page";

interface SettingsPageProps extends AdminPageProps {}

const SETTINGS_SECTIONS: Array<{ title: string; keys: string[] }> = [
  { title: "Instance settings", keys: ["INSTANCE_TIMEOUT", "MAX_INSTANCES_PER_USER", "MAX_INSTANCES_PER_TEAM"] },
  { title: "Resource limits", keys: ["CONTAINER_MAX_MEMORY", "CONTAINER_MAX_CPU", "CONTAINER_PIDS_LIMIT"] },
  { title: "Network and ports", keys: ["PORT_RANGE_START", "PORT_RANGE_END", "NETWORK_ISOLATION_ENABLED", "NETWORK_ICC_DISABLED", "PUBLIC_HOST"] },
  {
    title: "Traefik routing",
    keys: [
      "TRAEFIK_REDIS_ENABLED",
      "TRAEFIK_REDIS_URL",
      "TRAEFIK_BASE_DOMAIN",
      "TRAEFIK_BACKEND_HOST",
      "TRAEFIK_HTTP_ENTRYPOINT",
      "TRAEFIK_TCP_ENTRYPOINT",
      "TRAEFIK_TCP_EXTERNAL_PORT",
      "TRAEFIK_HTTP_TLS_OPTIONS",
      "TRAEFIK_TCP_TLS_OPTIONS",
      "TRAEFIK_BLOCK_ALL_ADDRESS",
      "TRAEFIK_DASHBOARD_USERS",
      "TRAEFIK_PERMANENT_KEYS_FILE",
      "TRAEFIK_PERMANENT_KEYS_JSON",
    ],
  },
  { title: "Features", keys: ["DYNAMIC_FLAGS_ENABLED", "FLAG_PREFIX"] },
  { title: "Authentication", keys: ["AUTH_MODE", "CTFD_URL", "CTFD_API_KEY"] },
  { title: "Forensics", keys: ["FORENSICS_AUTO_CAPTURE", "FORENSICS_RETENTION_HOURS"] },
];

export function SettingsPage({ client, isActive }: SettingsPageProps) {
  const { pushToast } = useToast();
  const { confirm } = useConfirm();

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [settings, setSettings] = useState<Record<string, SettingMeta>>({});
  const [draft, setDraft] = useState<Record<string, unknown>>({});

  const load = useCallback(async () => {
    if (!isActive) {
      return;
    }

    setLoading(true);
    try {
      const payload = await client.getSettings();
      setSettings(payload.settings || {});

      const nextDraft: Record<string, unknown> = {};
      Object.entries(payload.settings || {}).forEach(([key, meta]) => {
        nextDraft[key] = meta.value;
      });
      setDraft(nextDraft);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to load settings", "error");
    } finally {
      setLoading(false);
    }
  }, [client, isActive, pushToast]);

  useEffect(() => {
    if (!isActive) {
      return;
    }
    void load();
  }, [isActive, load]);

  const changedCount = useMemo(() => {
    return Object.entries(settings).filter(([key, meta]) => String(meta.value) !== String(draft[key])).length;
  }, [draft, settings]);

  async function saveChanges() {
    const updates: Record<string, unknown> = {};

    Object.entries(settings).forEach(([key, meta]) => {
      const current = meta.value;
      const next = draft[key];

      if (String(current) !== String(next)) {
        updates[key] = next;
      }
    });

    if (Object.keys(updates).length === 0) {
      pushToast("No setting changes to save", "info");
      return;
    }

    setSaving(true);
    try {
      const result = await client.saveSettings(updates);
      if (result.success) {
        pushToast(`Saved ${Object.keys(result.applied || {}).length} setting(s)`, "success");
      } else {
        const errors = Object.entries(result.errors || {})
          .map(([key, value]) => `${key}: ${value}`)
          .join(", ");
        pushToast(errors ? `Saved with errors: ${errors}` : "Saved with partial errors", "warning");
      }
      await load();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to save settings", "error");
    } finally {
      setSaving(false);
    }
  }

  async function resetSetting(key: string) {
    const approved = await confirm({
      title: `Reset ${key}?`,
      message: "The database override will be removed and default value restored.",
      confirmText: "Reset",
      danger: true,
    });

    if (!approved) {
      return;
    }

    try {
      const result = await client.resetSetting(key);
      pushToast(`Reset ${key} to ${result.default_value ?? "default"}`, "success");
      await load();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to reset setting", "error");
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="text-xs uppercase tracking-[0.15em] text-slate-400">Global configuration</p>
            <h3 className="mt-1 text-xl text-slate-100">MCTF 5.0 runtime settings</h3>
            <p className="mt-1 text-sm text-slate-300">
              Values with a highlighted override marker are persisted in the database and applied on startup.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge tone={changedCount > 0 ? "warning" : "neutral"}>{changedCount} pending change(s)</Badge>
            <Button variant="secondary" onClick={() => void load()}>
              Refresh
            </Button>
            <Button variant="primary" disabled={saving} onClick={() => void saveChanges()}>
              Save all
            </Button>
          </div>
        </div>
      </Card>

      {loading ? <Loader label="Loading settings..." /> : null}

      {!loading && Object.keys(settings).length === 0 ? (
        <Card>
          <EmptyState title="No settings loaded" hint="Check admin credentials and API availability." />
        </Card>
      ) : (
        SETTINGS_SECTIONS.map((section) => {
          const rows = section.keys.filter((key) => settings[key]);

          if (rows.length === 0) {
            return null;
          }

          return (
            <Card key={section.title}>
              <h3 className="text-lg text-slate-100">{section.title}</h3>
              <div className="mt-3 grid gap-3 lg:grid-cols-2">
                {rows.map((key) => {
                  const setting = settings[key];
                  const value = draft[key];

                  return (
                    <SettingField
                      key={key}
                      settingKey={key}
                      meta={setting}
                      value={value}
                      onChange={(nextValue) => {
                        setDraft((current) => ({
                          ...current,
                          [key]: nextValue,
                        }));
                      }}
                      onReset={() => {
                        void resetSetting(key);
                      }}
                    />
                  );
                })}
              </div>
            </Card>
          );
        })
      )}
    </div>
  );
}

function SettingField({
  settingKey,
  meta,
  value,
  onChange,
  onReset,
}: {
  settingKey: string;
  meta: SettingMeta;
  value: unknown;
  onChange: (value: unknown) => void;
  onReset: () => void;
}) {
  const changed = String(meta.value) !== String(value);

  return (
    <div className="rounded-xl border border-white/10 bg-black/20 p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        {meta.has_override ? <Badge tone="info">Override</Badge> : <Badge tone="neutral">Default</Badge>}
        {changed ? <Badge tone="warning">Modified</Badge> : null}
      </div>

      <p className="text-sm text-slate-100">{meta.label}</p>
      <p className="font-mono text-[11px] text-slate-400">{settingKey}</p>

      <div className="mt-3">
        {meta.type === "bool" ? (
          <label className="inline-flex items-center gap-2 rounded-lg border border-white/15 px-3 py-2 text-sm text-slate-100">
            <input
              type="checkbox"
              checked={Boolean(value === true || String(value).toLowerCase() === "true")}
              onChange={(event) => onChange(event.target.checked)}
            />
            {Boolean(value === true || String(value).toLowerCase() === "true") ? "Enabled" : "Disabled"}
          </label>
        ) : null}

        {meta.type === "select" ? (
          <Select value={String(value ?? "")} onChange={(event) => onChange(event.target.value)}>
            {(meta.options || []).map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </Select>
        ) : null}

        {meta.type === "int" || meta.type === "float" ? (
          <Input
            type="number"
            min={meta.min}
            max={meta.max}
            step={meta.type === "float" ? "0.1" : "1"}
            value={String(value ?? "")}
            onChange={(event) => onChange(event.target.value)}
          />
        ) : null}

        {meta.type === "str" ? (
          <Input value={String(value ?? "")} onChange={(event) => onChange(event.target.value)} />
        ) : null}
      </div>

      {meta.has_override ? (
        <Button className="mt-3" variant="danger" onClick={onReset}>
          Reset to default
        </Button>
      ) : null}
    </div>
  );
}
