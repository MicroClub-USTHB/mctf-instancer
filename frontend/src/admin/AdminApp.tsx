import { useEffect, useMemo, useState } from "react";
import { createAdminClient } from "../shared/api/adminApi";
import { PageShell } from "../shared/components/layout/PageShell";
import { Badge } from "../shared/components/ui/Badge";
import { Button } from "../shared/components/ui/Button";
import { Card } from "../shared/components/ui/Card";
import { EmptyState } from "../shared/components/ui/EmptyState";
import { Input } from "../shared/components/ui/Input";
import { Loader } from "../shared/components/ui/Loader";
import { Tabs } from "../shared/components/ui/Tabs";
import { useToast } from "../shared/hooks/useToast";
import { ChallengesPage } from "./pages/ChallengesPage";
import { DashboardPage } from "./pages/DashboardPage";
import { FlagsPage } from "./pages/FlagsPage";
import { LogsPage } from "./pages/LogsPage";
import { MonitoringPage } from "./pages/MonitoringPage";
import { SettingsPage } from "./pages/SettingsPage";

type AdminTab = "dashboard" | "logs" | "flags" | "challenges" | "monitoring" | "settings";

const TABS: Array<{ id: AdminTab; label: string; icon: string }> = [
  { id: "dashboard", label: "Dashboard", icon: "📊" },
  { id: "logs", label: "Logs", icon: "📜" },
  { id: "flags", label: "Flags", icon: "🚩" },
  { id: "challenges", label: "Challenges", icon: "📦" },
  { id: "monitoring", label: "Monitoring", icon: "📈" },
  { id: "settings", label: "Settings", icon: "⚙️" },
];

export function AdminApp() {
  const { pushToast } = useToast();

  const [verifying, setVerifying] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [adminKeyInput, setAdminKeyInput] = useState("");
  const [adminKey, setAdminKey] = useState(localStorage.getItem("admin_key") || "");
  const [tab, setTab] = useState<AdminTab>("dashboard");

  const client = useMemo(() => createAdminClient(() => adminKey), [adminKey]);

  useEffect(() => {
    const hash = window.location.hash.replace("#", "") as AdminTab;
    if (TABS.some((entry) => entry.id === hash)) {
      setTab(hash);
    }
  }, []);

  useEffect(() => {
    window.location.hash = tab;
  }, [tab]);

  useEffect(() => {
    if (!adminKey) {
      return;
    }

    void verifyKey(adminKey, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function verifyKey(candidate: string, silent = false) {
    setVerifying(true);

    try {
      const tempClient = createAdminClient(() => candidate);
      await tempClient.getStats();

      setAdminKey(candidate);
      setAuthenticated(true);
      localStorage.setItem("admin_key", candidate);
      if (!silent) {
        pushToast("Admin authentication successful", "success");
      }
      return true;
    } catch (error) {
      setAuthenticated(false);
      setAdminKey("");
      localStorage.removeItem("admin_key");
      if (!silent) {
        pushToast(error instanceof Error ? error.message : "Invalid admin key", "error");
      }
      return false;
    } finally {
      setVerifying(false);
    }
  }

  async function login() {
    const candidate = adminKeyInput.trim();
    if (!candidate) {
      pushToast("Enter the admin key first", "warning");
      return;
    }

    const ok = await verifyKey(candidate);
    if (ok) {
      setAdminKeyInput("");
    }
  }

  function logout() {
    setAuthenticated(false);
    setAdminKey("");
    setAdminKeyInput("");
    localStorage.removeItem("admin_key");
    pushToast("Admin session closed", "info");
  }

  return (
    <PageShell
      title="MCTF 5.0 Administrator Console"
      subtitle="Operate teams, lifecycle policy, forensics, and platform observability for MCTF 5.0"
      actions={
        <>
          <a href="/" className="inline-flex">
            <Button variant="secondary">User page</Button>
          </a>
          <Badge tone={authenticated ? "success" : "danger"}>{authenticated ? "Authenticated" : "Not authenticated"}</Badge>
          {authenticated ? (
            <Button variant="danger" onClick={logout}>
              Sign out
            </Button>
          ) : null}
        </>
      }
    >
      {!authenticated ? (
        <Card className="mx-auto w-full max-w-3xl">
          <div className="space-y-4">
            <div>
              <p className="text-xs uppercase tracking-[0.15em] text-slate-400">Admin authentication</p>
              <h2 className="mt-1 text-2xl text-slate-100">Unlock the control center</h2>
              <p className="mt-1 text-sm text-slate-300">Enter the server admin key. It is stored in browser localStorage for this device only.</p>
            </div>

            <div className="grid gap-3 sm:grid-cols-[1fr_auto] sm:items-end">
              <Input
                label="Admin key"
                type="password"
                value={adminKeyInput}
                onChange={(event) => setAdminKeyInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    void login();
                  }
                }}
              />
              <Button variant="primary" size="md" onClick={() => void login()} disabled={verifying}>
                Access dashboard
              </Button>
            </div>

            {verifying ? <Loader label="Verifying admin key..." /> : null}
          </div>
        </Card>
      ) : (
        <>
          <Tabs tabs={TABS} activeTab={tab} onChange={(nextTab) => setTab(nextTab as AdminTab)} />

          {verifying ? <Loader label="Refreshing admin session..." /> : null}

          {tab === "dashboard" ? <DashboardPage client={client} isActive={tab === "dashboard"} /> : null}
          {tab === "logs" ? <LogsPage client={client} isActive={tab === "logs"} /> : null}
          {tab === "flags" ? <FlagsPage client={client} isActive={tab === "flags"} /> : null}
          {tab === "challenges" ? <ChallengesPage client={client} isActive={tab === "challenges"} /> : null}
          {tab === "monitoring" ? <MonitoringPage client={client} isActive={tab === "monitoring"} /> : null}
          {tab === "settings" ? <SettingsPage client={client} isActive={tab === "settings"} /> : null}
        </>
      )}

      {!authenticated && !verifying ? (
        <Card>
          <EmptyState title="Admin key required" hint="Only authorized users can access the admin panel." />
        </Card>
      ) : null}

      <footer className="border-t border-white/12 pt-4 text-center text-xs uppercase tracking-[0.16em] text-slate-500">
        MCTF 5.0 Instancer
      </footer>
    </PageShell>
  );
}
