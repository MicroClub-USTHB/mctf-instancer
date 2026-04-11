import { useCallback, useEffect, useMemo, useState } from "react";
import { Badge } from "../../shared/components/ui/Badge";
import { Button } from "../../shared/components/ui/Button";
import { Card } from "../../shared/components/ui/Card";
import { EmptyState } from "../../shared/components/ui/EmptyState";
import { Input } from "../../shared/components/ui/Input";
import { Loader } from "../../shared/components/ui/Loader";
import { Textarea } from "../../shared/components/ui/Textarea";
import { useConfirm } from "../../shared/hooks/useConfirm";
import { useToast } from "../../shared/hooks/useToast";
import type { ChallengeFileNode, ChallengeItem, ChallengeSettingsItem } from "../types";
import type { AdminPageProps } from "../types/page";
import { classNames, safeString } from "../../shared/utils/format";

interface ChallengesPageProps extends AdminPageProps {}

export function ChallengesPage({ client, isActive }: ChallengesPageProps) {
  const { pushToast } = useToast();
  const { confirm } = useConfirm();

  const [loading, setLoading] = useState(false);
  const [challenges, setChallenges] = useState<ChallengeItem[]>([]);
  const [settings, setSettings] = useState<Record<string, ChallengeSettingsItem>>({});

  const [selectedChallenge, setSelectedChallenge] = useState("");
  const [fileTree, setFileTree] = useState<ChallengeFileNode[]>([]);
  const [selectedFilePath, setSelectedFilePath] = useState("");
  const [fileContent, setFileContent] = useState("");
  const [fileLoading, setFileLoading] = useState(false);
  const [fileSaving, setFileSaving] = useState(false);
  const [unsavedChanges, setUnsavedChanges] = useState(false);
  const [newFilePath, setNewFilePath] = useState("");

  const load = useCallback(async () => {
    if (!isActive) {
      return;
    }

    setLoading(true);
    try {
      const [challengeList, settingsPayload] = await Promise.all([client.getChallenges(), client.getChallengeSettings()]);
      setChallenges(challengeList || []);
      setSettings(settingsPayload.settings || {});
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to load challenge manager", "error");
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

  useEffect(() => {
    const handler = (event: BeforeUnloadEvent) => {
      if (!unsavedChanges) {
        return;
      }
      event.preventDefault();
      event.returnValue = "";
    };

    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [unsavedChanges]);

  const selectedChallengeData = useMemo(() => {
    return challenges.find((challenge) => challenge.id === selectedChallenge);
  }, [challenges, selectedChallenge]);

  async function ensureCanDiscardUnsaved(): Promise<boolean> {
    if (!unsavedChanges) {
      return true;
    }

    return confirm({
      title: "Discard unsaved edits?",
      message: "You have unsaved file content changes.",
      confirmText: "Discard",
      danger: true,
    });
  }

  async function loadTree(challengeId: string) {
    try {
      const payload = await client.getChallengeFiles(challengeId);
      setFileTree(payload.files || []);
    } catch (error) {
      setFileTree([]);
      pushToast(error instanceof Error ? error.message : "Failed to load challenge files", "error");
    }
  }

  async function handleUpload(file: File) {
    if (!file.name.endsWith(".zip")) {
      pushToast("Only .zip files are accepted", "warning");
      return;
    }

    try {
      pushToast("Uploading challenge archive...", "info");
      const response = await client.uploadChallenge(file);
      pushToast(response.message || "Challenge uploaded", "success");
      await load();
      if (response.challenge_id) {
        await selectChallenge(response.challenge_id);
      }
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Upload failed", "error");
    }
  }

  async function selectChallenge(challengeId: string) {
    const canContinue = await ensureCanDiscardUnsaved();
    if (!canContinue) {
      return;
    }

    setSelectedChallenge(challengeId);
    setSelectedFilePath("");
    setFileContent("");
    setUnsavedChanges(false);
    setNewFilePath("");
    await loadTree(challengeId);
  }

  async function openFile(path: string) {
    if (!selectedChallenge) {
      return;
    }

    const canContinue = await ensureCanDiscardUnsaved();
    if (!canContinue) {
      return;
    }

    setFileLoading(true);
    try {
      const payload = await client.readChallengeFile(selectedChallenge, path);
      setSelectedFilePath(path);
      setFileContent(payload.content || "");
      setUnsavedChanges(false);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to open file", "error");
    } finally {
      setFileLoading(false);
    }
  }

  async function closeEditor() {
    const canContinue = await ensureCanDiscardUnsaved();
    if (!canContinue) {
      return;
    }

    setSelectedChallenge("");
    setSelectedFilePath("");
    setFileContent("");
    setUnsavedChanges(false);
    setFileTree([]);
  }

  async function saveFile() {
    if (!selectedChallenge || !selectedFilePath) {
      return;
    }

    setFileSaving(true);
    try {
      const response = await client.writeChallengeFile(selectedChallenge, selectedFilePath, fileContent);
      pushToast(response.message || "File saved", "success");
      setUnsavedChanges(false);
      if (selectedFilePath.endsWith("instance.toml")) {
        await load();
      }
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to save file", "error");
    } finally {
      setFileSaving(false);
    }
  }

  async function createNewFile() {
    if (!selectedChallenge) {
      return;
    }

    const path = newFilePath.trim();
    if (!path) {
      pushToast("Enter a relative path for the new file", "warning");
      return;
    }

    try {
      const response = await client.writeChallengeFile(selectedChallenge, path, "");
      pushToast(response.message || "File created", "success");
      setNewFilePath("");
      await loadTree(selectedChallenge);
      await openFile(path);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to create file", "error");
    }
  }

  async function deleteCurrentFile() {
    if (!selectedChallenge || !selectedFilePath) {
      return;
    }

    const approved = await confirm({
      title: "Delete file?",
      message: `${selectedFilePath} will be permanently removed.`,
      confirmText: "Delete",
      danger: true,
    });

    if (!approved) {
      return;
    }

    try {
      const response = await client.deleteChallengeFile(selectedChallenge, selectedFilePath);
      pushToast(response.message || "File deleted", "success");
      setSelectedFilePath("");
      setFileContent("");
      setUnsavedChanges(false);
      await loadTree(selectedChallenge);
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to delete file", "error");
    }
  }

  async function toggleChallenge(challengeId: string, isActive: boolean) {
    try {
      const response = await client.toggleChallenge(challengeId, isActive);
      pushToast(response.message || "Challenge status updated", "success");
      await load();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to toggle challenge", "error");
      await load();
    }
  }

  async function reloadChallenge(challengeId: string) {
    try {
      const response = await client.reloadChallenge(challengeId);
      pushToast(response.message || "Challenge reloaded", response.success ? "success" : "warning");
      await load();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to reload challenge", "error");
    }
  }

  async function deleteChallenge(challengeId: string) {
    const approved = await confirm({
      title: "Delete challenge directory?",
      message: `${challengeId} and all contained files will be deleted.`,
      confirmText: "Delete challenge",
      danger: true,
    });

    if (!approved) {
      return;
    }

    try {
      const response = await client.deleteChallenge(challengeId);
      pushToast(response.message || "Challenge deleted", "success");
      if (selectedChallenge === challengeId) {
        await closeEditor();
      }
      await load();
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "Failed to delete challenge", "error");
    }
  }

  const challengeCards = challenges.map((challenge) => {
    const status = challengeStatus(challenge, settings[challenge.id]);

    return (
      <article
        key={challenge.id}
        className={classNames(
          "rounded-xl border p-3 transition",
          selectedChallenge === challenge.id ? "border-violet-300/40 bg-violet-950/30" : "border-white/10 bg-black/20",
        )}
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-base text-slate-100">{challenge.id}</p>
            <p className="font-mono text-[11px] text-slate-400">folder: {challenge.folder}</p>
            <div className="mt-2 flex flex-wrap gap-2">
              <Badge tone={status.tone}>{status.label}</Badge>
              <Badge tone={status.active ? "success" : "danger"}>{status.active ? "Active" : "Inactive"}</Badge>
              {challenge.disable_dynamic_flags ? <Badge tone="danger">Flags disabled</Badge> : null}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <label className="inline-flex items-center gap-2 rounded-lg border border-white/15 px-3 py-2 text-xs text-slate-200">
              <input
                type="checkbox"
                checked={status.active}
                onChange={(event) => {
                  void toggleChallenge(challenge.id, event.target.checked);
                }}
              />
              Active
            </label>
            <Button variant="primary" onClick={() => void selectChallenge(challenge.id)}>
              Edit files
            </Button>
            <Button variant="secondary" onClick={() => void reloadChallenge(challenge.id)}>
              Reload
            </Button>
            <Button variant="danger" onClick={() => void deleteChallenge(challenge.id)}>
              Delete
            </Button>
          </div>
        </div>
      </article>
    );
  });

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="text-xs uppercase tracking-[0.15em] text-slate-400">Challenge manager</p>
            <h3 className="mt-1 text-xl text-slate-100">Upload, activate, and edit challenge packages</h3>
          </div>
          <Button variant="secondary" onClick={() => void load()}>
            Refresh
          </Button>
        </div>

        <label className="mt-4 block rounded-xl border border-dashed border-white/25 bg-black/20 p-4 text-center transition hover:border-violet-300/45">
          <input
            type="file"
            accept=".zip"
            className="hidden"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) {
                void handleUpload(file);
                event.target.value = "";
              }
            }}
          />
          <p className="text-sm text-slate-200">
            <strong>Upload challenge zip</strong> (must include instance.toml and docker-compose.yaml)
          </p>
          <p className="mt-1 text-xs text-slate-400">Click this area to choose a file.</p>
        </label>

        {loading ? <Loader label="Loading challenge inventory..." /> : null}

        {!loading && challengeCards.length === 0 ? (
          <EmptyState title="No challenge directories" hint="Upload a .zip package to create a challenge." />
        ) : (
          <div className="mt-4 space-y-2">{challengeCards}</div>
        )}
      </Card>

      <Card>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="text-xs uppercase tracking-[0.15em] text-slate-400">File editor</p>
            <h3 className="mt-1 text-xl text-slate-100">{selectedChallengeData ? `Editing ${selectedChallengeData.id}` : "Select a challenge"}</h3>
          </div>
          {selectedChallenge ? (
            <Button variant="secondary" onClick={() => void closeEditor()}>
              Close editor
            </Button>
          ) : null}
        </div>

        {!selectedChallenge ? (
          <EmptyState title="No challenge selected" hint="Choose a challenge above and click Edit files." />
        ) : (
          <div className="grid gap-4 xl:grid-cols-[340px_minmax(0,1fr)]">
            <div className="rounded-xl border border-white/10 bg-black/20 p-3">
              <div className="space-y-2">
                <Input label="New file path" placeholder="path/to/file.txt" value={newFilePath} onChange={(event) => setNewFilePath(event.target.value)} />
                <Button className="w-full" variant="secondary" onClick={() => void createNewFile()}>
                  Create file
                </Button>
              </div>

              <div className="mt-4 max-h-[520px] overflow-auto rounded-lg border border-white/10 bg-black/15 p-2">
                {fileTree.length === 0 ? (
                  <p className="text-xs text-slate-400">No files available.</p>
                ) : (
                  fileTree.map((node) => (
                    <TreeNode
                      key={node.path}
                      node={node}
                      selectedPath={selectedFilePath}
                      onFileSelect={(path) => {
                        void openFile(path);
                      }}
                    />
                  ))
                )}
              </div>
            </div>

            <div className="rounded-xl border border-white/10 bg-black/20 p-3">
              {!selectedFilePath ? (
                <EmptyState title="No file selected" hint="Pick a file from the tree to start editing." />
              ) : (
                <>
                  <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <p className="font-mono text-xs text-slate-400">{selectedFilePath}</p>
                      {unsavedChanges ? <Badge tone="warning">Unsaved changes</Badge> : <Badge tone="success">Saved</Badge>}
                    </div>
                    <div className="flex gap-2">
                      <Button variant="primary" disabled={fileSaving || fileLoading} onClick={() => void saveFile()}>
                        Save
                      </Button>
                      <Button variant="danger" disabled={fileSaving || fileLoading} onClick={() => void deleteCurrentFile()}>
                        Delete
                      </Button>
                    </div>
                  </div>

                  {fileLoading ? <Loader label="Loading file content..." /> : null}

                  <Textarea
                    value={fileContent}
                    onChange={(event) => {
                      setFileContent(event.target.value);
                      setUnsavedChanges(true);
                    }}
                    className="min-h-[420px] font-mono text-xs"
                  />
                </>
              )}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

function challengeStatus(challenge: ChallengeItem, setting?: ChallengeSettingsItem): {
  label: string;
  tone: "success" | "warning" | "danger";
  active: boolean;
} {
  const active = setting?.is_active !== false;

  if (!challenge.has_config) {
    return {
      label: "Missing instance.toml",
      tone: "danger",
      active,
    };
  }

  if (!challenge.has_compose) {
    return {
      label: "Missing docker-compose",
      tone: "danger",
      active,
    };
  }

  if (challenge.loaded) {
    return {
      label: "Loaded",
      tone: "success",
      active,
    };
  }

  return {
    label: "Not loaded",
    tone: "warning",
    active,
  };
}

function TreeNode({
  node,
  selectedPath,
  onFileSelect,
}: {
  node: ChallengeFileNode;
  selectedPath: string;
  onFileSelect: (path: string) => void;
}) {
  if (node.type === "directory") {
    return (
      <details className="rounded-md px-1 py-1 text-xs text-slate-200" open>
        <summary className="cursor-pointer">📁 {node.name}</summary>
        <div className="ml-3 mt-1 space-y-1 border-l border-white/10 pl-2">
          {(node.children || []).map((child) => (
            <TreeNode key={child.path} node={child} selectedPath={selectedPath} onFileSelect={onFileSelect} />
          ))}
        </div>
      </details>
    );
  }

  const disabled = node.editable === false;

  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onFileSelect(node.path)}
      className={classNames(
        "block w-full rounded-md px-2 py-1 text-left text-xs transition",
        selectedPath === node.path ? "bg-violet-950/40 text-violet-100" : "text-slate-200 hover:bg-white/8",
        disabled ? "cursor-not-allowed opacity-50" : "",
      )}
      title={safeString(node.path)}
    >
      📄 {node.name}
    </button>
  );
}
