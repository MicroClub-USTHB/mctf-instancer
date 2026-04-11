export function classNames(...tokens: Array<string | false | null | undefined>): string {
  return tokens.filter(Boolean).join(" ");
}

export function formatBytes(bytes?: number | null): string {
  if (bytes === undefined || bytes === null || Number.isNaN(bytes)) {
    return "-";
  }

  if (bytes < 1024) {
    return `${bytes} B`;
  }

  const kb = bytes / 1024;
  if (kb < 1024) {
    return `${kb.toFixed(1)} KB`;
  }

  return `${(kb / 1024).toFixed(1)} MB`;
}

export function encodePathSegments(path: string): string {
  return path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
}

export function safeString(value: unknown, fallback = "-"): string {
  if (value === null || value === undefined) {
    return fallback;
  }
  const text = String(value);
  return text.trim() ? text : fallback;
}
