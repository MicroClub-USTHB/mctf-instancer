export function normalizeUtc(value?: string | null): string | null {
  if (!value) {
    return null;
  }
  if (value.endsWith("Z") || value.includes("+")) {
    return value;
  }
  return `${value}Z`;
}

export function formatDateTime(value?: string | null): string {
  const normalized = normalizeUtc(value);
  if (!normalized) {
    return "-";
  }

  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) {
    return "Invalid date";
  }

  return date.toLocaleString();
}

export function formatRelativeRemaining(value?: string | null, now = Date.now()): string {
  const normalized = normalizeUtc(value);
  if (!normalized) {
    return "Unknown";
  }

  const end = new Date(normalized).getTime();
  if (Number.isNaN(end)) {
    return "Invalid date";
  }

  const delta = end - now;
  if (delta <= 0) {
    return "Expired";
  }

  const hours = Math.floor(delta / (1000 * 60 * 60));
  const minutes = Math.floor((delta % (1000 * 60 * 60)) / (1000 * 60));
  const seconds = Math.floor((delta % (1000 * 60)) / 1000);

  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }
  return `${seconds}s`;
}
