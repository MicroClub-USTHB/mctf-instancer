interface LoaderProps {
  label?: string;
}

export function Loader({ label = "Loading..." }: LoaderProps) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-zinc-300/15 bg-zinc-900/45 px-4 py-3 text-sm text-zinc-300">
      <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-violet-300/35 border-t-violet-300" />
      <span>{label}</span>
    </div>
  );
}
