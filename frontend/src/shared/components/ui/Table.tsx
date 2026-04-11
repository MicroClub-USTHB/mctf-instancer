import type { ReactNode } from "react";
import { classNames } from "../../utils/format";

export interface Column<T> {
  key: string;
  header: string;
  className?: string;
  render: (row: T, index: number) => ReactNode;
}

interface TableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (row: T, index: number) => string;
  loading?: boolean;
  emptyTitle?: string;
  emptyHint?: string;
  rowClassName?: (row: T, index: number) => string;
}

export function Table<T>({
  columns,
  data,
  keyExtractor,
  loading = false,
  emptyTitle = "No results",
  emptyHint,
  rowClassName,
}: TableProps<T>) {
  if (loading) {
    return (
      <div className="flex items-center gap-3 rounded-xl border border-white/10 bg-black/20 px-4 py-8 text-sm text-slate-300">
        <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-violet-300/35 border-t-violet-300" />
        <span>Loading...</span>
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-white/18 bg-black/20 px-4 py-6 text-center">
        <p className="text-base text-slate-100">{emptyTitle}</p>
        {emptyHint ? <p className="mt-1 text-sm text-slate-400">{emptyHint}</p> : null}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-white/10">
      <table className="min-w-full text-left text-xs text-slate-200">
        <thead className="sticky top-0 z-10 bg-white/[0.07] text-[11px] uppercase tracking-[0.12em] text-slate-300">
          <tr>
            {columns.map((col) => (
              <th key={col.key} className={classNames("px-3 py-2.5 font-semibold", col.className)}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-white/8">
          {data.map((row, index) => (
            <tr
              key={keyExtractor(row, index)}
              className={classNames(
                "transition-colors hover:bg-white/[0.06]",
                index % 2 === 0 ? "bg-transparent" : "bg-white/[0.02]",
                rowClassName?.(row, index),
              )}
            >
              {columns.map((col) => (
                <td key={col.key} className={classNames("px-3 py-2.5", col.className)}>
                  {col.render(row, index)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
