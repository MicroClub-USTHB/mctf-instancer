import { Button } from "./Button";

interface PaginationProps {
  page: number;
  pageCount: number;
  total: number;
  onPageChange: (page: number) => void;
}

export function Pagination({ page, pageCount, total, onPageChange }: PaginationProps) {
  const current = Math.min(page, pageCount);
  const start = total === 0 ? 0 : (current - 1) * Math.max(1, Math.ceil(total / pageCount)) + 1;
  const end = Math.min(current * Math.max(1, Math.ceil(total / pageCount)), total);

  return (
    <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-300">
      <p className="text-slate-400">
        {total > 0 ? (
          <>
            <span className="text-slate-200">{start}&ndash;{end}</span> of{" "}
            <span className="text-slate-200">{total}</span>
          </>
        ) : (
          "0 results"
        )}
      </p>
      <div className="flex items-center gap-1.5">
        <Button variant="secondary" size="sm" disabled={current <= 1} onClick={() => onPageChange(1)}>
          First
        </Button>
        <Button variant="secondary" size="sm" disabled={current <= 1} onClick={() => onPageChange(Math.max(1, current - 1))}>
          Prev
        </Button>
        <span className="mx-1 text-slate-400">
          {current} / {pageCount}
        </span>
        <Button variant="secondary" size="sm" disabled={current >= pageCount} onClick={() => onPageChange(Math.min(pageCount, current + 1))}>
          Next
        </Button>
        <Button variant="secondary" size="sm" disabled={current >= pageCount} onClick={() => onPageChange(pageCount)}>
          Last
        </Button>
      </div>
    </div>
  );
}
