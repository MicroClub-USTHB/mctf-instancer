import type { ReactNode } from "react";
import { classNames } from "../../utils/format";

export interface TabDefinition {
  id: string;
  label: string;
  icon?: string;
}

interface TabsProps {
  tabs: TabDefinition[];
  activeTab: string;
  onChange: (tab: string) => void;
  rightSlot?: ReactNode;
}

export function Tabs({ tabs, activeTab, onChange, rightSlot }: TabsProps) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-2xl border border-white/12 bg-black/30 p-2">
      <div className="flex flex-wrap items-center gap-2">
        {tabs.map((tab) => {
          const active = tab.id === activeTab;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => onChange(tab.id)}
              className={classNames(
                "rounded-xl border px-3 py-2 text-xs font-semibold uppercase tracking-[0.12em] transition",
                active
                  ? "border-violet-300/45 bg-violet-950/40 text-violet-100"
                  : "border-white/20 bg-white/5 text-slate-200 hover:border-white/35 hover:bg-white/10",
              )}
            >
              {tab.icon ? <span className="mr-1.5">{tab.icon}</span> : null}
              {tab.label}
            </button>
          );
        })}
      </div>
      {rightSlot}
    </div>
  );
}
