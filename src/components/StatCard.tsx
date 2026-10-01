import { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string;
  description: string;
  icon: LucideIcon;
  severity?: "critical" | "high" | "normal";
}

export default function StatCard({
  title,
  value,
  description,
  icon: Icon,
  severity = "normal",
}: StatCardProps) {
  const iconStyle = {
    critical: "text-red-400 bg-red-500/10",
    high: "text-orange-400 bg-orange-500/10",
    normal: "text-emerald-400 bg-emerald-500/10",
  };

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5 transition hover:border-zinc-700">
      <div className="flex items-start justify-between">
        
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">
            {title}
          </p>

          <p className="mt-2 text-3xl font-bold tracking-tight text-white">
            {value}
          </p>

          <p className="mt-2 text-xs text-zinc-500">
            {description}
          </p>
        </div>

        <div
          className={`flex h-10 w-10 items-center justify-center rounded-lg ${iconStyle[severity]}`}
        >
          <Icon className="h-5 w-5" />
        </div>

      </div>
    </div>
  );
}