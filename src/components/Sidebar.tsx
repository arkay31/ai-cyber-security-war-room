"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  ShieldAlert,
  Radar,
  BrainCircuit,
  Network,
  BarChart3,
  FileText,
  Settings,
  Shield,
} from "lucide-react";

const menuItems = [
  {
    name: "Dashboard",
    icon: LayoutDashboard,
    href: "/",
  },
  {
    name: "Incidents",
    icon: ShieldAlert,
    href: "/incidents",
  },
  {
    name: "Threat Intelligence",
    icon: Radar,
    href: "/threat-intelligence",
  },
  {
    name: "AI Analyst",
    icon: BrainCircuit,
    href: "/ai-analyst",
  },
  {
    name: "Attack Graph",
    icon: Network,
    href: "/attack-graph",
  },
  {
    name: "Analytics",
    icon: BarChart3,
    href: "/analytics",
  },
  {
    name: "Reports",
    icon: FileText,
    href: "/reports",
  },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-64 flex-col border-r border-zinc-800 bg-zinc-950">
      {/* Logo */}
      <div className="flex h-20 items-center gap-3 border-b border-zinc-800 px-6">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/10">
          <Shield className="h-6 w-6 text-emerald-400" />
        </div>

        <div>
          <h1 className="text-sm font-bold tracking-wide text-white">
            WAR ROOM
          </h1>
          <p className="text-[10px] tracking-widest text-zinc-500">
            CYBER DEFENSE
          </p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 px-3 py-6">
        <p className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-widest text-zinc-600">
          Operations
        </p>

        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);

          return (
            <Link
              key={item.name}
              href={item.href}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-3 text-sm transition ${
                isActive
                  ? "bg-emerald-500/10 text-emerald-400 font-medium"
                  : "text-zinc-400 hover:bg-zinc-900 hover:text-white"
              }`}
            >
              <Icon className="h-4 w-4" />
              <span>{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* Bottom */}
      <div className="border-t border-zinc-800 p-3">
        <Link
          href="/"
          className="flex w-full items-center gap-3 rounded-lg px-3 py-3 text-sm text-zinc-400 transition hover:bg-zinc-900 hover:text-white"
        >
          <Settings className="h-4 w-4" />
          Settings
        </Link>
      </div>
    </aside>
  );
}