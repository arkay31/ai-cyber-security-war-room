"use client";

import { useEffect, useState } from "react";
import { Bell, Search, Circle, Play, CheckCircle2, AlertCircle } from "lucide-react";
import { api, HealthStatus } from "@/lib/api";

export default function Topbar() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [seeding, setSeeding] = useState(false);
  const [seedSuccess, setSeedSuccess] = useState(false);

  useEffect(() => {
    let isMounted = true;
    api
      .getHealth()
      .then((data) => {
        if (isMounted) setHealth(data);
      })
      .catch(() => {
        if (isMounted) setHealth(null);
      });
    return () => {
      isMounted = false;
    };
  }, []);

  const handleSeedAttack = async () => {
    try {
      setSeeding(true);
      const res = await api.simulateDemoAttack();
      setSeedSuccess(true);
      setTimeout(() => {
        setSeedSuccess(false);
        if (res?.incident_id) {
          window.location.href = `/incidents/${res.incident_id}`;
        } else {
          window.location.reload();
        }
      }, 1000);
    } catch (e) {
      console.error("Failed to simulate attack:", e);
      alert("Failed to simulate attack scenario. Ensure backend server is running.");
    } finally {
      setSeeding(false);
    }
  };

  const isOnline = health?.status === "healthy";

  return (
    <header className="fixed left-64 right-0 top-0 z-30 flex h-20 items-center justify-between border-b border-zinc-800 bg-zinc-950/95 px-8 backdrop-blur">
      <div>
        <p className="text-xs uppercase tracking-widest text-zinc-500">
          Security Operations Center
        </p>

        <h2 className="mt-1 text-lg font-semibold text-white">
          AI Cyber Security War Room
        </h2>
      </div>

      <div className="flex items-center gap-5">
        {/* Synthetic Attack Seed Action */}
        <button
          onClick={handleSeedAttack}
          disabled={seeding}
          className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-300 transition hover:bg-red-500/20 disabled:opacity-50"
          title="Seed realistic multi-stage attack scenarios into the database"
        >
          {seedSuccess ? (
            <>
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              <span className="text-emerald-400">Scenarios Ingested!</span>
            </>
          ) : (
            <>
              <Play className="h-3.5 w-3.5 fill-red-400 text-red-400" />
              <span>{seeding ? "Ingesting Attacks..." : "Simulate SOC Attacks"}</span>
            </>
          )}
        </button>

        {/* System status */}
        <div
          className={`flex items-center gap-2 rounded-full border px-4 py-2 ${
            isOnline
              ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-400"
              : "border-yellow-500/20 bg-yellow-500/5 text-yellow-400"
          }`}
        >
          <Circle
            className={`h-2 w-2 ${
              isOnline
                ? "fill-emerald-400 text-emerald-400"
                : "fill-yellow-400 text-yellow-400"
            }`}
          />
          <span className="text-xs font-medium">
            {isOnline ? "FASTAPI + POSTGRES LIVE" : "BACKEND CONNECTING..."}
          </span>
        </div>

        {/* Notifications */}
        <button className="relative text-zinc-400 transition hover:text-white">
          <Bell className="h-5 w-5" />
          <span className="absolute -right-1 -top-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white">
            3
          </span>
        </button>
      </div>
    </header>
  );
}