import React from 'react';
import { ShieldCheck, ShieldAlert, Activity, Cpu } from 'lucide-react';

interface StatsData {
  total_scanned: number;
  phishing_count: number;
  safe_count: number;
  phishing_rate: number;
}

interface DashboardStatsProps {
  stats: StatsData;
}

export const DashboardStats: React.FC<DashboardStatsProps> = ({ stats }) => {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
      
      {/* Total Scanned */}
      <div className="cyber-card flex items-center gap-4 py-4 px-5">
        <div className="w-10 h-10 rounded-xl bg-cyan-950/20 border border-cyan-500/15 flex items-center justify-center text-cyan-400">
          <Activity className="w-5 h-5" />
        </div>
        <div>
          <span className="text-[10px] uppercase font-bold tracking-widest text-dim block">Total URLs Scanned</span>
          <span className="text-xl md:text-2xl font-extrabold tracking-tight text-white mono-font">
            {stats.total_scanned}
          </span>
        </div>
      </div>

      {/* Phishing Rate */}
      <div className="cyber-card flex items-center gap-4 py-4 px-5 border-red-500/10 hover:border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.02)]">
        <div className="w-10 h-10 rounded-xl bg-red-950/20 border border-red-500/15 flex items-center justify-center text-red-400">
          <ShieldAlert className="w-5 h-5" />
        </div>
        <div>
          <span className="text-[10px] uppercase font-bold tracking-widest text-dim block">Phishing Rate</span>
          <span className="text-xl md:text-2xl font-extrabold tracking-tight text-red-400 mono-font">
            {stats.phishing_rate.toFixed(1)}%
          </span>
        </div>
      </div>

      {/* Safe Scans */}
      <div className="cyber-card flex items-center gap-4 py-4 px-5 border-emerald-500/10 hover:border-emerald-500/20 shadow-[0_0_15px_rgba(16,185,129,0.02)]">
        <div className="w-10 h-10 rounded-xl bg-emerald-950/20 border border-emerald-500/15 flex items-center justify-center text-emerald-400">
          <ShieldCheck className="w-5 h-5" />
        </div>
        <div>
          <span className="text-[10px] uppercase font-bold tracking-widest text-dim block">Legitimate URLs</span>
          <span className="text-xl md:text-2xl font-extrabold tracking-tight text-emerald-400 mono-font">
            {stats.safe_count}
          </span>
        </div>
      </div>

      {/* Threat Response Latency */}
      <div className="cyber-card flex items-center gap-4 py-4 px-5">
        <div className="w-10 h-10 rounded-xl bg-indigo-950/20 border border-indigo-500/15 flex items-center justify-center text-indigo-400">
          <Cpu className="w-5 h-5" />
        </div>
        <div>
          <span className="text-[10px] uppercase font-bold tracking-widest text-dim block">Inference Speed</span>
          <span className="text-xl md:text-2xl font-extrabold tracking-tight text-indigo-400 mono-font">
            &lt; 3.5ms
          </span>
        </div>
      </div>

    </div>
  );
};
