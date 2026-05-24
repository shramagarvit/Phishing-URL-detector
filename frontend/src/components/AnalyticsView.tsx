import React from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell, PieChart, Pie, Legend
} from 'recharts';
import { BarChart3, Clock, Globe2, Target, HelpCircle } from 'lucide-react';

interface BrandData {
  matched_brand: string;
  count: number;
}

interface HourData {
  hour: string;
  count: number;
}

interface TldData {
  tld: string;
  count: number;
}

interface RiskFactorData {
  flag_name: string;
  flag_severity: string;
  count: number;
}

interface TimelineItem {
  date: string;
  phishing: number;
  safe: number;
  total: number;
}

interface AnalyticsViewProps {
  analytics: {
    most_phished_brands: BrandData[];
    peak_attack_hours: HourData[];
    peak_attack_days: { day: string; count: number }[];
    risky_tlds: TldData[];
    top_risk_factors: RiskFactorData[];
  };
  timeline: TimelineItem[];
}

export const AnalyticsView: React.FC<AnalyticsViewProps> = ({ analytics, timeline }) => {
  
  // Custom tool tip component for recharts to fit Cyber-glass style
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-[#090d16] border border-glass rounded-xl p-3 shadow-2xl backdrop-blur-xl">
          <p className="text-xs text-dim uppercase tracking-wider font-bold mb-1 mono-font">{label}</p>
          {payload.map((entry: any, index: number) => (
            <p key={index} className="text-sm font-semibold uppercase flex items-center gap-2" style={{ color: entry.color }}>
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }}></span>
              {entry.name}: <span className="text-white mono-font">{entry.value}</span>
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  // Pie colors for TLD distribution
  const COLORS = ['#ef4444', '#f59e0b', '#06b6d4', '#8b5cf6', '#ec4899', '#3b82f6', '#10b981', '#14b8a6'];

  return (
    <div className="space-y-6">
      
      {/* Chart Row 1: Scan Activity Timeline */}
      <div className="cyber-card">
        <h3 className="text-md font-bold uppercase tracking-wider glowing-text-cyan mb-1 flex items-center gap-2">
          <BarChart3 className="w-5 h-5" /> Threat Volume Scan Timeline
        </h3>
        <p className="text-xs text-muted mb-6 uppercase tracking-wider">
          Aggregating total clean and malicious URLs resolved daily across the threat console database.
        </p>
        <div className="h-72 w-full">
          {timeline && timeline.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorPhish" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="colorSafe" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" />
                <XAxis dataKey="date" stroke="#6b7280" style={{ fontSize: '10px', fontFamily: 'JetBrains Mono' }} />
                <YAxis stroke="#6b7280" style={{ fontSize: '10px', fontFamily: 'JetBrains Mono' }} />
                <Tooltip content={<CustomTooltip />} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '11px', paddingTop: '10px', textTransform: 'uppercase', fontWeight: 'bold' }} />
                <Area name="Phishing Scans" type="monotone" dataKey="phishing" stroke="#ef4444" fillOpacity={1} fill="url(#colorPhish)" strokeWidth={2} />
                <Area name="Legitimate Scans" type="monotone" dataKey="safe" stroke="#10b981" fillOpacity={1} fill="url(#colorSafe)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-dim text-xs uppercase font-semibold">
              No timeline data logs found
            </div>
          )}
        </div>
      </div>

      {/* Chart Row 2: Hourly and Brand targets */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Hourly distribution */}
        <div className="cyber-card">
          <h3 className="text-md font-bold uppercase tracking-wider glowing-text-cyan mb-1 flex items-center gap-2">
            <Clock className="w-5 h-5" /> Peak Hour Attack Vectors
          </h3>
          <p className="text-xs text-muted mb-6 uppercase tracking-wider">
            Breakdown of malicious URL requests grouped by hour of day (00:00 to 23:00) to find peak operational hours.
          </p>
          <div className="h-64 w-full">
            {analytics.peak_attack_hours && analytics.peak_attack_hours.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={analytics.peak_attack_hours} margin={{ top: 5, right: 5, left: -25, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" />
                  <XAxis dataKey="hour" tickFormatter={(h) => `${h}:00`} stroke="#6b7280" style={{ fontSize: '9px', fontFamily: 'JetBrains Mono' }} />
                  <YAxis stroke="#6b7280" style={{ fontSize: '9px', fontFamily: 'JetBrains Mono' }} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar name="Attacks Detected" dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]}>
                    {analytics.peak_attack_hours.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={index % 2 === 0 ? '#06b6d4' : '#3b82f6'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-dim text-xs uppercase font-semibold">
                No hourly statistics available
              </div>
            )}
          </div>
        </div>

        {/* Most Phished brands */}
        <div className="cyber-card">
          <h3 className="text-md font-bold uppercase tracking-wider glowing-text-cyan mb-1 flex items-center gap-2">
            <Target className="w-5 h-5" /> Brand Impersonation Rankings
          </h3>
          <p className="text-xs text-muted mb-6 uppercase tracking-wider">
            Top targeted global brands hijacked in deceptive subdomain or folder naming schemes.
          </p>
          <div className="h-64 w-full">
            {analytics.most_phished_brands && analytics.most_phished_brands.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  layout="vertical"
                  data={analytics.most_phished_brands}
                  margin={{ top: 5, right: 5, left: -10, bottom: 5 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.02)" />
                  <XAxis type="number" stroke="#6b7280" style={{ fontSize: '9px', fontFamily: 'JetBrains Mono' }} />
                  <YAxis
                    type="category"
                    dataKey="matched_brand"
                    stroke="#ffffff"
                    style={{ fontSize: '10px', fontWeight: 'bold', textTransform: 'uppercase', fontFamily: 'Outfit' }}
                    width={90}
                  />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar name="Spoof Count" dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-dim text-xs uppercase font-semibold">
                No brand spoofing logs present
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Chart Row 3: Risky TLDs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Risky TLD distribution */}
        <div className="cyber-card lg:col-span-2">
          <h3 className="text-md font-bold uppercase tracking-wider glowing-text-cyan mb-1 flex items-center gap-2">
            <Globe2 className="w-5 h-5" /> Abuse TLD Extensions (SQL Aggregation)
          </h3>
          <p className="text-xs text-muted mb-6 uppercase tracking-wider">
            Visualizing top generic Top Level Domains (gTLDs) hosting malicious predictions.
          </p>
          <div className="flex flex-col md:flex-row items-center justify-between gap-6 h-64">
            <div className="h-full w-full md:w-3/5">
              {analytics.risky_tlds && analytics.risky_tlds.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={analytics.risky_tlds}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
                      paddingAngle={3}
                      dataKey="count"
                      nameKey="tld"
                    >
                      {analytics.risky_tlds.map((_, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-dim text-xs uppercase font-semibold">
                  No TLD records located
                </div>
              )}
            </div>

            {/* Manual Legend to fit Cyber Style */}
            <div className="flex-grow w-full md:w-2/5 flex flex-wrap gap-x-6 gap-y-2 overflow-y-auto max-h-56 pr-2">
              {analytics.risky_tlds.map((entry, index) => (
                <div key={index} className="flex items-center gap-2.5 min-w-[90px] text-xs">
                  <span className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: COLORS[index % COLORS.length] }}></span>
                  <span className="font-bold text-white uppercase mono-font">.{entry.tld}</span>
                  <span className="text-dim mono-font">({entry.count})</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Top risk factors triggers count */}
        <div className="cyber-card">
          <h3 className="text-md font-bold uppercase tracking-wider glowing-text-cyan mb-1 flex items-center gap-2">
            <HelpCircle className="w-5 h-5" /> Frequent Risk Signals
          </h3>
          <p className="text-xs text-muted mb-4 uppercase tracking-wider">
            Most frequent structural indicators parsed from threat prediction flags.
          </p>
          <div className="space-y-3 max-h-60 overflow-y-auto pr-1">
            {analytics.top_risk_factors && analytics.top_risk_factors.length > 0 ? (
              analytics.top_risk_factors.map((item, idx) => (
                <div key={idx} className="flex justify-between items-center bg-[#090d16]/40 p-2.5 border border-glass rounded-xl text-xs">
                  <div>
                    <span className="font-bold text-white uppercase block mb-0.5">{item.flag_name}</span>
                    <span className={`px-1.5 py-0.2 rounded font-extrabold uppercase text-[8px] ${
                      item.flag_severity === 'High' 
                        ? 'text-red-400 bg-red-950/20' 
                        : item.flag_severity === 'Medium'
                          ? 'text-amber-400 bg-amber-950/20'
                          : 'text-cyan-400 bg-cyan-950/20'
                    }`}>
                      {item.flag_severity}
                    </span>
                  </div>
                  <span className="font-extrabold text-sm text-cyan-400 mono-font">{item.count}x</span>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-dim uppercase tracking-wider text-xs">
                No risk triggers stored
              </div>
            )}
          </div>
        </div>

      </div>

    </div>
  );
};
