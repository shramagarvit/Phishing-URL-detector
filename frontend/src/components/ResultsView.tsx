import { useState } from 'react';
import { ShieldCheck, ShieldAlert, Calendar, Hash, Compass } from 'lucide-react';

interface RiskFlag {
  flag_name: string;
  flag_severity: 'Low' | 'Medium' | 'High';
  description: string;
}

interface ScanResult {
  url: string;
  verdict: 'Phishing' | 'Legitimate';
  risk_score: number;
  domain_age_days: number;
  explanation: string;
  flags: RiskFlag[];
  features: Record<string, number>;
  metadata: {
    hostname: string;
    matched_brand: string | null;
    tld: string;
  };
  scanned_at: string;
}

interface ResultsViewProps {
  result: ScanResult;
}

export const ResultsView: React.FC<ResultsViewProps> = ({ result }) => {
  const [activeTab, setActiveTab] = useState<'explanation' | 'features'>('explanation');
  
  const isMalicious = result.verdict === 'Phishing';
  const score = result.risk_score;
  
  // Dynamic color bindings based on risk score
  const getThemeColors = () => {
    if (score < 30) return {
      text: 'glowing-text-emerald',
      border: 'border-emerald-500/30',
      bgLight: 'bg-emerald-950/10',
      stroke: '#10b981',
      bgGlow: 'shadow-[0_0_20px_rgba(16,185,129,0.15)]'
    };
    if (score < 70) return {
      text: 'glowing-text-amber',
      border: 'border-amber-500/30',
      bgLight: 'bg-amber-950/10',
      stroke: '#f59e0b',
      bgGlow: 'shadow-[0_0_20px_rgba(245,158,11,0.15)]'
    };
    return {
      text: 'glowing-text-crimson',
      border: 'border-red-500/30',
      bgLight: 'bg-red-950/10',
      stroke: '#ef4444',
      bgGlow: 'shadow-[0_0_20px_rgba(239,68,68,0.15)]'
    };
  };

  const theme = getThemeColors();

  // SVG parameters for the radial gauge
  const radius = 60;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className={`cyber-card border ${theme.border} ${theme.bgGlow} animate-pulse-slow mb-8`}>
      <div className="flex flex-col lg:flex-row items-center gap-8 py-2">
        
        {/* Circular Risk score radial gauge */}
        <div className="relative flex-shrink-0 flex items-center justify-center">
          <svg className="w-40 h-40">
            {/* Background track circle */}
            <circle
              className="text-[#090d16]"
              strokeWidth={strokeWidth}
              stroke="currentColor"
              fill="transparent"
              r={radius}
              cx="80"
              cy="80"
            />
            {/* Fore ground colored progress circle */}
            <circle
              className="progress-ring__circle"
              strokeWidth={strokeWidth}
              strokeDasharray={`${circumference} ${circumference}`}
              strokeDashoffset={strokeDashoffset}
              stroke={theme.stroke}
              fill="transparent"
              r={radius}
              cx="80"
              cy="80"
              strokeLinecap="round"
            />
          </svg>
          <div className="absolute flex flex-col items-center justify-center">
            <span className="text-3xl font-extrabold tracking-tighter mono-font">
              {score.toFixed(1)}%
            </span>
            <span className="text-[10px] text-dim uppercase tracking-widest font-bold">Risk Index</span>
          </div>
        </div>

        {/* Verdict Details Panel */}
        <div className="flex-grow text-center lg:text-left">
          <div className="flex flex-wrap items-center justify-center lg:justify-start gap-3 mb-3">
            <span className={`px-4 py-1.5 rounded-full border text-xs md:text-sm font-extrabold tracking-wider uppercase flex items-center gap-2 ${
              isMalicious 
                ? 'bg-red-500/10 border-red-500/30 text-red-400' 
                : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
            }`}>
              {isMalicious ? (
                <>
                  <ShieldAlert className="w-4.5 h-4.5" />
                  Phishing Threat Detected
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4.5 h-4.5" />
                  Legitimate Address
                </>
              )}
            </span>
            <span className="text-xs text-dim uppercase font-bold tracking-widest mono-font flex items-center gap-1">
              <Calendar className="w-3.5 h-3.5" /> Checked: {new Date(result.scanned_at).toLocaleTimeString()}
            </span>
          </div>

          <h3 className="text-lg md:text-xl font-bold break-all text-white mono-font mb-3 selection:bg-cyan-500/30">
            {result.url}
          </h3>

          <div className="bg-[#090d16]/80 border border-glass rounded-xl p-4 text-sm md:text-base text-gray-300 leading-relaxed max-w-3xl">
            {result.explanation}
          </div>
        </div>
      </div>

      <hr className="border-glass my-6" />

      {/* Tabs for detail view */}
      <div className="flex border-b border-glass mb-6">
        <button
          onClick={() => setActiveTab('explanation')}
          className={`pb-3 px-4 font-bold uppercase tracking-wider text-xs md:text-sm border-b-2 transition-all duration-200 ${
            activeTab === 'explanation' 
              ? 'border-cyan-500 text-cyan-400' 
              : 'border-transparent text-muted hover:text-white'
          }`}
        >
          Risk Indicators ({result.flags.length})
        </button>
        <button
          onClick={() => setActiveTab('features')}
          className={`pb-3 px-4 font-bold uppercase tracking-wider text-xs md:text-sm border-b-2 transition-all duration-200 ${
            activeTab === 'features' 
              ? 'border-cyan-500 text-cyan-400' 
              : 'border-transparent text-muted hover:text-white'
          }`}
        >
          Model Input Vector (33 Features)
        </button>
      </div>

      {/* RISK INDICATORS TAB PANEL */}
      {activeTab === 'explanation' && (
        <div>
          {result.flags.length === 0 ? (
            <div className="flex flex-col items-center py-6 text-center">
              <ShieldCheck className="w-12 h-12 text-emerald-400 mb-3" />
              <p className="text-sm font-semibold uppercase tracking-wider text-emerald-400">Zero Risk Indicators Triggered</p>
              <p className="text-xs text-dim mt-1">This URL is structurally identical to high-trust corporate pages.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {result.flags.map((flag, idx) => (
                <div key={idx} className="bg-[#090d16]/60 border border-glass rounded-xl p-4 flex gap-4 items-start">
                  <div className={`w-2.5 h-2.5 rounded-full mt-1.5 flex-shrink-0 animate-pulse ${
                    flag.flag_severity === 'High' 
                      ? 'bg-red-500 shadow-[0_0_8px_#ef4444]' 
                      : flag.flag_severity === 'Medium' 
                        ? 'bg-amber-500 shadow-[0_0_8px_#f59e0b]' 
                        : 'bg-cyan-500 shadow-[0_0_8px_#06b6d4]'
                  }`} />
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-bold text-sm text-white uppercase tracking-wider">{flag.flag_name}</span>
                      <span className={`px-2 py-0.5 rounded text-[9px] font-extrabold uppercase ${
                        flag.flag_severity === 'High' 
                          ? 'bg-red-500/10 text-red-400 border border-red-500/20' 
                          : flag.flag_severity === 'Medium' 
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' 
                            : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                      }`}>
                        {flag.flag_severity} Risk
                      </span>
                    </div>
                    <p className="text-xs md:text-sm text-muted leading-relaxed">{flag.description}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* METRIC EXPLORER TAB PANEL */}
      {activeTab === 'features' && (
        <div>
          <p className="text-xs text-muted mb-4 uppercase tracking-widest">
            Detailed view of mathematical properties extracted from the URL. Model utilizes normalized forms of these parameters.
          </p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            
            {/* Domain Age */}
            <div className="bg-[#090d16]/50 border border-glass rounded-xl p-3">
              <span className="text-[10px] text-dim uppercase tracking-wider font-bold block mb-1 flex items-center gap-1">
                <Calendar className="w-3.5 h-3.5 text-cyan-500" /> Domain Age
              </span>
              <span className="text-sm font-bold text-white mono-font">{result.domain_age_days} Days</span>
            </div>

            {/* URL Length */}
            <div className="bg-[#090d16]/50 border border-glass rounded-xl p-3">
              <span className="text-[10px] text-dim uppercase tracking-wider font-bold block mb-1 flex items-center gap-1">
                <Hash className="w-3.5 h-3.5 text-cyan-500" /> URL Character Length
              </span>
              <span className="text-sm font-bold text-white mono-font">{result.features.url_len} chars</span>
            </div>

            {/* Subdomain depth */}
            <div className="bg-[#090d16]/50 border border-glass rounded-xl p-3">
              <span className="text-[10px] text-dim uppercase tracking-wider font-bold block mb-1 flex items-center gap-1">
                <Compass className="w-3.5 h-3.5 text-cyan-500" /> Subdomain depth
              </span>
              <span className="text-sm font-bold text-white mono-font">{result.features.num_subdomains} levels</span>
            </div>

            {/* Entropy */}
            <div className="bg-[#090d16]/50 border border-glass rounded-xl p-3">
              <span className="text-[10px] text-dim uppercase tracking-wider font-bold block mb-1 flex items-center gap-1">
                <Hash className="w-3.5 h-3.5 text-cyan-500" /> Shannon Entropy
              </span>
              <span className="text-sm font-bold text-white mono-font">{result.features.entropy.toFixed(3)}</span>
            </div>

            {/* Digit ratio */}
            <div className="bg-[#090d16]/50 border border-glass rounded-xl p-3">
              <span className="text-[10px] text-dim uppercase tracking-wider font-bold block mb-1">Hostname Digit ratio</span>
              <span className="text-sm font-bold text-white mono-font">{(result.features.digit_ratio_host * 100).toFixed(1)}%</span>
            </div>

            {/* Special char count */}
            <div className="bg-[#090d16]/50 border border-glass rounded-xl p-3">
              <span className="text-[10px] text-dim uppercase tracking-wider font-bold block mb-1">Special character count</span>
              <span className="text-sm font-bold text-white mono-font">{result.features.num_special_chars} symbols</span>
            </div>

            {/* Longest word */}
            <div className="bg-[#090d16]/50 border border-glass rounded-xl p-3">
              <span className="text-[10px] text-dim uppercase tracking-wider font-bold block mb-1">Longest alphabetical word</span>
              <span className="text-sm font-bold text-white mono-font">{result.features.longest_word_len} letters</span>
            </div>

            {/* vowel consonant ratio */}
            <div className="bg-[#090d16]/50 border border-glass rounded-xl p-3">
              <span className="text-[10px] text-dim uppercase tracking-wider font-bold block mb-1">Vowel-Consonant ratio</span>
              <span className="text-sm font-bold text-white mono-font">{result.features.vowel_consonant_ratio.toFixed(2)}</span>
            </div>

          </div>
        </div>
      )}
    </div>
  );
};
