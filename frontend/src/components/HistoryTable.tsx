import React, { useState } from 'react';
import { Search, Trash2, Calendar, AlertTriangle, ShieldCheck, ArrowRight, ShieldAlert } from 'lucide-react';

interface HistoryItem {
  id: number;
  url: string;
  hostname: string;
  verdict: 'Phishing' | 'Legitimate';
  risk_score: number;
  domain_age_days: number;
  scanned_at: string;
}

interface HistoryTableProps {
  history: HistoryItem[];
  onSelectUrl: (url: string) => void;
  onClearHistory: () => void;
}

export const HistoryTable: React.FC<HistoryTableProps> = ({ history, onSelectUrl, onClearHistory }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [confirmClear, setConfirmClear] = useState(false);

  // Filter history by search keyword
  const filteredHistory = history.filter(item => 
    item.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.hostname.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleClearClick = () => {
    if (confirmClear) {
      onClearHistory();
      setConfirmClear(false);
    } else {
      setConfirmClear(true);
      setTimeout(() => setConfirmClear(false), 3000); // Reset confirm state after 3s
    }
  };

  return (
    <div className="cyber-card">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6">
        <div>
          <h2 className="text-lg font-bold uppercase tracking-wider glowing-text-cyan flex items-center gap-2">
            <ShieldAlert className="w-5 h-5" /> Historical Scan Registry
          </h2>
          <p className="text-xs text-muted uppercase tracking-wider">
            Review and explore details of previous URL assessments stored in the SQL SQLite repository.
          </p>
        </div>

        {/* Clear History Button */}
        {history.length > 0 && (
          <button
            onClick={handleClearClick}
            className={`flex items-center gap-2 px-4 py-2 border rounded-xl text-xs font-bold uppercase tracking-wider transition-all duration-200 ${
              confirmClear 
                ? 'bg-red-950/20 border-red-500 text-red-400 shadow-[0_0_10px_rgba(239,68,68,0.2)]'
                : 'bg-transparent border-glass text-muted hover:text-red-400 hover:border-red-500/30'
            }`}
          >
            <Trash2 className="w-4 h-4" />
            {confirmClear ? 'CONFIRM DELETION?' : 'Reset Registry'}
          </button>
        )}
      </div>

      {/* Search Filter */}
      <div className="relative mb-6">
        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-dim" />
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Filter by scanned domain keyword or full URL..."
          className="w-full pl-11 pr-4 py-2.5 bg-[#090d16]/70 text-white font-medium border border-glass rounded-xl focus:border-cyan-500/40 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 transition-all duration-300 text-xs md:text-sm mono-font placeholder:text-dim"
        />
      </div>

      {/* History Log Table */}
      {filteredHistory.length === 0 ? (
        <div className="flex flex-col items-center py-10 text-center">
          <Calendar className="w-12 h-12 text-dim mb-3" />
          <p className="text-sm font-semibold uppercase tracking-wider text-muted">No Scan Logs Located</p>
          <p className="text-xs text-dim mt-1">URLs scanned via the live interface will persist in the database logs.</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-glass text-[10px] md:text-xs text-dim uppercase tracking-widest font-bold">
                <th className="py-3 px-4">Resolved Target URL</th>
                <th className="py-3 px-4">Verdict</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Domain Age</th>
                <th className="py-3 px-4">Scan Time</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-glass text-xs md:text-sm">
              {filteredHistory.map((item) => {
                const isPhish = item.verdict === 'Phishing';
                return (
                  <tr 
                    key={item.id} 
                    className="hover:bg-[#0a101c]/40 transition-colors duration-150 group"
                  >
                    {/* URL Link */}
                    <td className="py-3.5 px-4 font-medium max-w-[200px] md:max-w-[400px] truncate text-white mono-font">
                      {item.url}
                    </td>

                    {/* Verdict Badge */}
                    <td className="py-3.5 px-4">
                      <span className={`px-2.5 py-1 rounded-md text-[10px] font-extrabold uppercase tracking-wide flex items-center gap-1.5 w-fit border ${
                        isPhish
                          ? 'bg-red-500/10 border-red-500/20 text-red-400'
                          : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                      }`}>
                        {isPhish ? (
                          <AlertTriangle className="w-3.5 h-3.5" />
                        ) : (
                          <ShieldCheck className="w-3.5 h-3.5" />
                        )}
                        {item.verdict}
                      </span>
                    </td>

                    {/* Risk Score */}
                    <td className={`py-3.5 px-4 font-bold mono-font ${
                      isPhish ? 'text-red-400' : item.risk_score > 20 ? 'text-amber-400' : 'text-emerald-400'
                    }`}>
                      {item.risk_score.toFixed(1)}%
                    </td>

                    {/* Domain Age */}
                    <td className="py-3.5 px-4 text-muted mono-font">
                      {item.domain_age_days} days
                    </td>

                    {/* Scanned At */}
                    <td className="py-3.5 px-4 text-dim mono-font">
                      {new Date(item.scanned_at).toLocaleDateString()} {new Date(item.scanned_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>

                    {/* Re-scan button */}
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => onSelectUrl(item.url)}
                        className="inline-flex items-center justify-center p-1.5 rounded-lg border border-glass bg-transparent text-dim group-hover:text-cyan-400 group-hover:border-cyan-500/30 transition-all duration-200"
                        title="Reload in Live Scanner"
                      >
                        <ArrowRight className="w-4 h-4 transform group-hover:translate-x-0.5 transition-transform duration-200" />
                      </button>
                    </td>

                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
