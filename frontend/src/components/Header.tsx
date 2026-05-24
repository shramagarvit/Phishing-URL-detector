import React from 'react';
import { ShieldAlert, Activity, Database, Terminal } from 'lucide-react';

interface HeaderProps {
  activeTab: 'scanner' | 'analytics' | 'history';
  setActiveTab: (tab: 'scanner' | 'analytics' | 'history') => void;
  apiStatus: 'online' | 'offline';
}

export const Header: React.FC<HeaderProps> = ({ activeTab, setActiveTab, apiStatus }) => {
  return (
    <header className="cyber-card mb-8 flex flex-col md:flex-row items-center justify-between gap-4 py-4 px-6 border-b border-glass">
      {/* Brand Header */}
      <div className="flex items-center gap-3">
        <div className="relative">
          <ShieldAlert className="w-10 h-10 glowing-text-cyan animate-float" />
          <span className="absolute -bottom-1 -right-1 flex h-3.5 w-3.5">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
              apiStatus === 'online' ? 'bg-emerald-400' : 'bg-red-400'
            }`}></span>
            <span className={`relative inline-flex rounded-full h-3.5 w-3.5 ${
              apiStatus === 'online' ? 'bg-emerald-500' : 'bg-red-500'
            }`}></span>
          </span>
        </div>
        <div>
          <h1 className="text-xl md:text-2xl font-extrabold tracking-wider bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400 bg-clip-text text-transparent uppercase">
            AegisThreat AI
          </h1>
          <p className="text-xs text-dim uppercase tracking-widest font-semibold flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-cyan-500" /> Phishing URL Engine v2.4
          </p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav className="flex items-center bg-[#090d16] border border-glass rounded-xl p-1 gap-1">
        <button
          onClick={() => setActiveTab('scanner')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs md:text-sm font-semibold tracking-wider uppercase transition-all duration-200 ${
            activeTab === 'scanner'
              ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-400 border border-cyan-500/30'
              : 'text-muted hover:text-white border border-transparent'
          }`}
        >
          <Activity className="w-4 h-4" />
          Live Scanner
        </button>
        <button
          onClick={() => setActiveTab('analytics')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs md:text-sm font-semibold tracking-wider uppercase transition-all duration-200 ${
            activeTab === 'analytics'
              ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-400 border border-cyan-500/30'
              : 'text-muted hover:text-white border border-transparent'
          }`}
        >
          <Database className="w-4 h-4" />
          SQL Analytics
        </button>
        <button
          onClick={() => setActiveTab('history')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs md:text-sm font-semibold tracking-wider uppercase transition-all duration-200 ${
            activeTab === 'history'
              ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-400 border border-cyan-500/30'
              : 'text-muted hover:text-white border border-transparent'
          }`}
        >
          <Terminal className="w-4 h-4" />
          Scan Logs
        </button>
      </nav>

      {/* Network Status Info */}
      <div className="hidden lg:flex items-center gap-3 bg-[#0a101c]/60 px-4 py-2 border border-glass rounded-xl">
        <span className={`w-2.5 h-2.5 rounded-full ${apiStatus === 'online' ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`}></span>
        <span className="text-xs uppercase tracking-wider font-semibold text-muted">
          API Core: <span className={apiStatus === 'online' ? 'text-emerald-400' : 'text-red-400'}>{apiStatus === 'online' ? 'ONLINE' : 'OFFLINE'}</span>
        </span>
      </div>
    </header>
  );
};
