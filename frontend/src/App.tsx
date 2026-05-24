import { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Scanner } from './components/Scanner';
import { ResultsView } from './components/ResultsView';
import { DashboardStats } from './components/DashboardStats';
import { AnalyticsView } from './components/AnalyticsView';
import { HistoryTable } from './components/HistoryTable';
import { ShieldCheck, Terminal, AlertCircle, Database, Sparkles } from 'lucide-react';

const API_URL = "http://127.0.0.1:8000";

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

interface StatsData {
  total_scanned: number;
  phishing_count: number;
  safe_count: number;
  phishing_rate: number;
  timeline: any[];
}

function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'analytics' | 'history'>('scanner');
  const [apiStatus, setApiStatus] = useState<'online' | 'offline'>('offline');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  
  // Dashboard Metrics & SQL Analytics data structures
  const [stats, setStats] = useState<StatsData>({
    total_scanned: 0,
    phishing_count: 0,
    safe_count: 0,
    phishing_rate: 0.0,
    timeline: []
  });
  
  const [analytics, setAnalytics] = useState({
    most_phished_brands: [],
    peak_attack_hours: [],
    peak_attack_days: [],
    risky_tlds: [],
    top_risk_factors: []
  });
  
  const [history, setHistory] = useState([]);
  const [error, setError] = useState<string | null>(null);

  // Initial Fetch helper
  const fetchAllData = async () => {
    try {
      // 1. Fetch Stats
      const statsRes = await fetch(`${API_URL}/api/stats`);
      if (statsRes.ok) {
        const statsJson = await statsRes.json();
        setStats(statsJson);
        setApiStatus('online');
      }

      // 2. Fetch Analytics
      const analyticsRes = await fetch(`${API_URL}/api/analytics`);
      if (analyticsRes.ok) {
        const analyticsJson = await analyticsRes.json();
        setAnalytics(analyticsJson);
      }

      // 3. Fetch Logs History
      const historyRes = await fetch(`${API_URL}/api/history`);
      if (historyRes.ok) {
        const historyJson = await historyRes.json();
        setHistory(historyJson);
      }
      
      setError(null);
    } catch (err) {
      console.error("Backend fetch error: ", err);
      setApiStatus('offline');
    }
  };

  // Run on startup
  useEffect(() => {
    fetchAllData();
    
    // Background polling interval to keep stats and network status active (every 8 seconds)
    const interval = setInterval(() => {
      fetchAllData();
    }, 8000);
    
    return () => clearInterval(interval);
  }, []);

  // Dispatch Scan Call
  const handleScan = async (url: string) => {
    setIsScanning(true);
    setError(null);
    try {
      const response = await fetch(`${API_URL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url })
      });
      
      if (!response.ok) {
        const errJson = await response.json();
        throw new Error(errJson.detail || "Scan request failed.");
      }
      
      const data = await response.json();
      setScanResult(data);
      setActiveTab('scanner'); // Shift to scanner view to see report
      
      // Instantly refetch statistical aggregates to update charts in real-time!
      fetchAllData();
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Failed to establish secure communications with Aegis core.");
    } finally {
      setIsScanning(false);
    }
  };

  // Reset database logs
  const handleClearHistory = async () => {
    try {
      const response = await fetch(`${API_URL}/api/history`, {
        method: 'DELETE'
      });
      if (response.ok) {
        setScanResult(null);
        fetchAllData();
      } else {
        throw new Error("Failed to clear database logs.");
      }
    } catch (err: any) {
      setError(err.message || "Error clearing database logs.");
    }
  };

  // Click history row re-scan handler
  const handleSelectUrl = (url: string) => {
    setActiveTab('scanner');
    handleScan(url);
  };

  // Seed DB handler
  const handleSeedDatabase = async () => {
    try {
      setError(null);
      const response = await fetch(`${API_URL}/api/seed`, {
        method: 'POST'
      });
      if (response.ok) {
        fetchAllData();
      } else {
        throw new Error("Failed to seed database.");
      }
    } catch (err: any) {
      setError(err.message || "Error seeding database.");
    }
  };

  return (
    <div className="cyber-container min-h-screen flex flex-col">
      {/* Central Header */}
      <Header activeTab={activeTab} setActiveTab={setActiveTab} apiStatus={apiStatus} />

      {/* Global Error Banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-5 py-3 rounded-xl mb-6 flex items-center gap-3">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span className="text-xs md:text-sm font-semibold tracking-wide uppercase">
            [System Alert]: {error}
          </span>
        </div>
      )}

      {/* Main Tab Panels Routing */}
      <main className="flex-grow">
        
        {/* TAB 1: SCANNER CONSOLE */}
        {activeTab === 'scanner' && (
          <div className="space-y-6">
            
            {/* Real-time counters summary strip */}
            <DashboardStats stats={stats} />
            
            <Scanner onScan={handleScan} isScanning={isScanning} />
            
            {/* Show scan output if present */}
            {scanResult && <ResultsView result={scanResult} />}
            
            {/* Safe Welcome message if no scan run yet */}
            {!scanResult && !isScanning && (
              <div className="cyber-card py-10 flex flex-col items-center justify-center text-center">
                <div className="w-16 h-16 rounded-full bg-cyan-950/20 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mb-4 animate-pulse-slow">
                  <ShieldCheck className="w-8 h-8" />
                </div>
                <h3 className="text-md font-bold uppercase tracking-wider text-white mb-1">Scanner Engine Idle</h3>
                <p className="text-xs text-muted max-w-sm">
                  Waiting for URL inputs. Paste any address above or trigger quick presets to test classification accuracy.
                </p>
              </div>
            )}
            
          </div>
        )}

        {/* TAB 2: ADVANCED THREAT INTELLIGENCE ANALYTICS */}
        {activeTab === 'analytics' && (
          <div className="space-y-6">
            <DashboardStats stats={stats} />
            
            {/* DB Empty Seeder Prompt Helper */}
            {stats.total_scanned === 0 ? (
              <div className="cyber-card py-12 flex flex-col items-center justify-center text-center">
                <Database className="w-12 h-12 text-dim mb-4" />
                <h3 className="text-md font-bold uppercase tracking-wider text-white mb-2">Threat Intelligence Database Empty</h3>
                <p className="text-xs text-muted max-w-md mb-6 leading-relaxed">
                  No scan logs located. To see premium visual threat graphs, please seed the SQL database with 90+ realistic scans!
                </p>
                <button onClick={handleSeedDatabase} className="cyber-btn flex items-center gap-2">
                  <Sparkles className="w-4 h-4" /> Seed Intel Database
                </button>
              </div>
            ) : (
              <AnalyticsView analytics={analytics} timeline={stats.timeline} />
            )}
          </div>
        )}

        {/* TAB 3: THREAT LOGS TABLE REGISTRY */}
        {activeTab === 'history' && (
          <div className="space-y-6">
            <HistoryTable
              history={history}
              onSelectUrl={handleSelectUrl}
              onClearHistory={handleClearHistory}
            />
          </div>
        )}

      </main>

      {/* Footer Branding */}
      <footer className="mt-12 py-6 border-t border-glass flex flex-col md:flex-row items-center justify-between gap-4 text-dim text-xs uppercase tracking-widest font-bold">
        <span>© 2026 AegisThreat AI. ALL RIGHTS SECURED.</span>
        <span className="flex items-center gap-1.5 font-semibold">
          <Terminal className="w-4 h-4 text-cyan-500" /> SYSTEM CORE ONLINE
        </span>
      </footer>
    </div>
  );
}

export default App;
