import React, { useState, useEffect } from 'react';
import { Search, Loader2, Sparkles } from 'lucide-react';

interface ScannerProps {
  onScan: (url: string) => void;
  isScanning: boolean;
}

const DISPATCH_MESSAGES = [
  "Resolving DNS target...",
  "Computing Shannon entropy metrics...",
  "Running brand spoofing checklist...",
  "Calculating vowel-consonant ratios...",
  "Querying WHOIS domain age records...",
  "Extracting TLD abuse rankings...",
  "Scaling 33 lexical variables...",
  "Feeding vector to Random Forest model...",
  "Evaluating threat probability score..."
];

export const Scanner: React.FC<ScannerProps> = ({ onScan, isScanning }) => {
  const [urlInput, setUrlInput] = useState('');
  const [loadingMsgIdx, setLoadingMsgIdx] = useState(0);

  useEffect(() => {
    let timer: number;
    if (isScanning) {
      setLoadingMsgIdx(0);
      timer = setInterval(() => {
        setLoadingMsgIdx((prev) => (prev + 1) % DISPATCH_MESSAGES.length);
      }, 700);
    }
    return () => clearInterval(timer);
  }, [isScanning]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    onScan(urlInput.trim());
  };

  const handleQuickPaste = (sampleUrl: string) => {
    setUrlInput(sampleUrl);
    onScan(sampleUrl);
  };

  return (
    <div className={`cyber-card mb-8 ${isScanning ? 'scanner-active border-cyan-500/40' : ''}`}>
      <h2 className="text-lg font-bold uppercase tracking-wider glowing-text-cyan mb-2 flex items-center gap-2">
        <Sparkles className="w-5 h-5 text-cyan-400" />
        Live URL Threat Evaluation
      </h2>
      <p className="text-xs text-muted mb-6 uppercase tracking-wider">
        Enter any web address below. Our trained AI classifier will instantly parse 33 lexical features to detect phishing indicators.
      </p>

      <form onSubmit={handleSubmit} className="flex flex-col md:flex-row gap-3 mb-6">
        <div className="relative flex-grow">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-dim" />
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="e.g., login-paypal-security-alert.xyz/verify-billing"
            className="w-full pl-12 pr-4 py-3.5 bg-[#090d16]/80 text-white font-medium border border-glass rounded-xl focus:border-cyan-500/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/40 transition-all duration-300 mono-font text-sm md:text-base placeholder:text-dim"
            disabled={isScanning}
          />
        </div>
        <button
          type="submit"
          className="cyber-btn justify-center h-full min-h-[50px] md:min-h-0"
          disabled={isScanning || !urlInput.trim()}
        >
          {isScanning ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              Scanning...
            </>
          ) : (
            'Scan Address'
          )}
        </button>
      </form>

      {/* Loading Status Details */}
      {isScanning && (
        <div className="flex items-center gap-3 bg-[#0a101c]/40 border border-cyan-500/10 rounded-xl p-3 mb-4 animate-pulse">
          <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
          <span className="text-xs md:text-sm uppercase tracking-wider font-semibold text-cyan-400 mono-font">
            [AI Diagnostic]: {DISPATCH_MESSAGES[loadingMsgIdx]}
          </span>
        </div>
      )}

      {/* Quick Paste Presets */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-dim font-bold uppercase tracking-wider mr-2">Quick Presets:</span>
        <button
          onClick={() => handleQuickPaste("http://secure-login-paypal.com-verification-billing.xyz/signin")}
          className="px-3 py-1.5 bg-red-950/20 hover:bg-red-950/40 border border-red-500/15 hover:border-red-500/30 rounded-lg text-red-400 font-semibold text-xs mono-font transition-all duration-200"
          disabled={isScanning}
        >
          [Malicious Preset]
        </button>
        <button
          onClick={() => handleQuickPaste("https://netflix.com/youraccount")}
          className="px-3 py-1.5 bg-emerald-950/20 hover:bg-emerald-950/40 border border-emerald-500/15 hover:border-emerald-500/30 rounded-lg text-emerald-400 font-semibold text-xs mono-font transition-all duration-200"
          disabled={isScanning}
        >
          [Legitimate Preset]
        </button>
        <button
          onClick={() => handleQuickPaste("http://192.168.1.1/login.php")}
          className="px-3 py-1.5 bg-amber-950/20 hover:bg-amber-950/40 border border-amber-500/15 hover:border-amber-500/30 rounded-lg text-amber-400 font-semibold text-xs mono-font transition-all duration-200"
          disabled={isScanning}
        >
          [Suspicious Preset]
        </button>
      </div>
    </div>
  );
};
