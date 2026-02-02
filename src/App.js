import React, { useEffect, useMemo, useRef, useState } from 'react';
import { initializeApp } from 'firebase/app';
import {
  getAnalytics,
  isSupported,
  logEvent,
  setAnalyticsCollectionEnabled,
  setUserId,
  setUserProperties,
} from 'firebase/analytics';
import './App.css';

const firebaseConfig = {
  apiKey: 'AIzaSyDwoNwHmtu6hFINSuqtS1h_aHdf39ZLgu0',
  authDomain: 'checkmate-68921.firebaseapp.com',
  projectId: 'checkmate-68921',
  storageBucket: 'checkmate-68921.firebasestorage.app',
  messagingSenderId: '974961988931',
  appId: '1:974961988931:web:30e053ca901d8745700bf6',
  measurementId: 'G-TYLNYDG7WG',
};

const ANON_USER_ID_KEY = 'anon_user_id';
const ANALYTICS_CONSENT_KEY = 'analytics_consent';
const ANON_SESSION_ID_KEY = 'anon_session_id';
const ANON_SESSION_TS_KEY = 'anon_session_ts';
const SESSION_WINDOW_MS = 30 * 60 * 1000;

function generateUuid() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = Math.floor(Math.random() * 256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function getOrCreateAnonUserId() {
  const existing = localStorage.getItem(ANON_USER_ID_KEY);
  if (existing) return existing;
  const created = generateUuid();
  localStorage.setItem(ANON_USER_ID_KEY, created);
  return created;
}

function getOrCreateSessionId() {
  const now = Date.now();
  const existingId = sessionStorage.getItem(ANON_SESSION_ID_KEY);
  const existingTsRaw = sessionStorage.getItem(ANON_SESSION_TS_KEY);
  const existingTs = existingTsRaw ? Number(existingTsRaw) : 0;

  if (existingId && existingTs && Number.isFinite(existingTs) && now - existingTs < SESSION_WINDOW_MS) {
    return existingId;
  }

  const created = generateUuid();
  sessionStorage.setItem(ANON_SESSION_ID_KEY, created);
  sessionStorage.setItem(ANON_SESSION_TS_KEY, String(now));
  return created;
}

function normalizeSeverityCounts(data) {
  const summary = data && data.summary ? data.summary : null;
  const vulnerabilities = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];

  if (summary && typeof summary === 'object') {
    return {
      total: Number(summary.total || 0),
      critical: Number(summary.critical || 0),
      warning: Number(summary.warning || 0),
    };
  }

  const counts = { total: vulnerabilities.length, critical: 0, warning: 0 };
  for (const v of vulnerabilities) {
    if (!v || typeof v !== 'object') continue;
    if (v.severity === 'critical') counts.critical += 1;
    if (v.severity === 'warning') counts.warning += 1;
  }
  return counts;
}

function App() {
  const anonUserId = useMemo(() => getOrCreateAnonUserId(), []);
  const [consent, setConsent] = useState(() => localStorage.getItem(ANALYTICS_CONSENT_KEY) === 'true');
  const [analytics, setAnalytics] = useState(null);
  const analyticsInitRef = useRef(false);

  const [targetUrl, setTargetUrl] = useState('');
  const [scanStatus, setScanStatus] = useState('idle');
  const [scanError, setScanError] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [scanId, setScanId] = useState('');

  const logAnalyticsEvent = (eventName, params = {}) => {
    if (!analytics || !consent) return;
    logEvent(analytics, eventName, {
      ...params,
      session_id: getOrCreateSessionId(),
    });
  };

  useEffect(() => {
    if (analyticsInitRef.current) return;
    analyticsInitRef.current = true;

    let cancelled = false;
    isSupported()
      .then((supported) => {
        if (!supported || cancelled) return;

        const app = initializeApp(firebaseConfig);
        const a = getAnalytics(app);
        setUserId(a, anonUserId);
        setUserProperties(a, { anonymous: '1' });
        setAnalyticsCollectionEnabled(a, localStorage.getItem(ANALYTICS_CONSENT_KEY) === 'true');
        setAnalytics(a);

        if (localStorage.getItem(ANALYTICS_CONSENT_KEY) === 'true') {
          logEvent(a, 'app_initialized');
        }
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, [anonUserId]);

  useEffect(() => {
    localStorage.setItem(ANALYTICS_CONSENT_KEY, consent ? 'true' : 'false');
    if (!analytics) return;
    setAnalyticsCollectionEnabled(analytics, consent);
    if (consent) {
      logEvent(analytics, 'consent_granted');
    }
  }, [analytics, consent]);

  const handleStartScan = async (e) => {
    e.preventDefault();
    setScanError('');
    setScanResult(null);

    const trimmed = targetUrl.trim();
    if (!trimmed) {
      setScanError('Please enter a target URL.');
      return;
    }

    const currentScanId = generateUuid();
    setScanId(currentScanId);
    setScanStatus('started');

    const startedAt = performance.now();
    logAnalyticsEvent('scan_started', {
      scan_id: currentScanId,
      client: 'react',
    });

    try {
      const res = await fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
      });

      const data = await res.json().catch(() => null);
      const durationMs = Math.round(performance.now() - startedAt);

      if (!res.ok || !data || data.success !== true) {
        const message = (data && (data.error || data.message)) || `Scan failed (HTTP ${res.status})`;
        setScanError(message);
        setScanStatus('failed');

        logAnalyticsEvent('scan_failed', {
          scan_id: currentScanId,
          duration_ms: durationMs,
          error_class: res.ok ? 'scanner_error' : 'http_error',
        });
        return;
      }

      const counts = normalizeSeverityCounts(data);
      setScanResult({ ...data, summary: counts });
      setScanStatus('completed');

      if (counts.total > 0) {
        logAnalyticsEvent('vulnerability_detected', {
          scan_id: currentScanId,
          total: counts.total,
          critical: counts.critical,
          warning: counts.warning,
        });
      }

      logAnalyticsEvent('scan_completed', {
        scan_id: currentScanId,
        duration_ms: durationMs,
        vulnerabilities_total: counts.total,
        critical_count: counts.critical,
        warning_count: counts.warning,
      });
    } catch (err) {
      const durationMs = Math.round(performance.now() - startedAt);
      setScanError(err instanceof Error ? err.message : 'Network error');
      setScanStatus('failed');

      logAnalyticsEvent('scan_failed', {
        scan_id: currentScanId,
        duration_ms: durationMs,
        error_class: 'network_error',
      });
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>Vulnerability Scanner</h1>

        <label style={{ display: 'block', margin: '12px 0' }}>
          <input
            type="checkbox"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
          />{' '}
          Share anonymous usage analytics
        </label>

        <form onSubmit={handleStartScan} style={{ width: '100%', maxWidth: 520 }}>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="example.com"
              style={{ flex: 1 }}
              autoComplete="off"
              inputMode="url"
            />
            <button type="submit" disabled={scanStatus === 'started'}>
              {scanStatus === 'started' ? 'Scanning…' : 'Start Scan'}
            </button>
          </div>
        </form>

        {scanId ? <p style={{ marginTop: 8, fontSize: 14 }}>Scan ID: {scanId}</p> : null}
        {scanStatus !== 'idle' ? <p>Status: {scanStatus}</p> : null}
        {scanError ? <p style={{ color: '#ff6b6b' }}>{scanError}</p> : null}

        {scanResult ? (
          <div style={{ width: '100%', maxWidth: 720, textAlign: 'left' }}>
            <h2>Results</h2>
            <p>
              Total: {scanResult.summary?.total ?? 0} | Critical: {scanResult.summary?.critical ?? 0} |
              Warning: {scanResult.summary?.warning ?? 0}
            </p>
            <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
              {JSON.stringify(scanResult, null, 2)}
            </pre>
          </div>
        ) : null}
      </header>
    </div>
  );
}

export default App;
