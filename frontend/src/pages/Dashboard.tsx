import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { DashboardData } from '../types';
import { Link } from 'react-router-dom';

export const DashboardPage: React.FC = () => {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [simScenario, setSimScenario] = useState('brute_force');
  const [simulating, setSimulating] = useState(false);

  const fetchMetrics = () => {
    setLoading(true);
    api<DashboardData>('/dashboard')
      .then((res) => {
        setData(res);
        setError('');
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchMetrics();
    const timer = setInterval(fetchMetrics, 10000);
    return () => clearInterval(timer);
  }, []);

  const handleRunSimulation = async () => {
    setSimulating(true);
    try {
      await api('/simulation/run', {
        method: 'POST',
        body: JSON.stringify({ scenario: simScenario, count: 25, seed: Math.floor(Math.random() * 1000) }),
      });
      fetchMetrics();
    } catch (e: any) {
      alert(`Simulation failed: ${e.message}`);
    } finally {
      setSimulating(false);
    }
  };

  if (loading && !data) {
    return <div className="page-container"><p style={{ color: 'var(--text-muted)' }}>Loading live SOC telemetry…</p></div>;
  }

  return (
    <div className="page-container">
      {error && <div className="error-banner">{error}</div>}

      {/* KPI Tiles */}
      <div className="kpi-grid">
        <div className="kpi-tile">
          <span className="label">Total Events</span>
          <span className="value">{data?.kpis.total_events ?? 0}</span>
          <span className="subtext">Canonical Records</span>
        </div>
        <div className="kpi-tile">
          <span className="label">Active Alerts</span>
          <span className="value" style={{ color: 'var(--amber)' }}>{data?.kpis.active_alerts ?? 0}</span>
          <span className="subtext">Pending Triage</span>
        </div>
        <div className="kpi-tile">
          <span className="label">Open Incidents</span>
          <span className="value" style={{ color: 'var(--rose)' }}>{data?.kpis.open_incidents ?? 0}</span>
          <span className="subtext">{data?.kpis.critical_incidents ?? 0} Critical</span>
        </div>
        <div className="kpi-tile">
          <span className="label">ML Anomalies</span>
          <span className="value" style={{ color: 'var(--purple)' }}>{data?.kpis.anomalies_detected ?? 0}</span>
          <span className="subtext">Isolation Forest</span>
        </div>
        <div className="kpi-tile">
          <span className="label">Investigations</span>
          <span className="value" style={{ color: 'var(--cyan)' }}>{data?.kpis.investigations_running ?? 0}</span>
          <span className="subtext">Active Deep Scans</span>
        </div>
      </div>

      {/* Quick Simulation Bar */}
      <div className="card-panel" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(6, 182, 212, 0.05)', border: '1px solid var(--border-glow)' }}>
        <div>
          <h4 style={{ fontSize: '14px', color: '#fff' }}>⚡ Local Threat Simulator</h4>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Generate synthetic attack telemetry (brute force, credential spray, reconnaissance) to test detection rules.</p>
        </div>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <select
            className="select-input"
            value={simScenario}
            onChange={(e) => setSimScenario(e.target.value)}
          >
            <option value="brute_force">Brute Force Authentication (25 events)</option>
            <option value="credential_stuffing">Credential Stuffing (25 events)</option>
            <option value="port_scan">Port Reconnaissance (25 events)</option>
            <option value="mixed">Mixed Normal & Attack Activity (50 events)</option>
          </select>
          <button
            onClick={handleRunSimulation}
            disabled={simulating}
            className="btn btn-primary"
          >
            {simulating ? 'Injecting Telemetry…' : 'Run Attack Simulation →'}
          </button>
        </div>
      </div>

      {/* Distribution & Activity Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: '20px' }}>
        {/* Severity Distribution */}
        <div className="card-panel">
          <div className="card-header">
            <h3>Alert Severity Breakdown</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].map((sev) => {
              const count = Number(data?.alerts_by_severity?.[sev] || 0);
              const total = (Object.values(data?.alerts_by_severity || {}) as number[]).reduce((a: number, b: number) => a + Number(b), 0) || 1;
              const pct = Math.min(100, Math.round((count / total) * 100));
              return (
                <div key={sev} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                    <span className={`badge ${sev.toLowerCase()}`}>{sev}</span>
                    <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{count} ({pct}%)</span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'rgba(0,0,0,0.3)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: sev === 'CRITICAL' ? 'var(--rose)' : sev === 'HIGH' ? 'var(--amber)' : sev === 'MEDIUM' ? 'var(--blue)' : 'var(--emerald)', transition: 'width 0.3s' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Recent Alerts Feed */}
        <div className="card-panel">
          <div className="card-header">
            <h3>Recent Detection Activity</h3>
            <Link to="/alerts" style={{ fontSize: '12px', color: 'var(--cyan)', textDecoration: 'none' }}>View All →</Link>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {data?.recent_alerts.map((alt) => (
              <div
                key={alt.id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  background: 'rgba(10, 15, 29, 0.6)',
                  border: '1px solid var(--border)',
                  padding: '10px 14px',
                  borderRadius: '6px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className={`badge ${alt.severity.toLowerCase()}`}>{alt.severity}</span>
                  <span style={{ fontSize: '13px', color: '#fff' }}>{alt.title}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span style={{ fontSize: '11px', color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>
                    Risk: {alt.risk_score}
                  </span>
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                    {new Date(alt.created_at).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            ))}
            {(!data?.recent_alerts || data.recent_alerts.length === 0) && (
              <p style={{ fontSize: '13px', color: 'var(--text-dim)', textAlign: 'center', padding: '20px' }}>
                No active security alerts yet. Run a simulation above to populate telemetry.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
