import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Alert } from '../types';

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [loading, setLoading] = useState(false);
  const [escalating, setEscalating] = useState<string | null>(null);

  const fetchAlerts = () => {
    setLoading(true);
    const param = statusFilter !== 'ALL' ? `?status=${statusFilter}` : '';
    api<{ items: Alert[] }>(`/alerts${param}`)
      .then((res) => setAlerts(res.items))
      .catch((e) => console.error(e))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchAlerts();
  }, [statusFilter]);

  const handleUpdateStatus = async (alertId: string, newStatus: string) => {
    try {
      await api(`/alerts/${alertId}`, {
        method: 'PATCH',
        body: JSON.stringify({ status: newStatus, note: `Status transitioned to ${newStatus} by analyst.` }),
      });
      fetchAlerts();
    } catch (e: any) {
      alert(`Update failed: ${e.message}`);
    }
  };

  const handleEscalateToIncident = async (alertId: string) => {
    setEscalating(alertId);
    try {
      await api(`/incidents/from-alert/${alertId}`, {
        method: 'POST',
      });
      alert('Alert escalated into full Incident case.');
      fetchAlerts();
    } catch (e: any) {
      alert(`Escalation failed: ${e.message}`);
    } finally {
      setEscalating(null);
    }
  };

  return (
    <div className="page-container">
      {/* Header Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ fontSize: '18px', color: '#fff' }}>Detection Alerts & Triage Queue</h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Real-time rule matches and ML anomaly detections with SHAP feature explanations.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <select
            className="select-input"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="ALL">All Statuses</option>
            <option value="NEW">New</option>
            <option value="IN_TRIAGE">In Triage</option>
            <option value="ESCALATED">Escalated</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
          <button onClick={fetchAlerts} className="btn btn-secondary btn-sm">Refresh</button>
        </div>
      </div>

      {/* Alert Cards Grid */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        {alerts.map((alt) => (
          <div key={alt.id} className="card-panel" style={{ borderLeft: `4px solid ${alt.severity === 'CRITICAL' ? 'var(--rose)' : alt.severity === 'HIGH' ? 'var(--amber)' : 'var(--blue)'}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className={`badge ${alt.severity.toLowerCase()}`}>{alt.severity}</span>
                  <span className={`badge ${alt.status.toLowerCase()}`}>{alt.status}</span>
                  <strong style={{ fontSize: '15px', color: '#fff' }}>{alt.title}</strong>
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  {alt.description || 'Automated detection triggered from canonical event stream.'}
                </p>
              </div>

              <div style={{ textAlign: 'right' }}>
                <span style={{ fontSize: '11px', color: 'var(--cyan)', fontFamily: 'var(--font-mono)', display: 'block' }}>
                  Risk Score: {alt.risk_score} / 100
                </span>
                <span style={{ fontSize: '10px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                  Confidence: {Math.round((alt.confidence_score || 0.85) * 100)}%
                </span>
              </div>
            </div>

            {/* Explanation Breakdown */}
            {alt.explanation?.top_contributing_factors && alt.explanation.top_contributing_factors.length > 0 && (
              <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px', borderRadius: '6px', marginBottom: '12px' }}>
                <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--purple)', display: 'block', marginBottom: '4px' }}>
                  🧠 ML Feature Attributions & Explainability (SHAP-proxy):
                </span>
                <ul style={{ paddingLeft: '18px', fontSize: '11px', color: 'var(--text-muted)' }}>
                  {alt.explanation.top_contributing_factors.map((factor, idx) => (
                    <li key={idx}>
                      <strong>{factor.feature}:</strong> {factor.description}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Entities & Actions */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border)', paddingTop: '10px' }}>
              <div style={{ display: 'flex', gap: '14px', fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                {alt.entities?.source_ip && <span>IP: <code style={{ color: 'var(--cyan)' }}>{alt.entities.source_ip}</code></span>}
                {alt.entities?.username && <span>User: <code style={{ color: 'var(--purple)' }}>{alt.entities.username}</code></span>}
                {alt.entities?.hostname && <span>Host: <code style={{ color: 'var(--emerald)' }}>{alt.entities.hostname}</code></span>}
              </div>

              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <select
                  className="select-input"
                  style={{ padding: '4px 8px', fontSize: '11px' }}
                  value={alt.status}
                  onChange={(e) => handleUpdateStatus(alt.id, e.target.value)}
                >
                  <option value="NEW">New</option>
                  <option value="IN_TRIAGE">In Triage</option>
                  <option value="RESOLVED">Resolved</option>
                  <option value="FALSE_POSITIVE">False Positive</option>
                </select>

                {alt.status !== 'ESCALATED' && (
                  <button
                    disabled={escalating === alt.id}
                    onClick={() => handleEscalateToIncident(alt.id)}
                    className="btn btn-danger btn-sm"
                  >
                    {escalating === alt.id ? 'Escalating…' : '⚡ Escalate to Incident'}
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}

        {!loading && alerts.length === 0 && (
          <div className="card-panel" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-dim)' }}>
            No alerts found matching filter criteria.
          </div>
        )}
      </div>
    </div>
  );
};
