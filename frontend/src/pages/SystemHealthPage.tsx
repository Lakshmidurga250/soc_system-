import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { AuditLogItem } from '../types';

export const SystemHealthPage: React.FC = () => {
  const [health, setHealth] = useState<any>(null);
  const [mlStatus, setMlStatus] = useState<any>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [trainingMl, setTrainingMl] = useState(false);
  const [trainMsg, setTrainMsg] = useState('');

  const fetchSystemData = () => {
    api<any>('/health').then(setHealth).catch((e) => console.error(e));
    api<any>('/ml/status').then(setMlStatus).catch((e) => console.error(e));
    api<{ items: AuditLogItem[] }>('/audit').then((res) => setAuditLogs(res.items)).catch((e) => console.error(e));
  };

  useEffect(() => {
    fetchSystemData();
  }, []);

  const handleRetrainML = async () => {
    setTrainingMl(true);
    setTrainMsg('');
    try {
      const res = await api<any>('/ml/train', {
        method: 'POST',
        body: JSON.stringify({ sample_size: 2000, contamination: 0.08 }),
      });
      setTrainMsg(`ML Engine successfully retrained on ${res.samples_trained} behavioral telemetry vectors.`);
      fetchSystemData();
    } catch (e: any) {
      alert(`ML Retraining failed: ${e.message}`);
    } finally {
      setTrainingMl(false);
    }
  };

  return (
    <div className="page-container">
      <div>
        <h3 style={{ fontSize: '18px', color: '#fff' }}>System Diagnostics & Machine Learning Engine</h3>
        <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Monitor component health probes, ML IsolationForest baseline status, and inspect tamper-evident audit trails.
        </p>
      </div>

      {/* Component Status Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        {health?.components &&
          Object.entries(health.components).map(([k, v]) => (
            <div key={k} className="card-panel" style={{ padding: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>
                  {k.replace('_', ' ')}
                </span>
                <span className="badge resolved">● {String(v).toUpperCase()}</span>
              </div>
              <strong style={{ fontSize: '15px', color: '#fff', marginTop: '6px', display: 'block' }}>
                Operational
              </strong>
            </div>
          ))}
      </div>

      {/* Machine Learning Model Status & Controls */}
      <div className="card-panel">
        <div className="card-header">
          <h3>Local Machine Learning Intelligence (Isolation Forest)</h3>
          <button
            disabled={trainingMl}
            onClick={handleRetrainML}
            className="btn btn-primary btn-sm"
          >
            {trainingMl ? 'Training Local Model…' : '⚡ Retrain Behavioral Baseline'}
          </button>
        </div>

        {trainMsg && (
          <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#34d399', padding: '10px', borderRadius: '6px', fontSize: '12px', marginBottom: '12px' }}>
            ✓ {trainMsg}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', background: 'rgba(0,0,0,0.3)', padding: '14px', borderRadius: '6px' }}>
          <div>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>ALGORITHM</span>
            <strong style={{ fontSize: '14px', color: '#fff', display: 'block', fontFamily: 'var(--font-mono)' }}>
              {mlStatus?.model_type || 'IsolationForest'}
            </strong>
          </div>
          <div>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>TRAINED SAMPLES</span>
            <strong style={{ fontSize: '14px', color: 'var(--cyan)', display: 'block', fontFamily: 'var(--font-mono)' }}>
              {mlStatus?.samples_trained || 0} vectors
            </strong>
          </div>
          <div>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>LAST RETRAINED</span>
            <strong style={{ fontSize: '14px', color: 'var(--emerald)', display: 'block', fontFamily: 'var(--font-mono)' }}>
              {mlStatus?.last_trained_at ? new Date(mlStatus.last_trained_at).toLocaleString() : 'Ready'}
            </strong>
          </div>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="card-panel">
        <div className="card-header">
          <h3>Forensic Audit Trail ({auditLogs.length} Records)</h3>
          <button onClick={fetchSystemData} className="btn btn-secondary btn-sm">Refresh</button>
        </div>

        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Action</th>
                <th>Target Resource</th>
                <th>Outcome</th>
                <th>Context Metadata</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.slice(0, 25).map((log) => (
                <tr key={log.id}>
                  <td style={{ fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td>
                    <code style={{ color: 'var(--cyan)' }}>{log.action}</code>
                  </td>
                  <td style={{ fontSize: '12px' }}>{log.resource}</td>
                  <td>
                    <span className={`badge ${log.result === 'SUCCESS' ? 'resolved' : 'critical'}`}>
                      {log.result}
                    </span>
                  </td>
                  <td>
                    <code style={{ fontSize: '10px' }}>{JSON.stringify(log.metadata)}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
