import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { ThreatIndicator } from '../types';

export const ThreatIntelPage: React.FC = () => {
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [indicator, setIndicator] = useState('');
  const [indicatorType, setIndicatorType] = useState('IP');
  const [riskLevel, setRiskLevel] = useState('HIGH');
  const [description, setDescription] = useState('');
  const [loading, setLoading] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [error, setError] = useState('');

  const fetchIndicators = () => {
    api<{ items: ThreatIndicator[] }>('/intelligence/indicators')
      .then((res) => setIndicators(res.items))
      .catch((e) => console.error(e));
  };

  useEffect(() => {
    fetchIndicators();
  }, []);

  const handleAddIndicator = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!indicator.trim()) return;

    setLoading(true);
    setError('');
    try {
      await api('/intelligence/indicators', {
        method: 'POST',
        body: JSON.stringify({
          indicator,
          indicator_type: indicatorType,
          risk_level: riskLevel,
          description,
          source: 'local_soc',
        }),
      });
      setIndicator('');
      setDescription('');
      setModalOpen(false);
      fetchIndicators();
    } catch (err: any) {
      setError(err.message || 'Failed to add indicator');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ fontSize: '18px', color: '#fff' }}>Threat Intelligence & IOC Feeds</h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Maintain active Indicators of Compromise (IPs, domains, file hashes) for automated threat reputation scoring.
          </p>
        </div>
        <button onClick={() => setModalOpen(true)} className="btn btn-primary">
          + Add Threat Indicator
        </button>
      </div>

      <div className="card-panel">
        <div className="card-header">
          <h3>Active IOC Database ({indicators.length} Items)</h3>
          <button onClick={fetchIndicators} className="btn btn-secondary btn-sm">Refresh</button>
        </div>

        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Indicator / Artifact</th>
                <th>Type</th>
                <th>Risk Level</th>
                <th>Source</th>
                <th>Status</th>
                <th>Context / Notes</th>
              </tr>
            </thead>
            <tbody>
              {indicators.map((ioc) => (
                <tr key={ioc.id}>
                  <td>
                    <code>{ioc.indicator}</code>
                  </td>
                  <td>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)' }}>{ioc.indicator_type}</span>
                  </td>
                  <td>
                    <span className={`badge ${ioc.risk_level.toLowerCase()}`}>{ioc.risk_level}</span>
                  </td>
                  <td style={{ fontSize: '12px' }}>{ioc.source}</td>
                  <td>
                    <span className="badge resolved">{ioc.status}</span>
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{ioc.description || '—'}</td>
                </tr>
              ))}
              {indicators.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)' }}>
                    No threat indicators cataloged yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {modalOpen && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: '500px' }}>
            <div className="modal-header">
              <h3>Add Threat Indicator</h3>
              <button onClick={() => setModalOpen(false)} className="modal-close">✕</button>
            </div>

            {error && <div className="error-banner">{error}</div>}

            <form onSubmit={handleAddIndicator} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="form-group">
                <label>Indicator Value</label>
                <input
                  value={indicator}
                  onChange={(e) => setIndicator(e.target.value)}
                  placeholder="e.g. 198.51.100.44 or evil-domain.org"
                  required
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label>Indicator Type</label>
                  <select className="select-input" value={indicatorType} onChange={(e) => setIndicatorType(e.target.value)}>
                    <option value="IP">IP Address</option>
                    <option value="DOMAIN">Domain Name</option>
                    <option value="HASH">SHA256 Hash</option>
                    <option value="URL">URL Endpoint</option>
                  </select>
                </div>

                <div className="form-group">
                  <label>Threat Risk Level</label>
                  <select className="select-input" value={riskLevel} onChange={(e) => setRiskLevel(e.target.value)}>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label>Description & Threat Intelligence Context</label>
                <input
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="e.g. Known Cobalt Strike C2 server or brute-force scanner"
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '8px' }}>
                <button type="button" onClick={() => setModalOpen(false)} className="btn btn-secondary">Cancel</button>
                <button type="submit" disabled={loading} className="btn btn-primary">
                  {loading ? 'Adding…' : 'Add Indicator →'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
