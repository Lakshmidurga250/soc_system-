import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

interface UEBAResponse {
  user_id: string;
  department: string;
  peer_group: string;
  composite_risk_score: number;
  anomaly_flag: boolean;
  active_anomalies: string[];
  features: {
    login_hour: number;
    hourly_event_rate: number;
    egress_bytes_mb: number;
    failed_attempts_ratio: number;
    accessed_sensitive_dc: boolean;
  };
  peer_baselines: {
    mean_event_rate: number;
    expected_work_hours: string;
    mean_egress_mb: number;
  };
}

export const UEBAAnalysisPage: React.FC = () => {
  const [selectedUser, setSelectedUser] = useState('svc_backup_admin');
  const [department, setDepartment] = useState('IT_INFRASTRUCTURE');
  const [loginHour, setLoginHour] = useState(3);
  const [hourlyRate, setHourlyRate] = useState(85);
  const [egressMB, setEgressMB] = useState(1420);
  const [failedRatio, setFailedRatio] = useState(0.45);
  const [sensitiveDC, setSensitiveDC] = useState(true);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<UEBAResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const evaluateUEBA = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api<UEBAResponse>('/advanced/ueba/evaluate-user', {
        method: 'POST',
        body: JSON.stringify({
          user_id: selectedUser,
          department: department,
          login_hour: Number(loginHour),
          hourly_event_rate: Number(hourlyRate),
          egress_bytes_mb: Number(egressMB),
          failed_attempts_ratio: Number(failedRatio),
          accessed_sensitive_dc: sensitiveDC,
        }),
      });
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to evaluate UEBA baseline');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    evaluateUEBA();
  }, []);

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">User & Entity Behavioral Analytics (UEBA)</h1>
          <p className="page-subtitle">
            Departmental peer-group anomaly modeling, off-hours authentication detection, and egress deviation analysis.
          </p>
        </div>
        <button className="btn btn-primary" onClick={evaluateUEBA} disabled={loading}>
          {loading ? 'Evaluating Model...' : 'Run UEBA Assessment'}
        </button>
      </div>

      {error && <div className="alert alert-danger" style={{ marginBottom: '20px' }}>{error}</div>}

      <div className="grid-2col" style={{ display: 'grid', gridTemplateColumns: '1fr 1.6fr', gap: '24px' }}>
        {/* Behavioral Input Card */}
        <div className="card" style={{ padding: '24px', background: '#ffffff', borderRadius: '12px', border: '1px solid #e9d5ff' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#4c1d95', marginBottom: '16px' }}>
            Identity & Activity Simulator
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>Target User / Service Identity</label>
              <select
                className="input-field"
                value={selectedUser}
                onChange={(e) => setSelectedUser(e.target.value)}
                style={{ width: '100%', padding: '8px 12px', marginTop: '4px', borderRadius: '8px', border: '1px solid #cbd5e1' }}
              >
                <option value="svc_backup_admin">svc_backup_admin (IT Admin)</option>
                <option value="finance_dir">finance_dir (Executive)</option>
                <option value="jdoe_dev">jdoe_dev (Software Engineer)</option>
                <option value="hr_manager">hr_manager (Human Resources)</option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>Department Peer Group</label>
              <select
                className="input-field"
                value={department}
                onChange={(e) => setDepartment(e.target.value)}
                style={{ width: '100%', padding: '8px 12px', marginTop: '4px', borderRadius: '8px', border: '1px solid #cbd5e1' }}
              >
                <option value="IT_INFRASTRUCTURE">IT Infrastructure & Domain Admins</option>
                <option value="FINANCE">Finance & Accounting</option>
                <option value="ENGINEERING">Software Engineering</option>
                <option value="HUMAN_RESOURCES">Human Resources</option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>
                Authentication Hour (UTC 0-23): <strong>{loginHour}:00</strong>
              </label>
              <input
                type="range"
                min={0}
                max={23}
                value={loginHour}
                onChange={(e) => setLoginHour(Number(e.target.value))}
                style={{ width: '100%', marginTop: '6px' }}
              />
            </div>

            <div>
              <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>
                Hourly Event Rate: <strong>{hourlyRate} events/hr</strong>
              </label>
              <input
                type="range"
                min={1}
                max={200}
                value={hourlyRate}
                onChange={(e) => setHourlyRate(Number(e.target.value))}
                style={{ width: '100%', marginTop: '6px' }}
              />
            </div>

            <div>
              <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>
                Network Egress Volume: <strong>{egressMB} MB</strong>
              </label>
              <input
                type="range"
                min={0}
                max={5000}
                step={50}
                value={egressMB}
                onChange={(e) => setEgressMB(Number(e.target.value))}
                style={{ width: '100%', marginTop: '6px' }}
              />
            </div>

            <div>
              <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>
                Failed Logon Ratio: <strong>{(failedRatio * 100).toFixed(0)}%</strong>
              </label>
              <input
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={failedRatio}
                onChange={(e) => setFailedRatio(Number(e.target.value))}
                style={{ width: '100%', marginTop: '6px' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '6px' }}>
              <input
                type="checkbox"
                id="dcCheck"
                checked={sensitiveDC}
                onChange={(e) => setSensitiveDC(e.target.checked)}
                style={{ width: '16px', height: '16px' }}
              />
              <label htmlFor="dcCheck" style={{ fontSize: '0.85rem', fontWeight: 500, color: '#374151', cursor: 'pointer' }}>
                Accessed Tier-0 Domain Controller / S3 Backup
              </label>
            </div>
          </div>
        </div>

        {/* Evaluation Output Card */}
        <div className="card" style={{ padding: '24px', background: '#ffffff', borderRadius: '12px', border: '1px solid #e9d5ff' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#4c1d95', marginBottom: '16px' }}>
            Behavioral Risk Profile
          </h3>

          {result ? (
            <div>
              <div
                style={{
                  padding: '20px',
                  borderRadius: '10px',
                  background: result.composite_risk_score > 70 ? '#fef2f2' : result.composite_risk_score > 40 ? '#fffbeb' : '#f0fdf4',
                  border: `1px solid ${result.composite_risk_score > 70 ? '#fecaca' : result.composite_risk_score > 40 ? '#fef3c7' : '#bbf7d0'}`,
                  marginBottom: '20px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#4b5563', textTransform: 'uppercase' }}>
                    Composite UEBA Risk Index
                  </div>
                  <div
                    style={{
                      fontSize: '2.2rem',
                      fontWeight: 700,
                      color: result.composite_risk_score > 70 ? '#dc2626' : result.composite_risk_score > 40 ? '#d97706' : '#16a34a',
                    }}
                  >
                    {result.composite_risk_score.toFixed(1)} <span style={{ fontSize: '1rem', fontWeight: 400 }}>/ 100</span>
                  </div>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <span
                    style={{
                      display: 'inline-block',
                      padding: '6px 14px',
                      borderRadius: '20px',
                      fontSize: '0.8rem',
                      fontWeight: 700,
                      background: result.anomaly_flag ? '#ef4444' : '#10b981',
                      color: '#ffffff',
                    }}
                  >
                    {result.anomaly_flag ? '⚠️ ANOMALY DETECTED' : '✓ NORMAL PROFILE'}
                  </span>
                  <div style={{ fontSize: '0.8rem', color: '#6b7280', marginTop: '4px' }}>
                    Peer Group: {result.peer_group}
                  </div>
                </div>
              </div>

              {/* Active Anomaly Alerts */}
              <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#374151', marginBottom: '10px' }}>
                Detected Deviations ({result.active_anomalies.length})
              </h4>
              {result.active_anomalies.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '20px' }}>
                  {result.active_anomalies.map((anom, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '10px 14px',
                        borderRadius: '8px',
                        background: '#faf5ff',
                        borderLeft: '4px solid #7c3aed',
                        fontSize: '0.85rem',
                        color: '#4c1d95',
                        fontWeight: 500,
                      }}
                    >
                      • {anom}
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ padding: '12px', background: '#f8fafc', borderRadius: '8px', color: '#64748b', fontSize: '0.85rem', marginBottom: '20px' }}>
                  No significant statistical deviations detected compared to peer group baseline.
                </div>
              )}

              {/* Peer Group Baseline Comparison */}
              <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#374151', marginBottom: '10px' }}>
                Peer Baseline Reference Telemetry
              </h4>
              <table className="table" style={{ width: '100%', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ background: '#f5f3ff', textAlign: 'left' }}>
                    <th style={{ padding: '8px 12px' }}>Metric</th>
                    <th style={{ padding: '8px 12px' }}>Subject Value</th>
                    <th style={{ padding: '8px 12px' }}>Peer Group Mean</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td style={{ padding: '8px 12px' }}>Standard Working Hours</td>
                    <td style={{ padding: '8px 12px' }}>{loginHour}:00 UTC</td>
                    <td style={{ padding: '8px 12px' }}>{result.peer_baselines.expected_work_hours}</td>
                  </tr>
                  <tr>
                    <td style={{ padding: '8px 12px' }}>Hourly Event Velocity</td>
                    <td style={{ padding: '8px 12px' }}>{hourlyRate} events/hr</td>
                    <td style={{ padding: '8px 12px' }}>~{result.peer_baselines.mean_event_rate} events/hr</td>
                  </tr>
                  <tr>
                    <td style={{ padding: '8px 12px' }}>Daily Egress Volume</td>
                    <td style={{ padding: '8px 12px' }}>{egressMB} MB</td>
                    <td style={{ padding: '8px 12px' }}>~{result.peer_baselines.mean_egress_mb} MB</td>
                  </tr>
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ padding: '40px', textAlign: 'center', color: '#9ca3af' }}>
              Run assessment to view baseline profiling results.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
