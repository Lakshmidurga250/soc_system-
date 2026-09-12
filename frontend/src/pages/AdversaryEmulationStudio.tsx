import React, { useState } from 'react';
import { api } from '../services/api';

interface EmulationResult {
  test_id: string;
  technique_id: string;
  technique_name: string;
  description: string;
  command: string;
  simulated_status: string;
  detection_engine_triggered: string;
  detection_success: boolean;
  alert_severity: string;
}

interface EmulationRunResponse {
  total_emulated_tests: number;
  detections_triggered: number;
  soc_efficacy_rate: number;
  results: EmulationResult[];
}

export const AdversaryEmulationStudio: React.FC = () => {
  const [data, setData] = useState<EmulationRunResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runEmulations = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api<EmulationRunResponse>('/advanced/emulation/run', {
        method: 'POST',
      });
      setData(res);
    } catch (err: any) {
      setError(err.message || 'Adversary emulation failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Adversary Emulation Studio & SOC Efficacy</h1>
          <p className="page-subtitle">
            Safe dry-run Atomic Red Team adversary simulations to validate detection rules, Sigma ASTs, and YARA signatures.
          </p>
        </div>
        <button className="btn btn-primary" onClick={runEmulations} disabled={loading}>
          {loading ? 'Simulating Atomic Techniques...' : 'Execute Emulation Suite'}
        </button>
      </div>

      {error && <div className="alert alert-danger" style={{ marginBottom: '20px' }}>{error}</div>}

      {data ? (
        <div>
          {/* Efficacy Scorecard */}
          <div
            className="card"
            style={{
              padding: '24px',
              background: '#ffffff',
              borderRadius: '12px',
              border: '1px solid #e9d5ff',
              marginBottom: '24px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#6b7280' }}>
                SENTINELAI SOC DETECTION EFFICACY
              </div>
              <div style={{ fontSize: '2.5rem', fontWeight: 800, color: '#7c3aed' }}>
                {data.soc_efficacy_rate.toFixed(1)}%
              </div>
              <div style={{ fontSize: '0.85rem', color: '#4b5563', marginTop: '4px' }}>
                Verified Detections: <strong>{data.detections_triggered} / {data.total_emulated_tests}</strong> Techniques
              </div>
            </div>

            <div style={{ padding: '12px 18px', borderRadius: '8px', background: '#f0fdf4', border: '1px solid #bbf7d0', fontSize: '0.82rem', color: '#166534' }}>
              🔒 <strong>Safe Sandbox Mode:</strong> Emulations are executed within synthetic AST and signature engines with zero system modification.
            </div>
          </div>

          {/* Test Results Table */}
          <div className="card" style={{ padding: '24px', background: '#ffffff', borderRadius: '12px', border: '1px solid #e9d5ff' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#4c1d95', marginBottom: '16px' }}>
              Atomic Emulation Results & Detection Mapping
            </h3>

            <div style={{ overflowX: 'auto' }}>
              <table className="table" style={{ width: '100%', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ background: '#f5f3ff', textAlign: 'left' }}>
                    <th style={{ padding: '10px 14px' }}>Test ID</th>
                    <th style={{ padding: '10px 14px' }}>MITRE Technique</th>
                    <th style={{ padding: '10px 14px' }}>Emulated Command</th>
                    <th style={{ padding: '10px 14px' }}>Triggered Engine</th>
                    <th style={{ padding: '10px 14px' }}>Detection Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {data.results.map((res) => (
                    <tr key={res.test_id} style={{ borderBottom: '1px solid #f3e8ff' }}>
                      <td style={{ padding: '10px 14px', fontWeight: 600, color: '#4c1d95' }}>{res.test_id}</td>
                      <td style={{ padding: '10px 14px' }}>
                        <div><strong>{res.technique_id}</strong></div>
                        <div style={{ fontSize: '0.78rem', color: '#64748b' }}>{res.technique_name}</div>
                      </td>
                      <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontSize: '0.78rem', color: '#334155' }}>
                        {res.command}
                      </td>
                      <td style={{ padding: '10px 14px', fontSize: '0.8rem', color: '#6b21a8', fontWeight: 500 }}>
                        {res.detection_engine_triggered}
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        <span
                          style={{
                            padding: '4px 10px',
                            borderRadius: '12px',
                            fontSize: '0.75rem',
                            fontWeight: 700,
                            background: res.detection_success ? '#dcfce7' : '#fee2e2',
                            color: res.detection_success ? '#15803d' : '#991b1b',
                          }}
                        >
                          {res.detection_success ? '✓ DETECTED' : '✗ MISSED'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : (
        <div className="card" style={{ padding: '60px', textAlign: 'center', background: '#ffffff', borderRadius: '12px', border: '1px solid #e9d5ff' }}>
          <div style={{ fontSize: '2.5rem', marginBottom: '12px' }}>🎯</div>
          <h3 style={{ fontSize: '1.2rem', fontWeight: 600, color: '#4c1d95', marginBottom: '8px' }}>
            Ready to Verify Detection Posture
          </h3>
          <p style={{ color: '#64748b', fontSize: '0.9rem', maxWidth: '480px', margin: '0 auto 20px' }}>
            Click Execute Emulation Suite to safely validate your detection rules against Atomic Red Team behaviors.
          </p>
          <button className="btn btn-primary" onClick={runEmulations} disabled={loading}>
            {loading ? 'Running Simulations...' : 'Execute Emulation Suite'}
          </button>
        </div>
      )}
    </div>
  );
};
