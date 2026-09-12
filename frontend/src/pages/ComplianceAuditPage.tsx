import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

interface FrameworkScore {
  framework_id: string;
  name: string;
  score: number;
  grade: string;
  status: string;
  controls_total: number;
  controls_passing: number;
  identified_gaps: string[];
}

interface ComplianceResponse {
  organization_compliance_index: number;
  overall_rating: string;
  framework_posture: Record<string, FrameworkScore>;
  priority_compliance_remediations: string[];
  assessment_timestamp: string;
}

export const ComplianceAuditPage: React.FC = () => {
  const [data, setData] = useState<ComplianceResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadCompliance = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api<ComplianceResponse>('/advanced/compliance/posture');
      setData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch compliance posture');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCompliance();
  }, []);

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Regulatory Compliance & Governance Posture</h1>
          <p className="page-subtitle">
            Continuous posture evaluation across NIST CSF 2.0, ISO 27001, PCI-DSS v4.0, HIPAA, and SOC 2 Type II.
          </p>
        </div>
        <button className="btn btn-primary" onClick={loadCompliance} disabled={loading}>
          {loading ? 'Evaluating Controls...' : 'Re-evaluate Compliance'}
        </button>
      </div>

      {error && <div className="alert alert-danger" style={{ marginBottom: '20px' }}>{error}</div>}

      {data && (
        <>
          {/* Executive Overview Banner */}
          <div
            className="card"
            style={{
              padding: '24px',
              background: 'linear-gradient(135deg, #f5f3ff 0%, #ede9fe 100%)',
              borderRadius: '12px',
              border: '1px solid #c4b5fd',
              marginBottom: '24px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#6b21a8' }}>
                ORGANIZATION COMPLIANCE INDEX
              </div>
              <div style={{ fontSize: '2.5rem', fontWeight: 800, color: '#4c1d95' }}>
                {data.organization_compliance_index.toFixed(1)}%
              </div>
              <div style={{ fontSize: '0.85rem', color: '#5b21b6', marginTop: '4px' }}>
                Overall Governance Grade: <strong>{data.overall_rating}</strong>
              </div>
            </div>

            <div style={{ maxWidth: '400px', fontSize: '0.82rem', color: '#581c87', background: 'rgba(255,255,255,0.7)', padding: '14px', borderRadius: '8px' }}>
              🛡️ <strong>Automated Continuous Audit:</strong> 5 enterprise security frameworks continuously monitored via telemetry, access controls, and logging configuration.
            </div>
          </div>

          {/* Framework Cards Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px', marginBottom: '24px' }}>
            {Object.entries(data.framework_posture).map(([key, fw]) => (
              <div key={key} className="card" style={{ padding: '20px', background: '#ffffff', borderRadius: '12px', border: '1px solid #e9d5ff' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#1e293b', margin: 0 }}>
                    {fw.name}
                  </h3>
                  <span
                    style={{
                      padding: '4px 10px',
                      borderRadius: '12px',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      background: fw.score >= 85 ? '#dcfce7' : fw.score >= 70 ? '#fef3c7' : '#fee2e2',
                      color: fw.score >= 85 ? '#15803d' : fw.score >= 70 ? '#b45309' : '#b91c1c',
                    }}
                  >
                    {fw.score.toFixed(1)}% ({fw.grade})
                  </span>
                </div>

                <div style={{ fontSize: '0.82rem', color: '#64748b', marginBottom: '14px' }}>
                  Passing Controls: <strong>{fw.controls_passing} / {fw.controls_total}</strong>
                </div>

                {fw.identified_gaps.length > 0 ? (
                  <div>
                    <div style={{ fontSize: '0.78rem', fontWeight: 600, color: '#dc2626', marginBottom: '6px' }}>
                      IDENTIFIED COMPLIANCE GAPS:
                    </div>
                    <ul style={{ margin: 0, paddingLeft: '16px', fontSize: '0.78rem', color: '#4b5563' }}>
                      {fw.identified_gaps.map((gap, gIdx) => (
                        <li key={gIdx} style={{ marginBottom: '4px' }}>{gap}</li>
                      ))}
                    </ul>
                  </div>
                ) : (
                  <div style={{ fontSize: '0.78rem', color: '#16a34a', fontWeight: 500 }}>
                    ✓ All evaluated controls currently meeting standard.
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
};
