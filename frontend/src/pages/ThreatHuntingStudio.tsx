import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

interface HuntPackage {
  hunt_id: string;
  title: string;
  mitre_technique_id: string;
  target_data_sources: string[];
  hypothesis: string;
  severity: string;
}

interface QueryTranslationResponse {
  hunt_id: string;
  language: string;
  query: string;
}

export const ThreatHuntingStudio: React.FC = () => {
  const [packages, setPackages] = useState<HuntPackage[]>([]);
  const [selectedHuntId, setSelectedHuntId] = useState<string>('HUNT-2026-KERBEROAST');
  const [selectedLanguage, setSelectedLanguage] = useState<string>('SPLUNK_SPL');
  const [translatedQuery, setTranslatedQuery] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadHuntPackages = async () => {
    try {
      const data = await api<HuntPackage[]>('/advanced/hunting/packages');
      setPackages(data);
      if (data.length > 0 && !selectedHuntId) {
        setSelectedHuntId(data[0].hunt_id);
      }
    } catch (err: any) {
      console.error(err);
    }
  };

  const fetchTranslatedQuery = async () => {
    if (!selectedHuntId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api<QueryTranslationResponse>(
        `/advanced/hunting/query/${selectedHuntId}?language=${selectedLanguage}`
      );
      setTranslatedQuery(data.query);
    } catch (err: any) {
      setError(err.message || 'Failed to translate query');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHuntPackages();
  }, []);

  useEffect(() => {
    fetchTranslatedQuery();
  }, [selectedHuntId, selectedLanguage]);

  const selectedPkg = packages.find((p) => p.hunt_id === selectedHuntId);

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Threat Hunting Studio & Multi-Query Compiler</h1>
          <p className="page-subtitle">
            Hypothesis-driven proactive hunts translated across Splunk SPL, Elastic EQL, Kusto KQL, and Sigma AST.
          </p>
        </div>
      </div>

      <div className="grid-2col" style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.5fr', gap: '24px' }}>
        {/* Hunt Packages List */}
        <div className="card" style={{ padding: '24px', background: '#ffffff', borderRadius: '12px', border: '1px solid #e9d5ff' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#4c1d95', marginBottom: '16px' }}>
            Curated Threat Hunt Packages ({packages.length})
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {packages.map((pkg) => {
              const isSelected = pkg.hunt_id === selectedHuntId;
              return (
                <div
                  key={pkg.hunt_id}
                  onClick={() => setSelectedHuntId(pkg.hunt_id)}
                  style={{
                    padding: '14px 16px',
                    borderRadius: '10px',
                    cursor: 'pointer',
                    background: isSelected ? '#f5f3ff' : '#ffffff',
                    border: `1px solid ${isSelected ? '#8b5cf6' : '#e2e8f0'}`,
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 600, fontSize: '0.9rem', color: isSelected ? '#5b21b6' : '#1e293b' }}>
                      {pkg.title}
                    </span>
                    <span
                      style={{
                        fontSize: '0.72rem',
                        fontWeight: 700,
                        padding: '2px 8px',
                        borderRadius: '12px',
                        background: pkg.severity === 'CRITICAL' ? '#fee2e2' : '#fef3c7',
                        color: pkg.severity === 'CRITICAL' ? '#991b1b' : '#92400e',
                      }}
                    >
                      {pkg.mitre_technique_id}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.8rem', color: '#64748b', marginTop: '6px', marginBottom: 0 }}>
                    {pkg.hypothesis}
                  </p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Translation Studio */}
        <div className="card" style={{ padding: '24px', background: '#ffffff', borderRadius: '12px', border: '1px solid #e9d5ff' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#4c1d95', margin: 0 }}>
              Query Translation Dialects
            </h3>

            {/* Dialect Selector */}
            <div style={{ display: 'flex', gap: '6px' }}>
              {['SPLUNK_SPL', 'ELASTIC_EQL', 'KUSTO_KQL', 'SIGMA'].map((lang) => (
                <button
                  key={lang}
                  onClick={() => setSelectedLanguage(lang)}
                  style={{
                    padding: '6px 12px',
                    borderRadius: '6px',
                    border: 'none',
                    background: selectedLanguage === lang ? '#7c3aed' : '#f3e8ff',
                    color: selectedLanguage === lang ? '#ffffff' : '#6b21a8',
                    fontWeight: 600,
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                  }}
                >
                  {lang.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>

          {selectedPkg && (
            <div style={{ padding: '12px 16px', background: '#faf5ff', borderRadius: '8px', border: '1px solid #e9d5ff', marginBottom: '16px', fontSize: '0.82rem' }}>
              <div><strong>Hunt ID:</strong> {selectedPkg.hunt_id}</div>
              <div><strong>Data Sources:</strong> {selectedPkg.target_data_sources.join(', ')}</div>
            </div>
          )}

          {error && <div className="alert alert-danger" style={{ marginBottom: '16px' }}>{error}</div>}

          <div>
            <label style={{ fontSize: '0.82rem', fontWeight: 600, color: '#4b5563', marginBottom: '6px', display: 'block' }}>
              Generated {selectedLanguage.replace('_', ' ')} Query:
            </label>
            <pre
              style={{
                background: '#0f172a',
                color: '#38bdf8',
                padding: '16px',
                borderRadius: '8px',
                fontSize: '0.82rem',
                fontFamily: 'monospace',
                overflowX: 'auto',
                minHeight: '140px',
                whiteSpace: 'pre-wrap',
                margin: 0,
              }}
            >
              {loading ? 'Compiling AST to target SIEM dialect...' : translatedQuery}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
