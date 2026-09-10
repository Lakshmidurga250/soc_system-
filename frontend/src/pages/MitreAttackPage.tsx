import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { MitreTechnique } from '../types';

export const MitreAttackPage: React.FC = () => {
  const [matrix, setMatrix] = useState<MitreTechnique[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);
  const [search, setSearch] = useState('');

  useEffect(() => {
    api<{ matrix: MitreTechnique[] }>('/assistant/mitre/matrix')
      .then((res) => {
        setMatrix(res.matrix || []);
        if (res.matrix && res.matrix.length > 0) {
          setSelectedTechnique(res.matrix[0]);
        }
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  const filtered = matrix.filter((m) =>
    m.category.toLowerCase().includes(search.toLowerCase()) ||
    m.technique.toLowerCase().includes(search.toLowerCase()) ||
    m.technique_id.toLowerCase().includes(search.toLowerCase()) ||
    m.tactic.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h2>MITRE ATT&CK® Enterprise Matrix</h2>
          <p>Local tactical mapping of detected threat categories to adversary techniques and countermeasures</p>
        </div>
        <div style={{ width: '300px' }}>
          <input
            type="text"
            className="search-input"
            placeholder="Search tactic, technique or ID (e.g. T1110)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '20px' }}>
        {/* Left: Matrix Grid */}
        <div className="card-panel">
          <div className="card-header">
            <h3>Covered Tactics & Techniques ({filtered.length})</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '650px', overflowY: 'auto' }}>
            {filtered.map((item) => (
              <div
                key={item.technique_id + item.category}
                onClick={() => setSelectedTechnique(item)}
                style={{
                  padding: '14px',
                  borderRadius: '6px',
                  background: selectedTechnique?.technique_id === item.technique_id ? 'rgba(6, 182, 212, 0.12)' : 'rgba(15, 23, 42, 0.6)',
                  border: selectedTechnique?.technique_id === item.technique_id ? '1px solid var(--cyan)' : '1px solid var(--border)',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-main)', fontSize: '14px' }}>{item.category}</span>
                  <span className="badge medium" style={{ fontFamily: 'var(--font-mono)' }}>{item.technique_id}</span>
                </div>
                <div style={{ display: 'flex', gap: '8px', fontSize: '12px', color: 'var(--text-dim)' }}>
                  <span>Tactic: <strong style={{ color: 'var(--cyan)' }}>{item.tactic}</strong> ({item.tactic_id})</span>
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px', lineHeight: 1.4 }}>
                  {item.technique}
                </p>
              </div>
            ))}
            {!loading && filtered.length === 0 && (
              <p style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)' }}>No techniques matched query.</p>
            )}
          </div>
        </div>

        {/* Right: Technique Deep Dive & Mitigations */}
        <div className="card-panel">
          <div className="card-header">
            <h3>Technique Details & Countermeasures</h3>
          </div>
          {selectedTechnique ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <span className="badge high" style={{ marginBottom: '8px', display: 'inline-block' }}>
                  {selectedTechnique.tactic_id}: {selectedTechnique.tactic}
                </span>
                <h3 style={{ color: 'var(--text-main)', fontSize: '18px', marginTop: '4px' }}>
                  {selectedTechnique.technique} ({selectedTechnique.technique_id})
                </h3>
              </div>

              <div>
                <label style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-dim)', letterSpacing: '0.05em' }}>
                  Adversary Behavior Description
                </label>
                <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px', lineHeight: 1.5 }}>
                  {selectedTechnique.description}
                </p>
              </div>

              <div style={{ background: 'rgba(16, 185, 129, 0.08)', padding: '14px', borderRadius: '6px', borderLeft: '3px solid var(--emerald)' }}>
                <strong style={{ color: 'var(--emerald)', fontSize: '13px', display: 'block', marginBottom: '4px' }}>
                  🛡️ Prescribed SOC Mitigation & Hardening
                </strong>
                <p style={{ fontSize: '12px', color: 'var(--text-main)', lineHeight: 1.5 }}>
                  {selectedTechnique.mitigation}
                </p>
              </div>

              <div>
                <label style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-dim)', letterSpacing: '0.05em' }}>
                  Active Telemetry Detection Signatures
                </label>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                  {selectedTechnique.detection_signatures?.map((sig, idx) => (
                    <span key={idx} style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', padding: '4px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>
                      {sig}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <p style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '40px' }}>Select a technique to view details.</p>
          )}
        </div>
      </div>
    </div>
  );
};
