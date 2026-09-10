import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { DetectionRule } from '../types';
import { RuleBuilderModal } from '../components/RuleBuilderModal';

export const DetectionPage: React.FC = () => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [modalOpen, setModalOpen] = useState(false);

  const fetchRules = () => {
    api<{ items: DetectionRule[] }>('/detection/rules')
      .then((res) => setRules(res.items))
      .catch((e) => console.error(e));
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggleRule = async (rule: DetectionRule) => {
    try {
      await api(`/detection/rules/${rule.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: rule.name,
          description: rule.description,
          rule_type: rule.rule_type,
          config: rule.config,
          severity: rule.severity,
          enabled: !rule.enabled,
        }),
      });
      fetchRules();
    } catch (e: any) {
      alert(`Toggle failed: ${e.message}`);
    }
  };

  return (
    <div className="page-container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ fontSize: '18px', color: '#fff' }}>Behavioral Detection Engine</h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Real-time threshold rules and correlation triggers evaluating every incoming security event.
          </p>
        </div>
        <button onClick={() => setModalOpen(true)} className="btn btn-primary">
          + Author Detection Rule
        </button>
      </div>

      <div className="card-panel">
        <div className="card-header">
          <h3>Active Detection Catalog ({rules.length} Rules)</h3>
          <button onClick={fetchRules} className="btn btn-secondary btn-sm">Refresh</button>
        </div>

        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Rule Name</th>
                <th>Severity</th>
                <th>Target Event / Config</th>
                <th>Matches</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td>
                    <strong style={{ color: '#fff', fontSize: '13px' }}>{r.name}</strong>
                    <p style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px' }}>{r.description}</p>
                  </td>
                  <td>
                    <span className={`badge ${r.severity.toLowerCase()}`}>{r.severity}</span>
                  </td>
                  <td>
                    <code style={{ fontSize: '11px' }}>{JSON.stringify(r.config)}</code>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--cyan)' }}>
                    {r.match_count} hits
                  </td>
                  <td>
                    <span className={`badge ${r.enabled ? 'resolved' : 'low'}`}>
                      {r.enabled ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </td>
                  <td>
                    <button
                      onClick={() => handleToggleRule(r)}
                      className="btn btn-secondary btn-sm"
                    >
                      {r.enabled ? 'Disable' : 'Enable'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <RuleBuilderModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        onRuleCreated={fetchRules}
      />
    </div>
  );
};
