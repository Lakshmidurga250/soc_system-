import React, { useState } from 'react';
import { MitigationPlaybook } from '../types';
import { api } from '../services/api';

interface Props {
  playbook: MitigationPlaybook | null;
  onClose: () => void;
  onActionTriggered: () => void;
}

export const PlaybookModal: React.FC<Props> = ({ playbook, onClose, onActionTriggered }) => {
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState('');

  if (!playbook) return null;

  const handleTriggerAction = async (act: any) => {
    setLoadingAction(act.target);
    setSuccessMsg('');
    try {
      await api('/response/actions', {
        method: 'POST',
        body: JSON.stringify({
          incident_id: playbook.incident_id,
          action_type: act.action_type,
          mode: act.mode,
          payload: { target: act.target },
          reason: act.reason,
        }),
      });
      setSuccessMsg(`Action ${act.action_type} for ${act.target} queued in Approval Center.`);
      onActionTriggered();
    } catch (e: any) {
      alert(`Error triggering action: ${e.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: '720px' }}>
        <div className="modal-header">
          <div>
            <h3>AI Mitigation & Response Playbook</h3>
            <p style={{ fontSize: '11px', color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>
              PROFILE: {playbook.threat_category} | CONFIDENCE: {int(playbook.confidence_level * 100)}%
            </p>
          </div>
          <button onClick={onClose} className="modal-close">✕</button>
        </div>

        {successMsg && (
          <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#34d399', padding: '10px', borderRadius: '6px', fontSize: '12px' }}>
            ✓ {successMsg}
          </div>
        )}

        <div style={{ background: 'rgba(0,0,0,0.3)', padding: '14px', borderRadius: '8px', borderLeft: '3px solid var(--purple)' }}>
          <h4 style={{ fontSize: '12px', color: 'var(--purple)', marginBottom: '4px' }}>Forensic Root-Cause Hypothesis</h4>
          <p style={{ fontSize: '12px', color: 'var(--text-main)', lineHeight: '1.4' }}>{playbook.forensic_hypothesis}</p>
        </div>

        <div>
          <h4 style={{ fontSize: '13px', color: '#fff', marginBottom: '10px' }}>Suggested Containment & Response Actions</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {playbook.suggested_actions.map((act, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(15, 23, 42, 0.9)', border: '1px solid var(--border)', padding: '10px 14px', borderRadius: '6px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="badge critical">{act.action_type}</span>
                    <strong style={{ fontSize: '13px', color: '#fff' }}>{act.target}</strong>
                  </div>
                  <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>{act.reason}</p>
                </div>
                <button
                  disabled={loadingAction === act.target}
                  onClick={() => handleTriggerAction(act)}
                  className="btn btn-danger btn-sm"
                >
                  {loadingAction === act.target ? 'Queuing…' : 'Request Approval →'}
                </button>
              </div>
            ))}
          </div>
        </div>

        <div>
          <h4 style={{ fontSize: '13px', color: '#fff', marginBottom: '10px' }}>Phased Remediation Plan</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {playbook.response_playbook.map((phase, pIdx) => (
              <div key={pIdx} style={{ background: 'rgba(10, 15, 29, 0.6)', border: '1px solid var(--border)', borderRadius: '6px', padding: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <strong style={{ fontSize: '12px', color: 'var(--cyan)' }}>{phase.phase}</strong>
                  <span style={{ fontSize: '10px', color: 'var(--amber)', fontFamily: 'var(--font-mono)' }}>{phase.priority}</span>
                </div>
                <ul style={{ paddingLeft: '18px', fontSize: '11px', color: 'var(--text-muted)' }}>
                  {phase.actions.map((step, sIdx) => (
                    <li key={sIdx} style={{ marginBottom: '2px' }}>{step}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '10px' }}>
          <button onClick={onClose} className="btn btn-secondary">Close Playbook</button>
        </div>
      </div>
    </div>
  );
};

function int(val: number) {
  return Math.round(val || 0);
}
