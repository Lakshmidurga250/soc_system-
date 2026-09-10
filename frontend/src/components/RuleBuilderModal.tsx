import React, { useState } from 'react';
import { api } from '../services/api';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onRuleCreated: () => void;
}

export const RuleBuilderModal: React.FC<Props> = ({ isOpen, onClose, onRuleCreated }) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState('HIGH');
  const [eventType, setEventType] = useState('login');
  const [status, setStatus] = useState('FAILURE');
  const [thresholdCount, setThresholdCount] = useState(5);
  const [timeWindowSec, setTimeWindowSec] = useState(300);

  const [testResult, setTestResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleTestDryRun = async () => {
    try {
      const res = await api('/detection/rules/test', {
        method: 'POST',
        body: JSON.stringify({
          rule_config: {
            event_type: eventType,
            status: status,
            threshold_count: thresholdCount,
            time_window_seconds: timeWindowSec,
          },
          event_payload: {
            event_type: 'login',
            status: 'FAILURE',
            severity: 'HIGH',
          },
        }),
      });
      setTestResult(res);
    } catch (e: any) {
      alert(`Dry run test failed: ${e.message}`);
    }
  };

  const handleSaveRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    setLoading(true);
    setError('');
    try {
      await api('/detection/rules', {
        method: 'POST',
        body: JSON.stringify({
          name,
          description,
          severity,
          rule_type: 'threshold',
          config: {
            event_type: eventType,
            status: status,
            threshold_count: thresholdCount,
            time_window_seconds: timeWindowSec,
          },
        }),
      });
      onRuleCreated();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to create rule');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: '640px' }}>
        <div className="modal-header">
          <h3>Create Behavioral Detection Rule</h3>
          <button onClick={onClose} className="modal-close">✕</button>
        </div>

        {error && <div className="error-banner">{error}</div>}

        <form onSubmit={handleSaveRule} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div className="form-group">
            <label>Rule Name</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Brute Force Velocity Exceeded"
              required
            />
          </div>

          <div className="form-group">
            <label>Description & Detection Rationale</label>
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Detects rapid successive authentication failures targeting user accounts"
              required
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div className="form-group">
              <label>Alert Severity</label>
              <select className="select-input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>

            <div className="form-group">
              <label>Target Event Type</label>
              <input
                value={eventType}
                onChange={(e) => setEventType(e.target.value)}
                placeholder="login / http_request / api_access"
                required
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
            <div className="form-group">
              <label>Status Filter</label>
              <input
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                placeholder="FAILURE / SUCCESS"
              />
            </div>

            <div className="form-group">
              <label>Threshold Count</label>
              <input
                type="number"
                min="1"
                max="1000"
                value={thresholdCount}
                onChange={(e) => setThresholdCount(Number(e.target.value))}
              />
            </div>

            <div className="form-group">
              <label>Time Window (sec)</label>
              <input
                type="number"
                min="10"
                max="86400"
                value={timeWindowSec}
                onChange={(e) => setTimeWindowSec(Number(e.target.value))}
              />
            </div>
          </div>

          {testResult && (
            <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px', borderRadius: '6px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
              <span style={{ color: testResult.matches ? 'var(--emerald)' : 'var(--rose)' }}>
                {testResult.matches ? '✓ Rule Dry-Run: MATCHED Simulated Event' : '✕ Rule Dry-Run: NO MATCH'}
              </span>
              <p style={{ color: 'var(--text-dim)', marginTop: '4px' }}>{testResult.reasons?.join(', ')}</p>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px' }}>
            <button type="button" onClick={handleTestDryRun} className="btn btn-secondary btn-sm">
              ⚡ Test Dry-Run Sandbox
            </button>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button type="button" onClick={onClose} className="btn btn-secondary">Cancel</button>
              <button type="submit" disabled={loading} className="btn btn-primary">
                {loading ? 'Creating…' : 'Deploy Rule →'}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};
