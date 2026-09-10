import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { ApprovalItem } from '../types';

export const ResponsePage: React.FC = () => {
  const [approvals, setApprovals] = useState<ApprovalItem[]>([]);
  const [actionType, setActionType] = useState('BLOCK_IP');
  const [target, setTarget] = useState('');
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const fetchApprovals = () => {
    api<{ items: ApprovalItem[] }>('/approvals')
      .then((res) => setApprovals(res.items))
      .catch((e) => console.error(e));
  };

  useEffect(() => {
    fetchApprovals();
  }, []);

  const handleCreateAction = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setLoading(true);
    setError('');
    setSuccess('');
    try {
      await api('/response/actions', {
        method: 'POST',
        body: JSON.stringify({
          action_type: actionType,
          mode: 'APPROVAL_REQUIRED',
          payload: { target },
          reason: reason || 'Manual containment requested by SOC Analyst',
        }),
      });
      setSuccess(`Action queued: ${actionType} for ${target}. Awaiting dual-custody authorization.`);
      setTarget('');
      setReason('');
      fetchApprovals();
    } catch (err: any) {
      setError(err.message || 'Action dispatch failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDecision = async (approvalId: string, approved: boolean) => {
    try {
      await api(`/approvals/${approvalId}/decision`, {
        method: 'POST',
        body: JSON.stringify({
          approved,
          note: approved ? 'Authorized by Senior SOC Analyst' : 'Rejected after analyst review',
        }),
      });
      fetchApprovals();
    } catch (e: any) {
      alert(`Decision failed: ${e.message}`);
    }
  };

  return (
    <div className="page-container">
      <div>
        <h3 style={{ fontSize: '18px', color: '#fff' }}>Response Center & Dual-Custody Approval Queue</h3>
        <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Execute safe containment actions with approval-gated authorization and auditable logs.
        </p>
      </div>

      {/* Action Dispatch Form */}
      <div className="card-panel">
        <div className="card-header">
          <h3>Request Safe Containment Action</h3>
        </div>

        {error && <div className="error-banner" style={{ marginBottom: '12px' }}>{error}</div>}
        {success && (
          <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#34d399', padding: '10px', borderRadius: '6px', fontSize: '12px', marginBottom: '12px' }}>
            ✓ {success}
          </div>
        )}

        <form onSubmit={handleCreateAction} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.5fr 2fr auto', gap: '12px', alignItems: 'flex-end' }}>
          <div className="form-group">
            <label>Action Type</label>
            <select className="select-input" value={actionType} onChange={(e) => setActionType(e.target.value)}>
              <option value="BLOCK_IP">BLOCK IP Address</option>
              <option value="QUARANTINE_HOST">QUARANTINE Host</option>
              <option value="REVOKE_SESSION">REVOKE User Session</option>
              <option value="ISOLATE_PROCESS">ISOLATE Process</option>
            </select>
          </div>

          <div className="form-group">
            <label>Target Identifier</label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. 198.51.100.44 or CORP-WKST01"
              required
            />
          </div>

          <div className="form-group">
            <label>Justification & Rationale</label>
            <input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Reason for triggering immediate containment"
            />
          </div>

          <button type="submit" disabled={loading} className="btn btn-primary" style={{ height: '38px' }}>
            {loading ? 'Submitting…' : 'Queue Request →'}
          </button>
        </form>
      </div>

      {/* Pending Approvals Table */}
      <div className="card-panel">
        <div className="card-header">
          <h3>Pending Dual-Custody Approvals ({approvals.length} Requests)</h3>
          <button onClick={fetchApprovals} className="btn btn-secondary btn-sm">Refresh</button>
        </div>

        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Request ID</th>
                <th>Target Payload</th>
                <th>Justification</th>
                <th>Requested At</th>
                <th>Status</th>
                <th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {approvals.map((req) => (
                <tr key={req.id}>
                  <td>
                    <code>{req.id.slice(0, 8)}</code>
                  </td>
                  <td>
                    <strong style={{ color: 'var(--cyan)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                      {req.action?.action_type || 'CONTAINMENT'}: {req.action?.payload?.target || 'target'}
                    </strong>
                  </td>
                  <td style={{ fontSize: '12px' }}>{req.reason}</td>
                  <td style={{ fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                    {new Date(req.created_at).toLocaleString()}
                  </td>
                  <td>
                    <span className="badge pending">{req.status}</span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <button
                        onClick={() => handleDecision(req.id, true)}
                        className="btn btn-primary btn-sm"
                        style={{ background: 'var(--emerald)', border: 'none' }}
                      >
                        ✓ Authorize
                      </button>
                      <button
                        onClick={() => handleDecision(req.id, false)}
                        className="btn btn-danger btn-sm"
                      >
                        ✕ Reject
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {approvals.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)' }}>
                    No pending response approval requests in queue.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
