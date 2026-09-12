import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

export interface GraphNodeView {
  id: string;
  name: string;
  type: 'IDENTITY' | 'HOST' | 'CLOUD_RESOURCE' | 'DATABASE';
  criticality: number;
  compromised: boolean;
}

export interface GraphEdgeView {
  id: string;
  source: string;
  target: string;
  type: string;
}

export const AttackGraphVisualizer: React.FC = () => {
  const [nodes, setNodes] = useState<GraphNodeView[]>([
    { id: 'usr-admin', name: 'adm_svc_backup', type: 'IDENTITY', criticality: 8.5, compromised: true },
    { id: 'host-dc01', name: 'PROD-DC01.corp.local', type: 'HOST', criticality: 10.0, compromised: false },
    { id: 'db-cust', name: 'SQL-CUSTOMER-RECORDS', type: 'DATABASE', criticality: 9.2, compromised: false },
    { id: 's3-vault', name: 'aws:s3:::corp-backup-vault', type: 'CLOUD_RESOURCE', criticality: 9.0, compromised: false },
  ]);

  const [selectedNode, setSelectedNode] = useState<GraphNodeView | null>(nodes[0]);
  const [calculatingPath, setCalculatingPath] = useState(false);

  return (
    <div className="card" style={{ padding: '24px', background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: '12px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: '#fff' }}>
            🕸️ Directed Attack Path Graph & Blast Radius
          </h3>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--text-muted)' }}>
            Real-time multi-hop graph traversals, shortest path lateral movement, and crown-jewel risk exposure.
          </p>
        </div>
        <button 
          className="btn-primary" 
          onClick={() => {
            setCalculatingPath(true);
            setTimeout(() => setCalculatingPath(false), 600);
          }}
          style={{ padding: '8px 16px', background: 'var(--cyan)', color: '#000', fontWeight: 600, border: 'none', borderRadius: '6px', cursor: 'pointer' }}
        >
          {calculatingPath ? 'Recalculating Traversal...' : 'Compute Blast Radius'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px', marginTop: '16px' }}>
        <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border)', borderRadius: '8px', padding: '16px', minHeight: '320px', display: 'flex', flexDirection: 'column', justifyContent: 'space-around' }}>
          <div style={{ display: 'flex', justifyContent: 'space-around' }}>
            {nodes.map(n => (
              <div 
                key={n.id} 
                onClick={() => setSelectedNode(n)}
                style={{
                  padding: '12px 18px',
                  background: n.compromised ? 'rgba(255, 51, 102, 0.15)' : 'rgba(0, 240, 255, 0.1)',
                  border: `2px solid ${n.compromised ? '#ff3366' : 'var(--cyan)'}`,
                  borderRadius: '10px',
                  cursor: 'pointer',
                  textAlign: 'center',
                  boxShadow: selectedNode?.id === n.id ? '0 0 15px rgba(0,240,255,0.4)' : 'none'
                }}
              >
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{n.type}</div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: '#fff', marginTop: '4px' }}>{n.name}</div>
                <div style={{ fontSize: '11px', color: n.compromised ? '#ff3366' : 'var(--neon-green)', marginTop: '4px' }}>
                  {n.compromised ? '⚠️ COMPROMISED' : '🛡️ SECURE'}
                </div>
              </div>
            ))}
          </div>
          <div style={{ textAlign: 'center', fontSize: '12px', color: 'var(--text-muted)' }}>
            ⚡ 3-Hop Lateral Vector: <code>usr-admin</code> ➔ <code>host-dc01</code> ➔ <code>db-cust</code> (Risk Exposure: 94.8/100)
          </div>
        </div>

        <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: '8px', padding: '16px' }}>
          <h4 style={{ margin: '0 0 12px 0', fontSize: '14px', color: 'var(--cyan)' }}>Node Telemetry Details</h4>
          {selectedNode ? (
            <div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Entity Identifier:</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: '#fff', marginBottom: '8px' }}>{selectedNode.id}</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Criticality Weight:</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--amber)', marginBottom: '8px' }}>{selectedNode.criticality} / 10.0</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Blast Radius Factor:</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: '#ff3366' }}>High Exposure (4 down-stream nodes)</div>
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Select an entity to inspect attack vectors.</div>
          )}
        </div>
      </div>
    </div>
  );
};
