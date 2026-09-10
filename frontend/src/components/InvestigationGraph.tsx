import React from 'react';

interface Props {
  incidentTitle: string;
  entities: {
    source_ips?: string[];
    usernames?: string[];
    hostnames?: string[];
  };
}

export const InvestigationGraph: React.FC<Props> = ({ incidentTitle, entities }) => {
  const ips = entities.source_ips || [];
  const users = entities.usernames || [];
  const hosts = entities.hostnames || [];

  const width = 540;
  const height = 300;
  const centerX = width / 2;
  const centerY = height / 2;

  // Build node coordinates
  const nodes: Array<{ id: string; label: string; type: string; x: number; y: number; color: string }> = [
    { id: 'root', label: incidentTitle.slice(0, 24) + '…', type: 'incident', x: centerX, y: centerY, color: '#f43f5e' },
  ];

  const allRelated = [
    ...ips.map(ip => ({ id: ip, label: `IP: ${ip}`, type: 'ip', color: '#06b6d4' })),
    ...users.map(u => ({ id: u, label: `User: ${u}`, type: 'user', color: '#a855f7' })),
    ...hosts.map(h => ({ id: h, label: `Host: ${h}`, type: 'host', color: '#10b981' })),
  ];

  const total = allRelated.length || 1;
  allRelated.forEach((item, index) => {
    const angle = (index / total) * 2 * Math.PI;
    const radius = 110;
    nodes.push({
      ...item,
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    });
  });

  return (
    <div style={{ background: 'rgba(10, 15, 29, 0.9)', border: '1px solid var(--border)', borderRadius: '8px', padding: '16px', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>AI Correlation Topology Graph</span>
        <div style={{ display: 'flex', gap: '12px', fontSize: '10px', fontFamily: 'var(--font-mono)' }}>
          <span style={{ color: '#f43f5e' }}>● Incident</span>
          <span style={{ color: '#06b6d4' }}>● Source IP</span>
          <span style={{ color: '#a855f7' }}>● Identity</span>
          <span style={{ color: '#10b981' }}>● Endpoint</span>
        </div>
      </div>

      <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`}>
        {/* Draw connection lines */}
        {nodes.slice(1).map((node) => (
          <line
            key={`line-${node.id}`}
            x1={centerX}
            y1={centerY}
            x2={node.x}
            y2={node.y}
            stroke="rgba(148, 163, 184, 0.25)"
            strokeWidth="1.5"
            strokeDasharray="4 2"
          />
        ))}

        {/* Draw Nodes */}
        {nodes.map((node) => (
          <g key={node.id} transform={`translate(${node.x}, ${node.y})`}>
            <circle
              r={node.type === 'incident' ? 24 : 18}
              fill="rgba(15, 23, 42, 0.9)"
              stroke={node.color}
              strokeWidth="2"
            />
            <circle
              r={node.type === 'incident' ? 8 : 5}
              fill={node.color}
            />
            <text
              y={node.type === 'incident' ? 36 : 28}
              textAnchor="middle"
              fill="var(--text-main)"
              fontSize={node.type === 'incident' ? '11px' : '9px'}
              fontFamily="var(--font-mono)"
            >
              {node.label}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
};
