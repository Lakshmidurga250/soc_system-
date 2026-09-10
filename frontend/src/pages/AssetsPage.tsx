import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Asset } from '../types';

export const AssetsPage: React.FC = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [criticalityFilter, setCriticalityFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const qParam = search ? `?q=${encodeURIComponent(search)}` : '';
    const critParam = criticalityFilter !== 'ALL' ? `${qParam ? '&' : '?'}criticality=${criticalityFilter}` : '';
    api<{ items: Asset[]; total: number }>(`/assets${qParam}${critParam}`)
      .then((res) => setAssets(res.items || []))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, [criticalityFilter, search]);

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h2>Enterprise Asset Inventory & Criticality Matrix</h2>
          <p>Track enterprise infrastructure, host criticality tiers, operating systems, and live risk ratings</p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <input
            type="text"
            className="search-input"
            placeholder="Search hostname, IP or owner..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className="select-input"
            value={criticalityFilter}
            onChange={(e) => setCriticalityFilter(e.target.value)}
          >
            <option value="ALL">All Criticality Tiers</option>
            <option value="TIER_1">Tier 1 (Mission Critical)</option>
            <option value="TIER_2">Tier 2 (High)</option>
            <option value="TIER_3">Tier 3 (Medium)</option>
            <option value="TIER_4">Tier 4 (Low)</option>
          </select>
        </div>
      </div>

      <div className="card-panel">
        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>Asset Type</th>
                <th>Criticality Tier</th>
                <th>Operating System</th>
                <th>Owner / Team</th>
                <th>Current Risk Rating</th>
                <th>Operational Status</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((ast) => (
                <tr key={ast.id}>
                  <td>
                    <strong style={{ color: '#fff' }}>{ast.hostname}</strong>
                  </td>
                  <td>
                    <code style={{ color: 'var(--cyan)' }}>{ast.ip_address}</code>
                  </td>
                  <td>
                    <span style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                      {ast.asset_type}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${ast.criticality === 'TIER_1' ? 'critical' : ast.criticality === 'TIER_2' ? 'high' : 'medium'}`}>
                      {ast.criticality}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>
                    {ast.operating_system || 'Linux / Unix'}
                  </td>
                  <td style={{ color: 'var(--text-dim)' }}>
                    {ast.owner || 'SecOps Team'}
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontWeight: 600, color: (ast.current_risk_score || 0) > 70 ? 'var(--rose)' : (ast.current_risk_score || 0) > 40 ? 'var(--amber)' : 'var(--emerald)' }}>
                        {ast.current_risk_score || 25.0}
                      </span>
                      <div style={{ width: '50px', height: '4px', background: 'rgba(0,0,0,0.4)', borderRadius: '2px' }}>
                        <div
                          style={{
                            width: `${Math.min(100, ast.current_risk_score || 25)}%`,
                            height: '100%',
                            background: (ast.current_risk_score || 0) > 70 ? 'var(--rose)' : 'var(--cyan)',
                          }}
                        />
                      </div>
                    </div>
                  </td>
                  <td>
                    <span className="badge low" style={{ color: 'var(--emerald)', borderColor: 'var(--emerald)' }}>
                      {ast.status || 'ONLINE'}
                    </span>
                  </td>
                </tr>
              ))}
              {!loading && assets.length === 0 && (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)' }}>
                    No assets found matching current criteria.
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
