import React, { useState } from 'react';
import { api } from '../services/api';

export const ITDRDashboardPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'kerberoast' | 'dcsync' | 'spray' | 'asrep'>('kerberoast');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // Kerberoast test inputs
  const [servicePrincipal, setServicePrincipal] = useState('MSSQLSvc/db01.corp.local:1433');
  const [encType, setEncType] = useState('0x17 (RC4_HMAC)');
  const [ticketRequests, setTicketRequests] = useState(15);

  // DCSync test inputs
  const [sourceHost, setSourceHost] = useState('ws-developer-44');
  const [requestedGuid, setRequestedGuid] = useState('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All)');

  // Spray test inputs
  const [targetAccountsCount, setTargetAccountsCount] = useState(42);
  const [windowSeconds, setWindowSeconds] = useState(180);

  const runITDRCheck = async () => {
    setLoading(true);
    setError(null);
    try {
      let endpoint = '/advanced/itdr/kerberoasting-check';
      let payload: any = {};

      if (activeTab === 'kerberoast') {
        endpoint = '/advanced/itdr/kerberoasting-check';
        payload = {
          service_principal_name: servicePrincipal,
          encryption_type: encType,
          ticket_requests_count: Number(ticketRequests),
        };
      } else if (activeTab === 'dcsync') {
        endpoint = '/advanced/itdr/dcsync-check';
        payload = {
          source_host: sourceHost,
          is_domain_controller: false,
          extended_rights_guid: requestedGuid,
        };
      } else if (activeTab === 'spray') {
        endpoint = '/advanced/itdr/password-spray-check';
        payload = {
          unique_target_accounts: Number(targetAccountsCount),
          time_window_seconds: Number(windowSeconds),
          failed_ratio: 0.95,
        };
      }

      const data = await api(endpoint, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'ITDR analysis failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Identity Threat Detection & Response (ITDR)</h1>
          <p className="page-subtitle">
            Active Directory & Kerberos telemetry analytics: DCSync replication, Kerberoasting, AS-REP roasting, and password sprays.
          </p>
        </div>
        <button className="btn btn-primary" onClick={runITDRCheck} disabled={loading}>
          {loading ? 'Analyzing Identity Telemetry...' : 'Execute ITDR Inspection'}
        </button>
      </div>

      {/* Attack Vector Tabs */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', borderBottom: '1px solid #e2e8f0', paddingBottom: '10px' }}>
        {[
          { id: 'kerberoast', label: '🛡️ Kerberoasting (T1558.003)' },
          { id: 'dcsync', label: '🚨 DCSync DRSUAPI (T1003.006)' },
          { id: 'spray', label: '🌊 Password Spraying (T1110.003)' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => {
              setActiveTab(tab.id as any);
              setResult(null);
            }}
            style={{
              padding: '8px 18px',
              borderRadius: '8px',
              border: 'none',
              background: activeTab === tab.id ? '#7c3aed' : '#f3e8ff',
              color: activeTab === tab.id ? '#ffffff' : '#6b21a8',
              fontWeight: 600,
              fontSize: '0.85rem',
              cursor: 'pointer',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {error && <div className="alert alert-danger" style={{ marginBottom: '20px' }}>{error}</div>}

      <div className="grid-2col" style={{ display: 'grid', gridTemplateColumns: '1fr 1.4fr', gap: '24px' }}>
        {/* Configuration Card */}
        <div className="card" style={{ padding: '24px', background: '#ffffff', borderRadius: '12px', border: '1px solid #e9d5ff' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#4c1d95', marginBottom: '16px' }}>
            Identity Threat Parameters
          </h3>

          {activeTab === 'kerberoast' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>Target SPN (Service Principal Name)</label>
                <input
                  className="input-field"
                  value={servicePrincipal}
                  onChange={(e) => setServicePrincipal(e.target.value)}
                  style={{ width: '100%', padding: '8px 12px', marginTop: '4px', borderRadius: '8px', border: '1px solid #cbd5e1' }}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>Kerberos Ticket Encryption Type</label>
                <select
                  className="input-field"
                  value={encType}
                  onChange={(e) => setEncType(e.target.value)}
                  style={{ width: '100%', padding: '8px 12px', marginTop: '4px', borderRadius: '8px', border: '1px solid #cbd5e1' }}
                >
                  <option value="0x17 (RC4_HMAC)">0x17 (RC4_HMAC - Vulnerable / Weak)</option>
                  <option value="0x12 (AES256_CTS_HMAC_SHA1_96)">0x12 (AES256_CTS - Strong / Modern)</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>TGS Ticket Requests Count: {ticketRequests}</label>
                <input
                  type="range"
                  min={1}
                  max={50}
                  value={ticketRequests}
                  onChange={(e) => setTicketRequests(Number(e.target.value))}
                  style={{ width: '100%', marginTop: '6px' }}
                />
              </div>
            </div>
          )}

          {activeTab === 'dcsync' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>Source Originating Host</label>
                <input
                  className="input-field"
                  value={sourceHost}
                  onChange={(e) => setSourceHost(e.target.value)}
                  style={{ width: '100%', padding: '8px 12px', marginTop: '4px', borderRadius: '8px', border: '1px solid #cbd5e1' }}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>DRSUAPI Replication Right GUID</label>
                <input
                  className="input-field"
                  value={requestedGuid}
                  onChange={(e) => setRequestedGuid(e.target.value)}
                  style={{ width: '100%', padding: '8px 12px', marginTop: '4px', borderRadius: '8px', border: '1px solid #cbd5e1' }}
                />
              </div>
            </div>
          )}

          {activeTab === 'spray' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>
                  Target Accounts Probed: {targetAccountsCount}
                </label>
                <input
                  type="range"
                  min={5}
                  max={100}
                  value={targetAccountsCount}
                  onChange={(e) => setTargetAccountsCount(Number(e.target.value))}
                  style={{ width: '100%', marginTop: '6px' }}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>
                  Time Window (Seconds): {windowSeconds}s
                </label>
                <input
                  type="range"
                  min={30}
                  max={600}
                  step={30}
                  value={windowSeconds}
                  onChange={(e) => setWindowSeconds(Number(e.target.value))}
                  style={{ width: '100%', marginTop: '6px' }}
                />
              </div>
            </div>
          )}
        </div>

        {/* Results Card */}
        <div className="card" style={{ padding: '24px', background: '#ffffff', borderRadius: '12px', border: '1px solid #e9d5ff' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#4c1d95', marginBottom: '16px' }}>
            Detection Verdict & Evidence
          </h3>

          {result ? (
            <div>
              <div
                style={{
                  padding: '16px 20px',
                  borderRadius: '10px',
                  background: result.detected ? '#fef2f2' : '#f0fdf4',
                  border: `1px solid ${result.detected ? '#fecaca' : '#bbf7d0'}`,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '16px',
                }}
              >
                <div>
                  <div style={{ fontSize: '0.8rem', color: '#6b7280', fontWeight: 600 }}>STATUS</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, color: result.detected ? '#dc2626' : '#16a34a' }}>
                    {result.detected ? '🚨 THREAT CONFIRMED' : '✓ BENIGN TRAFFIC'}
                  </div>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '0.8rem', color: '#6b7280', fontWeight: 600 }}>SEVERITY</div>
                  <span
                    style={{
                      display: 'inline-block',
                      padding: '4px 12px',
                      borderRadius: '12px',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      background: result.severity === 'CRITICAL' ? '#991b1b' : result.severity === 'HIGH' ? '#dc2626' : '#2563eb',
                      color: '#ffffff',
                    }}
                  >
                    {result.severity || 'LOW'}
                  </span>
                </div>
              </div>

              {result.details && (
                <div style={{ background: '#faf5ff', padding: '16px', borderRadius: '8px', border: '1px solid #e9d5ff', marginBottom: '16px' }}>
                  <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#4c1d95', marginBottom: '8px' }}>Forensic Evidence</h4>
                  <pre style={{ fontSize: '0.8rem', color: '#374151', margin: 0, whiteSpace: 'pre-wrap' }}>
                    {JSON.stringify(result.details, null, 2)}
                  </pre>
                </div>
              )}

              {result.recommended_containment && (
                <div>
                  <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#374151', marginBottom: '8px' }}>Recommended Defensive Actions</h4>
                  <div style={{ padding: '12px 16px', background: '#f8fafc', borderRadius: '8px', borderLeft: '4px solid #3b82f6', fontSize: '0.85rem' }}>
                    {result.recommended_containment}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div style={{ padding: '40px', textAlign: 'center', color: '#9ca3af' }}>
              Select attack parameters and click Execute ITDR Inspection.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
