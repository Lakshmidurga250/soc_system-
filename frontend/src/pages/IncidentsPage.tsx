import React, { useEffect, useState } from 'react';
import { api, downloadPdf } from '../services/api';
import { Incident, Investigation, MitigationPlaybook } from '../types';
import { InvestigationGraph } from '../components/InvestigationGraph';
import { PlaybookModal } from '../components/PlaybookModal';

export const IncidentsPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [playbook, setPlaybook] = useState<MitigationPlaybook | null>(null);
  const [investigating, setInvestigating] = useState(false);
  const [loadingPlaybook, setLoadingPlaybook] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const fetchIncidents = () => {
    api<{ items: Incident[] }>('/incidents')
      .then((res) => {
        setIncidents(res.items);
        if (res.items.length > 0 && !selectedIncident) {
          setSelectedIncident(res.items[0]);
        }
      })
      .catch((e) => console.error(e));
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  useEffect(() => {
    if (selectedIncident?.investigation_id) {
      api<Investigation>(`/investigations/${selectedIncident.investigation_id}`)
        .then(setInvestigation)
        .catch(() => setInvestigation(null));
    } else {
      setInvestigation(null);
    }
  }, [selectedIncident]);

  const handleRunInvestigation = async () => {
    if (!selectedIncident) return;
    setInvestigating(true);
    try {
      const inv = await api<Investigation>(`/incidents/${selectedIncident.id}/investigate`, {
        method: 'POST',
      });
      setInvestigation(inv);
      fetchIncidents();
    } catch (e: any) {
      alert(`Investigation failed: ${e.message}`);
    } finally {
      setInvestigating(false);
    }
  };

  const handleOpenPlaybook = async () => {
    if (!selectedIncident) return;
    setLoadingPlaybook(true);
    try {
      const pb = await api<MitigationPlaybook>(`/incidents/${selectedIncident.id}/playbook`);
      setPlaybook(pb);
    } catch (e: any) {
      alert(`Failed to generate playbook: ${e.message}`);
    } finally {
      setLoadingPlaybook(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!selectedIncident) return;
    setDownloadingPdf(true);
    try {
      await downloadPdf(`/reports/incidents/${selectedIncident.id}/pdf`, `incident_${selectedIncident.id.slice(0, 8)}_forensic.pdf`);
    } catch (e: any) {
      alert(`PDF download failed: ${e.message}`);
    } finally {
      setDownloadingPdf(false);
    }
  };

  return (
    <div className="page-container">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ fontSize: '18px', color: '#fff' }}>Incidents & AI Deep Investigation</h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Correlate related entity timelines, extract evidence, generate mitigation playbooks, and export forensic reports.
          </p>
        </div>
        <button onClick={fetchIncidents} className="btn btn-secondary btn-sm">Refresh</button>
      </div>

      {/* Main Grid: Incident List on left, Deep Investigation on right */}
      <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: '20px', alignItems: 'flex-start' }}>
        {/* Left: Incident List */}
        <div className="card-panel" style={{ padding: '16px' }}>
          <h4 style={{ fontSize: '14px', color: '#fff', marginBottom: '12px' }}>Active Incident Cases</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {incidents.map((inc) => (
              <div
                key={inc.id}
                onClick={() => setSelectedIncident(inc)}
                style={{
                  padding: '12px',
                  borderRadius: '6px',
                  background: selectedIncident?.id === inc.id ? 'rgba(6, 182, 212, 0.12)' : 'rgba(10, 15, 29, 0.6)',
                  border: `1px solid ${selectedIncident?.id === inc.id ? 'var(--cyan)' : 'var(--border)'}`,
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <span className={`badge ${inc.severity.toLowerCase()}`}>{inc.severity}</span>
                  <span className={`badge ${inc.status.toLowerCase()}`}>{inc.status}</span>
                </div>
                <strong style={{ fontSize: '13px', color: '#fff', display: 'block' }}>{inc.title}</strong>
                <span style={{ fontSize: '10px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                  {new Date(inc.created_at).toLocaleString()}
                </span>
              </div>
            ))}
            {incidents.length === 0 && (
              <p style={{ fontSize: '12px', color: 'var(--text-dim)', textAlign: 'center', padding: '20px' }}>
                No active incidents. Escalate an alert to create an incident.
              </p>
            )}
          </div>
        </div>

        {/* Right: Incident Deep Investigation & Evidence */}
        {selectedIncident ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* Overview Banner */}
            <div className="card-panel">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '14px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span className={`badge ${selectedIncident.severity.toLowerCase()}`}>{selectedIncident.severity}</span>
                    <h3 style={{ fontSize: '16px', color: '#fff' }}>{selectedIncident.title}</h3>
                  </div>
                  <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                    {selectedIncident.description || 'Multi-source correlated threat incident.'}
                  </p>
                </div>

                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    disabled={loadingPlaybook}
                    onClick={handleOpenPlaybook}
                    className="btn btn-secondary btn-sm"
                  >
                    {loadingPlaybook ? 'Generating…' : '🛡 AI Playbook'}
                  </button>
                  <button
                    disabled={downloadingPdf}
                    onClick={handleDownloadPdf}
                    className="btn btn-secondary btn-sm"
                  >
                    {downloadingPdf ? 'Generating…' : '📄 Export PDF'}
                  </button>
                  <button
                    disabled={investigating}
                    onClick={handleRunInvestigation}
                    className="btn btn-primary btn-sm"
                  >
                    {investigating ? 'Investigating…' : '⚡ Run AI Deep Scan'}
                  </button>
                </div>
              </div>

              {/* Investigation Statistics */}
              {investigation?.statistics && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '6px' }}>
                  <div>
                    <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Candidate Events</span>
                    <strong style={{ fontSize: '16px', color: '#fff', display: 'block', fontFamily: 'var(--font-mono)' }}>
                      {investigation.statistics.candidate_events}
                    </strong>
                  </div>
                  <div>
                    <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Correlated Evidence</span>
                    <strong style={{ fontSize: '16px', color: 'var(--cyan)', display: 'block', fontFamily: 'var(--font-mono)' }}>
                      {investigation.statistics.selected_evidence}
                    </strong>
                  </div>
                  <div>
                    <span style={{ fontSize: '10px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Noise Reduction</span>
                    <strong style={{ fontSize: '16px', color: 'var(--emerald)', display: 'block', fontFamily: 'var(--font-mono)' }}>
                      {Math.round((investigation.statistics.reduction_ratio || 0) * 100)}%
                    </strong>
                  </div>
                </div>
              )}
            </div>

            {/* Topology Graph */}
            {investigation && (
              <InvestigationGraph
                incidentTitle={selectedIncident.title}
                entities={{
                  source_ips: Array.from(new Set(investigation.evidence.map(e => e.source_ip).filter(Boolean) as string[])),
                  usernames: Array.from(new Set(investigation.evidence.map(e => e.username).filter(Boolean) as string[])),
                  hostnames: Array.from(new Set(investigation.evidence.map(e => e.hostname).filter(Boolean) as string[])),
                }}
              />
            )}

            {/* Evidence Timeline */}
            <div className="card-panel">
              <div className="card-header">
                <h3>Correlated Forensic Evidence Timeline</h3>
              </div>

              {investigation?.timeline && investigation.timeline.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {investigation.timeline.slice(0, 15).map((item, idx) => (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        gap: '12px',
                        alignItems: 'center',
                        padding: '8px 12px',
                        background: 'rgba(10, 15, 29, 0.5)',
                        borderLeft: '2px solid var(--cyan)',
                        borderRadius: '4px',
                      }}
                    >
                      <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--cyan)', minWidth: '130px' }}>
                        {new Date(item.at).toLocaleTimeString()}
                      </span>
                      <span style={{ fontSize: '12px', color: 'var(--text-main)' }}>
                        {item.description}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p style={{ fontSize: '12px', color: 'var(--text-dim)', textAlign: 'center', padding: '20px' }}>
                  Click "Run AI Deep Scan" above to correlate candidate security telemetry and build the evidence timeline.
                </p>
              )}
            </div>
          </div>
        ) : (
          <div className="card-panel" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-dim)' }}>
            Select an incident to view deep investigation details.
          </div>
        )}
      </div>

      {/* Playbook Modal */}
      <PlaybookModal
        playbook={playbook}
        onClose={() => setPlaybook(null)}
        onActionTriggered={() => {}}
      />
    </div>
  );
};
