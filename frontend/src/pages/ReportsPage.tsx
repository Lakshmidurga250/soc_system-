import React, { useEffect, useState } from 'react';
import { api, downloadPdf } from '../services/api';
import { Incident } from '../types';

export const ReportsPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncId, setSelectedIncId] = useState('');
  const [generatingExec, setGeneratingExec] = useState(false);
  const [generatingInc, setGeneratingInc] = useState(false);

  useEffect(() => {
    api<{ items: Incident[] }>('/incidents')
      .then((res) => {
        setIncidents(res.items);
        if (res.items.length > 0) {
          setSelectedIncId(res.items[0].id);
        }
      })
      .catch((e) => console.error(e));
  }, []);

  const handleDownloadExecutive = async () => {
    setGeneratingExec(true);
    try {
      await downloadPdf('/reports/executive-summary/pdf', 'sentinelai_soc_executive_summary.pdf');
    } catch (e: any) {
      alert(`Executive PDF generation failed: ${e.message}`);
    } finally {
      setGeneratingExec(false);
    }
  };

  const handleDownloadIncident = async () => {
    if (!selectedIncId) return;
    setGeneratingInc(true);
    try {
      await downloadPdf(`/reports/incidents/${selectedIncId}/pdf`, `incident_${selectedIncId.slice(0, 8)}_forensic.pdf`);
    } catch (e: any) {
      alert(`Incident PDF generation failed: ${e.message}`);
    } finally {
      setGeneratingInc(false);
    }
  };

  return (
    <div className="page-container">
      <div>
        <h3 style={{ fontSize: '18px', color: '#fff' }}>Forensic & Executive PDF Reporting Hub</h3>
        <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Export branded, local PDF compliance artifacts generated via ReportLab.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        {/* Executive Summary Card */}
        <div className="card-panel" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <span className="badge medium" style={{ marginBottom: '10px' }}>EXECUTIVE BRIEF</span>
            <h4 style={{ fontSize: '16px', color: '#fff', marginBottom: '8px' }}>SOC Posture & Threat Summary Report</h4>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: '1.5' }}>
              Comprehensive snapshot of overall security posture, total ingested events, alert distribution breakdown by severity, active incident counts, and operational readiness metrics.
            </p>
          </div>
          <button
            disabled={generatingExec}
            onClick={handleDownloadExecutive}
            className="btn btn-primary"
            style={{ width: '100%' }}
          >
            {generatingExec ? 'Generating PDF Document…' : '📥 Export Executive Summary PDF'}
          </button>
        </div>

        {/* Incident Forensic Card */}
        <div className="card-panel" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <span className="badge critical" style={{ marginBottom: '10px' }}>FORENSIC DOSSIER</span>
            <h4 style={{ fontSize: '16px', color: '#fff', marginBottom: '8px' }}>Incident Forensic Investigation Report</h4>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: '1.5', marginBottom: '12px' }}>
              Detailed timeline of correlated evidence, affected endpoint and identity entities, SHAP feature attributions, and mitigation history for compliance archives.
            </p>

            <div className="form-group">
              <label>Select Target Incident</label>
              <select
                className="select-input"
                value={selectedIncId}
                onChange={(e) => setSelectedIncId(e.target.value)}
              >
                {incidents.map((inc) => (
                  <option key={inc.id} value={inc.id}>
                    [{inc.severity}] {inc.title} ({inc.id.slice(0, 8)})
                  </option>
                ))}
                {incidents.length === 0 && <option disabled>No incidents available</option>}
              </select>
            </div>
          </div>

          <button
            disabled={generatingInc || !selectedIncId}
            onClick={handleDownloadIncident}
            className="btn btn-primary"
            style={{ width: '100%' }}
          >
            {generatingInc ? 'Compiling Forensic Dossier…' : '📥 Export Incident Forensic PDF'}
          </button>
        </div>
      </div>
    </div>
  );
};
