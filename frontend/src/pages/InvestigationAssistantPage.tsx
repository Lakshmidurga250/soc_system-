import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Incident } from '../types';

interface AssistantQueryResponse {
  incident_id: string;
  question: string;
  answer: string;
  mitre_technique?: string;
  evidence_references?: string[];
  suggested_next_steps?: string[];
}

export const InvestigationAssistantPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState('');
  const [question, setQuestion] = useState('');
  const [history, setHistory] = useState<AssistantQueryResponse[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api<{ items: Incident[] }>('/incidents')
      .then((res) => {
        setIncidents(res.items || []);
        if (res.items && res.items.length > 0) {
          setSelectedIncidentId(res.items[0].id);
        }
      })
      .catch((err) => console.error(err));
  }, []);

  const handleAsk = (e: React.FormEvent, customQ?: string) => {
    if (e) e.preventDefault();
    const qToSend = customQ || question;
    if (!qToSend.trim() || !selectedIncidentId) return;

    setLoading(true);
    api<AssistantQueryResponse>('/assistant/query', {
      method: 'POST',
      body: JSON.stringify({
        incident_id: selectedIncidentId,
        question: qToSend,
      }),
    })
      .then((res) => {
        setHistory((prev) => [res, ...prev]);
        setQuestion('');
      })
      .catch((err) => alert(`Assistant error: ${err.message}`))
      .finally(() => setLoading(false));
  };

  const sampleQuestions = [
    'What happened in this incident?',
    'Why was this alert generated?',
    'Which asset and user account is affected?',
    'Why is the risk score high?',
    'What should the analyst investigate next?',
  ];

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h2>Local SOC Investigation Assistant</h2>
          <p>Deterministic structured incident reasoning referencing actual stored telemetry & MITRE ATT&CK evidence</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '20px' }}>
        {/* Left: Incident Selector & Suggested Questions */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="card-panel">
            <div className="card-header">
              <h3>Target Incident Dossier</h3>
            </div>
            <div className="form-group">
              <label>Select Incident Case</label>
              <select
                className="select-input"
                value={selectedIncidentId}
                onChange={(e) => setSelectedIncidentId(e.target.value)}
              >
                {incidents.map((inc) => (
                  <option key={inc.id} value={inc.id}>
                    [{inc.severity}] {inc.title} ({inc.id.slice(0, 8)})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="card-panel">
            <div className="card-header">
              <h3>Structured Investigation Questions</h3>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {sampleQuestions.map((sq, i) => (
                <button
                  key={i}
                  type="button"
                  onClick={() => handleAsk(null as any, sq)}
                  className="btn btn-secondary btn-sm"
                  style={{ textAlign: 'left', fontSize: '12px', padding: '8px 10px', lineHeight: 1.3 }}
                >
                  ⚡ {sq}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Interactive Assistant Chat View */}
        <div className="card-panel" style={{ display: 'flex', flexDirection: 'column', height: '700px' }}>
          <div className="card-header">
            <h3>Autonomous Telemetry Reasoning Feed</h3>
            <span className="badge low">100% LOCAL DETERMINISTIC AI</span>
          </div>

          {/* Conversation Stream */}
          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '14px', padding: '10px 0' }}>
            {history.map((item, idx) => (
              <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {/* User Prompt */}
                <div style={{ alignSelf: 'flex-end', background: 'rgba(6, 182, 212, 0.15)', border: '1px solid var(--border-glow)', padding: '10px 14px', borderRadius: '8px 8px 0 8px', maxWidth: '80%' }}>
                  <p style={{ color: 'var(--text-main)', fontSize: '13px', fontWeight: 500 }}>{item.question}</p>
                </div>

                {/* Assistant Answer */}
                <div style={{ alignSelf: 'flex-start', background: 'rgba(15, 23, 42, 0.8)', border: '1px solid var(--border)', padding: '14px', borderRadius: '8px 8px 8px 0', maxWidth: '90%' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                    <span style={{ color: 'var(--cyan)', fontWeight: 700, fontSize: '12px' }}>SENTINEL-AI INVESTIGATOR</span>
                    {item.mitre_technique && (
                      <span className="badge medium" style={{ fontSize: '10px' }}>{item.mitre_technique}</span>
                    )}
                  </div>
                  <p style={{ color: 'var(--text-main)', fontSize: '13px', lineHeight: 1.5 }}>
                    {item.answer}
                  </p>

                  {/* Evidence References */}
                  {item.evidence_references && item.evidence_references.length > 0 && (
                    <div style={{ marginTop: '10px', background: 'rgba(0,0,0,0.3)', padding: '8px 10px', borderRadius: '4px' }}>
                      <strong style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Ground Truth Evidence:</strong>
                      <ul style={{ fontSize: '11px', color: 'var(--text-muted)', marginLeft: '16px', marginTop: '4px' }}>
                        {item.evidence_references.map((ev, ei) => (
                          <li key={ei}>{ev}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Recommended Next Steps */}
                  {item.suggested_next_steps && item.suggested_next_steps.length > 0 && (
                    <div style={{ marginTop: '8px', borderLeft: '2px solid var(--emerald)', paddingLeft: '8px' }}>
                      <strong style={{ fontSize: '11px', color: 'var(--emerald)' }}>Recommended Next SOC Step:</strong>
                      <p style={{ fontSize: '12px', color: 'var(--text-main)', marginTop: '2px' }}>
                        {item.suggested_next_steps[0]}
                      </p>
                    </div>
                  )}
                </div>
              </div>
            ))}

            {history.length === 0 && (
              <div style={{ textAlign: 'center', color: 'var(--text-dim)', marginTop: '150px' }}>
                <p style={{ fontSize: '16px', fontWeight: 500, color: 'var(--text-muted)' }}>Ready for Investigation Queries</p>
                <p style={{ fontSize: '13px', marginTop: '6px' }}>
                  Select an incident and choose a suggested question or type your custom query below.
                </p>
              </div>
            )}
          </div>

          {/* Input Form */}
          <form onSubmit={(e) => handleAsk(e)} style={{ display: 'flex', gap: '10px', marginTop: '14px', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
            <input
              type="text"
              className="search-input"
              style={{ flex: 1 }}
              placeholder="Ask structured investigation question (e.g. Why is the risk score high?)..."
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
            />
            <button type="submit" disabled={loading || !question.trim()} className="btn btn-primary">
              {loading ? 'Analyzing…' : 'Investigate →'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
