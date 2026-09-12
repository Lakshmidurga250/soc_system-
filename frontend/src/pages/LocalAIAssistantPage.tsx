import React, { useState } from 'react';
import { api } from '../services/api';

interface AssistantResponse {
  query: string;
  intent: string;
  confidence: number;
  headline: string;
  markdown_content: string;
  structured_data: any;
  suggested_actions: string[];
  mitre_references: string[];
  timestamp: string;
}

const SAMPLE_QUERIES = [
  'Summarize incident INC-2026-001 and show MITRE techniques',
  'Why was alert #402 flagged as critical risk?',
  'Check Kerberoasting and Active Directory identity threats',
  'Which hosts have the highest CVSS vulnerability exposure?',
  'Lookup IP 198.51.100.42 in local threat intelligence',
  'Recommend response actions for compromised service accounts',
];

export const LocalAIAssistantPage: React.FC = () => {
  const [prompt, setPrompt] = useState('');
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<Array<{ sender: 'user' | 'assistant'; text: string; data?: AssistantResponse }>>([
    {
      sender: 'assistant',
      text: 'Hello, I am **SentinelAI Copilot** — your 100% offline, privacy-first autonomous SOC intelligence engine. Ask me about active incidents, behavioral anomalies, ITDR detections, CVSS vulnerabilities, or response recommendations.',
    },
  ]);

  const handleSend = async (queryText?: string) => {
    const q = queryText || prompt;
    if (!q.trim()) return;

    setMessages((prev) => [...prev, { sender: 'user', text: q }]);
    setPrompt('');
    setLoading(true);

    try {
      const resp = await api<AssistantResponse>('/advanced/assistant/query', {
        method: 'POST',
        body: JSON.stringify({ query: q }),
      });

      setMessages((prev) => [
        ...prev,
        {
          sender: 'assistant',
          text: resp.markdown_content,
          data: resp,
        },
      ]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          sender: 'assistant',
          text: `⚠️ Query processing error: ${err.message || 'Unable to analyze local database state.'}`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Local AI Security Copilot</h1>
          <p className="page-subtitle">
            Deterministic local intelligence, entity risk synthesis, and playbooks without external cloud APIs.
          </p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: '24px' }}>
        {/* Chat Interface */}
        <div className="card" style={{ padding: '24px', background: '#ffffff', borderRadius: '12px', border: '1px solid #e9d5ff', display: 'flex', flexDirection: 'column', height: '640px' }}>
          {/* Message Stream */}
          <div style={{ flex: 1, overflowY: 'auto', paddingRight: '12px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {messages.map((m, idx) => (
              <div
                key={idx}
                style={{
                  alignSelf: m.sender === 'user' ? 'flex-end' : 'flex-start',
                  maxWidth: m.sender === 'user' ? '75%' : '90%',
                  background: m.sender === 'user' ? '#7c3aed' : '#f5f3ff',
                  color: m.sender === 'user' ? '#ffffff' : '#1e1b4b',
                  padding: '14px 18px',
                  borderRadius: '12px',
                  border: m.sender === 'assistant' ? '1px solid #ddd6fe' : 'none',
                  fontSize: '0.9rem',
                  lineHeight: 1.5,
                }}
              >
                <div style={{ whiteSpace: 'pre-wrap' }}>{m.text}</div>

                {m.data?.suggested_actions && m.data.suggested_actions.length > 0 && (
                  <div style={{ marginTop: '12px', paddingTop: '10px', borderTop: '1px solid #c4b5fd' }}>
                    <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#4c1d95', marginBottom: '6px' }}>
                      SUGGESTED TRIAGE ACTIONS:
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                      {m.data.suggested_actions.map((act, aIdx) => (
                        <span
                          key={aIdx}
                          style={{
                            padding: '3px 8px',
                            background: '#ede9fe',
                            borderRadius: '6px',
                            fontSize: '0.75rem',
                            fontWeight: 600,
                            color: '#5b21b6',
                          }}
                        >
                          ⚡ {act}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
            {loading && (
              <div style={{ alignSelf: 'flex-start', padding: '12px 18px', background: '#f5f3ff', borderRadius: '12px', color: '#7c3aed', fontSize: '0.85rem' }}>
                Analyzing local security telemetry & knowledge graphs...
              </div>
            )}
          </div>

          {/* Input Bar */}
          <div style={{ display: 'flex', gap: '10px', marginTop: '16px', paddingTop: '16px', borderTop: '1px solid #f3e8ff' }}>
            <input
              className="input-field"
              placeholder="Ask SentinelAI (e.g. 'Summarize incident INC-2026-001')..."
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              style={{ flex: 1, padding: '10px 14px', borderRadius: '8px', border: '1px solid #cbd5e1' }}
            />
            <button className="btn btn-primary" onClick={() => handleSend()} disabled={loading || !prompt.trim()}>
              Send Query
            </button>
          </div>
        </div>

        {/* Suggested Prompts Sidebar */}
        <div className="card" style={{ padding: '20px', background: '#faf5ff', borderRadius: '12px', border: '1px solid #e9d5ff' }}>
          <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#4c1d95', marginBottom: '14px' }}>
            Sample Investigative Prompts
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {SAMPLE_QUERIES.map((q, idx) => (
              <button
                key={idx}
                onClick={() => handleSend(q)}
                style={{
                  textAlign: 'left',
                  padding: '10px 12px',
                  borderRadius: '8px',
                  border: '1px solid #ddd6fe',
                  background: '#ffffff',
                  color: '#4c1d95',
                  fontSize: '0.8rem',
                  fontWeight: 500,
                  cursor: 'pointer',
                  lineHeight: 1.3,
                }}
              >
                💬 {q}
              </button>
            ))}
          </div>

          <div style={{ marginTop: '20px', padding: '12px', background: '#f0fdf4', borderRadius: '8px', border: '1px solid #bbf7d0', fontSize: '0.78rem', color: '#166534' }}>
            🔒 <strong>100% Offline Guarantee:</strong> Queries are evaluated against local SQLite models without external cloud inference.
          </div>
        </div>
      </div>
    </div>
  );
};
