import React, { useState } from 'react';
import { uploadLogFile } from '../services/api';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onUploadComplete: () => void;
}

export const LogUploadModal: React.FC<Props> = ({ isOpen, onClose, onUploadComplete }) => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<any>(null);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError('');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;

    setLoading(true);
    setError('');
    try {
      const res = await uploadLogFile(file);
      setResult(res);
      setTimeout(() => {
        onUploadComplete();
        onClose();
      }, 1500);
    } catch (err: any) {
      setError(err.message || 'Upload failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div className="modal-header">
          <h3>Ingest External Log File</h3>
          <button onClick={onClose} className="modal-close">✕</button>
        </div>

        <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          Upload security telemetry for automatic parsing, normalization, and real-time rule detection.
          Supported formats: <strong>CSV, JSON, JSONL, Syslog (.log/.syslog), CEF (.cef), Windows Event XML (.xml)</strong>.
        </p>

        {error && <div className="error-banner">{error}</div>}

        {result && (
          <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#34d399', padding: '12px', borderRadius: '6px', fontSize: '13px' }}>
            ✓ Ingested <strong>{result.accepted_records}</strong> records ({result.alerts_created} alerts generated).
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ border: '2px dashed var(--border)', padding: '24px', borderRadius: '8px', textAlign: 'center', background: 'rgba(0,0,0,0.2)' }}>
            <input
              type="file"
              onChange={handleFileChange}
              accept=".csv,.json,.jsonl,.ndjson,.log,.syslog,.cef,.xml"
              style={{ display: 'block', margin: '0 auto', fontSize: '13px', color: 'var(--text-muted)' }}
            />
            {file && <p style={{ marginTop: '10px', fontSize: '12px', color: 'var(--cyan)' }}>Selected: {file.name} ({(file.size / 1024).toFixed(1)} KB)</p>}
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
            <button type="button" onClick={onClose} className="btn btn-secondary">Cancel</button>
            <button type="submit" disabled={!file || loading} className="btn btn-primary">
              {loading ? 'Processing & Ingesting…' : 'Start Ingestion →'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
