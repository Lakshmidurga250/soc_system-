import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { SecurityEvent } from '../types';
import { LogUploadModal } from '../components/LogUploadModal';

export const EventsPage: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const fetchEvents = () => {
    setLoading(true);
    const qParam = searchQuery ? `&q=${encodeURIComponent(searchQuery)}` : '';
    const sevParam = severityFilter !== 'ALL' ? `&severity=${severityFilter}` : '';
    api<{ items: SecurityEvent[]; total: number }>(`/events?page=${page}&page_size=25${qParam}${sevParam}`)
      .then((res) => {
        setEvents(res.items);
        setTotal(res.total);
      })
      .catch((e) => console.error(e))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchEvents();
  }, [page, severityFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchEvents();
  };

  return (
    <div className="page-container">
      {/* Controls Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '10px', flex: 1, maxWidth: '500px' }}>
          <input
            type="text"
            className="search-input"
            style={{ width: '100%' }}
            placeholder="Search by IP, username, hostname, or message…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          <button type="submit" className="btn btn-secondary">Search</button>
        </form>

        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <select
            className="select-input"
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <button onClick={() => setUploadOpen(true)} className="btn btn-primary">
            + Upload Log File
          </button>
        </div>
      </div>

      {/* Events Table */}
      <div className="card-panel">
        <div className="card-header">
          <h3>Security Event Telemetry ({total} Total Records)</h3>
          <button onClick={fetchEvents} className="btn btn-secondary btn-sm">Refresh</button>
        </div>

        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Source IP</th>
                <th>User / Host</th>
                <th>Event Type</th>
                <th>Action / Status</th>
                <th>Severity</th>
                <th>Format</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {events.map((evt) => (
                <tr key={evt.id}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                    {new Date(evt.timestamp).toLocaleString()}
                  </td>
                  <td>
                    <code>{evt.source_ip || '127.0.0.1'}</code>
                  </td>
                  <td>
                    <span style={{ color: '#fff', fontWeight: 500 }}>{evt.username || 'system'}</span>
                    {evt.hostname && <span style={{ color: 'var(--text-dim)', fontSize: '11px' }}> @ {evt.hostname}</span>}
                  </td>
                  <td>{evt.event_type}</td>
                  <td>
                    <span style={{ color: evt.status === 'FAILURE' ? 'var(--rose)' : 'var(--emerald)' }}>
                      {evt.status || evt.action || 'EVENT'}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${evt.severity.toLowerCase()}`}>{evt.severity}</span>
                  </td>
                  <td>
                    <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                      {evt.source}
                    </span>
                  </td>
                  <td>
                    <button
                      onClick={() => setSelectedEvent(evt)}
                      className="btn btn-secondary btn-sm"
                    >
                      Inspect JSON
                    </button>
                  </td>
                </tr>
              ))}
              {!loading && events.length === 0 && (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)' }}>
                    No security events found matching current query.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-dim)' }}>
            Showing page {page} of {Math.max(1, Math.ceil(total / 25))}
          </span>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              disabled={page <= 1}
              onClick={() => setPage(p => p - 1)}
              className="btn btn-secondary btn-sm"
            >
              ← Previous
            </button>
            <button
              disabled={page >= Math.ceil(total / 25)}
              onClick={() => setPage(p => p + 1)}
              className="btn btn-secondary btn-sm"
            >
              Next →
            </button>
          </div>
        </div>
      </div>

      {/* JSON Inspector Modal */}
      {selectedEvent && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: '700px' }}>
            <div className="modal-header">
              <h3>Canonical Event Inspector: {selectedEvent.id.slice(0, 8)}</h3>
              <button onClick={() => setSelectedEvent(null)} className="modal-close">✕</button>
            </div>
            <pre style={{ background: 'rgba(0,0,0,0.5)', padding: '16px', borderRadius: '8px', color: 'var(--cyan)', fontSize: '12px', fontFamily: 'var(--font-mono)', overflowX: 'auto', maxHeight: '400px' }}>
              {JSON.stringify(selectedEvent, null, 2)}
            </pre>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button onClick={() => setSelectedEvent(null)} className="btn btn-secondary">Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Upload Modal */}
      <LogUploadModal
        isOpen={uploadOpen}
        onClose={() => setUploadOpen(false)}
        onUploadComplete={fetchEvents}
      />
    </div>
  );
};
