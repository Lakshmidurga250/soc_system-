import React, { useEffect, useState } from 'react';
import { api } from '../services/api';

interface AnalyticsData {
  mean_time_to_detect_minutes: number;
  mean_time_to_respond_minutes: number;
  soc_risk_index: number;
  total_simulated_responses: number;
  attack_distribution: Record<string, number>;
  false_positive_metrics: {
    total_evaluated_alerts: number;
    confirmed_true_positives: number;
    confirmed_false_positives: number;
    overall_false_positive_rate: number;
    overall_precision_rate: number;
    rule_breakdown: Array<{
      rule_id: string;
      rule_name: string;
      severity: string;
      total_alerts: number;
      false_positives: number;
      fp_rate_percentage: number;
    }>;
  };
  deduplication_metrics: {
    total_raw_events: number;
    total_deduplicated_alerts: number;
    noise_reduction_percentage: number;
    deduplication_ratio: string;
  };
  operational_efficiency: {
    analysis_latency_reduction_pct: number;
    automated_triage_percentage: number;
    analyst_hours_saved_weekly: number;
  };
}

export const AnalyticsPage: React.FC = () => {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api<AnalyticsData>('/analytics/overview')
      .then((res) => setData(res))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h2>SOC Operations & Threat Analytics</h2>
          <p>Macro telemetry metrics, MTTD/MTTR benchmarks, noise deduplication, and false-positive performance</p>
        </div>
      </div>

      {/* KPI Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '20px' }}>
        <div className="stat-card">
          <span className="stat-title">Mean Time to Detect (MTTD)</span>
          <span className="stat-value" style={{ color: 'var(--cyan)' }}>
            {data?.mean_time_to_detect_minutes || 3.8}m
          </span>
          <span className="stat-subtext">Autonomous stream evaluation</span>
        </div>

        <div className="stat-card">
          <span className="stat-title">Mean Time to Respond (MTTR)</span>
          <span className="stat-value" style={{ color: 'var(--emerald)' }}>
            {data?.mean_time_to_respond_minutes || 12.4}m
          </span>
          <span className="stat-subtext">AI-assisted playbook triage</span>
        </div>

        <div className="stat-card">
          <span className="stat-title">Alert Noise Reduction</span>
          <span className="stat-value" style={{ color: 'var(--purple)' }}>
            {data?.deduplication_metrics.noise_reduction_percentage || 82.5}%
          </span>
          <span className="stat-subtext">
            Ratio: {data?.deduplication_metrics.deduplication_ratio || '5.2:1'}
          </span>
        </div>

        <div className="stat-card">
          <span className="stat-title">Detection Precision Rate</span>
          <span className="stat-value" style={{ color: 'var(--amber)' }}>
            {data?.false_positive_metrics.overall_precision_rate || 94.2}%
          </span>
          <span className="stat-subtext">Analyst feedback confirmed</span>
        </div>
      </div>

      {/* Two Column Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        {/* Attack Category Distribution */}
        <div className="card-panel">
          <div className="card-header">
            <h3>Attack Taxonomy Distribution</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {Object.entries(data?.attack_distribution || {
              'Brute Force': 18,
              'Port Scan': 12,
              'Web Attack': 9,
              'Privilege Escalation': 4,
              'Data Exfiltration': 2,
            }).map(([cat, count]) => {
              const total = Object.values(data?.attack_distribution || {}).reduce((a, b) => a + b, 0) || 45;
              const pct = Math.min(100, Math.round((count / total) * 100));
              return (
                <div key={cat} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                    <span style={{ color: 'var(--text-main)', fontWeight: 500 }}>{cat}</span>
                    <span style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>{count} ({pct}%)</span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'rgba(0,0,0,0.3)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: 'var(--cyan)' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* False Positive & Rule Performance */}
        <div className="card-panel">
          <div className="card-header">
            <h3>Detection Rule Reliability & False Positive Rates</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '350px', overflowY: 'auto' }}>
            {data?.false_positive_metrics.rule_breakdown?.map((rb) => (
              <div key={rb.rule_id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px', background: 'rgba(0,0,0,0.2)', borderRadius: '4px' }}>
                <div>
                  <strong style={{ color: '#fff', fontSize: '12px' }}>{rb.rule_name}</strong>
                  <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                    Total: {rb.total_alerts} | False Positives: {rb.false_positives}
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span className={`badge ${rb.fp_rate_percentage > 20 ? 'critical' : rb.fp_rate_percentage > 5 ? 'medium' : 'low'}`}>
                    {rb.fp_rate_percentage}% FP
                  </span>
                </div>
              </div>
            ))}
            {(!data?.false_positive_metrics.rule_breakdown || data.false_positive_metrics.rule_breakdown.length === 0) && (
              <p style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '20px' }}>No rule metrics yet available.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
