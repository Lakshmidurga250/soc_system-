export interface User {
  id: string;
  full_name: string;
  username?: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
  updated_at?: string;
  last_login_at?: string;
  failed_login_count?: number;
  settings_json?: Record<string, any>;
}

export interface SecurityEvent {
  id: string;
  event_id: string;
  timestamp: string;
  source: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  hostname?: string;
  event_type: string;
  category: string;
  status?: string;
  action?: string;
  resource?: string;
  severity: string;
  synthetic: boolean;
  metadata_json: Record<string, any>;
}

export interface Alert {
  id: string;
  title: string;
  description?: string;
  severity: string;
  risk_score: number;
  confidence_score: number;
  status: string;
  source?: string;
  detection_method?: string;
  created_at: string;
  explanation?: {
    risk_score?: number;
    risk_level?: string;
    dominant_factor?: string;
    factors?: Array<{ factor: string; contribution: number; description: string }>;
    top_contributing_factors?: Array<{ feature: string; weight: number; description: string }>;
  };
  entities?: {
    source_ip?: string;
    username?: string;
    hostname?: string;
    destination_ip?: string;
  };
  event_ids?: string[];
  event_count?: number;
  notes?: Array<{ author: string; note: string; at: string }>;
}

export interface Incident {
  id: string;
  title: string;
  description?: string;
  severity: string;
  risk_score: number;
  confidence: number;
  status: string;
  assigned_to?: string;
  alert_ids: string[];
  root_cause?: string;
  resolution?: string;
  created_at: string;
  investigation_id?: string;
}

export interface Asset {
  id: string;
  hostname: string;
  ip_address: string;
  asset_type: string;
  criticality: string;
  operating_system?: string;
  owner?: string;
  last_active?: string;
  current_risk_score?: number;
  status: string;
}

export interface MitreTechnique {
  category: string;
  tactic: string;
  tactic_id: string;
  technique: string;
  technique_id: string;
  subtechnique_id?: string;
  description: string;
  mitigation: string;
  detection_signatures: string[];
}

export interface ModelBenchmarkItem {
  accuracy: number;
  f1_weighted: number;
  precision_weighted: number;
  recall_weighted: number;
  roc_auc?: number;
  training_time_sec: number;
  inference_time_sec: number;
  samples_evaluated: number;
  feature_importances: Array<{ feature: string; importance: number }>;
}

export interface OptimizationMetrics {
  severity_evaluated: string;
  risk_score: number;
  selected_stages: string[];
  skipped_stages: Array<{ stage: string; reason: string }>;
  total_stages_count: number;
  executed_stages_count: number;
  baseline_compute_units: number;
  optimized_compute_units: number;
  compute_savings_percentage: number;
  estimated_latency_ms: number;
  latency_reduction_percentage: number;
  confidence_retained_percentage: number;
}

export interface Investigation {
  id: string;
  incident_id: string;
  status: string;
  summary: string;
  evidence: Array<{
    event_id: string;
    timestamp: string;
    event_type: string;
    source_ip?: string;
    username?: string;
    hostname?: string;
    relevance: number;
  }>;
  timeline: Array<{
    at: string;
    event_id: string;
    description: string;
  }>;
  statistics: {
    candidate_events: number;
    selected_evidence: number;
    reduction_ratio: number;
    correlated_entities?: string[];
  };
}

export interface MitigationPlaybook {
  incident_id: string;
  threat_category: string;
  confidence_level: number;
  forensic_hypothesis: string;
  affected_entities: {
    source_ips: string[];
    usernames: string[];
    hostnames: string[];
  };
  response_playbook: Array<{
    phase: string;
    priority: string;
    actions: string[];
  }>;
  suggested_actions: Array<{
    action_type: string;
    target: string;
    mode: string;
    reason: string;
    impact: string;
  }>;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  rule_type: string;
  config: Record<string, any>;
  severity: string;
  enabled: boolean;
  execution_count: number;
  match_count: number;
}

export interface ThreatIndicator {
  id: string;
  indicator: string;
  indicator_type: string;
  risk_level: string;
  description: string;
  source: string;
  status: string;
  last_seen?: string;
}

export interface ApprovalItem {
  id: string;
  response_action_id: string;
  reason: string;
  status: string;
  created_at: string;
  action?: {
    id: string;
    incident_id?: string;
    action_type: string;
    mode: string;
    status: string;
    payload: Record<string, any>;
  };
}

export interface AuditLogItem {
  id: string;
  action: string;
  resource: string;
  result: string;
  timestamp: string;
  metadata: Record<string, any>;
  user_id?: string;
}

export interface DashboardData {
  kpis: {
    total_events: number;
    active_alerts: number;
    open_incidents: number;
    critical_incidents: number;
    anomalies_detected: number;
    investigations_running: number;
  };
  alerts_by_severity: Record<string, number>;
  incidents_by_status: Record<string, number>;
  recent_alerts: Array<{
    id: string;
    title: string;
    severity: string;
    risk_score: number;
    created_at: string;
  }>;
}
