# SentinelAI: API Reference Specification

## 1. Authentication & Session Management
All endpoints (except `/api/v1/auth/token` and `/health`) require a valid Bearer JWT token in the `Authorization: Bearer <token>` header.

### 1.1 `POST /api/v1/auth/token`
Authenticate user credentials and receive JWT access token.
- **Request (OAuth2 Password Form)**:
  - `username`: Email address (e.g., `admin@sentinelai.local`)
  - `password`: User password (e.g., `SentinelDemo!2026`)
- **Response `200 OK`**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "token_type": "bearer"
  }
  ```

### 1.2 `GET /api/v1/auth/me`
Retrieve currently authenticated user profile and RBAC role.
- **Response `200 OK`**:
  ```json
  {
    "id": "usr-9a01",
    "email": "admin@sentinelai.local",
    "role": "ADMIN",
    "is_active": true
  }
  ```

---

## 2. Dashboard & Telemetry Metrics

### 2.1 `GET /api/v1/dashboard/metrics`
Aggregated high-level SOC operations metrics for charts, stat tiles, and health indicators.
- **Response `200 OK`**:
  ```json
  {
    "total_events": 5240,
    "total_alerts": 42,
    "open_incidents": 5,
    "critical_incidents": 1,
    "mean_time_to_detect_minutes": 4.2,
    "mean_time_to_respond_minutes": 14.8,
    "risk_index": 72.4,
    "severity_distribution": {
      "CRITICAL": 3,
      "HIGH": 12,
      "MEDIUM": 18,
      "LOW": 9
    }
  }
  ```

---

## 3. Events & Ingestion Subsystem

### 3.1 `GET /api/v1/events`
Query normalized canonical security events with pagination and filtering.
- **Query Parameters**:
  - `skip` (int, default: 0)
  - `limit` (int, default: 50, max: 500)
  - `source_ip` (str, optional)
  - `event_type` (str, optional)
  - `severity` (str, optional)
- **Response `200 OK`**: Array of `SecurityEventResponse`.

### 3.2 `POST /api/v1/events/ingest`
Ingest raw log string or parsed JSON for real-time detection and correlation.
- **Request Body**:
  ```json
  {
    "source_type": "SYSLOG",
    "raw_data": "Sep 10 14:00:00 bastion sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2"
  }
  ```

### 3.3 `POST /api/v1/logs/upload`
Upload raw log files (e.g. `.log`, `.csv`, `.json`, `.xml`) with multipart form-data.
- **Form Data**: `file` (UploadFile)

---

## 4. Incidents & AI Investigations

### 4.1 `GET /api/v1/incidents`
List correlated security incidents with status, severity, and root cause indicators.

### 4.2 `GET /api/v1/incidents/{incident_id}`
Retrieve full incident dossier, timeline, correlated alerts, affected assets, and recommended playbooks.

### 4.3 `POST /api/v1/incidents/{incident_id}/investigate`
Execute local heuristic investigation path optimizer and generate ranked evidence graph.

---

## 5. Knowledge Graph & Threat Topology

### 5.1 `GET /api/v1/graph/topology`
Retrieve full security knowledge graph nodes (Entities, IPs, Users, Hosts, Alerts) and edges (ATTACKED, ACCESSED, CORRELATED_WITH).

---

## 6. Approvals & Automated Remediation

### 6.1 `GET /api/v1/approvals`
List pending human-in-the-loop remediation action requests.

### 6.2 `POST /api/v1/approvals/{approval_id}/action`
Approve or reject a remediation action.
- **Request Body**:
  ```json
  {
    "action": "APPROVE",
    "reason": "Authorized quarantine of compromised host ws-finance-04"
  }
  ```

---

## 7. Forensic Reporting & PDF Export

### 7.1 `GET /api/v1/reports/incident/{incident_id}/pdf`
Stream a professionally styled multi-page Forensic Incident Dossier PDF generated on-the-fly via ReportLab.

### 7.2 `GET /api/v1/reports/executive/pdf`
Stream a comprehensive Executive SOC Summary PDF.
