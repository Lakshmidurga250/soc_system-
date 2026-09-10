# SentinelAI: SOC Analyst & Operator Manual

## 1. Getting Started

### 1.1 Accessing the Workstation
1. Launch the backend application:
   ```bash
   python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
2. Navigate to [http://127.0.0.1:8000/](http://127.0.0.1:8000/) in any modern web browser.
3. Sign in with standard credentials:
   - **Email**: `admin@sentinelai.local`
   - **Password**: `SentinelDemo!2026`

---

## 2. SOC Analyst Workflow

### 2.1 Live Monitoring & Triage
- **Overview Dashboard**: Monitor real-time MTTD, MTTR, overall SOC Risk Index, and severity distributions.
- **Security Events**: Filter live log streams by severity, source IP, or event type. Search specific payload strings.
- **Detection Rules**: Enable, disable, or adjust threshold parameters across detection rules.

### 2.2 Autonomous Incident Investigation
1. Navigate to the **Incidents** page.
2. Select any active incident to open its investigation dossier.
3. Review the AI-generated **Root Cause Analysis**, **Threat Timeline**, and **Ranked Evidence Graph**.
4. Click **Launch Investigation** to run the local heuristic path optimizer.

### 2.3 Executing Remediation Playbooks
1. Review recommended playbooks generated for the incident (e.g., *Ransomware Containment Playbook*, *Credential Stuffing Mitigation*).
2. For high-impact actions (e.g., Host Network Isolation, IP Blacklisting), open the **Action Approvals** page.
3. Click **Approve** or **Reject** with an audit comment.

### 2.4 Generating Forensic PDF Reports
1. In the Incident view, click **Generate Incident PDF** to instantly download a formatted multi-page Forensic Dossier.
2. Under Reports, select **Export Executive SOC Summary** for leadership and audit compliance.
