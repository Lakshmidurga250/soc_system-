# SentinelAI

SentinelAI is a local, safe-by-design AI-assisted Security Operations Center. It ingests canonical security events, runs configurable behavioral rules, calculates transparent risk, creates alerts/incidents, ranks investigation evidence, and keeps an auditable, approval-gated response trail. All demonstrations use synthetic local data.

## Current implementation

- JWT local authentication with Admin, SOC Analyst, and Viewer roles
- SQLite-backed canonical security events, local event simulator, dashboard, audit history
- Configurable threshold detection rules; transparent risk and explanation indicators
- Alert lifecycle, incident creation, entity-centred evidence ranking and timelines
- Local threat indicators and approval-gated safe response actions
- React SOC workspace showing real API/database data

## Run locally

Backend (Python 3.12+):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.app.main:app --reload
```

Frontend (Node 20+):

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The local demo administrator is `admin@sentinelai.local` / `SentinelDemo!2026`; change it before any non-demo use. The API documentation is at `http://localhost:8000/docs`.

## Verification

```powershell
python -m pytest
cd frontend; npm run build
```

## Limitations and roadmap

This initial foundation is intentionally not represented as a finished 50,000-LOC product. Full file-upload parsers, trained local ML models, formal Alembic migrations, report exporters, the full API/page set, and extensive test coverage remain to be implemented as genuine next phases.
