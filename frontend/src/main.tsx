import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';

import './styles.css';
import { Navigation } from './components/Navigation';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { ProfilePage } from './pages/ProfilePage';
import { UsersManagementPage } from './pages/UsersManagementPage';
import { DashboardPage } from './pages/Dashboard';
import { EventsPage } from './pages/EventsPage';
import { AlertsPage } from './pages/AlertsPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { DetectionPage } from './pages/DetectionPage';
import { ResponsePage } from './pages/ResponsePage';
import { ReportsPage } from './pages/ReportsPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import { UEBAAnalysisPage } from './pages/UEBAAnalysisPage';
import { ITDRDashboardPage } from './pages/ITDRDashboardPage';
import { VulnerabilityManagerPage } from './pages/VulnerabilityManagerPage';
import { ThreatHuntingStudio } from './pages/ThreatHuntingStudio';
import { AdversaryEmulationStudio } from './pages/AdversaryEmulationStudio';
import { ComplianceAuditPage } from './pages/ComplianceAuditPage';
import { LocalAIAssistantPage } from './pages/LocalAIAssistantPage';

const ProtectedLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const token = localStorage.getItem('token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="shell">
      <Navigation />
      <div className="main-content">
        <header className="top-bar">
          <div className="title-group">
            <h2>Operations Control Center</h2>
            <p>LOCAL STANDALONE SOC WORKSPACE // ACTIVE PROTECTION</p>
          </div>
          <div className="top-bar-actions">
            <div className="system-badge">
              <span className="pulse-dot" />
              <span>LIVE TELEMETRY ACTIVE</span>
            </div>
          </div>
        </header>
        <main>{children}</main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        
        <Route path="/dashboard" element={<ProtectedLayout><DashboardPage /></ProtectedLayout>} />
        <Route path="/events" element={<ProtectedLayout><EventsPage /></ProtectedLayout>} />
        <Route path="/alerts" element={<ProtectedLayout><AlertsPage /></ProtectedLayout>} />
        <Route path="/incidents" element={<ProtectedLayout><IncidentsPage /></ProtectedLayout>} />
        <Route path="/ueba" element={<ProtectedLayout><UEBAAnalysisPage /></ProtectedLayout>} />
        <Route path="/itdr" element={<ProtectedLayout><ITDRDashboardPage /></ProtectedLayout>} />
        <Route path="/vulnerability" element={<ProtectedLayout><VulnerabilityManagerPage /></ProtectedLayout>} />
        <Route path="/hunting" element={<ProtectedLayout><ThreatHuntingStudio /></ProtectedLayout>} />
        <Route path="/emulation" element={<ProtectedLayout><AdversaryEmulationStudio /></ProtectedLayout>} />
        <Route path="/compliance" element={<ProtectedLayout><ComplianceAuditPage /></ProtectedLayout>} />
        <Route path="/assistant" element={<ProtectedLayout><LocalAIAssistantPage /></ProtectedLayout>} />
        <Route path="/threat-intel" element={<ProtectedLayout><ThreatIntelPage /></ProtectedLayout>} />
        <Route path="/detection" element={<ProtectedLayout><DetectionPage /></ProtectedLayout>} />
        <Route path="/response" element={<ProtectedLayout><ResponsePage /></ProtectedLayout>} />
        <Route path="/reports" element={<ProtectedLayout><ReportsPage /></ProtectedLayout>} />
        <Route path="/system-health" element={<ProtectedLayout><SystemHealthPage /></ProtectedLayout>} />
        <Route path="/profile" element={<ProtectedLayout><ProfilePage /></ProtectedLayout>} />
        <Route path="/users" element={<ProtectedLayout><UsersManagementPage /></ProtectedLayout>} />

        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  );
};

const root = createRoot(document.getElementById('root')!);
root.render(<App />);
