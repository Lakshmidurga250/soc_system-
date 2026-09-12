import React from "react";

export const ThreatActorDossierPage: React.FC = () => {
  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">APT & Threat Actor Intelligence Dossiers</h1>
          <p className="page-subtitle">Diamond models, TTPs, C2 infrastructure, and targeted sectors for 40+ nation-state groups.</p>
        </div>
      </div>
      <div className="card" style={{ padding: "24px", background: "#ffffff", borderRadius: "12px", border: "1px solid #e9d5ff" }}>
        <h3 style={{ color: "#4c1d95" }}>APT28, APT29, Lazarus, APT41, and LockBit Profiles</h3>
        <p>Structured MITRE ATT&CK mapping with active infrastructure feeds.</p>
      </div>
    </div>
  );
};
