import React from "react";

export const KernelSecurityAuditor: React.FC = () => {
  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Kernel & Host System Forensics Auditor</h1>
          <p className="page-subtitle">Inspect Linux eBPF probe hooks, Windows Token privileges, and POSIX capabilities.</p>
        </div>
      </div>
      <div className="card" style={{ padding: "24px", background: "#ffffff", borderRadius: "12px", border: "1px solid #e9d5ff" }}>
        <h3 style={{ color: "#4c1d95" }}>Low-Level Kernel Integrity</h3>
        <p>Continuous auditing of process tokens, SeDebugPrivilege, and eBPF bytecode loaders.</p>
      </div>
    </div>
  );
};
