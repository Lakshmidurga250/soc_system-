import React from "react";

export const K8sSecurityConsole: React.FC = () => {
  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Kubernetes & Container Workload Security</h1>
          <p className="page-subtitle">Privileged container detection, cluster-admin role bindings, and container escape defense.</p>
        </div>
      </div>
      <div className="card" style={{ padding: "24px", background: "#ffffff", borderRadius: "12px", border: "1px solid #e9d5ff" }}>
        <h3 style={{ color: "#4c1d95" }}>Cluster Guard Posture</h3>
        <p>Monitoring pods, namespaces, daemonsets, and cluster-role-bindings in real-time.</p>
      </div>
    </div>
  );
};
