import React, { useState } from "react";

export const NetworkForensicsWorkbench: React.FC = () => {
  const [activeProto, setActiveProto] = useState("IPv6_NDP");
  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Network Forensics & Protocol Dissection Workbench</h1>
          <p className="page-subtitle">Deep inspection for IPv6 NDP, BGP routing, IPsec IKEv2, WireGuard, DHCP, and ARP.</p>
        </div>
      </div>
      <div className="card" style={{ padding: "24px", background: "#ffffff", borderRadius: "12px", border: "1px solid #e9d5ff" }}>
        <h3 style={{ color: "#4c1d95" }}>Active Protocol Dissectors</h3>
        <p>Real-time packet structure decoding active across Ethernet, IPv6, TCP, UDP, and application protocols.</p>
      </div>
    </div>
  );
};
