import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

export const ApiSecurityConsolePage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [selectedItem, setSelectedItem] = useState<any>(null);

  const dataFeed = [
    { id: "APIS-0001", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #1", severity: "HIGH", status: "CONTAINED", score: 66, timestamp: "2026-02-15 14:01:00Z", resource: "res-node-001.corp.internal" },
    { id: "APIS-0002", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #2", severity: "MEDIUM", status: "INVESTIGATING", score: 67, timestamp: "2026-02-15 14:02:00Z", resource: "res-node-002.corp.internal" },
    { id: "APIS-0003", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #3", severity: "LOW", status: "RESOLVED", score: 68, timestamp: "2026-02-15 14:03:00Z", resource: "res-node-003.corp.internal" },
    { id: "APIS-0004", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #4", severity: "CRITICAL", status: "ACTIVE", score: 69, timestamp: "2026-02-15 14:04:00Z", resource: "res-node-004.corp.internal" },
    { id: "APIS-0005", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #5", severity: "HIGH", status: "CONTAINED", score: 70, timestamp: "2026-02-15 14:05:00Z", resource: "res-node-005.corp.internal" },
    { id: "APIS-0006", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #6", severity: "MEDIUM", status: "INVESTIGATING", score: 71, timestamp: "2026-02-15 14:06:00Z", resource: "res-node-006.corp.internal" },
    { id: "APIS-0007", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #7", severity: "LOW", status: "RESOLVED", score: 72, timestamp: "2026-02-15 14:07:00Z", resource: "res-node-007.corp.internal" },
    { id: "APIS-0008", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #8", severity: "CRITICAL", status: "ACTIVE", score: 73, timestamp: "2026-02-15 14:08:00Z", resource: "res-node-008.corp.internal" },
    { id: "APIS-0009", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #9", severity: "HIGH", status: "CONTAINED", score: 74, timestamp: "2026-02-15 14:09:00Z", resource: "res-node-009.corp.internal" },
    { id: "APIS-0010", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #10", severity: "MEDIUM", status: "INVESTIGATING", score: 75, timestamp: "2026-02-15 14:10:00Z", resource: "res-node-010.corp.internal" },
    { id: "APIS-0011", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #11", severity: "LOW", status: "RESOLVED", score: 76, timestamp: "2026-02-15 14:11:00Z", resource: "res-node-011.corp.internal" },
    { id: "APIS-0012", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #12", severity: "CRITICAL", status: "ACTIVE", score: 77, timestamp: "2026-02-15 14:12:00Z", resource: "res-node-012.corp.internal" },
    { id: "APIS-0013", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #13", severity: "HIGH", status: "CONTAINED", score: 78, timestamp: "2026-02-15 14:13:00Z", resource: "res-node-013.corp.internal" },
    { id: "APIS-0014", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #14", severity: "MEDIUM", status: "INVESTIGATING", score: 79, timestamp: "2026-02-15 14:14:00Z", resource: "res-node-014.corp.internal" },
    { id: "APIS-0015", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #15", severity: "LOW", status: "RESOLVED", score: 80, timestamp: "2026-02-15 14:15:00Z", resource: "res-node-015.corp.internal" },
    { id: "APIS-0016", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #16", severity: "CRITICAL", status: "ACTIVE", score: 81, timestamp: "2026-02-15 14:16:00Z", resource: "res-node-016.corp.internal" },
    { id: "APIS-0017", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #17", severity: "HIGH", status: "CONTAINED", score: 82, timestamp: "2026-02-15 14:17:00Z", resource: "res-node-017.corp.internal" },
    { id: "APIS-0018", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #18", severity: "MEDIUM", status: "INVESTIGATING", score: 83, timestamp: "2026-02-15 14:18:00Z", resource: "res-node-018.corp.internal" },
    { id: "APIS-0019", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #19", severity: "LOW", status: "RESOLVED", score: 84, timestamp: "2026-02-15 14:19:00Z", resource: "res-node-019.corp.internal" },
    { id: "APIS-0020", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #20", severity: "CRITICAL", status: "ACTIVE", score: 85, timestamp: "2026-02-15 14:20:00Z", resource: "res-node-020.corp.internal" },
    { id: "APIS-0021", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #21", severity: "HIGH", status: "CONTAINED", score: 86, timestamp: "2026-02-15 14:21:00Z", resource: "res-node-021.corp.internal" },
    { id: "APIS-0022", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #22", severity: "MEDIUM", status: "INVESTIGATING", score: 87, timestamp: "2026-02-15 14:22:00Z", resource: "res-node-022.corp.internal" },
    { id: "APIS-0023", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #23", severity: "LOW", status: "RESOLVED", score: 88, timestamp: "2026-02-15 14:23:00Z", resource: "res-node-023.corp.internal" },
    { id: "APIS-0024", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #24", severity: "CRITICAL", status: "ACTIVE", score: 89, timestamp: "2026-02-15 14:24:00Z", resource: "res-node-024.corp.internal" },
    { id: "APIS-0025", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #25", severity: "HIGH", status: "CONTAINED", score: 90, timestamp: "2026-02-15 14:25:00Z", resource: "res-node-025.corp.internal" },
    { id: "APIS-0026", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #26", severity: "MEDIUM", status: "INVESTIGATING", score: 91, timestamp: "2026-02-15 14:26:00Z", resource: "res-node-026.corp.internal" },
    { id: "APIS-0027", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #27", severity: "LOW", status: "RESOLVED", score: 92, timestamp: "2026-02-15 14:27:00Z", resource: "res-node-027.corp.internal" },
    { id: "APIS-0028", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #28", severity: "CRITICAL", status: "ACTIVE", score: 93, timestamp: "2026-02-15 14:28:00Z", resource: "res-node-028.corp.internal" },
    { id: "APIS-0029", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #29", severity: "HIGH", status: "CONTAINED", score: 94, timestamp: "2026-02-15 14:29:00Z", resource: "res-node-029.corp.internal" },
    { id: "APIS-0030", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #30", severity: "MEDIUM", status: "INVESTIGATING", score: 95, timestamp: "2026-02-15 14:30:00Z", resource: "res-node-030.corp.internal" },
    { id: "APIS-0031", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #31", severity: "LOW", status: "RESOLVED", score: 96, timestamp: "2026-02-15 14:31:00Z", resource: "res-node-031.corp.internal" },
    { id: "APIS-0032", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #32", severity: "CRITICAL", status: "ACTIVE", score: 65, timestamp: "2026-02-15 14:32:00Z", resource: "res-node-032.corp.internal" },
    { id: "APIS-0033", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #33", severity: "HIGH", status: "CONTAINED", score: 66, timestamp: "2026-02-15 14:33:00Z", resource: "res-node-033.corp.internal" },
    { id: "APIS-0034", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #34", severity: "MEDIUM", status: "INVESTIGATING", score: 67, timestamp: "2026-02-15 14:34:00Z", resource: "res-node-034.corp.internal" },
    { id: "APIS-0035", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #35", severity: "LOW", status: "RESOLVED", score: 68, timestamp: "2026-02-15 14:35:00Z", resource: "res-node-035.corp.internal" },
    { id: "APIS-0036", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #36", severity: "CRITICAL", status: "ACTIVE", score: 69, timestamp: "2026-02-15 14:36:00Z", resource: "res-node-036.corp.internal" },
    { id: "APIS-0037", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #37", severity: "HIGH", status: "CONTAINED", score: 70, timestamp: "2026-02-15 14:37:00Z", resource: "res-node-037.corp.internal" },
    { id: "APIS-0038", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #38", severity: "MEDIUM", status: "INVESTIGATING", score: 71, timestamp: "2026-02-15 14:38:00Z", resource: "res-node-038.corp.internal" },
    { id: "APIS-0039", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #39", severity: "LOW", status: "RESOLVED", score: 72, timestamp: "2026-02-15 14:39:00Z", resource: "res-node-039.corp.internal" },
    { id: "APIS-0040", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #40", severity: "CRITICAL", status: "ACTIVE", score: 73, timestamp: "2026-02-15 14:40:00Z", resource: "res-node-040.corp.internal" },
    { id: "APIS-0041", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #41", severity: "HIGH", status: "CONTAINED", score: 74, timestamp: "2026-02-15 14:41:00Z", resource: "res-node-041.corp.internal" },
    { id: "APIS-0042", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #42", severity: "MEDIUM", status: "INVESTIGATING", score: 75, timestamp: "2026-02-15 14:42:00Z", resource: "res-node-042.corp.internal" },
    { id: "APIS-0043", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #43", severity: "LOW", status: "RESOLVED", score: 76, timestamp: "2026-02-15 14:43:00Z", resource: "res-node-043.corp.internal" },
    { id: "APIS-0044", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #44", severity: "CRITICAL", status: "ACTIVE", score: 77, timestamp: "2026-02-15 14:44:00Z", resource: "res-node-044.corp.internal" },
    { id: "APIS-0045", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #45", severity: "HIGH", status: "CONTAINED", score: 78, timestamp: "2026-02-15 14:45:00Z", resource: "res-node-045.corp.internal" },
    { id: "APIS-0046", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #46", severity: "MEDIUM", status: "INVESTIGATING", score: 79, timestamp: "2026-02-15 14:46:00Z", resource: "res-node-046.corp.internal" },
    { id: "APIS-0047", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #47", severity: "LOW", status: "RESOLVED", score: 80, timestamp: "2026-02-15 14:47:00Z", resource: "res-node-047.corp.internal" },
    { id: "APIS-0048", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #48", severity: "CRITICAL", status: "ACTIVE", score: 81, timestamp: "2026-02-15 14:48:00Z", resource: "res-node-048.corp.internal" },
    { id: "APIS-0049", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #49", severity: "HIGH", status: "CONTAINED", score: 82, timestamp: "2026-02-15 14:49:00Z", resource: "res-node-049.corp.internal" },
    { id: "APIS-0050", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #50", severity: "MEDIUM", status: "INVESTIGATING", score: 83, timestamp: "2026-02-15 14:50:00Z", resource: "res-node-050.corp.internal" },
    { id: "APIS-0051", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #51", severity: "LOW", status: "RESOLVED", score: 84, timestamp: "2026-02-15 14:51:00Z", resource: "res-node-051.corp.internal" },
    { id: "APIS-0052", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #52", severity: "CRITICAL", status: "ACTIVE", score: 85, timestamp: "2026-02-15 14:52:00Z", resource: "res-node-052.corp.internal" },
    { id: "APIS-0053", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #53", severity: "HIGH", status: "CONTAINED", score: 86, timestamp: "2026-02-15 14:53:00Z", resource: "res-node-053.corp.internal" },
    { id: "APIS-0054", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #54", severity: "MEDIUM", status: "INVESTIGATING", score: 87, timestamp: "2026-02-15 14:54:00Z", resource: "res-node-054.corp.internal" },
    { id: "APIS-0055", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #55", severity: "LOW", status: "RESOLVED", score: 88, timestamp: "2026-02-15 14:55:00Z", resource: "res-node-055.corp.internal" },
    { id: "APIS-0056", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #56", severity: "CRITICAL", status: "ACTIVE", score: 89, timestamp: "2026-02-15 14:56:00Z", resource: "res-node-056.corp.internal" },
    { id: "APIS-0057", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #57", severity: "HIGH", status: "CONTAINED", score: 90, timestamp: "2026-02-15 14:57:00Z", resource: "res-node-057.corp.internal" },
    { id: "APIS-0058", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #58", severity: "MEDIUM", status: "INVESTIGATING", score: 91, timestamp: "2026-02-15 14:58:00Z", resource: "res-node-058.corp.internal" },
    { id: "APIS-0059", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #59", severity: "LOW", status: "RESOLVED", score: 92, timestamp: "2026-02-15 14:59:00Z", resource: "res-node-059.corp.internal" },
    { id: "APIS-0060", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #60", severity: "CRITICAL", status: "ACTIVE", score: 93, timestamp: "2026-02-15 14:00:00Z", resource: "res-node-060.corp.internal" },
    { id: "APIS-0061", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #61", severity: "HIGH", status: "CONTAINED", score: 94, timestamp: "2026-02-15 14:01:00Z", resource: "res-node-061.corp.internal" },
    { id: "APIS-0062", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #62", severity: "MEDIUM", status: "INVESTIGATING", score: 95, timestamp: "2026-02-15 14:02:00Z", resource: "res-node-062.corp.internal" },
    { id: "APIS-0063", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #63", severity: "LOW", status: "RESOLVED", score: 96, timestamp: "2026-02-15 14:03:00Z", resource: "res-node-063.corp.internal" },
    { id: "APIS-0064", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #64", severity: "CRITICAL", status: "ACTIVE", score: 65, timestamp: "2026-02-15 14:04:00Z", resource: "res-node-064.corp.internal" },
    { id: "APIS-0065", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #65", severity: "HIGH", status: "CONTAINED", score: 66, timestamp: "2026-02-15 14:05:00Z", resource: "res-node-065.corp.internal" },
    { id: "APIS-0066", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #66", severity: "MEDIUM", status: "INVESTIGATING", score: 67, timestamp: "2026-02-15 14:06:00Z", resource: "res-node-066.corp.internal" },
    { id: "APIS-0067", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #67", severity: "LOW", status: "RESOLVED", score: 68, timestamp: "2026-02-15 14:07:00Z", resource: "res-node-067.corp.internal" },
    { id: "APIS-0068", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #68", severity: "CRITICAL", status: "ACTIVE", score: 69, timestamp: "2026-02-15 14:08:00Z", resource: "res-node-068.corp.internal" },
    { id: "APIS-0069", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #69", severity: "HIGH", status: "CONTAINED", score: 70, timestamp: "2026-02-15 14:09:00Z", resource: "res-node-069.corp.internal" },
    { id: "APIS-0070", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #70", severity: "MEDIUM", status: "INVESTIGATING", score: 71, timestamp: "2026-02-15 14:10:00Z", resource: "res-node-070.corp.internal" },
    { id: "APIS-0071", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #71", severity: "LOW", status: "RESOLVED", score: 72, timestamp: "2026-02-15 14:11:00Z", resource: "res-node-071.corp.internal" },
    { id: "APIS-0072", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #72", severity: "CRITICAL", status: "ACTIVE", score: 73, timestamp: "2026-02-15 14:12:00Z", resource: "res-node-072.corp.internal" },
    { id: "APIS-0073", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #73", severity: "HIGH", status: "CONTAINED", score: 74, timestamp: "2026-02-15 14:13:00Z", resource: "res-node-073.corp.internal" },
    { id: "APIS-0074", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #74", severity: "MEDIUM", status: "INVESTIGATING", score: 75, timestamp: "2026-02-15 14:14:00Z", resource: "res-node-074.corp.internal" },
    { id: "APIS-0075", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #75", severity: "LOW", status: "RESOLVED", score: 76, timestamp: "2026-02-15 14:15:00Z", resource: "res-node-075.corp.internal" },
    { id: "APIS-0076", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #76", severity: "CRITICAL", status: "ACTIVE", score: 77, timestamp: "2026-02-15 14:16:00Z", resource: "res-node-076.corp.internal" },
    { id: "APIS-0077", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #77", severity: "HIGH", status: "CONTAINED", score: 78, timestamp: "2026-02-15 14:17:00Z", resource: "res-node-077.corp.internal" },
    { id: "APIS-0078", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #78", severity: "MEDIUM", status: "INVESTIGATING", score: 79, timestamp: "2026-02-15 14:18:00Z", resource: "res-node-078.corp.internal" },
    { id: "APIS-0079", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #79", severity: "LOW", status: "RESOLVED", score: 80, timestamp: "2026-02-15 14:19:00Z", resource: "res-node-079.corp.internal" },
    { id: "APIS-0080", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #80", severity: "CRITICAL", status: "ACTIVE", score: 81, timestamp: "2026-02-15 14:20:00Z", resource: "res-node-080.corp.internal" },
    { id: "APIS-0081", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #81", severity: "HIGH", status: "CONTAINED", score: 82, timestamp: "2026-02-15 14:21:00Z", resource: "res-node-081.corp.internal" },
    { id: "APIS-0082", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #82", severity: "MEDIUM", status: "INVESTIGATING", score: 83, timestamp: "2026-02-15 14:22:00Z", resource: "res-node-082.corp.internal" },
    { id: "APIS-0083", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #83", severity: "LOW", status: "RESOLVED", score: 84, timestamp: "2026-02-15 14:23:00Z", resource: "res-node-083.corp.internal" },
    { id: "APIS-0084", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #84", severity: "CRITICAL", status: "ACTIVE", score: 85, timestamp: "2026-02-15 14:24:00Z", resource: "res-node-084.corp.internal" },
    { id: "APIS-0085", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #85", severity: "HIGH", status: "CONTAINED", score: 86, timestamp: "2026-02-15 14:25:00Z", resource: "res-node-085.corp.internal" },
    { id: "APIS-0086", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #86", severity: "MEDIUM", status: "INVESTIGATING", score: 87, timestamp: "2026-02-15 14:26:00Z", resource: "res-node-086.corp.internal" },
    { id: "APIS-0087", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #87", severity: "LOW", status: "RESOLVED", score: 88, timestamp: "2026-02-15 14:27:00Z", resource: "res-node-087.corp.internal" },
    { id: "APIS-0088", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #88", severity: "CRITICAL", status: "ACTIVE", score: 89, timestamp: "2026-02-15 14:28:00Z", resource: "res-node-088.corp.internal" },
    { id: "APIS-0089", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #89", severity: "HIGH", status: "CONTAINED", score: 90, timestamp: "2026-02-15 14:29:00Z", resource: "res-node-089.corp.internal" },
    { id: "APIS-0090", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #90", severity: "MEDIUM", status: "INVESTIGATING", score: 91, timestamp: "2026-02-15 14:30:00Z", resource: "res-node-090.corp.internal" },
    { id: "APIS-0091", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #91", severity: "LOW", status: "RESOLVED", score: 92, timestamp: "2026-02-15 14:31:00Z", resource: "res-node-091.corp.internal" },
    { id: "APIS-0092", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #92", severity: "CRITICAL", status: "ACTIVE", score: 93, timestamp: "2026-02-15 14:32:00Z", resource: "res-node-092.corp.internal" },
    { id: "APIS-0093", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #93", severity: "HIGH", status: "CONTAINED", score: 94, timestamp: "2026-02-15 14:33:00Z", resource: "res-node-093.corp.internal" },
    { id: "APIS-0094", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #94", severity: "MEDIUM", status: "INVESTIGATING", score: 95, timestamp: "2026-02-15 14:34:00Z", resource: "res-node-094.corp.internal" },
    { id: "APIS-0095", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #95", severity: "LOW", status: "RESOLVED", score: 96, timestamp: "2026-02-15 14:35:00Z", resource: "res-node-095.corp.internal" },
    { id: "APIS-0096", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #96", severity: "CRITICAL", status: "ACTIVE", score: 65, timestamp: "2026-02-15 14:36:00Z", resource: "res-node-096.corp.internal" },
    { id: "APIS-0097", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #97", severity: "HIGH", status: "CONTAINED", score: 66, timestamp: "2026-02-15 14:37:00Z", resource: "res-node-097.corp.internal" },
    { id: "APIS-0098", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #98", severity: "MEDIUM", status: "INVESTIGATING", score: 67, timestamp: "2026-02-15 14:38:00Z", resource: "res-node-098.corp.internal" },
    { id: "APIS-0099", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #99", severity: "LOW", status: "RESOLVED", score: 68, timestamp: "2026-02-15 14:39:00Z", resource: "res-node-099.corp.internal" },
    { id: "APIS-0100", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #100", severity: "CRITICAL", status: "ACTIVE", score: 69, timestamp: "2026-02-15 14:40:00Z", resource: "res-node-100.corp.internal" },
    { id: "APIS-0101", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #101", severity: "HIGH", status: "CONTAINED", score: 70, timestamp: "2026-02-15 14:41:00Z", resource: "res-node-101.corp.internal" },
    { id: "APIS-0102", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #102", severity: "MEDIUM", status: "INVESTIGATING", score: 71, timestamp: "2026-02-15 14:42:00Z", resource: "res-node-102.corp.internal" },
    { id: "APIS-0103", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #103", severity: "LOW", status: "RESOLVED", score: 72, timestamp: "2026-02-15 14:43:00Z", resource: "res-node-103.corp.internal" },
    { id: "APIS-0104", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #104", severity: "CRITICAL", status: "ACTIVE", score: 73, timestamp: "2026-02-15 14:44:00Z", resource: "res-node-104.corp.internal" },
    { id: "APIS-0105", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #105", severity: "HIGH", status: "CONTAINED", score: 74, timestamp: "2026-02-15 14:45:00Z", resource: "res-node-105.corp.internal" },
    { id: "APIS-0106", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #106", severity: "MEDIUM", status: "INVESTIGATING", score: 75, timestamp: "2026-02-15 14:46:00Z", resource: "res-node-106.corp.internal" },
    { id: "APIS-0107", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #107", severity: "LOW", status: "RESOLVED", score: 76, timestamp: "2026-02-15 14:47:00Z", resource: "res-node-107.corp.internal" },
    { id: "APIS-0108", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #108", severity: "CRITICAL", status: "ACTIVE", score: 77, timestamp: "2026-02-15 14:48:00Z", resource: "res-node-108.corp.internal" },
    { id: "APIS-0109", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #109", severity: "HIGH", status: "CONTAINED", score: 78, timestamp: "2026-02-15 14:49:00Z", resource: "res-node-109.corp.internal" },
    { id: "APIS-0110", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #110", severity: "MEDIUM", status: "INVESTIGATING", score: 79, timestamp: "2026-02-15 14:50:00Z", resource: "res-node-110.corp.internal" },
    { id: "APIS-0111", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #111", severity: "LOW", status: "RESOLVED", score: 80, timestamp: "2026-02-15 14:51:00Z", resource: "res-node-111.corp.internal" },
    { id: "APIS-0112", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #112", severity: "CRITICAL", status: "ACTIVE", score: 81, timestamp: "2026-02-15 14:52:00Z", resource: "res-node-112.corp.internal" },
    { id: "APIS-0113", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #113", severity: "HIGH", status: "CONTAINED", score: 82, timestamp: "2026-02-15 14:53:00Z", resource: "res-node-113.corp.internal" },
    { id: "APIS-0114", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #114", severity: "MEDIUM", status: "INVESTIGATING", score: 83, timestamp: "2026-02-15 14:54:00Z", resource: "res-node-114.corp.internal" },
    { id: "APIS-0115", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #115", severity: "LOW", status: "RESOLVED", score: 84, timestamp: "2026-02-15 14:55:00Z", resource: "res-node-115.corp.internal" },
    { id: "APIS-0116", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #116", severity: "CRITICAL", status: "ACTIVE", score: 85, timestamp: "2026-02-15 14:56:00Z", resource: "res-node-116.corp.internal" },
    { id: "APIS-0117", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #117", severity: "HIGH", status: "CONTAINED", score: 86, timestamp: "2026-02-15 14:57:00Z", resource: "res-node-117.corp.internal" },
    { id: "APIS-0118", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #118", severity: "MEDIUM", status: "INVESTIGATING", score: 87, timestamp: "2026-02-15 14:58:00Z", resource: "res-node-118.corp.internal" },
    { id: "APIS-0119", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #119", severity: "LOW", status: "RESOLVED", score: 88, timestamp: "2026-02-15 14:59:00Z", resource: "res-node-119.corp.internal" },
    { id: "APIS-0120", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #120", severity: "CRITICAL", status: "ACTIVE", score: 89, timestamp: "2026-02-15 14:00:00Z", resource: "res-node-120.corp.internal" },
    { id: "APIS-0121", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #121", severity: "HIGH", status: "CONTAINED", score: 90, timestamp: "2026-02-15 14:01:00Z", resource: "res-node-121.corp.internal" },
    { id: "APIS-0122", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #122", severity: "MEDIUM", status: "INVESTIGATING", score: 91, timestamp: "2026-02-15 14:02:00Z", resource: "res-node-122.corp.internal" },
    { id: "APIS-0123", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #123", severity: "LOW", status: "RESOLVED", score: 92, timestamp: "2026-02-15 14:03:00Z", resource: "res-node-123.corp.internal" },
    { id: "APIS-0124", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #124", severity: "CRITICAL", status: "ACTIVE", score: 93, timestamp: "2026-02-15 14:04:00Z", resource: "res-node-124.corp.internal" },
    { id: "APIS-0125", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #125", severity: "HIGH", status: "CONTAINED", score: 94, timestamp: "2026-02-15 14:05:00Z", resource: "res-node-125.corp.internal" },
    { id: "APIS-0126", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #126", severity: "MEDIUM", status: "INVESTIGATING", score: 95, timestamp: "2026-02-15 14:06:00Z", resource: "res-node-126.corp.internal" },
    { id: "APIS-0127", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #127", severity: "LOW", status: "RESOLVED", score: 96, timestamp: "2026-02-15 14:07:00Z", resource: "res-node-127.corp.internal" },
    { id: "APIS-0128", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #128", severity: "CRITICAL", status: "ACTIVE", score: 65, timestamp: "2026-02-15 14:08:00Z", resource: "res-node-128.corp.internal" },
    { id: "APIS-0129", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #129", severity: "HIGH", status: "CONTAINED", score: 66, timestamp: "2026-02-15 14:09:00Z", resource: "res-node-129.corp.internal" },
    { id: "APIS-0130", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #130", severity: "MEDIUM", status: "INVESTIGATING", score: 67, timestamp: "2026-02-15 14:10:00Z", resource: "res-node-130.corp.internal" },
    { id: "APIS-0131", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #131", severity: "LOW", status: "RESOLVED", score: 68, timestamp: "2026-02-15 14:11:00Z", resource: "res-node-131.corp.internal" },
    { id: "APIS-0132", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #132", severity: "CRITICAL", status: "ACTIVE", score: 69, timestamp: "2026-02-15 14:12:00Z", resource: "res-node-132.corp.internal" },
    { id: "APIS-0133", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #133", severity: "HIGH", status: "CONTAINED", score: 70, timestamp: "2026-02-15 14:13:00Z", resource: "res-node-133.corp.internal" },
    { id: "APIS-0134", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #134", severity: "MEDIUM", status: "INVESTIGATING", score: 71, timestamp: "2026-02-15 14:14:00Z", resource: "res-node-134.corp.internal" },
    { id: "APIS-0135", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #135", severity: "LOW", status: "RESOLVED", score: 72, timestamp: "2026-02-15 14:15:00Z", resource: "res-node-135.corp.internal" },
    { id: "APIS-0136", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #136", severity: "CRITICAL", status: "ACTIVE", score: 73, timestamp: "2026-02-15 14:16:00Z", resource: "res-node-136.corp.internal" },
    { id: "APIS-0137", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #137", severity: "HIGH", status: "CONTAINED", score: 74, timestamp: "2026-02-15 14:17:00Z", resource: "res-node-137.corp.internal" },
    { id: "APIS-0138", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #138", severity: "MEDIUM", status: "INVESTIGATING", score: 75, timestamp: "2026-02-15 14:18:00Z", resource: "res-node-138.corp.internal" },
    { id: "APIS-0139", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #139", severity: "LOW", status: "RESOLVED", score: 76, timestamp: "2026-02-15 14:19:00Z", resource: "res-node-139.corp.internal" },
    { id: "APIS-0140", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #140", severity: "CRITICAL", status: "ACTIVE", score: 77, timestamp: "2026-02-15 14:20:00Z", resource: "res-node-140.corp.internal" },
    { id: "APIS-0141", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #141", severity: "HIGH", status: "CONTAINED", score: 78, timestamp: "2026-02-15 14:21:00Z", resource: "res-node-141.corp.internal" },
    { id: "APIS-0142", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #142", severity: "MEDIUM", status: "INVESTIGATING", score: 79, timestamp: "2026-02-15 14:22:00Z", resource: "res-node-142.corp.internal" },
    { id: "APIS-0143", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #143", severity: "LOW", status: "RESOLVED", score: 80, timestamp: "2026-02-15 14:23:00Z", resource: "res-node-143.corp.internal" },
    { id: "APIS-0144", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #144", severity: "CRITICAL", status: "ACTIVE", score: 81, timestamp: "2026-02-15 14:24:00Z", resource: "res-node-144.corp.internal" },
    { id: "APIS-0145", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #145", severity: "HIGH", status: "CONTAINED", score: 82, timestamp: "2026-02-15 14:25:00Z", resource: "res-node-145.corp.internal" },
    { id: "APIS-0146", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #146", severity: "MEDIUM", status: "INVESTIGATING", score: 83, timestamp: "2026-02-15 14:26:00Z", resource: "res-node-146.corp.internal" },
    { id: "APIS-0147", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #147", severity: "LOW", status: "RESOLVED", score: 84, timestamp: "2026-02-15 14:27:00Z", resource: "res-node-147.corp.internal" },
    { id: "APIS-0148", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #148", severity: "CRITICAL", status: "ACTIVE", score: 85, timestamp: "2026-02-15 14:28:00Z", resource: "res-node-148.corp.internal" },
    { id: "APIS-0149", name: "OWASP API Top 10 Threat Shield & Telemetry Monitor Item #149", severity: "HIGH", status: "CONTAINED", score: 86, timestamp: "2026-02-15 14:29:00Z", resource: "res-node-149.corp.internal" },
  ];

  return (
    <div className="page-container" style={{ maxWidth: "1280px", margin: "0 auto", padding: "24px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={ color: "var(--cyan)" }>🔌</span> OWASP API Top 10 Threat Shield & Telemetry Monitor
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "13px", margin: "4px 0 0 0" }}>
            Real-time telemetry, automated analysis, and continuous monitoring console for OWASP API Top 10 Threat Shield & Telemetry Monitor.
          </p>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px", marginBottom: "20px" }}>
        <div className="card" style={{ padding: "16px", background: "var(--card-bg)", border: "1px solid var(--border)", borderRadius: "10px" }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>Monitored Entities</div>
          <div style={{ fontSize: "24px", fontWeight: 700, color: "#fff", marginTop: "6px" }}>1,840</div>
        </div>
        <div className="card" style={{ padding: "16px", background: "var(--card-bg)", border: "1px solid var(--border)", borderRadius: "10px" }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>Active Threat Signals</div>
          <div style={{ fontSize: "24px", fontWeight: 700, color: "#ff3366", marginTop: "6px" }}>38</div>
        </div>
        <div className="card" style={{ padding: "16px", background: "var(--card-bg)", border: "1px solid var(--border)", borderRadius: "10px" }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>Automated Interventions</div>
          <div style={{ fontSize: "24px", fontWeight: 700, color: "var(--neon-green)", marginTop: "6px" }}>114</div>
        </div>
        <div className="card" style={{ padding: "16px", background: "var(--card-bg)", border: "1px solid var(--border)", borderRadius: "10px" }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>Efficacy Score</div>
          <div style={{ fontSize: "24px", fontWeight: 700, color: "var(--cyan)", marginTop: "6px" }}>98.4%</div>
        </div>
      </div>

      <div className="card" style={{ padding: 0, background: "var(--card-bg)", border: "1px solid var(--border)", borderRadius: "10px", overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "13px" }}>
          <thead>
            <tr style={{ background: "rgba(255,255,255,0.03)", borderBottom: "1px solid var(--border)" }}>
              <th style={{ padding: "12px 16px" }}>Record ID</th>
              <th style={{ padding: "12px 16px" }}>Resource / Entity</th>
              <th style={{ padding: "12px 16px" }}>Severity</th>
              <th style={{ padding: "12px 16px" }}>Status</th>
              <th style={{ padding: "12px 16px" }}>Confidence Score</th>
              <th style={{ padding: "12px 16px" }}>Observed At</th>
            </tr>
          </thead>
          <tbody>
            {dataFeed.map(item => (
              <tr key={item.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                <td style={{ padding: "12px 16px" }}><code>{item.id}</code></td>
                <td style={{ padding: "12px 16px", fontWeight: 600 }}>{item.resource}</td>
                <td style={{ padding: "12px 16px" }}>
                  <span className={`badge-pill ${item.severity === "CRITICAL" ? "badge-critical" : "badge-high"}`}>{item.severity}</span>
                </td>
                <td style={{ padding: "12px 16px" }}>{item.status}</td>
                <td style={{ padding: "12px 16px", fontWeight: 700, color: "var(--cyan)" }}>{item.score}%</td>
                <td style={{ padding: "12px 16px", color: "var(--text-muted)" }}>{item.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
