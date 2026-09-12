import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

export const ThreatGraphStudioPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [selectedItem, setSelectedItem] = useState<any>(null);

  const dataFeed = [
    { id: "THRE-0001", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #1", severity: "HIGH", status: "CONTAINED", score: 66, timestamp: "2026-02-15 14:01:00Z", resource: "res-node-001.corp.internal" },
    { id: "THRE-0002", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #2", severity: "MEDIUM", status: "INVESTIGATING", score: 67, timestamp: "2026-02-15 14:02:00Z", resource: "res-node-002.corp.internal" },
    { id: "THRE-0003", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #3", severity: "LOW", status: "RESOLVED", score: 68, timestamp: "2026-02-15 14:03:00Z", resource: "res-node-003.corp.internal" },
    { id: "THRE-0004", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #4", severity: "CRITICAL", status: "ACTIVE", score: 69, timestamp: "2026-02-15 14:04:00Z", resource: "res-node-004.corp.internal" },
    { id: "THRE-0005", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #5", severity: "HIGH", status: "CONTAINED", score: 70, timestamp: "2026-02-15 14:05:00Z", resource: "res-node-005.corp.internal" },
    { id: "THRE-0006", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #6", severity: "MEDIUM", status: "INVESTIGATING", score: 71, timestamp: "2026-02-15 14:06:00Z", resource: "res-node-006.corp.internal" },
    { id: "THRE-0007", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #7", severity: "LOW", status: "RESOLVED", score: 72, timestamp: "2026-02-15 14:07:00Z", resource: "res-node-007.corp.internal" },
    { id: "THRE-0008", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #8", severity: "CRITICAL", status: "ACTIVE", score: 73, timestamp: "2026-02-15 14:08:00Z", resource: "res-node-008.corp.internal" },
    { id: "THRE-0009", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #9", severity: "HIGH", status: "CONTAINED", score: 74, timestamp: "2026-02-15 14:09:00Z", resource: "res-node-009.corp.internal" },
    { id: "THRE-0010", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #10", severity: "MEDIUM", status: "INVESTIGATING", score: 75, timestamp: "2026-02-15 14:10:00Z", resource: "res-node-010.corp.internal" },
    { id: "THRE-0011", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #11", severity: "LOW", status: "RESOLVED", score: 76, timestamp: "2026-02-15 14:11:00Z", resource: "res-node-011.corp.internal" },
    { id: "THRE-0012", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #12", severity: "CRITICAL", status: "ACTIVE", score: 77, timestamp: "2026-02-15 14:12:00Z", resource: "res-node-012.corp.internal" },
    { id: "THRE-0013", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #13", severity: "HIGH", status: "CONTAINED", score: 78, timestamp: "2026-02-15 14:13:00Z", resource: "res-node-013.corp.internal" },
    { id: "THRE-0014", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #14", severity: "MEDIUM", status: "INVESTIGATING", score: 79, timestamp: "2026-02-15 14:14:00Z", resource: "res-node-014.corp.internal" },
    { id: "THRE-0015", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #15", severity: "LOW", status: "RESOLVED", score: 80, timestamp: "2026-02-15 14:15:00Z", resource: "res-node-015.corp.internal" },
    { id: "THRE-0016", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #16", severity: "CRITICAL", status: "ACTIVE", score: 81, timestamp: "2026-02-15 14:16:00Z", resource: "res-node-016.corp.internal" },
    { id: "THRE-0017", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #17", severity: "HIGH", status: "CONTAINED", score: 82, timestamp: "2026-02-15 14:17:00Z", resource: "res-node-017.corp.internal" },
    { id: "THRE-0018", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #18", severity: "MEDIUM", status: "INVESTIGATING", score: 83, timestamp: "2026-02-15 14:18:00Z", resource: "res-node-018.corp.internal" },
    { id: "THRE-0019", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #19", severity: "LOW", status: "RESOLVED", score: 84, timestamp: "2026-02-15 14:19:00Z", resource: "res-node-019.corp.internal" },
    { id: "THRE-0020", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #20", severity: "CRITICAL", status: "ACTIVE", score: 85, timestamp: "2026-02-15 14:20:00Z", resource: "res-node-020.corp.internal" },
    { id: "THRE-0021", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #21", severity: "HIGH", status: "CONTAINED", score: 86, timestamp: "2026-02-15 14:21:00Z", resource: "res-node-021.corp.internal" },
    { id: "THRE-0022", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #22", severity: "MEDIUM", status: "INVESTIGATING", score: 87, timestamp: "2026-02-15 14:22:00Z", resource: "res-node-022.corp.internal" },
    { id: "THRE-0023", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #23", severity: "LOW", status: "RESOLVED", score: 88, timestamp: "2026-02-15 14:23:00Z", resource: "res-node-023.corp.internal" },
    { id: "THRE-0024", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #24", severity: "CRITICAL", status: "ACTIVE", score: 89, timestamp: "2026-02-15 14:24:00Z", resource: "res-node-024.corp.internal" },
    { id: "THRE-0025", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #25", severity: "HIGH", status: "CONTAINED", score: 90, timestamp: "2026-02-15 14:25:00Z", resource: "res-node-025.corp.internal" },
    { id: "THRE-0026", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #26", severity: "MEDIUM", status: "INVESTIGATING", score: 91, timestamp: "2026-02-15 14:26:00Z", resource: "res-node-026.corp.internal" },
    { id: "THRE-0027", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #27", severity: "LOW", status: "RESOLVED", score: 92, timestamp: "2026-02-15 14:27:00Z", resource: "res-node-027.corp.internal" },
    { id: "THRE-0028", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #28", severity: "CRITICAL", status: "ACTIVE", score: 93, timestamp: "2026-02-15 14:28:00Z", resource: "res-node-028.corp.internal" },
    { id: "THRE-0029", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #29", severity: "HIGH", status: "CONTAINED", score: 94, timestamp: "2026-02-15 14:29:00Z", resource: "res-node-029.corp.internal" },
    { id: "THRE-0030", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #30", severity: "MEDIUM", status: "INVESTIGATING", score: 95, timestamp: "2026-02-15 14:30:00Z", resource: "res-node-030.corp.internal" },
    { id: "THRE-0031", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #31", severity: "LOW", status: "RESOLVED", score: 96, timestamp: "2026-02-15 14:31:00Z", resource: "res-node-031.corp.internal" },
    { id: "THRE-0032", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #32", severity: "CRITICAL", status: "ACTIVE", score: 65, timestamp: "2026-02-15 14:32:00Z", resource: "res-node-032.corp.internal" },
    { id: "THRE-0033", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #33", severity: "HIGH", status: "CONTAINED", score: 66, timestamp: "2026-02-15 14:33:00Z", resource: "res-node-033.corp.internal" },
    { id: "THRE-0034", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #34", severity: "MEDIUM", status: "INVESTIGATING", score: 67, timestamp: "2026-02-15 14:34:00Z", resource: "res-node-034.corp.internal" },
    { id: "THRE-0035", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #35", severity: "LOW", status: "RESOLVED", score: 68, timestamp: "2026-02-15 14:35:00Z", resource: "res-node-035.corp.internal" },
    { id: "THRE-0036", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #36", severity: "CRITICAL", status: "ACTIVE", score: 69, timestamp: "2026-02-15 14:36:00Z", resource: "res-node-036.corp.internal" },
    { id: "THRE-0037", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #37", severity: "HIGH", status: "CONTAINED", score: 70, timestamp: "2026-02-15 14:37:00Z", resource: "res-node-037.corp.internal" },
    { id: "THRE-0038", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #38", severity: "MEDIUM", status: "INVESTIGATING", score: 71, timestamp: "2026-02-15 14:38:00Z", resource: "res-node-038.corp.internal" },
    { id: "THRE-0039", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #39", severity: "LOW", status: "RESOLVED", score: 72, timestamp: "2026-02-15 14:39:00Z", resource: "res-node-039.corp.internal" },
    { id: "THRE-0040", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #40", severity: "CRITICAL", status: "ACTIVE", score: 73, timestamp: "2026-02-15 14:40:00Z", resource: "res-node-040.corp.internal" },
    { id: "THRE-0041", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #41", severity: "HIGH", status: "CONTAINED", score: 74, timestamp: "2026-02-15 14:41:00Z", resource: "res-node-041.corp.internal" },
    { id: "THRE-0042", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #42", severity: "MEDIUM", status: "INVESTIGATING", score: 75, timestamp: "2026-02-15 14:42:00Z", resource: "res-node-042.corp.internal" },
    { id: "THRE-0043", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #43", severity: "LOW", status: "RESOLVED", score: 76, timestamp: "2026-02-15 14:43:00Z", resource: "res-node-043.corp.internal" },
    { id: "THRE-0044", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #44", severity: "CRITICAL", status: "ACTIVE", score: 77, timestamp: "2026-02-15 14:44:00Z", resource: "res-node-044.corp.internal" },
    { id: "THRE-0045", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #45", severity: "HIGH", status: "CONTAINED", score: 78, timestamp: "2026-02-15 14:45:00Z", resource: "res-node-045.corp.internal" },
    { id: "THRE-0046", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #46", severity: "MEDIUM", status: "INVESTIGATING", score: 79, timestamp: "2026-02-15 14:46:00Z", resource: "res-node-046.corp.internal" },
    { id: "THRE-0047", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #47", severity: "LOW", status: "RESOLVED", score: 80, timestamp: "2026-02-15 14:47:00Z", resource: "res-node-047.corp.internal" },
    { id: "THRE-0048", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #48", severity: "CRITICAL", status: "ACTIVE", score: 81, timestamp: "2026-02-15 14:48:00Z", resource: "res-node-048.corp.internal" },
    { id: "THRE-0049", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #49", severity: "HIGH", status: "CONTAINED", score: 82, timestamp: "2026-02-15 14:49:00Z", resource: "res-node-049.corp.internal" },
    { id: "THRE-0050", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #50", severity: "MEDIUM", status: "INVESTIGATING", score: 83, timestamp: "2026-02-15 14:50:00Z", resource: "res-node-050.corp.internal" },
    { id: "THRE-0051", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #51", severity: "LOW", status: "RESOLVED", score: 84, timestamp: "2026-02-15 14:51:00Z", resource: "res-node-051.corp.internal" },
    { id: "THRE-0052", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #52", severity: "CRITICAL", status: "ACTIVE", score: 85, timestamp: "2026-02-15 14:52:00Z", resource: "res-node-052.corp.internal" },
    { id: "THRE-0053", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #53", severity: "HIGH", status: "CONTAINED", score: 86, timestamp: "2026-02-15 14:53:00Z", resource: "res-node-053.corp.internal" },
    { id: "THRE-0054", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #54", severity: "MEDIUM", status: "INVESTIGATING", score: 87, timestamp: "2026-02-15 14:54:00Z", resource: "res-node-054.corp.internal" },
    { id: "THRE-0055", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #55", severity: "LOW", status: "RESOLVED", score: 88, timestamp: "2026-02-15 14:55:00Z", resource: "res-node-055.corp.internal" },
    { id: "THRE-0056", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #56", severity: "CRITICAL", status: "ACTIVE", score: 89, timestamp: "2026-02-15 14:56:00Z", resource: "res-node-056.corp.internal" },
    { id: "THRE-0057", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #57", severity: "HIGH", status: "CONTAINED", score: 90, timestamp: "2026-02-15 14:57:00Z", resource: "res-node-057.corp.internal" },
    { id: "THRE-0058", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #58", severity: "MEDIUM", status: "INVESTIGATING", score: 91, timestamp: "2026-02-15 14:58:00Z", resource: "res-node-058.corp.internal" },
    { id: "THRE-0059", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #59", severity: "LOW", status: "RESOLVED", score: 92, timestamp: "2026-02-15 14:59:00Z", resource: "res-node-059.corp.internal" },
    { id: "THRE-0060", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #60", severity: "CRITICAL", status: "ACTIVE", score: 93, timestamp: "2026-02-15 14:00:00Z", resource: "res-node-060.corp.internal" },
    { id: "THRE-0061", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #61", severity: "HIGH", status: "CONTAINED", score: 94, timestamp: "2026-02-15 14:01:00Z", resource: "res-node-061.corp.internal" },
    { id: "THRE-0062", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #62", severity: "MEDIUM", status: "INVESTIGATING", score: 95, timestamp: "2026-02-15 14:02:00Z", resource: "res-node-062.corp.internal" },
    { id: "THRE-0063", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #63", severity: "LOW", status: "RESOLVED", score: 96, timestamp: "2026-02-15 14:03:00Z", resource: "res-node-063.corp.internal" },
    { id: "THRE-0064", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #64", severity: "CRITICAL", status: "ACTIVE", score: 65, timestamp: "2026-02-15 14:04:00Z", resource: "res-node-064.corp.internal" },
    { id: "THRE-0065", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #65", severity: "HIGH", status: "CONTAINED", score: 66, timestamp: "2026-02-15 14:05:00Z", resource: "res-node-065.corp.internal" },
    { id: "THRE-0066", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #66", severity: "MEDIUM", status: "INVESTIGATING", score: 67, timestamp: "2026-02-15 14:06:00Z", resource: "res-node-066.corp.internal" },
    { id: "THRE-0067", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #67", severity: "LOW", status: "RESOLVED", score: 68, timestamp: "2026-02-15 14:07:00Z", resource: "res-node-067.corp.internal" },
    { id: "THRE-0068", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #68", severity: "CRITICAL", status: "ACTIVE", score: 69, timestamp: "2026-02-15 14:08:00Z", resource: "res-node-068.corp.internal" },
    { id: "THRE-0069", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #69", severity: "HIGH", status: "CONTAINED", score: 70, timestamp: "2026-02-15 14:09:00Z", resource: "res-node-069.corp.internal" },
    { id: "THRE-0070", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #70", severity: "MEDIUM", status: "INVESTIGATING", score: 71, timestamp: "2026-02-15 14:10:00Z", resource: "res-node-070.corp.internal" },
    { id: "THRE-0071", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #71", severity: "LOW", status: "RESOLVED", score: 72, timestamp: "2026-02-15 14:11:00Z", resource: "res-node-071.corp.internal" },
    { id: "THRE-0072", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #72", severity: "CRITICAL", status: "ACTIVE", score: 73, timestamp: "2026-02-15 14:12:00Z", resource: "res-node-072.corp.internal" },
    { id: "THRE-0073", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #73", severity: "HIGH", status: "CONTAINED", score: 74, timestamp: "2026-02-15 14:13:00Z", resource: "res-node-073.corp.internal" },
    { id: "THRE-0074", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #74", severity: "MEDIUM", status: "INVESTIGATING", score: 75, timestamp: "2026-02-15 14:14:00Z", resource: "res-node-074.corp.internal" },
    { id: "THRE-0075", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #75", severity: "LOW", status: "RESOLVED", score: 76, timestamp: "2026-02-15 14:15:00Z", resource: "res-node-075.corp.internal" },
    { id: "THRE-0076", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #76", severity: "CRITICAL", status: "ACTIVE", score: 77, timestamp: "2026-02-15 14:16:00Z", resource: "res-node-076.corp.internal" },
    { id: "THRE-0077", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #77", severity: "HIGH", status: "CONTAINED", score: 78, timestamp: "2026-02-15 14:17:00Z", resource: "res-node-077.corp.internal" },
    { id: "THRE-0078", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #78", severity: "MEDIUM", status: "INVESTIGATING", score: 79, timestamp: "2026-02-15 14:18:00Z", resource: "res-node-078.corp.internal" },
    { id: "THRE-0079", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #79", severity: "LOW", status: "RESOLVED", score: 80, timestamp: "2026-02-15 14:19:00Z", resource: "res-node-079.corp.internal" },
    { id: "THRE-0080", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #80", severity: "CRITICAL", status: "ACTIVE", score: 81, timestamp: "2026-02-15 14:20:00Z", resource: "res-node-080.corp.internal" },
    { id: "THRE-0081", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #81", severity: "HIGH", status: "CONTAINED", score: 82, timestamp: "2026-02-15 14:21:00Z", resource: "res-node-081.corp.internal" },
    { id: "THRE-0082", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #82", severity: "MEDIUM", status: "INVESTIGATING", score: 83, timestamp: "2026-02-15 14:22:00Z", resource: "res-node-082.corp.internal" },
    { id: "THRE-0083", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #83", severity: "LOW", status: "RESOLVED", score: 84, timestamp: "2026-02-15 14:23:00Z", resource: "res-node-083.corp.internal" },
    { id: "THRE-0084", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #84", severity: "CRITICAL", status: "ACTIVE", score: 85, timestamp: "2026-02-15 14:24:00Z", resource: "res-node-084.corp.internal" },
    { id: "THRE-0085", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #85", severity: "HIGH", status: "CONTAINED", score: 86, timestamp: "2026-02-15 14:25:00Z", resource: "res-node-085.corp.internal" },
    { id: "THRE-0086", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #86", severity: "MEDIUM", status: "INVESTIGATING", score: 87, timestamp: "2026-02-15 14:26:00Z", resource: "res-node-086.corp.internal" },
    { id: "THRE-0087", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #87", severity: "LOW", status: "RESOLVED", score: 88, timestamp: "2026-02-15 14:27:00Z", resource: "res-node-087.corp.internal" },
    { id: "THRE-0088", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #88", severity: "CRITICAL", status: "ACTIVE", score: 89, timestamp: "2026-02-15 14:28:00Z", resource: "res-node-088.corp.internal" },
    { id: "THRE-0089", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #89", severity: "HIGH", status: "CONTAINED", score: 90, timestamp: "2026-02-15 14:29:00Z", resource: "res-node-089.corp.internal" },
    { id: "THRE-0090", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #90", severity: "MEDIUM", status: "INVESTIGATING", score: 91, timestamp: "2026-02-15 14:30:00Z", resource: "res-node-090.corp.internal" },
    { id: "THRE-0091", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #91", severity: "LOW", status: "RESOLVED", score: 92, timestamp: "2026-02-15 14:31:00Z", resource: "res-node-091.corp.internal" },
    { id: "THRE-0092", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #92", severity: "CRITICAL", status: "ACTIVE", score: 93, timestamp: "2026-02-15 14:32:00Z", resource: "res-node-092.corp.internal" },
    { id: "THRE-0093", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #93", severity: "HIGH", status: "CONTAINED", score: 94, timestamp: "2026-02-15 14:33:00Z", resource: "res-node-093.corp.internal" },
    { id: "THRE-0094", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #94", severity: "MEDIUM", status: "INVESTIGATING", score: 95, timestamp: "2026-02-15 14:34:00Z", resource: "res-node-094.corp.internal" },
    { id: "THRE-0095", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #95", severity: "LOW", status: "RESOLVED", score: 96, timestamp: "2026-02-15 14:35:00Z", resource: "res-node-095.corp.internal" },
    { id: "THRE-0096", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #96", severity: "CRITICAL", status: "ACTIVE", score: 65, timestamp: "2026-02-15 14:36:00Z", resource: "res-node-096.corp.internal" },
    { id: "THRE-0097", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #97", severity: "HIGH", status: "CONTAINED", score: 66, timestamp: "2026-02-15 14:37:00Z", resource: "res-node-097.corp.internal" },
    { id: "THRE-0098", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #98", severity: "MEDIUM", status: "INVESTIGATING", score: 67, timestamp: "2026-02-15 14:38:00Z", resource: "res-node-098.corp.internal" },
    { id: "THRE-0099", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #99", severity: "LOW", status: "RESOLVED", score: 68, timestamp: "2026-02-15 14:39:00Z", resource: "res-node-099.corp.internal" },
    { id: "THRE-0100", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #100", severity: "CRITICAL", status: "ACTIVE", score: 69, timestamp: "2026-02-15 14:40:00Z", resource: "res-node-100.corp.internal" },
    { id: "THRE-0101", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #101", severity: "HIGH", status: "CONTAINED", score: 70, timestamp: "2026-02-15 14:41:00Z", resource: "res-node-101.corp.internal" },
    { id: "THRE-0102", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #102", severity: "MEDIUM", status: "INVESTIGATING", score: 71, timestamp: "2026-02-15 14:42:00Z", resource: "res-node-102.corp.internal" },
    { id: "THRE-0103", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #103", severity: "LOW", status: "RESOLVED", score: 72, timestamp: "2026-02-15 14:43:00Z", resource: "res-node-103.corp.internal" },
    { id: "THRE-0104", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #104", severity: "CRITICAL", status: "ACTIVE", score: 73, timestamp: "2026-02-15 14:44:00Z", resource: "res-node-104.corp.internal" },
    { id: "THRE-0105", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #105", severity: "HIGH", status: "CONTAINED", score: 74, timestamp: "2026-02-15 14:45:00Z", resource: "res-node-105.corp.internal" },
    { id: "THRE-0106", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #106", severity: "MEDIUM", status: "INVESTIGATING", score: 75, timestamp: "2026-02-15 14:46:00Z", resource: "res-node-106.corp.internal" },
    { id: "THRE-0107", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #107", severity: "LOW", status: "RESOLVED", score: 76, timestamp: "2026-02-15 14:47:00Z", resource: "res-node-107.corp.internal" },
    { id: "THRE-0108", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #108", severity: "CRITICAL", status: "ACTIVE", score: 77, timestamp: "2026-02-15 14:48:00Z", resource: "res-node-108.corp.internal" },
    { id: "THRE-0109", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #109", severity: "HIGH", status: "CONTAINED", score: 78, timestamp: "2026-02-15 14:49:00Z", resource: "res-node-109.corp.internal" },
    { id: "THRE-0110", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #110", severity: "MEDIUM", status: "INVESTIGATING", score: 79, timestamp: "2026-02-15 14:50:00Z", resource: "res-node-110.corp.internal" },
    { id: "THRE-0111", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #111", severity: "LOW", status: "RESOLVED", score: 80, timestamp: "2026-02-15 14:51:00Z", resource: "res-node-111.corp.internal" },
    { id: "THRE-0112", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #112", severity: "CRITICAL", status: "ACTIVE", score: 81, timestamp: "2026-02-15 14:52:00Z", resource: "res-node-112.corp.internal" },
    { id: "THRE-0113", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #113", severity: "HIGH", status: "CONTAINED", score: 82, timestamp: "2026-02-15 14:53:00Z", resource: "res-node-113.corp.internal" },
    { id: "THRE-0114", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #114", severity: "MEDIUM", status: "INVESTIGATING", score: 83, timestamp: "2026-02-15 14:54:00Z", resource: "res-node-114.corp.internal" },
    { id: "THRE-0115", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #115", severity: "LOW", status: "RESOLVED", score: 84, timestamp: "2026-02-15 14:55:00Z", resource: "res-node-115.corp.internal" },
    { id: "THRE-0116", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #116", severity: "CRITICAL", status: "ACTIVE", score: 85, timestamp: "2026-02-15 14:56:00Z", resource: "res-node-116.corp.internal" },
    { id: "THRE-0117", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #117", severity: "HIGH", status: "CONTAINED", score: 86, timestamp: "2026-02-15 14:57:00Z", resource: "res-node-117.corp.internal" },
    { id: "THRE-0118", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #118", severity: "MEDIUM", status: "INVESTIGATING", score: 87, timestamp: "2026-02-15 14:58:00Z", resource: "res-node-118.corp.internal" },
    { id: "THRE-0119", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #119", severity: "LOW", status: "RESOLVED", score: 88, timestamp: "2026-02-15 14:59:00Z", resource: "res-node-119.corp.internal" },
    { id: "THRE-0120", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #120", severity: "CRITICAL", status: "ACTIVE", score: 89, timestamp: "2026-02-15 14:00:00Z", resource: "res-node-120.corp.internal" },
    { id: "THRE-0121", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #121", severity: "HIGH", status: "CONTAINED", score: 90, timestamp: "2026-02-15 14:01:00Z", resource: "res-node-121.corp.internal" },
    { id: "THRE-0122", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #122", severity: "MEDIUM", status: "INVESTIGATING", score: 91, timestamp: "2026-02-15 14:02:00Z", resource: "res-node-122.corp.internal" },
    { id: "THRE-0123", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #123", severity: "LOW", status: "RESOLVED", score: 92, timestamp: "2026-02-15 14:03:00Z", resource: "res-node-123.corp.internal" },
    { id: "THRE-0124", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #124", severity: "CRITICAL", status: "ACTIVE", score: 93, timestamp: "2026-02-15 14:04:00Z", resource: "res-node-124.corp.internal" },
    { id: "THRE-0125", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #125", severity: "HIGH", status: "CONTAINED", score: 94, timestamp: "2026-02-15 14:05:00Z", resource: "res-node-125.corp.internal" },
    { id: "THRE-0126", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #126", severity: "MEDIUM", status: "INVESTIGATING", score: 95, timestamp: "2026-02-15 14:06:00Z", resource: "res-node-126.corp.internal" },
    { id: "THRE-0127", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #127", severity: "LOW", status: "RESOLVED", score: 96, timestamp: "2026-02-15 14:07:00Z", resource: "res-node-127.corp.internal" },
    { id: "THRE-0128", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #128", severity: "CRITICAL", status: "ACTIVE", score: 65, timestamp: "2026-02-15 14:08:00Z", resource: "res-node-128.corp.internal" },
    { id: "THRE-0129", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #129", severity: "HIGH", status: "CONTAINED", score: 66, timestamp: "2026-02-15 14:09:00Z", resource: "res-node-129.corp.internal" },
    { id: "THRE-0130", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #130", severity: "MEDIUM", status: "INVESTIGATING", score: 67, timestamp: "2026-02-15 14:10:00Z", resource: "res-node-130.corp.internal" },
    { id: "THRE-0131", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #131", severity: "LOW", status: "RESOLVED", score: 68, timestamp: "2026-02-15 14:11:00Z", resource: "res-node-131.corp.internal" },
    { id: "THRE-0132", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #132", severity: "CRITICAL", status: "ACTIVE", score: 69, timestamp: "2026-02-15 14:12:00Z", resource: "res-node-132.corp.internal" },
    { id: "THRE-0133", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #133", severity: "HIGH", status: "CONTAINED", score: 70, timestamp: "2026-02-15 14:13:00Z", resource: "res-node-133.corp.internal" },
    { id: "THRE-0134", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #134", severity: "MEDIUM", status: "INVESTIGATING", score: 71, timestamp: "2026-02-15 14:14:00Z", resource: "res-node-134.corp.internal" },
    { id: "THRE-0135", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #135", severity: "LOW", status: "RESOLVED", score: 72, timestamp: "2026-02-15 14:15:00Z", resource: "res-node-135.corp.internal" },
    { id: "THRE-0136", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #136", severity: "CRITICAL", status: "ACTIVE", score: 73, timestamp: "2026-02-15 14:16:00Z", resource: "res-node-136.corp.internal" },
    { id: "THRE-0137", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #137", severity: "HIGH", status: "CONTAINED", score: 74, timestamp: "2026-02-15 14:17:00Z", resource: "res-node-137.corp.internal" },
    { id: "THRE-0138", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #138", severity: "MEDIUM", status: "INVESTIGATING", score: 75, timestamp: "2026-02-15 14:18:00Z", resource: "res-node-138.corp.internal" },
    { id: "THRE-0139", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #139", severity: "LOW", status: "RESOLVED", score: 76, timestamp: "2026-02-15 14:19:00Z", resource: "res-node-139.corp.internal" },
    { id: "THRE-0140", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #140", severity: "CRITICAL", status: "ACTIVE", score: 77, timestamp: "2026-02-15 14:20:00Z", resource: "res-node-140.corp.internal" },
    { id: "THRE-0141", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #141", severity: "HIGH", status: "CONTAINED", score: 78, timestamp: "2026-02-15 14:21:00Z", resource: "res-node-141.corp.internal" },
    { id: "THRE-0142", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #142", severity: "MEDIUM", status: "INVESTIGATING", score: 79, timestamp: "2026-02-15 14:22:00Z", resource: "res-node-142.corp.internal" },
    { id: "THRE-0143", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #143", severity: "LOW", status: "RESOLVED", score: 80, timestamp: "2026-02-15 14:23:00Z", resource: "res-node-143.corp.internal" },
    { id: "THRE-0144", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #144", severity: "CRITICAL", status: "ACTIVE", score: 81, timestamp: "2026-02-15 14:24:00Z", resource: "res-node-144.corp.internal" },
    { id: "THRE-0145", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #145", severity: "HIGH", status: "CONTAINED", score: 82, timestamp: "2026-02-15 14:25:00Z", resource: "res-node-145.corp.internal" },
    { id: "THRE-0146", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #146", severity: "MEDIUM", status: "INVESTIGATING", score: 83, timestamp: "2026-02-15 14:26:00Z", resource: "res-node-146.corp.internal" },
    { id: "THRE-0147", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #147", severity: "LOW", status: "RESOLVED", score: 84, timestamp: "2026-02-15 14:27:00Z", resource: "res-node-147.corp.internal" },
    { id: "THRE-0148", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #148", severity: "CRITICAL", status: "ACTIVE", score: 85, timestamp: "2026-02-15 14:28:00Z", resource: "res-node-148.corp.internal" },
    { id: "THRE-0149", name: "Enterprise Attack Path Graph & Lateral Traversal Studio Item #149", severity: "HIGH", status: "CONTAINED", score: 86, timestamp: "2026-02-15 14:29:00Z", resource: "res-node-149.corp.internal" },
  ];

  return (
    <div className="page-container" style={{ maxWidth: "1280px", margin: "0 auto", padding: "24px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={ color: "var(--cyan)" }>🕸️</span> Enterprise Attack Path Graph & Lateral Traversal Studio
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "13px", margin: "4px 0 0 0" }}>
            Real-time telemetry, automated analysis, and continuous monitoring console for Enterprise Attack Path Graph & Lateral Traversal Studio.
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
