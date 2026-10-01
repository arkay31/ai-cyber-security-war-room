
export interface Incident {
  id: string;
  attack: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  sourceIp: string;
  target: string;
  technique: string;
  timestamp: string;
  status: "Investigating" | "Contained" | "Resolved";
}

export const mockIncidents: Incident[] = [
  {
    id: "INC-001",
    attack: "Brute Force Attack",
    severity: "CRITICAL",
    confidence: 96,
    sourceIp: "192.168.1.25",
    target: "Admin Server",
    technique: "T1110",
    timestamp: "12:04 PM",
    status: "Investigating",
  },
  {
    id: "INC-002",
    attack: "Port Scanning",
    severity: "HIGH",
    confidence: 91,
    sourceIp: "10.24.8.91",
    target: "Web Server",
    technique: "T1046",
    timestamp: "11:58 AM",
    status: "Investigating",
  },
  {
    id: "INC-003",
    attack: "Unusual Login",
    severity: "HIGH",
    confidence: 88,
    sourceIp: "172.16.2.44",
    target: "Database Server",
    technique: "T1078",
    timestamp: "11:43 AM",
    status: "Contained",
  },
  {
    id: "INC-004",
    attack: "Web Attack",
    severity: "MEDIUM",
    confidence: 79,
    sourceIp: "45.12.87.20",
    target: "API Gateway",
    technique: "T1190",
    timestamp: "11:21 AM",
    status: "Resolved",
  },
];