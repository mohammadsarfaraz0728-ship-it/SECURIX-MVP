import { Router, type IRouter } from "express";

type Classification = "MALICIOUS" | "SUSPICIOUS" | "SAFE";

type ForensicCase = {
  id: number;
  caseNumber: string;
  emailId: number;
  classification: Classification;
  riskScore: number;
  threatType: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  summary: string;
};

type ThreatEvidence = {
  id: number;
  evidenceId: string;
  caseId: string;
  year: string;
  evidenceType: string;
  evidenceValue: string;
  relatedThreat: string;
  location: string;
  forensicUse: string;
};

type CaseTimeline = {
  id: number;
  caseId: number;
  eventTime: string;
  eventType: string;
  description: string;
  severity: string;
};

type EmailRecord = {
  id: number;
  sender: string;
  recipient: string;
  subject: string;
  body: string;
};

const now = new Date();
const hoursAgo = (hours: number) =>
  new Date(now.getTime() - hours * 60 * 60 * 1000).toISOString();

const emails: EmailRecord[] = [
  {
    id: 101,
    sender: "billing@paypa1-alerts.com",
    recipient: "analyst@northstar.io",
    subject: "Urgent account verification required",
    body: "Your account will be suspended. Verify now at https://paypa1-alerts.com/verify from 185.44.18.9.",
  },
  {
    id: 102,
    sender: "updates@github.com",
    recipient: "analyst@northstar.io",
    subject: "Your weekly security summary",
    body: "Your weekly security report is ready in the GitHub dashboard.",
  },
  {
    id: 103,
    sender: "finance@vendor-corp.co",
    recipient: "analyst@northstar.io",
    subject: "Updated wire instructions",
    body: "Please review the attached invoice and reply with confirmation.",
  },
];

const cases: ForensicCase[] = [
  {
    id: 1,
    caseNumber: "SEC-2026-0142",
    emailId: 101,
    classification: "MALICIOUS",
    riskScore: 94,
    threatType: "Credential phishing",
    status: "OPEN",
    createdAt: hoursAgo(2),
    updatedAt: hoursAgo(1),
    summary: "Credential-harvesting campaign impersonating a payment provider.",
  },
  {
    id: 2,
    caseNumber: "SEC-2026-0141",
    emailId: 103,
    classification: "SUSPICIOUS",
    riskScore: 63,
    threatType: "Business email compromise",
    status: "INVESTIGATING",
    createdAt: hoursAgo(7),
    updatedAt: hoursAgo(4),
    summary: "Unusual payment instruction change from a known vendor contact.",
  },
  {
    id: 3,
    caseNumber: "SEC-2026-0139",
    emailId: 102,
    classification: "SAFE",
    riskScore: 8,
    threatType: "Routine notification",
    status: "CLOSED",
    createdAt: hoursAgo(22),
    updatedAt: hoursAgo(18),
    summary: "Legitimate weekly security digest with no actionable indicators.",
  },
];

const evidence: ThreatEvidence[] = [
  {
    id: 1,
    evidenceId: "EVD-7F31A",
    caseId: "SEC-2026-0142",
    year: "2026",
    evidenceType: "DOMAIN",
    evidenceValue: "paypa1-alerts.com",
    relatedThreat: "Credential phishing",
    location: "Email body",
    forensicUse: "Lookalike payment provider domain",
  },
  {
    id: 2,
    evidenceId: "EVD-2B08C",
    caseId: "SEC-2026-0142",
    year: "2026",
    evidenceType: "IP_ADDRESS",
    evidenceValue: "185.44.18.9",
    relatedThreat: "Credential phishing",
    location: "URL host",
    forensicUse: "Known hostile infrastructure",
  },
  {
    id: 3,
    evidenceId: "EVD-91C10",
    caseId: "SEC-2026-0141",
    year: "2026",
    evidenceType: "SENDER",
    evidenceValue: "finance@vendor-corp.co",
    relatedThreat: "Business email compromise",
    location: "From header",
    forensicUse: "Unexpected sender identity",
  },
];

const timelines: CaseTimeline[] = [
  {
    id: 1,
    caseId: 1,
    eventTime: hoursAgo(2),
    eventType: "EMAIL_RECEIVED",
    description: "Email received by SECURIX for forensic analysis.",
    severity: "INFO",
  },
  {
    id: 2,
    caseId: 1,
    eventTime: hoursAgo(1.8),
    eventType: "EVIDENCE_MATCH",
    description: "2 forensic evidence records matched.",
    severity: "HIGH",
  },
  {
    id: 3,
    caseId: 1,
    eventTime: hoursAgo(1),
    eventType: "RISK_ASSESSMENT",
    description: "SECURIX calculated a final risk score of 94/100.",
    severity: "HIGH",
  },
  {
    id: 4,
    caseId: 2,
    eventTime: hoursAgo(7),
    eventType: "EMAIL_RECEIVED",
    description: "Email received by SECURIX for forensic analysis.",
    severity: "INFO",
  },
];

const nextId = (items: { id: number }[]) =>
  Math.max(0, ...items.map((item) => item.id)) + 1;

const extract = (body: string, pattern: RegExp) =>
  Array.from(new Set(body.match(pattern) ?? []));

const emailForCase = (caseId: number) =>
  emails.find((email) => email.id === cases.find((item) => item.id === caseId)?.emailId);

function stats() {
  const averageRiskScore =
    cases.length === 0
      ? 0
      : Math.round((cases.reduce((sum, item) => sum + item.riskScore, 0) / cases.length) * 10) / 10;
  return {
    totalCases: cases.length,
    maliciousCases: cases.filter((item) => item.classification === "MALICIOUS").length,
    suspiciousCases: cases.filter((item) => item.classification === "SUSPICIOUS").length,
    safeCases: cases.filter((item) => item.classification === "SAFE").length,
    openCases: cases.filter((item) => item.status !== "CLOSED").length,
    averageRiskScore,
  };
}

function classifyEmail(email: { sender: string; subject: string; body: string }) {
  const combined = `${email.sender} ${email.subject} ${email.body}`;
  const urls = extract(combined, /https?:\/\/[^\s)]+/gi);
  const domains = Array.from(
    new Set(
      extract(combined, /(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+\.)+[a-z]{2,}/gi).map((value) =>
        value.replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/[),.]+$/, ""),
      ),
    ),
  );
  const ipAddresses = extract(combined, /\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
  const emailAddresses = extract(combined, /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi);
  const signals = [
    /urgent|suspend|verify|wire|payment/i.test(combined),
    /https?:\/\//i.test(combined),
    /paypa1|micros0ft|githhub|credential/i.test(combined),
    ipAddresses.length > 0,
  ].filter(Boolean).length;
  const riskScore = Math.min(98, Math.max(5, 12 + signals * 22 + (domains.length > 0 ? 8 : 0)));
  const classification: Classification =
    riskScore >= 70 ? "MALICIOUS" : riskScore >= 35 ? "SUSPICIOUS" : "SAFE";
  const matchedEvidence = evidence.filter(
    (item) =>
      domains.some((domain) => item.evidenceValue.toLowerCase().includes(domain.toLowerCase())) ||
      ipAddresses.includes(item.evidenceValue) ||
      email.sender.toLowerCase() === item.evidenceValue.toLowerCase(),
  );
  return {
    classification,
    riskScore,
    explanation:
      classification === "MALICIOUS"
        ? "Multiple high-confidence indicators suggest an active phishing or malware delivery attempt."
        : classification === "SUSPICIOUS"
          ? "The message contains behavioral signals that warrant investigator review."
          : "No significant threat indicators were found in the submitted message.",
    urls,
    domains,
    ipAddresses,
    emailAddresses,
    geoLocations: ipAddresses.map((ipAddress) => ({
      ipAddress,
      country: "Unknown",
      state: "Unknown",
      city: "Unknown",
      isp: "Unresolved",
    })),
    matchedEvidence,
  };
}

const router: IRouter = Router();

router.get("/healthz", (_req, res) => {
  res.json({ status: "ok" });
});

router.post("/auth/login", (req, res) => {
  const { username, password } = req.body as { username?: string; password?: string };
  if (!username || !password) {
    res.status(400).json({ error: "Username and password are required." });
    return;
  }
  res.json({ token: `demo-token-${username}`, username, role: username.toLowerCase().includes("admin") ? "ADMIN" : "INVESTIGATOR" });
});

router.post("/auth/register", (req, res) => {
  const { username, role = "INVESTIGATOR" } = req.body as { username?: string; role?: string };
  if (!username) {
    res.status(400).json({ error: "Username is required." });
    return;
  }
  res.json({ id: Date.now(), username, role });
});

router.get("/dashboard/stats", (_req, res) => {
  res.json(stats());
});

router.get("/cases", (_req, res) => {
  res.json([...cases].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)));
});

router.get("/cases/:caseId/timeline", (req, res) => {
  const caseId = Number(req.params.caseId);
  res.json(timelines.filter((item) => item.caseId === caseId).sort((a, b) => a.eventTime.localeCompare(b.eventTime)));
});

router.post("/cases/:caseId/timeline", (req, res) => {
  const caseId = Number(req.params.caseId);
  const { eventType, description, severity } = req.body as { eventType?: string; description?: string; severity?: string };
  if (!eventType || !description || !severity) {
    res.status(400).json({ error: "eventType, description, and severity are required." });
    return;
  }
  const item: CaseTimeline = {
    id: nextId(timelines),
    caseId,
    eventTime: new Date().toISOString(),
    eventType,
    description,
    severity,
  };
  timelines.push(item);
  res.json(item);
});

router.get("/cases/:caseId/report", (req, res) => {
  const caseId = Number(req.params.caseId);
  const caseDetails = cases.find((item) => item.id === caseId);
  if (!caseDetails) {
    res.status(404).json({ error: "Case not found." });
    return;
  }
  res.json({
    caseDetails,
    email: emailForCase(caseId),
    evidence: evidence.filter((item) => item.caseId === caseDetails.caseNumber),
    timeline: timelines.filter((item) => item.caseId === caseId),
  });
});

router.get("/cases/:caseId/evidence", (req, res) => {
  const caseDetails = cases.find((item) => item.id === Number(req.params.caseId));
  res.json(evidence.filter((item) => item.caseId === caseDetails?.caseNumber));
});

router.get("/cases/:caseId", (req, res) => {
  const item = cases.find((candidate) => candidate.id === Number(req.params.caseId));
  if (!item) {
    res.status(404).json({ error: "Case not found." });
    return;
  }
  res.json(item);
});

router.get("/evidence", (_req, res) => {
  res.json(evidence);
});

router.post("/email/analyze", (req, res) => {
  const { sender, recipient, subject, body } = req.body as Partial<EmailRecord>;
  if (!sender || !recipient || !subject || !body) {
    res.status(400).json({ error: "sender, recipient, subject, and body are required." });
    return;
  }
  const email: EmailRecord = { id: nextId(emails), sender, recipient, subject, body };
  emails.push(email);
  const result = classifyEmail(email);
  const timestamp = new Date().toISOString();
  const newCase: ForensicCase = {
    id: nextId(cases),
    caseNumber: `SEC-${new Date().getFullYear()}-${String(140 + cases.length).padStart(4, "0")}`,
    emailId: email.id,
    classification: result.classification,
    riskScore: result.riskScore,
    threatType: result.classification === "MALICIOUS" ? "Credential phishing" : "Email threat analysis",
    status: "OPEN",
    createdAt: timestamp,
    updatedAt: timestamp,
    summary: result.explanation,
  };
  cases.push(newCase);
  timelines.push(
    {
      id: nextId(timelines),
      caseId: newCase.id,
      eventTime: timestamp,
      eventType: "EMAIL_RECEIVED",
      description: "Email received by SECURIX for forensic analysis.",
      severity: "INFO",
    },
    {
      id: nextId(timelines) + 1,
      caseId: newCase.id,
      eventTime: timestamp,
      eventType: "RISK_ASSESSMENT",
      description: `SECURIX calculated a final risk score of ${result.riskScore}/100.`,
      severity: result.riskScore >= 70 ? "HIGH" : result.riskScore >= 35 ? "MEDIUM" : "LOW",
    },
  );
  res.json({ emailId: email.id, ...result });
});

export default router;