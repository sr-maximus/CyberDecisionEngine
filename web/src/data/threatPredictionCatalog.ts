export interface PredictionModeDefinition {
  id: string;
  label: string;
  technique: string;
  keywords: string[];
  decision: string;
  baseWeight: number;
}

export const predictionModes: PredictionModeDefinition[] = [
  {
    id: "credential_targeting",
    label: "Credential targeting / phishing",
    technique: "T1566 Phishing",
    keywords: ["phishing", "smishing", "vishing", "credential", "login", "account", "password", "fraud"],
    decision: "Prioritize anti-phishing, brand takedown, MFA resistance and customer communications.",
    baseWeight: 0.22
  },
  {
    id: "public_app_exploit",
    label: "Public application exploitation",
    technique: "T1190 Exploit Public-Facing Application",
    keywords: ["cve", "kev", "exploit", "vulnerability", "patch", "rce", "authentication bypass"],
    decision: "Prioritize exposed asset validation, KEV patching, WAF rules and exploit telemetry.",
    baseWeight: 0.21
  },
  {
    id: "ransomware_extortion",
    label: "Ransomware / extortion pressure",
    technique: "T1486 Data Encrypted for Impact",
    keywords: ["ransomware", "encrypt", "extortion", "leak site", "darkweb", "onion", "ransom"],
    decision: "Validate backup restore, segmentation, EDR coverage, crisis comms and extortion monitoring.",
    baseWeight: 0.18
  },
  {
    id: "data_exposure",
    label: "Data exposure / leak narrative",
    technique: "T1530 Data from Cloud Storage",
    keywords: ["leak", "data breach", "filtration", "filtracion", "privacy", "personal data", "dump"],
    decision: "Validate data exposure evidence, legal notification path and takedown workflow.",
    baseWeight: 0.14
  },
  {
    id: "brand_abuse",
    label: "Brand abuse / impersonation",
    technique: "T1589 Gather Victim Identity Information",
    keywords: ["impersonation", "suplantacion", "brand", "fake", "scam", "fraude", "clon"],
    decision: "Increase brand monitoring, takedown SLAs and fraud operations coordination.",
    baseWeight: 0.13
  },
  {
    id: "supply_chain_ai",
    label: "Supply chain or AI-enabled abuse",
    technique: "T1195 Supply Chain Compromise",
    keywords: ["supply chain", "dependency", "github", "ai", "llm", "model", "agent", "prompt"],
    decision: "Review third-party exposure, SBOM/SCA, AI governance and high-risk integrations.",
    baseWeight: 0.12
  }
];

export const sectorPredictionWeights: Record<string, number> = {
  financial: 0.88,
  banking: 0.88,
  fintech: 0.84,
  multi_sector: 0.82,
  multi_sector_financial_holding: 0.88,
  energy: 0.76,
  healthcare: 0.74,
  government: 0.72,
  technology: 0.70,
  retail: 0.66,
  education: 0.58,
  default: 0.55
};

export const predictionModelWeights = {
  baselineDailyLambda: 0.018,
  previousDailyLambda: 0.025,
  alpha: 0.65,
  frequency: 0.18,
  recency: 0.16,
  kev: 0.18,
  sector: 0.14,
  socmint: 0.1,
  darkweb: 0.12,
  riskHeat: 0.16,
  controlGap: 0.08
};
