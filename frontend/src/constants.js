// Status definitions used across multiple components
export const STATUSES = {
  pending:  { label: "Pending",  color: "#f59e0b", bg: "rgba(245,158,11,0.1)",   border: "rgba(245,158,11,0.3)"   },
  tp:       { label: "True Positive",  color: "#f43f5e", bg: "rgba(244,63,94,0.1)",  border: "rgba(244,63,94,0.3)"   },
  fp:       { label: "False Positive", color: "#10b981", bg: "rgba(16,185,129,0.1)", border: "rgba(16,185,129,0.3)"  },
  unclear:  { label: "Unclear",  color: "#94a3b8", bg: "rgba(148,163,184,0.1)",  border: "rgba(148,163,184,0.3)"  },
};

export function severityColor(severity) {
  const s = (severity || "").toLowerCase();
  if (s === "critical") return "#f43f5e";
  if (s === "high")     return "#fb923c";
  if (s === "medium")   return "#f59e0b";
  if (s === "low")      return "#10b981";
  return "#94a3b8";
}

export const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"];
export const SEVERITY = SEVERITY_OPTIONS; // Alias for backward compatibility

export const CATEGORY_OPTIONS = [
  "Malware / Endpoint",
  "Cloud / IAM",
  "Phishing / Email",
  "Unauthorized Access",
  "Network Anomaly",
  "Data Exfiltration",
  "Ransomware",
  "Privilege Escalation",
  "Lateral Movement",
  "Other",
];
export const CATEGORIES = CATEGORY_OPTIONS; // Alias for backward compatibility

export const PROVIDERS = [
  { id: "openai", label: "OpenAI", model: "gpt-4o-mini" },
  { id: "anthropic", label: "Anthropic", model: "claude-3-5-haiku-20241022" },
  { id: "ollama", label: "Ollama", model: "llama3.2" },
  { id: "openai_compatible", label: "OpenAI-Compatible", model: "custom-model" },
];
