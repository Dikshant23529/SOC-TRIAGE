const API = "/api";

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...options.headers };
  
  // Attach JWT token if stored
  const token = localStorage.getItem("soc_token");
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API}${path}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    // Session expired or unauthorized, clear token and refresh or let the app handle it
    localStorage.removeItem("soc_token");
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || res.statusText || "Request failed");
  }
  
  if (res.status === 204) return null;
  return res.json();
}

async function downloadFile(path, filename) {
  const headers = {};
  const token = localStorage.getItem("soc_token");
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  
  const res = await fetch(`${API}${path}`, { headers });
  if (res.status === 401) {
    localStorage.removeItem("soc_token");
    window.location.reload();
    throw new Error("Session expired. Please log in again.");
  }
  
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || res.statusText || "Download failed");
  }
  
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export const api = {
  // Token handlers
  setToken: (token) => localStorage.setItem("soc_token", token),
  getToken: () => localStorage.getItem("soc_token"),
  clearToken: () => localStorage.removeItem("soc_token"),

  // Auth endpoints
  checkAuthStatus: () => request("/auth/status"),
  register: (body) => request("/auth/register", { method: "POST", body: JSON.stringify(body) }),
  login: (body) => request("/auth/login", { method: "POST", body: JSON.stringify(body) }),
  verifyMfa: (body) => request("/auth/verify-mfa", { method: "POST", body: JSON.stringify(body) }),
  setupMfa: () => request("/auth/setup-mfa", { method: "POST" }),
  enableMfa: (body) => request("/auth/enable-mfa", { method: "POST", body: JSON.stringify(body) }),
  disableMfa: () => request("/auth/disable-mfa", { method: "POST" }),
  getMe: () => request("/auth/me"),

  // Core endpoints
  health: () => request("/health"),
  listAlerts: (params = {}) => {
    const qs = new URLSearchParams();
    if (params.q) qs.set("q", params.q);
    if (params.status) qs.set("status", params.status);
    if (params.resolved !== undefined) qs.set("resolved", params.resolved);
    if (params.tag) qs.set("tag", params.tag);
    if (params.severity) qs.set("severity", params.severity);
    if (params.category) qs.set("category", params.category);
    const qstring = qs.toString();
    return request(`/alerts${qstring ? `?${qstring}` : ""}`);
  },
  getAlert: (id) => request(`/alerts/${id}`),
  createAlert: (body) => request("/alerts", { method: "POST", body: JSON.stringify(body) }),
  updateAlert: (id, body) => request(`/alerts/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteAlert: (id) => request(`/alerts/${id}`, { method: "DELETE" }),
  investigate: (id) => request(`/alerts/${id}/investigate`, { method: "POST" }),
  listInvestigations: (alertId) => request(`/alerts/${alertId}/investigations`),
  getInvestigation: (id) => request(`/investigations/${id}`),
  getSettings: () => request("/settings"),
  updateSettings: (body) => request("/settings", { method: "PUT", body: JSON.stringify(body) }),
  testKey: () => request("/settings/test-key", { method: "POST" }),

  // Similarity & matching
  getMatches: (alertId) => request(`/alerts/${alertId}/matches`),
  getLikelihood: (alertId) => request(`/alerts/${alertId}/likelihood`),

  // Exports
  exportAllCSV: () => downloadFile("/alerts/export/csv", "all_alerts.csv"),
  exportSingleCSV: (alertId, code) => downloadFile(`/alerts/${alertId}/export/csv`, `alert_${code}.csv`),
  exportReportPDF: (alertId, code) => downloadFile(`/alerts/${alertId}/export/pdf`, `investigation_report_${code}.pdf`),
};
