import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import AgentPanel from "./components/AgentPanel";
import AuthModal from "./components/AuthModal";
import TraceGraph from "./components/TraceGraph";
import ValidationFramework from "./components/ValidationFramework";
import { CATEGORIES, PROVIDERS, SEVERITY, STATUSES, severityColor } from "./constants";

const emptyForm = () => ({
  title: "",
  severity: "High",
  category: "",
  source: "",
  timestamp: new Date().toISOString().slice(0, 16),
  affected_asset: "",
  affected_user: "",
  owner_team: "",
  owner_email: "",
  description: "",
  ioc_list: "",
  raw_log: "",
  process_tree: "",
  timeline_logs: "",
  status: "pending",
  notes: "",
});

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!api.getToken());
  const [currentUser, setCurrentUser] = useState(null);
  const [view, setView] = useState("new");
  const [alerts, setAlerts] = useState([]);
  const [form, setForm] = useState(emptyForm);
  const [active, setActive] = useState(null);
  const [investigation, setInvestigation] = useState(null);
  const [settings, setSettings] = useState(null);
  const [settingsForm, setSettingsForm] = useState({ ai_enabled: false, ai_provider: "openai", ai_model: "gpt-4o-mini", api_base_url: "", api_key: "" });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filterStatus, setFilterStatus] = useState("all");
  const [testResult, setTestResult] = useState(null);
  const [autoInvestigate, setAutoInvestigate] = useState(true);

  // Tab views inside alert detail
  const [detailTab, setDetailTab] = useState("overview"); // 'overview' | 'trace' | 'similarity' | 'validation'
  const [similarMatches, setSimilarMatches] = useState([]);
  const [validationAnswers, setValidationAnswers] = useState({});

  // MFA settings states
  const [mfaSetupData, setMfaSetupData] = useState(null);
  const [mfaVerifyCode, setMfaVerifyCode] = useState("");

  const load = useCallback(async () => {
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }
    try {
      setError(null);
      const [a, s, me] = await Promise.all([api.listAlerts(), api.getSettings(), api.getMe()]);
      setAlerts(a);
      setSettings(s);
      setCurrentUser(me);
      setSettingsForm((f) => ({
        ...f,
        ai_enabled: s.ai_enabled,
        ai_provider: s.ai_provider,
        ai_model: s.ai_model,
        api_base_url: s.api_base_url || "",
      }));
    } catch (e) {
      setError(e.message);
      if (e.message.includes("401") || e.message.includes("credentials") || e.message.includes("expired")) {
        api.clearToken();
        setIsAuthenticated(false);
      }
    } finally {
      setLoading(false);
    }
  }, [isAuthenticated]);

  useEffect(() => { load(); }, [load]);

  const handleLogout = () => {
    api.clearToken();
    setIsAuthenticated(false);
    setCurrentUser(null);
    setAlerts([]);
  };

  const setField = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  const submitAlert = async () => {
    if (!form.title || !form.category || !form.affected_asset) {
      alert("Fill in Title, Category, and Affected Asset.");
      return;
    }
    try {
      const created = await api.createAlert(form);
      setAlerts((list) => [created, ...list]);
      setForm(emptyForm());
      openAlert(created);
      if (autoInvestigate) {
        const inv = await api.investigate(created.id);
        setInvestigation(inv);
      }
    } catch (e) {
      alert(e.message);
    }
  };

  const openAlert = async (al) => {
    setActive(al);
    setView("detail");
    setDetailTab("overview");
    setInvestigation(null);
    setSimilarMatches([]);
    try {
      const [invs, matches] = await Promise.all([
        api.listInvestigations(al.id),
        api.getMatches(al.id)
      ]);
      if (invs[0]) setInvestigation(invs[0]);
      setSimilarMatches(matches);
    } catch { /* noop */ }
  };

  const runInvestigation = async () => {
    if (!active) return;
    try {
      const inv = await api.investigate(active.id);
      setInvestigation(inv);
    } catch (e) {
      alert(e.message);
    }
  };

  const saveSettings = async () => {
    const body = {
      ai_enabled: settingsForm.ai_enabled,
      ai_provider: settingsForm.ai_provider,
      ai_model: settingsForm.ai_model,
      api_base_url: settingsForm.api_base_url || null,
    };
    if (settingsForm.api_key) body.api_key = settingsForm.api_key;
    const s = await api.updateSettings(body);
    setSettings(s);
    setSettingsForm((f) => ({ ...f, api_key: "" }));
    setTestResult(null);
  };

  // Setup MFA flow inside Settings
  const handleSetupMfa = async () => {
    try {
      const res = await api.setupMfa();
      setMfaSetupData(res);
    } catch (e) {
      alert("Failed to start MFA setup: " + e.message);
    }
  };

  const handleEnableMfa = async () => {
    try {
      await api.enableMfa({ code: mfaVerifyCode });
      alert("MFA enabled successfully!");
      setMfaSetupData(null);
      setMfaVerifyCode("");
      const me = await api.getMe();
      setCurrentUser(me);
    } catch (e) {
      alert("Failed to verify MFA: " + e.message);
    }
  };

  const handleDisableMfa = async () => {
    if (!confirm("Are you sure you want to disable MFA?")) return;
    try {
      await api.disableMfa();
      alert("MFA disabled successfully!");
      const me = await api.getMe();
      setCurrentUser(me);
    } catch (e) {
      alert("Failed to disable MFA: " + e.message);
    }
  };

  const filtered = filterStatus === "all" ? alerts : alerts.filter((a) => a.status === filterStatus);
  const statCounts = Object.fromEntries(
    Object.keys(STATUSES).map((s) => [s, alerts.filter((a) => a.status === s).length])
  );

  const shareText = active ? buildShareText(active) : "";

  if (!isAuthenticated) {
    return <AuthModal onAuthSuccess={(token) => {
      api.setToken(token);
      setIsAuthenticated(true);
      setLoading(true);
    }} />;
  }

  if (loading) {
    return <div className="app-shell" style={{ padding: 48, textAlign: "center", color: "#64748b" }}>Connecting to SOC Triage API…</div>;
  }

  return (
    <div className="app-shell">
      <header className="header">
        <div className="brand">
          <span className="brand-dot" />
          <span className="brand-title">SOC TRIAGE</span>
        </div>
        <nav className="nav" style={{ flex: 1 }}>
          {[["new", "+ New Alert"], ["list", `Alerts (${alerts.length})`], ["stats", "Dashboard"], ["settings", "Settings"]].map(([v, l]) => (
            <button key={v} type="button" className={`nav-btn${view === v ? " active" : ""}`} onClick={() => setView(v)}>{l}</button>
          ))}
        </nav>
        {currentUser && (
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 10, color: "#64748b" }}>
              ANALYST: <strong style={{ color: "#e2e8f0" }}>{currentUser.username.toUpperCase()}</strong>
            </span>
            <button
              type="button"
              style={{
                background: "none",
                border: "1px solid #7f1d1d",
                color: "#fca5a5",
                padding: "4px 8px",
                borderRadius: 3,
                fontSize: 9,
                cursor: "pointer",
                fontFamily: "inherit",
                textTransform: "uppercase",
                fontWeight: 700
              }}
              onClick={handleLogout}
            >
              Logout
            </button>
          </div>
        )}
      </header>

      <main className="main">
        {error && (
          <div className="banner-warn">API unreachable: {error}. Start backend with <code>uvicorn app.main:app --reload</code> or Docker.</div>
        )}

        {/* Dynamic Connection Indicator */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20, flexWrap: "wrap", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 12px", backgroundColor: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 4, fontSize: 10 }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", backgroundColor: settings?.ai_enabled ? "#10b981" : "#64748b", boxShadow: settings?.ai_enabled ? "0 0 6px #10b981" : "none" }} />
            <span style={{ color: "#cbd5e1" }}>AI Agent Status: <strong>{settings?.ai_enabled ? `${settings.ai_provider.toUpperCase()} (${settings.ai_model})` : "Disabled (Rule Engine Running)"}</strong></span>
          </div>
          {investigation?.status === "running" && (
            <div style={{ fontSize: 10, color: "#38bdf8", animation: "pulse 2s infinite" }}>
              ● Agent working on {active?.alert_id}...
            </div>
          )}
        </div>

        {view === "new" && (
          <>
            <h1 className="page-title">Log New Alert</h1>
            <p className="subtitle">Phase 1 — paste process tree, timeline logs, and evidence. Investigations run in parallel agents (rule-based until you enable AI in Settings).</p>
            <label style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16, fontSize: 12, color: "#94a3b8" }}>
              <input type="checkbox" checked={autoInvestigate} onChange={(e) => setAutoInvestigate(e.target.checked)} />
              Launch investigation agent automatically after save
            </label>

            <div className="grid-2">
              <div>
                <label className="field-label">Severity</label>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {SEVERITY.map((s) => (
                    <button
                      key={s}
                      type="button"
                      style={{
                        border: `1px solid ${severityColor(s)}`,
                        color: form.severity === s ? "#000" : severityColor(s),
                        background: form.severity === s ? severityColor(s) : "transparent",
                        borderRadius: 3, padding: "5px 12px", fontSize: 11, fontWeight: 700, cursor: "pointer", fontFamily: "inherit",
                      }}
                      onClick={() => setField("severity", s)}
                    >{s}</button>
                  ))}
                </div>
              </div>
              <div>
                <label className="field-label">Alert Timestamp</label>
                <input className="field-input" type="datetime-local" value={form.timestamp} onChange={(e) => setField("timestamp", e.target.value)} />
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label className="field-label">Alert Title *</label>
              <input className="field-input" placeholder="Suspicious PowerShell on WKST-042" value={form.title} onChange={(e) => setField("title", e.target.value)} />
            </div>

            <div className="grid-2">
              <div>
                <label className="field-label">Category *</label>
                <select className="field-input" value={form.category} onChange={(e) => setField("category", e.target.value)}>
                  <option value="">Select category…</option>
                  {CATEGORIES.map((c) => <option key={c}>{c}</option>)}
                </select>
              </div>
              <div>
                <label className="field-label">Detection Source</label>
                <input className="field-input" placeholder="Splunk, Defender, CrowdStrike" value={form.source} onChange={(e) => setField("source", e.target.value)} />
              </div>
            </div>

            <div className="grid-2">
              <div>
                <label className="field-label">Affected Asset / Host *</label>
                <input className="field-input" value={form.affected_asset} onChange={(e) => setField("affected_asset", e.target.value)} />
              </div>
              <div>
                <label className="field-label">Affected User</label>
                <input className="field-input" value={form.affected_user} onChange={(e) => setField("affected_user", e.target.value)} />
              </div>
            </div>

            <div className="grid-2">
              <div>
                <label className="field-label">Owner Team</label>
                <input className="field-input" value={form.owner_team} onChange={(e) => setField("owner_team", e.target.value)} />
              </div>
              <div>
                <label className="field-label">Owner Email</label>
                <input className="field-input" value={form.owner_email} onChange={(e) => setField("owner_email", e.target.value)} />
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label className="field-label">Description</label>
              <textarea className="field-input" rows={3} value={form.description} onChange={(e) => setField("description", e.target.value)} />
            </div>

            <div style={{ marginBottom: 16 }}>
              <label className="field-label">Process Tree (paste EDR / Sysmon lineage)</label>
              <textarea className="field-input" rows={5} placeholder="explorer.exe → cmd.exe → powershell.exe -enc ..." value={form.process_tree} onChange={(e) => setField("process_tree", e.target.value)} />
            </div>

            <div style={{ marginBottom: 16 }}>
              <label className="field-label">Timeline Logs (chronological SIEM / EDR events)</label>
              <textarea className="field-input" rows={5} placeholder="2024-01-15T10:01:00Z | ProcessCreate | powershell.exe" value={form.timeline_logs} onChange={(e) => setField("timeline_logs", e.target.value)} />
            </div>

            <div style={{ marginBottom: 16 }}>
              <label className="field-label">IOCs</label>
              <textarea className="field-input" rows={2} value={form.ioc_list} onChange={(e) => setField("ioc_list", e.target.value)} />
            </div>

            <div style={{ marginBottom: 20 }}>
              <label className="field-label">Raw Log Snippet</label>
              <textarea className="field-input" rows={3} value={form.raw_log} onChange={(e) => setField("raw_log", e.target.value)} />
            </div>

            <button type="button" className="btn-primary" onClick={submitAlert}>Save Alert &amp; Start Triage</button>
          </>
        )}

        {view === "list" && (
          <>
            <h1 className="page-title">Alert Queue</h1>
            <p className="subtitle">Each alert can run an independent investigation agent in parallel.</p>
            
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20, flexWrap: "wrap", gap: 12 }}>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {["all", ...Object.keys(STATUSES)].map((s) => (
                  <button key={s} type="button" className="nav-btn" style={{ color: filterStatus === s ? "#38bdf8" : "#475569" }} onClick={() => setFilterStatus(s)}>
                    {s === "all" ? "All" : STATUSES[s].label}
                  </button>
                ))}
              </div>
              <button type="button" className="btn-secondary" style={{ padding: "6px 12px", fontSize: 10 }} onClick={() => api.exportAllCSV()}>
                Export All Alerts (CSV)
              </button>
            </div>

            {filtered.map((al) => (
              <div key={al.id} className="alert-card" onClick={() => openAlert(al)}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                  <div>
                    <div style={{ fontSize: 10, color: "#475569", marginBottom: 4 }}>{al.alert_id}</div>
                    <div style={{ fontWeight: 600, color: "#e2e8f0" }}>{al.title}</div>
                    <div style={{ fontSize: 11, color: "#64748b", marginTop: 6 }}>{al.affected_asset} · {al.category}</div>
                  </div>
                  <span className="pill" style={{ background: STATUSES[al.status]?.bg, color: STATUSES[al.status]?.color }}>{STATUSES[al.status]?.label}</span>
                </div>
              </div>
            ))}
            {filtered.length === 0 && <p style={{ color: "#475569", fontSize: 13 }}>No alerts yet.</p>}
          </>
        )}

        {view === "detail" && active && (
          <>
            <button type="button" className="nav-btn" style={{ marginBottom: 16 }} onClick={() => setView("list")}>← Back</button>
            <h1 className="page-title">{active.title}</h1>
            <p className="subtitle">{active.alert_id} · {active.severity} · {active.affected_asset}</p>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {Object.entries(STATUSES).map(([k, v]) => (
                  <button
                    key={k}
                    type="button"
                    className="btn-secondary"
                    style={{ opacity: active.status === k ? 1 : 0.6 }}
                    onClick={async () => {
                      const updated = await api.updateAlert(active.id, { status: k });
                      setActive(updated);
                      setAlerts((list) => list.map((a) => (a.id === updated.id ? updated : a)));
                    }}
                  >{v.label}</button>
                ))}
                <button type="button" className="btn-primary" onClick={runInvestigation}>Run / Re-run Agent</button>
              </div>

              {/* Exports Actions */}
              <div style={{ display: "flex", gap: 8 }}>
                <button type="button" className="btn-secondary" onClick={() => api.exportReportPDF(active.id, active.alert_id)}>
                  Download PDF Report
                </button>
                <button type="button" className="btn-secondary" onClick={() => api.exportSingleCSV(active.id, active.alert_id)}>
                  Export Alert CSV
                </button>
              </div>
            </div>

            {/* Premium Multi-Tab System */}
            <div style={{ display: "flex", borderBottom: "1px solid #1e3a5f", marginBottom: 16 }}>
              {["overview", "validation", "trace", "similarity"].map((tab) => (
                <button
                  key={tab}
                  type="button"
                  style={{
                    background: "none",
                    border: "none",
                    borderBottom: detailTab === tab ? "2px solid #38bdf8" : "2px solid transparent",
                    color: detailTab === tab ? "#38bdf8" : "#64748b",
                    padding: "8px 16px",
                    cursor: "pointer",
                    fontSize: 11,
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.05em",
                    fontFamily: "inherit"
                  }}
                  onClick={() => setDetailTab(tab)}
                >
                  {tab === "overview" && "Overview & Agent"}
                  {tab === "validation" && "Validation Checklist"}
                  {tab === "trace" && "OTel Graph & Logs"}
                  {tab === "similarity" && `DB Similar Matches (${similarMatches.length})`}
                </button>
              ))}
            </div>

            {detailTab === "overview" && (
              <>
                <AgentPanel investigation={investigation} onUpdate={setInvestigation} />

                <div style={{ marginTop: 24 }}>
                  <label className="field-label">Owner validation message</label>
                  <textarea className="field-input" rows={12} readOnly value={shareText} />
                  <button type="button" className="btn-secondary" style={{ marginTop: 8 }} onClick={() => navigator.clipboard.writeText(shareText)}>Copy validation request</button>
                </div>
              </>
            )}

            {detailTab === "validation" && (
              <ValidationFramework 
                alert={active}
                answers={validationAnswers}
                onAnswersChange={setValidationAnswers}
                onSaveValidation={async (data) => {
                  try {
                    const updates = { 
                      validation_json: JSON.stringify({ answers: data.answers, notes: data.notes })
                    };
                    // If outcome is provided, update the alert status
                    if (data.outcome) {
                      updates.status = data.outcome;
                    }
                    const updated = await api.updateAlert(active.id, updates);
                    setActive(updated);
                    setAlerts(list => list.map(a => a.id === updated.id ? updated : a));
                  } catch (e) {
                    throw new Error(e.message);
                  }
                }}
              />
            )}

            {detailTab === "trace" && (
              <TraceGraph />
            )}

            {detailTab === "similarity" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                <h3 style={{ fontSize: 13, fontWeight: 700, color: "#f1f5f9", fontFamily: "Syne, sans-serif" }}>Similar Alerts Check</h3>
                <p style={{ fontSize: 11, color: "#64748b" }}>Matched against the database of previous incident responses before escalating or calling AI.</p>
                {similarMatches.map((m) => {
                  const details = JSON.parse(m.details_json);
                  return (
                    <div key={m.id} style={{ border: "1px solid #1e3a5f", borderRadius: 6, padding: 16, backgroundColor: "#0a1628" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                        <div>
                          <span style={{ fontSize: 9, color: "#64748b", fontWeight: 700 }}>PAST THREAT EVENT</span>
                          <h4 style={{ color: "#f1f5f9", fontSize: 13, fontWeight: 700, marginTop: 2 }}>{m.matched_alert_title || "Unknown Alert"}</h4>
                        </div>
                        <span style={{ fontSize: 14, fontWeight: 700, color: m.score >= 70 ? "#f43f5e" : m.score >= 40 ? "#fb923c" : "#10b981" }}>
                          {m.score}% Similarity
                        </span>
                      </div>
                      
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 8, fontSize: 10, color: "#cbd5e1", backgroundColor: "#060b14", padding: 10, borderRadius: 4, marginBottom: 12 }}>
                        <div>Title Match: <strong>{details.title_match}%</strong></div>
                        <div>Category Match: <strong>{details.category_match}%</strong></div>
                        <div>Severity Match: <strong>{details.severity_match}%</strong></div>
                        <div>Asset Match: <strong>{details.asset_match}%</strong></div>
                        <div>User Match: <strong>{details.user_match}%</strong></div>
                        <div>Script Match: <strong>{details.script_match}%</strong></div>
                      </div>
                      
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: 10, color: "#64748b" }}>Resolution Status: <span style={{ color: STATUSES[m.matched_alert_status]?.color, fontWeight: 700 }}>{STATUSES[m.matched_alert_status]?.label}</span></span>
                        <button type="button" className="btn-secondary" style={{ padding: "4px 8px", fontSize: 9 }} onClick={() => {
                          api.getAlert(m.matched_alert_id).then(res => openAlert(res));
                        }}>View Match Detail</button>
                      </div>
                    </div>
                  );
                })}
                {similarMatches.length === 0 && (
                  <p style={{ color: "#475569", fontSize: 12, textAlign: "center", padding: 24, border: "1px dashed #1e3a5f", borderRadius: 4 }}>No similar historical alerts found in database (Minimum threshold: 25% overlap).</p>
                )}
              </div>
            )}
          </>
        )}

        {view === "stats" && (
          <>
            <h1 className="page-title">Dashboard</h1>
            <div className="stat-row">
              <div className="stat-card"><div className="num">{alerts.length}</div><div style={{ fontSize: 11, color: "#64748b" }}>Total alerts</div></div>
              {Object.entries(statCounts).map(([k, n]) => (
                <div key={k} className="stat-card">
                  <div className="num" style={{ color: STATUSES[k].color }}>{n}</div>
                  <div style={{ fontSize: 11, color: "#64748b" }}>{STATUSES[k].label}</div>
                </div>
              ))}
            </div>
            <p className="subtitle">AI investigations: {settings?.ai_enabled ? "enabled" : "disabled (rule-based only)"}</p>
          </>
        )}

        {view === "settings" && (
          <>
            <h1 className="page-title">Settings</h1>
            <p className="subtitle">AI is off by default. Add your own API key (OpenAI, Anthropic, Ollama, or compatible endpoint) to enable LLM investigation.</p>

            <div className="banner-warn">
              Keys are encrypted at rest with SECRET_KEY. For production, use Docker secrets and rotate keys regularly. No AI calls are made unless you enable AI below.
            </div>

            {/* MFA Configuration Panel */}
            <div className="settings-card" style={{ marginBottom: 20 }}>
              <h3 style={{ fontSize: 13, fontWeight: 700, color: "#f1f5f9", marginBottom: 12, fontFamily: "Syne, sans-serif" }}>Multi-Factor Authentication (MFA)</h3>
              {currentUser?.mfa_enabled ? (
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, color: "#10b981", fontSize: 12, marginBottom: 12 }}>
                    <span style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "#10b981", boxShadow: "0 0 6px #10b981" }} />
                    MFA is currently active on your account.
                  </div>
                  <button type="button" className="btn-secondary" style={{ backgroundColor: "#311010", borderColor: "#7f1d1d", color: "#fca5a5" }} onClick={handleDisableMfa}>Disable MFA</button>
                </div>
              ) : (
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, color: "#64748b", fontSize: 12, marginBottom: 12 }}>
                    <span style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "#64748b" }} />
                    MFA is disabled. Enable MFA to secure your account.
                  </div>
                  {!mfaSetupData ? (
                    <button type="button" className="btn-primary" onClick={handleSetupMfa}>Setup MFA</button>
                  ) : (
                    <div style={{ border: "1px solid #1e3a5f", borderRadius: 4, padding: 16, backgroundColor: "#060b14", marginTop: 12 }}>
                      <p style={{ fontSize: 11, color: "#cbd5e1", marginBottom: 12 }}>
                        Scan this QR Code with your Authenticator app (Google Authenticator, Duo, Microsoft Authenticator) or enter the manual key below.
                      </p>
                      
                      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "center", marginBottom: 16 }}>
                        <div style={{ background: "#fff", padding: 8, borderRadius: 4 }}>
                          <img
                            src={`https://chart.googleapis.com/chart?chs=160x160&chld=M|0&cht=qr&chl=${encodeURIComponent(mfaSetupData.provisioning_uri)}`}
                            alt="MFA QR Code"
                            style={{ display: "block" }}
                          />
                        </div>
                        <div>
                          <div style={{ fontSize: 10, color: "#475569", textTransform: "uppercase" }}>Manual Key</div>
                          <div style={{ fontFamily: "monospace", fontSize: 14, color: "#38bdf8", letterSpacing: 1, padding: "4px 0" }}>{mfaSetupData.mfa_secret}</div>
                        </div>
                      </div>

                      <div style={{ maxWidth: 300 }}>
                        <label className="field-label">Verification Code</label>
                        <div style={{ display: "flex", gap: 8 }}>
                          <input
                            className="field-input"
                            type="text"
                            maxLength={6}
                            placeholder="000000"
                            value={mfaVerifyCode}
                            onChange={(e) => setMfaVerifyCode(e.target.value)}
                            style={{ textAlign: "center", letterSpacing: 2 }}
                          />
                          <button type="button" className="btn-primary" onClick={handleEnableMfa}>Verify &amp; Enable</button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="settings-card">
              <label className="toggle">
                <input type="checkbox" checked={settingsForm.ai_enabled} onChange={(e) => setSettingsForm((f) => ({ ...f, ai_enabled: e.target.checked }))} />
                <span>Enable AI investigation (requires API key)</span>
              </label>

              <div className="grid-2">
                <div>
                  <label className="field-label">Provider</label>
                  <select
                    className="field-input"
                    value={settingsForm.ai_provider}
                    onChange={(e) => {
                      const p = PROVIDERS.find((x) => x.id === e.target.value);
                      setSettingsForm((f) => ({
                        ...f,
                        ai_provider: e.target.value,
                        ai_model: p?.model || f.ai_model,
                      }));
                    }}
                  >
                    {PROVIDERS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="field-label">Model</label>
                  <input className="field-input" value={settingsForm.ai_model} onChange={(e) => setSettingsForm((f) => ({ ...f, ai_model: e.target.value }))} />
                </div>
              </div>

              <div style={{ marginTop: 16 }}>
                <label className="field-label">API Base URL (Ollama / custom — optional)</label>
                <input className="field-input" placeholder="http://localhost:11434/v1" value={settingsForm.api_base_url} onChange={(e) => setSettingsForm((f) => ({ ...f, api_base_url: e.target.value }))} />
              </div>

              <div style={{ marginTop: 16 }}>
                <label className="field-label">API Key {settings?.has_api_key ? "(stored — leave blank to keep)" : ""}</label>
                <input className="field-input" type="password" placeholder="sk-..." value={settingsForm.api_key} onChange={(e) => setSettingsForm((f) => ({ ...f, api_key: e.target.value }))} />
              </div>

              <div style={{ display: "flex", gap: 12, marginTop: 20, flexWrap: "wrap" }}>
                <button type="button" className="btn-primary" onClick={saveSettings}>Save settings</button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={async () => {
                    const r = await api.testKey();
                    setTestResult(r);
                  }}
                >Test API key</button>
              </div>
              {testResult && <p style={{ marginTop: 12, fontSize: 12, color: testResult.ok ? "#10b981" : "#f87171" }}>{testResult.message}</p>}
            </div>
          </>
        )}
      </main>
    </div>
  );
}

function buildShareText(al) {
  return `SECURITY ALERT VALIDATION REQUEST
Alert ID: ${al.alert_id}
Title: ${al.title}
Severity: ${al.severity}
Asset: ${al.affected_asset}
User: ${al.affected_user || "N/A"}

${al.description || ""}

IOCs:
${al.ioc_list || "None"}

Reply: TRUE POSITIVE | FALSE POSITIVE (with reason) | UNCLEAR`;
}
