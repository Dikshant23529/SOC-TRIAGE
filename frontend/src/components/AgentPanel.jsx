import { useEffect, useRef } from "react";
import ReactMarkdown from "react-markdown";
import { api } from "../api";

export default function AgentPanel({ investigation, onUpdate }) {
  const pollRef = useRef(null);

  useEffect(() => {
    if (!investigation?.id) return;
    if (investigation.status === "completed" || investigation.status === "failed") return;

    pollRef.current = setInterval(async () => {
      try {
        const fresh = await api.getInvestigation(investigation.id);
        onUpdate(fresh);
        if (fresh.status === "completed" || fresh.status === "failed") {
          clearInterval(pollRef.current);
        }
      } catch {
        /* ignore transient poll errors */
      }
    }, 800);

    return () => clearInterval(pollRef.current);
  }, [investigation?.id, investigation?.status]);

  if (!investigation) return null;

  const running = investigation.status === "running" || investigation.status === "queued";

  return (
    <div className="agent-panel">
      <div className="agent-header">
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", color: "#94a3b8" }}>
            Investigation Agent {running && <span style={{ color: "#38bdf8" }}>● working</span>}
          </div>
          <div style={{ fontSize: 11, color: "#64748b", marginTop: 4 }}>
            {investigation.current_step || investigation.status}
            {investigation.ai_used ? " · AI assisted" : " · Rule-based"}
          </div>
        </div>
        <span style={{ fontSize: 12, color: "#38bdf8" }}>{investigation.progress_pct}%</span>
      </div>
      <div className="progress-bar">
        <div className="progress-fill" style={{ width: `${investigation.progress_pct}%` }} />
      </div>
      <div className="agent-feed">
        {(investigation.messages || []).map((m, i) => (
          <div key={i} className={`agent-msg ${m.role}`}>
            <div className="role">{m.role}</div>
            <div style={{ color: "#cbd5e1", whiteSpace: "pre-wrap" }}>{m.content}</div>
          </div>
        ))}
        {running && (
          <div className="agent-msg agent">
            <div className="role">agent</div>
            <div style={{ color: "#64748b" }}>Analyzing evidence…</div>
          </div>
        )}
      </div>
      {investigation.error && <div className="error-text" style={{ padding: "0 16px 12px" }}>{investigation.error}</div>}
      {investigation.report_markdown && (
        <div className="report-box">
          <ReactMarkdown>{investigation.report_markdown}</ReactMarkdown>
        </div>
      )}
    </div>
  );
}
