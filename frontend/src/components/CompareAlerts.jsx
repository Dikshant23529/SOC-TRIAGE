import { useMemo } from "react";
import { STATUSES, severityColor } from "../constants";

// Simple line-by-line diff algorithm (LCS-based visual diff)
function computeDiff(textA = "", textB = "") {
  const linesA = (textA || "").split("\n").filter(l => l.trim());
  const linesB = (textB || "").split("\n").filter(l => l.trim());
  const setA = new Set(linesA);
  const setB = new Set(linesB);

  const common = linesA.filter(l => setB.has(l));
  const onlyA  = linesA.filter(l => !setB.has(l));
  const onlyB  = linesB.filter(l => !setA.has(l));

  return { common, onlyA, onlyB };
}

function MetaRow({ label, valA, valB }) {
  const same = String(valA || "").toLowerCase() === String(valB || "").toLowerCase();
  return (
    <tr>
      <td style={cell.label}>{label}</td>
      <td style={{ ...cell.val, color: same ? "#94a3b8" : "#fbbf24" }}>{valA || "—"}</td>
      <td style={{ ...cell.val, color: same ? "#94a3b8" : "#fbbf24" }}>{valB || "—"}</td>
      <td style={{ ...cell.diff, color: same ? "#10b981" : "#f59e0b" }}>{same ? "=" : "≠"}</td>
    </tr>
  );
}

function DiffPanel({ label, textA, textB }) {
  const { common, onlyA, onlyB } = useMemo(() => computeDiff(textA, textB), [textA, textB]);
  const allLines = [];

  // Interleave: removed → added → common sections
  onlyA.forEach(l => allLines.push({ text: l, side: "A" }));
  onlyB.forEach(l => allLines.push({ text: l, side: "B" }));
  common.forEach(l => allLines.push({ text: l, side: "both" }));

  return (
    <div style={{ marginBottom: 16 }}>
      <div style={sectionHeader}>{label}</div>
      {allLines.length === 0 ? (
        <div style={{ color: "#475569", fontSize: 11, padding: "8px 0" }}>No data provided.</div>
      ) : (
        <div style={codeBox}>
          {allLines.map((item, i) => (
            <div key={i} style={{
              fontFamily: "monospace", fontSize: 10, padding: "2px 6px",
              borderRadius: 2, marginBottom: 1,
              backgroundColor:
                item.side === "A" ? "rgba(244,63,94,0.12)"
                : item.side === "B" ? "rgba(16,185,129,0.12)"
                : "transparent",
              color:
                item.side === "A" ? "#f87171"
                : item.side === "B" ? "#34d399"
                : "#64748b",
              borderLeft: `2px solid ${
                item.side === "A" ? "#f43f5e"
                : item.side === "B" ? "#10b981"
                : "#1e3a5f"
              }`,
            }}>
              <span style={{ marginRight: 8, opacity: 0.6 }}>
                {item.side === "A" ? "−" : item.side === "B" ? "+" : " "}
              </span>
              {item.text}
            </div>
          ))}
        </div>
      )}
      <div style={{ display: "flex", gap: 16, fontSize: 10, color: "#475569", marginTop: 4 }}>
        <span><span style={{ color: "#f87171" }}>■</span> {onlyA.length} only in Alert A</span>
        <span><span style={{ color: "#34d399" }}>■</span> {onlyB.length} only in Alert B</span>
        <span><span style={{ color: "#1e3a5f" }}>■</span> {common.length} common lines</span>
      </div>
    </div>
  );
}

export default function CompareAlerts({ alertA, alertB, onClose }) {
  if (!alertA || !alertB) return null;

  const tagListA = (alertA.tags || "").split(",").map(t => t.trim()).filter(Boolean);
  const tagListB = (alertB.tags || "").split(",").map(t => t.trim()).filter(Boolean);
  const sharedTags = tagListA.filter(t => tagListB.includes(t));

  return (
    <div style={{
      position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: "rgba(3,7,18,0.96)", zIndex: 8000,
      overflow: "auto", padding: 24,
    }}>
      {/* Header */}
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        marginBottom: 20, paddingBottom: 16, borderBottom: "1px solid #1e3a5f",
      }}>
        <div>
          <div style={{ fontSize: 10, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.1em" }}>
            Side-by-Side Alert Comparison
          </div>
          <h2 style={{ fontFamily: "Syne, sans-serif", fontSize: 18, color: "#f1f5f9", marginTop: 4 }}>
            {alertA.alert_id} vs {alertB.alert_id}
          </h2>
        </div>
        <button type="button" onClick={onClose} style={{
          backgroundColor: "#1e3a5f", color: "#7dd3fc",
          border: "1px solid #1e5a8f", borderRadius: 4,
          padding: "8px 18px", fontSize: 11, fontWeight: 700, cursor: "pointer", fontFamily: "inherit",
        }}>✕ Close Comparison</button>
      </div>

      {/* Header Cards side-by-side */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
        {[alertA, alertB].map((al, idx) => (
          <div key={al.id} style={{
            backgroundColor: "#0a1628", border: `1px solid ${idx === 0 ? "#1e3a5f" : "#1e4a5f"}`,
            borderRadius: 6, padding: 16,
          }}>
            <div style={{ fontSize: 9, color: "#475569", textTransform: "uppercase", marginBottom: 6 }}>
              Alert {idx === 0 ? "A" : "B"}
            </div>
            <div style={{ fontSize: 14, fontWeight: 700, color: "#f1f5f9", fontFamily: "Syne, sans-serif" }}>{al.title}</div>
            <div style={{ fontSize: 10, color: "#64748b", marginTop: 4 }}>{al.alert_id} · {al.affected_asset}</div>
            <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
              <span style={{ fontSize: 9, fontWeight: 700, padding: "2px 8px", borderRadius: 3,
                            border: `1px solid ${severityColor(al.severity)}`, color: severityColor(al.severity) }}>
                {al.severity}
              </span>
              <span style={{ fontSize: 9, fontWeight: 700, padding: "2px 8px", borderRadius: 3,
                            backgroundColor: STATUSES[al.status]?.bg, color: STATUSES[al.status]?.color }}>
                {STATUSES[al.status]?.label || al.status}
              </span>
            </div>
            {(idx === 0 ? tagListA : tagListB).length > 0 && (
              <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 8 }}>
                {(idx === 0 ? tagListA : tagListB).map(t => (
                  <span key={t} style={{
                    fontSize: 9, backgroundColor: sharedTags.includes(t) ? "rgba(56,189,248,0.15)" : "#0d1928",
                    border: sharedTags.includes(t) ? "1px solid #38bdf8" : "1px solid #1e3a5f",
                    color: sharedTags.includes(t) ? "#38bdf8" : "#475569",
                    padding: "1px 6px", borderRadius: 3,
                  }}>#{t}</span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Metadata Comparison Table */}
      <div style={{ backgroundColor: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 6, padding: 16, marginBottom: 16 }}>
        <div style={sectionHeader}>Metadata Comparison</div>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={cell.head}></th>
              <th style={{ ...cell.head, color: "#7dd3fc" }}>Alert A — {alertA.alert_id}</th>
              <th style={{ ...cell.head, color: "#5eead4" }}>Alert B — {alertB.alert_id}</th>
              <th style={cell.head}>Match</th>
            </tr>
          </thead>
          <tbody>
            <MetaRow label="Category"      valA={alertA.category}      valB={alertB.category} />
            <MetaRow label="Severity"      valA={alertA.severity}      valB={alertB.severity} />
            <MetaRow label="Affected Host" valA={alertA.affected_asset} valB={alertB.affected_asset} />
            <MetaRow label="Affected User" valA={alertA.affected_user}  valB={alertB.affected_user} />
            <MetaRow label="Owner Team"    valA={alertA.owner_team}     valB={alertB.owner_team} />
            <MetaRow label="Source"        valA={alertA.source}         valB={alertB.source} />
            <MetaRow label="Status"        valA={alertA.status}         valB={alertB.status} />
            <MetaRow label="Tags"          valA={alertA.tags}           valB={alertB.tags} />
            <MetaRow label="Timestamp"     valA={alertA.timestamp}      valB={alertB.timestamp} />
          </tbody>
        </table>
      </div>

      {/* Visual Diffs */}
      <div style={{ backgroundColor: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 6, padding: 16, marginBottom: 16 }}>
        <DiffPanel label="Process Tree / Execution Chain" textA={alertA.process_tree} textB={alertB.process_tree} />
        <DiffPanel label="Timeline Logs" textA={alertA.timeline_logs} textB={alertB.timeline_logs} />
        <DiffPanel label="IOCs (Indicators of Compromise)" textA={alertA.ioc_list} textB={alertB.ioc_list} />
      </div>

      {/* Description Comparison */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        {[alertA, alertB].map((al, idx) => (
          <div key={al.id} style={{ backgroundColor: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 6, padding: 16 }}>
            <div style={sectionHeader}>Alert {idx === 0 ? "A" : "B"} — Description</div>
            <div style={{ fontSize: 11, color: "#94a3b8", lineHeight: 1.6 }}>
              {al.description || "No description provided."}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

const sectionHeader = {
  fontSize: 10, fontWeight: 700, color: "#475569",
  textTransform: "uppercase", letterSpacing: "0.1em",
  marginBottom: 10, paddingBottom: 6, borderBottom: "1px solid #0d1928",
};

const codeBox = {
  backgroundColor: "#060b14", border: "1px solid #1e3a5f",
  borderRadius: 4, padding: 10, maxHeight: 220, overflowY: "auto",
};

const cell = {
  label: { fontSize: 10, color: "#475569", padding: "6px 12px", fontWeight: 700, textTransform: "uppercase", borderBottom: "1px solid #0d1928", whiteSpace: "nowrap" },
  val:   { fontSize: 11, color: "#cbd5e1", padding: "6px 12px", borderBottom: "1px solid #0d1928", wordBreak: "break-word" },
  head:  { fontSize: 9, fontWeight: 700, color: "#64748b", textTransform: "uppercase", padding: "6px 12px", borderBottom: "1px solid #1e3a5f", textAlign: "left" },
  diff:  { fontSize: 14, textAlign: "center", padding: "6px 8px", borderBottom: "1px solid #0d1928" },
};
