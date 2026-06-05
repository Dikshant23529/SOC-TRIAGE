import { useState } from "react";
import { SEVERITY_OPTIONS, CATEGORY_OPTIONS, STATUSES } from "../constants";

export default function AdvancedSearch({ onSearch, onReset }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [tag, setTag] = useState("");
  const [resolvedOnly, setResolvedOnly] = useState(null); // null | true | false

  const hasFilters = q || statusFilter || severity || category || tag || resolvedOnly !== null;

  const applySearch = () => {
    const params = {};
    if (q) params.q = q;
    if (statusFilter) params.status = statusFilter;
    if (severity) params.severity = severity;
    if (category) params.category = category;
    if (tag) params.tag = tag;
    if (resolvedOnly !== null) params.resolved = resolvedOnly;
    onSearch(params);
  };

  const reset = () => {
    setQ(""); setStatusFilter(""); setSeverity(""); setCategory(""); setTag(""); setResolvedOnly(null);
    onReset();
  };

  return (
    <div style={{ marginBottom: 16 }}>
      {/* Quick search bar */}
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <div style={{ flex: 1, position: "relative" }}>
          <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "#475569", fontSize: 13 }}>🔍</span>
          <input
            type="text"
            placeholder="Search alerts — title, host, user, IOCs, tags..."
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={e => e.key === "Enter" && applySearch()}
            style={{
              width: "100%", backgroundColor: "#0a1628", border: "1px solid #1e3a5f",
              borderRadius: 4, color: "#e2e8f0", padding: "9px 12px 9px 32px",
              fontSize: 12, outline: "none", boxSizing: "border-box",
            }}
          />
        </div>
        <button type="button" onClick={applySearch} style={btnPrimary}>Search</button>
        <button type="button" onClick={() => setOpen(s => !s)} style={{
          ...btnSecondary,
          border: hasFilters ? "1px solid #0ea5e9" : "1px solid #1e3a5f",
          color: hasFilters ? "#38bdf8" : "#7dd3fc",
        }}>
          ⚙ Filters {hasFilters ? "•" : ""}
        </button>
        {hasFilters && (
          <button type="button" onClick={reset} style={{ ...btnSecondary, color: "#f43f5e", border: "1px solid rgba(244,63,94,0.3)" }}>
            ✕ Clear
          </button>
        )}
      </div>

      {/* Advanced filter panel */}
      {open && (
        <div style={{
          backgroundColor: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 6,
          padding: 20, marginTop: 8, display: "flex", flexWrap: "wrap", gap: 16,
        }}>
          {/* Status tabs */}
          <div style={{ minWidth: 220 }}>
            <div style={filterLabel}>Status</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {/* Open/Resolved toggles */}
              {[
                { key: null, label: "All Alerts" },
                { key: false, label: "Open / Pending" },
                { key: true, label: "Resolved (TP/FP)" },
              ].map(opt => (
                <button key={String(opt.key)} type="button"
                  onClick={() => { setResolvedOnly(opt.key); setStatusFilter(""); }}
                  style={{
                    ...chipBtn,
                    backgroundColor: resolvedOnly === opt.key && !statusFilter ? "rgba(56,189,248,0.15)" : "transparent",
                    color: resolvedOnly === opt.key && !statusFilter ? "#38bdf8" : "#475569",
                    border: resolvedOnly === opt.key && !statusFilter ? "1px solid #38bdf8" : "1px solid #1e3a5f",
                  }}
                >{opt.label}</button>
              ))}
              <div style={{ width: "100%", marginTop: 4 }}>
                {Object.entries(STATUSES).map(([key, s]) => (
                  <button key={key} type="button"
                    onClick={() => { setStatusFilter(prev => prev === key ? "" : key); setResolvedOnly(null); }}
                    style={{
                      ...chipBtn, marginRight: 4, marginBottom: 4,
                      backgroundColor: statusFilter === key ? s.bg : "transparent",
                      color: statusFilter === key ? s.color : "#475569",
                      border: statusFilter === key ? `1px solid ${s.border}` : "1px solid #1e3a5f",
                    }}
                  >{s.label}</button>
                ))}
              </div>
            </div>
          </div>

          {/* Severity */}
          <div>
            <div style={filterLabel}>Severity</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {SEVERITY_OPTIONS.map(sev => (
                <button key={sev} type="button"
                  onClick={() => setSeverity(prev => prev === sev ? "" : sev)}
                  style={{
                    ...chipBtn,
                    color: severity === sev ? "#f1f5f9" : "#475569",
                    backgroundColor: severity === sev ? "#1e3a5f" : "transparent",
                    border: severity === sev ? "1px solid #38bdf8" : "1px solid #1e3a5f",
                  }}
                >{sev}</button>
              ))}
            </div>
          </div>

          {/* Category */}
          <div style={{ minWidth: 200 }}>
            <div style={filterLabel}>Category</div>
            <select
              value={category}
              onChange={e => setCategory(e.target.value)}
              style={{
                backgroundColor: "#060b14", border: "1px solid #1e3a5f",
                color: category ? "#e2e8f0" : "#475569", borderRadius: 4,
                padding: "6px 10px", fontSize: 11, width: 200, outline: "none",
              }}
            >
              <option value="">All Categories</option>
              {CATEGORY_OPTIONS.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>

          {/* Tag filter */}
          <div>
            <div style={filterLabel}>Tag</div>
            <input
              type="text"
              placeholder="e.g. cloud, malware"
              value={tag}
              onChange={e => setTag(e.target.value)}
              style={{
                backgroundColor: "#060b14", border: "1px solid #1e3a5f",
                borderRadius: 4, color: "#e2e8f0", padding: "6px 10px",
                fontSize: 11, width: 160, outline: "none",
              }}
            />
          </div>

          <div style={{ alignSelf: "flex-end" }}>
            <button type="button" onClick={applySearch} style={btnPrimary}>Apply Filters</button>
          </div>
        </div>
      )}
    </div>
  );
}

const btnPrimary = {
  backgroundColor: "#0ea5e9", color: "#fff", border: "none", borderRadius: 4,
  padding: "9px 18px", fontSize: 11, fontWeight: 700, letterSpacing: "0.06em",
  textTransform: "uppercase", cursor: "pointer", fontFamily: "inherit", whiteSpace: "nowrap",
};
const btnSecondary = {
  backgroundColor: "#0a1628", color: "#7dd3fc", border: "1px solid #1e3a5f",
  borderRadius: 4, padding: "8px 14px", fontSize: 11, fontWeight: 700,
  cursor: "pointer", fontFamily: "inherit", whiteSpace: "nowrap", textTransform: "uppercase",
};
const chipBtn = {
  fontSize: 10, padding: "4px 10px", borderRadius: 3,
  cursor: "pointer", fontFamily: "inherit", fontWeight: 700, textTransform: "uppercase",
};
const filterLabel = {
  fontSize: 9, fontWeight: 700, color: "#475569", textTransform: "uppercase",
  letterSpacing: "0.1em", marginBottom: 8,
};
