import { useState, useEffect } from "react";
import { api } from "../api";

// ─── Category-specific question sets ──────────────────────────────────────────
const QUESTION_SETS = {
  default: [
    { id: "is_production",   step: 2, label: "Is the affected asset in a Production environment?" },
    { id: "is_internet",     step: 2, label: "Is the asset internet-facing or publicly accessible?" },
    { id: "has_sensitive",   step: 2, label: "Does the asset process or store sensitive / regulated data?" },
    { id: "known_actor",     step: 3, label: "Is the identity (user / service account) known and authorized for this action?" },
    { id: "pim_activated",   step: 3, label: "Was there a PIM / privileged access activation recorded for this account?" },
    { id: "change_ticket",   step: 4, label: "Is there an approved change ticket or maintenance window covering this activity?" },
    { id: "change_approved", step: 4, label: "Was the change formally approved by the relevant change board or team lead?" },
    { id: "attacker_benefit",step: 5, label: "Could an attacker gain significant privilege or data access from this activity?" },
    { id: "lateral_risk",    step: 5, label: "Is there a risk of lateral movement or persistence from this host/identity?" },
    { id: "owner_contacted", step: 6, label: "Has the resource owner been contacted and acknowledged the alert?" },
  ],

  "Malware / Endpoint": [
    { id: "is_production",   step: 2, label: "Is the endpoint in a Production / critical environment?" },
    { id: "is_internet",     step: 2, label: "Is this endpoint exposed to the internet?" },
    { id: "is_edr_isolated", step: 2, label: "Has EDR automatically isolated or quarantined the endpoint?" },
    { id: "known_actor",     step: 3, label: "Is the executing user known and authorized to run this binary or script?" },
    { id: "encoded_cmd",     step: 3, label: "Does the process tree contain encoded/obfuscated commands (e.g., -enc, IEX)?" },
    { id: "change_ticket",   step: 4, label: "Is there a software deployment or patch ticket that explains this execution?" },
    { id: "attacker_benefit",step: 5, label: "Could this execution establish persistence, exfiltrate data, or move laterally?" },
    { id: "c2_indicators",   step: 5, label: "Are there known C2 domains, IPs, or hashes in the IOC list?" },
    { id: "owner_contacted", step: 6, label: "Has the endpoint owner confirmed whether the activity was authorized?" },
  ],

  "Cloud / IAM": [
    { id: "is_production",   step: 2, label: "Is the cloud resource in a Production subscription / account?" },
    { id: "is_internet",     step: 2, label: "Is the resource publicly accessible (e.g., public blob, open security group)?" },
    { id: "has_sensitive",   step: 2, label: "Does the resource store sensitive or regulated data (PII, credentials, keys)?" },
    { id: "known_actor",     step: 3, label: "Was this action performed by a known service principal or human identity?" },
    { id: "pim_activated",   step: 3, label: "Was a Privileged Identity Management (PIM) activation recorded for this role assignment?" },
    { id: "change_ticket",   step: 4, label: "Is there a change request approving this configuration change or role assignment?" },
    { id: "change_approved", step: 4, label: "Was the change approved through the formal approval chain?" },
    { id: "attacker_benefit",step: 5, label: "Could an attacker abuse this configuration to access, exfiltrate, or destroy data?" },
    { id: "static_website",  step: 5, label: "Is public access required for a legitimate use case (e.g., static website, public dataset)?" },
    { id: "owner_contacted", step: 6, label: "Has the cloud resource owner confirmed the business need for public access?" },
  ],

  "Phishing / Email": [
    { id: "email_opened",    step: 1, label: "Was the phishing email opened or links/attachments clicked?" },
    { id: "creds_entered",   step: 1, label: "Did the user enter credentials on the phishing page?" },
    { id: "is_production",   step: 2, label: "Is the targeted user in a high-privilege or sensitive role?" },
    { id: "has_sensitive",   step: 2, label: "Does the user have access to sensitive systems or data?" },
    { id: "known_actor",     step: 3, label: "Was the sending domain spoofed or impersonating a known trusted entity?" },
    { id: "change_ticket",   step: 4, label: "Was this a legitimate phishing simulation test that was scheduled?" },
    { id: "attacker_benefit",step: 5, label: "Could successful credential theft allow access to critical systems?" },
    { id: "mfa_bypass",      step: 5, label: "Could the attacker bypass MFA using an adversary-in-the-middle (AiTM) technique?" },
    { id: "owner_contacted", step: 6, label: "Has the user been interviewed and their machine sent for forensic review?" },
  ],

  "Unauthorized Access": [
    { id: "is_production",   step: 2, label: "Is the accessed system in Production?" },
    { id: "is_internet",     step: 2, label: "Is the access occurring from an external / untrusted IP?" },
    { id: "known_actor",     step: 3, label: "Is the accessing identity a valid user or service account?" },
    { id: "pim_activated",   step: 3, label: "Was privileged access (PIM/PAM) activated before this access?" },
    { id: "change_ticket",   step: 4, label: "Is there an approved change ticket for this access event?" },
    { id: "attacker_benefit",step: 5, label: "Could this access expose credentials, intellectual property, or PII?" },
    { id: "impossible_travel",step: 5, label: "Does the access originate from an impossible travel location?" },
    { id: "owner_contacted", step: 6, label: "Has the asset owner confirmed whether this access was authorized?" },
  ],
};

const STEPS = [
  { num: 1, label: "Alert Details",      icon: "🔍" },
  { num: 2, label: "Asset Criticality",  icon: "🏗️" },
  { num: 3, label: "Identity Analysis",  icon: "👤" },
  { num: 4, label: "Change Validation",  icon: "📋" },
  { num: 5, label: "Risk Assessment",    icon: "⚠️" },
  { num: 6, label: "Owner Confirmation", icon: "📧" },
];

function getSuggestion(answers, questions) {
  const yesCount = Object.values(answers).filter(v => v === "yes").length;
  const noCount  = Object.values(answers).filter(v => v === "no").length;
  const total = Object.keys(answers).length;
  if (total === 0) return null;

  const hasChangeTicket = answers["change_ticket"] === "yes";
  const hasKnownActor   = answers["known_actor"] === "yes";
  const isProduction    = answers["is_production"] === "yes";
  const attackerBenefit = answers["attacker_benefit"] === "yes";
  const encodedCmd      = answers["encoded_cmd"] === "yes";
  const c2Indicators    = answers["c2_indicators"] === "yes";
  const credEntered     = answers["creds_entered"] === "yes";
  const impossibleTravel= answers["impossible_travel"] === "yes";

  // Hard escalation signals
  if (c2Indicators || encodedCmd || credEntered || impossibleTravel || (attackerBenefit && !hasChangeTicket && isProduction)) {
    return {
      level: "ESCALATE",
      color: "#f43f5e",
      bg: "rgba(244,63,94,0.08)",
      border: "rgba(244,63,94,0.3)",
      icon: "🚨",
      label: "Escalate Incident",
      text: "High-confidence indicators of malicious activity detected. Escalate immediately for incident response.",
    };
  }

  // Close as expected
  if (hasChangeTicket && hasKnownActor && !attackerBenefit) {
    return {
      level: "CLOSE",
      color: "#10b981",
      bg: "rgba(16,185,129,0.08)",
      border: "rgba(16,185,129,0.3)",
      icon: "✅",
      label: "Close as Expected Activity",
      text: "Valid change ticket and known authorized actor found. Activity appears legitimate. Close as False Positive.",
    };
  }

  // Awaiting owner
  if (noCount > 0 && yesCount > 0) {
    return {
      level: "OWNER",
      color: "#f59e0b",
      bg: "rgba(245,158,11,0.08)",
      border: "rgba(245,158,11,0.3)",
      icon: "📧",
      label: "Await Owner Confirmation",
      text: "Ambiguous signals detected. Contact the asset/resource owner for confirmation before closing or escalating.",
    };
  }

  return null;
}

function buildOwnerEmail(alert, answers, questions) {
  const lines = [];
  lines.push(`Subject: [SECURITY] Alert Validation Required — ${alert.alert_id}: ${alert.title}`);
  lines.push("");
  lines.push(`Dear ${alert.owner_team || "Resource Owner"},`);
  lines.push("");
  lines.push(`The SOC Security team has detected the following security alert and requires your confirmation to determine the appropriate response:`);
  lines.push("");
  lines.push(`  Alert ID   : ${alert.alert_id}`);
  lines.push(`  Title      : ${alert.title}`);
  lines.push(`  Severity   : ${alert.severity}`);
  lines.push(`  Asset/Host : ${alert.affected_asset}`);
  lines.push(`  User/Actor : ${alert.affected_user || "N/A"}`);
  lines.push(`  Detected   : ${alert.timestamp || "N/A"}`);
  lines.push(`  Source     : ${alert.source || "N/A"}`);
  lines.push("");

  const validatedItems = [];
  if (answers["is_production"] === "yes")    validatedItems.push("✓ Asset is in a Production environment");
  if (answers["is_internet"] === "yes")      validatedItems.push("✓ Asset is publicly/internet-facing");
  if (answers["has_sensitive"] === "yes")    validatedItems.push("✓ Asset processes or stores sensitive data");
  if (answers["encoded_cmd"] === "yes")      validatedItems.push("✓ Obfuscated command-line execution detected in process tree");
  if (answers["c2_indicators"] === "yes")    validatedItems.push("✓ Known threat indicators (C2/IOCs) present");
  if (answers["impossible_travel"] === "yes")validatedItems.push("✓ Access from an impossible travel location detected");

  if (validatedItems.length > 0) {
    lines.push("Our validation checks have confirmed:");
    validatedItems.forEach(i => lines.push(`  ${i}`));
    lines.push("");
  }

  lines.push("We need you to confirm the following:");
  lines.push("");

  if (alert.category === "Cloud / IAM" || answers["is_internet"] === "yes") {
    lines.push("  1. Is public access to this resource required for a legitimate business function?");
    lines.push("  2. Was a recent configuration change made to this resource, and if so, was it formally approved?");
    lines.push("  3. Is sensitive or regulated data (PII, credentials, IP) stored in this resource?");
  } else if (alert.category === "Malware / Endpoint") {
    lines.push("  1. Was this binary or script execution authorized (e.g., software deployment, IT maintenance)?");
    lines.push("  2. Is there a change ticket or deployment record covering this activity?");
    lines.push("  3. Have you observed anything unusual on this endpoint recently?");
  } else {
    lines.push("  1. Was this activity performed by you or someone on your team with proper authorization?");
    lines.push("  2. Is there an approved change request or maintenance activity that explains this alert?");
    lines.push("  3. Are you aware of any unexpected changes to this resource or system?");
  }

  lines.push("");
  lines.push("Please reply with one of the following:");
  lines.push("  ✅ AUTHORIZED — Activity was planned and approved (attach change ticket reference if available)");
  lines.push("  ❌ UNAUTHORIZED — This activity was not authorized by my team");
  lines.push("  ❓ UNKNOWN — I am not aware of this activity and require investigation support");
  lines.push("");
  lines.push("Please respond within 4 business hours. If this activity is UNAUTHORIZED, please do not use the affected system until further notice.");
  lines.push("");
  lines.push("Thank you,");
  lines.push("Security Operations Center (SOC)");
  if (alert.owner_email) lines.push(`CC: ${alert.owner_email}`);

  return lines.join("\n");
}

export default function ValidationFramework({ alert, onSaved, answers: externalAnswers, onAnswersChange, onSaveValidation }) {
  const [activeStep, setActiveStep] = useState(1);
  const [answers, setAnswersState] = useState(externalAnswers || {});
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveStatus, setSaveStatus] = useState(null); // 'success', 'error', or null
  const [saveMessage, setSaveMessage] = useState("");
  const [validationComplete, setValidationComplete] = useState(false);
  const [selectedOutcome, setSelectedOutcome] = useState(null); // 'tp', 'fp', 'unclear'
  const [submittingOutcome, setSubmittingOutcome] = useState(false);

  const questions = QUESTION_SETS[alert?.category] || QUESTION_SETS.default;
  const stepQuestions = questions.filter(q => q.step === activeStep);
  const suggestion = getSuggestion(answers, questions);

  // Load saved validation if it exists
  useEffect(() => {
    if (alert?.validation_json) {
      try {
        const saved = JSON.parse(alert.validation_json);
        if (saved.answers) {
          setAnswersState(saved.answers);
          if (onAnswersChange) onAnswersChange(saved.answers);
        }
        if (saved.notes)   setNotes(saved.notes);
      } catch {}
    }
  }, [alert?.id]);

  // Auto-hide notification after 3 seconds
  useEffect(() => {
    if (saveStatus) {
      const timer = setTimeout(() => setSaveStatus(null), 3000);
      return () => clearTimeout(timer);
    }
  }, [saveStatus]);

  const setAnswer = (id, val) => {
    const newAnswers = { ...answers, [id]: val };
    setAnswersState(newAnswers);
    if (onAnswersChange) onAnswersChange(newAnswers);
  };

  const saveValidation = async () => {
    setSaving(true);
    setSaveStatus(null);
    try {
      if (onSaveValidation) {
        await onSaveValidation({ answers, notes });
      } else {
        const payload = { validation_json: JSON.stringify({ answers, notes }) };
        await api.updateAlert(alert.id, payload);
      }
      setSaveStatus('success');
      setSaveMessage('Validation checklist saved successfully!');
      setValidationComplete(true);
      if (onSaved) onSaved();
    } catch (e) {
      setSaveStatus('error');
      setSaveMessage('Failed to save validation: ' + e.message);
    } finally {
      setSaving(false);
    }
  };

  const submitOutcome = async (outcome) => {
    setSubmittingOutcome(true);
    try {
      // Call parent handler if available, otherwise make direct API call
      if (onSaveValidation) {
        await onSaveValidation({ answers, notes, outcome });
      } else {
        await api.updateAlert(alert.id, { status: outcome });
      }
      setSaveStatus('success');
      setSaveMessage(`Alert marked as ${outcome === 'tp' ? 'True Positive' : outcome === 'fp' ? 'False Positive' : 'Unclear'}`);
      setSelectedOutcome(outcome);
    } catch (e) {
      setSaveStatus('error');
      setSaveMessage('Failed to update outcome: ' + e.message);
    } finally {
      setSubmittingOutcome(false);
    }
  };

  const ownerEmail = buildOwnerEmail(alert, answers, questions);
  const answeredAll = questions.every(q => answers[q.id]);
  const completedSteps = STEPS.filter(s => questions.filter(q => q.step === s.num).every(q => answers[q.id]));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Success/Error Notification */}
      {saveStatus && (
        <div style={{
          border: `1px solid ${saveStatus === 'success' ? '#10b981' : '#f43f5e'}`,
          backgroundColor: saveStatus === 'success' ? 'rgba(16,185,129,0.1)' : 'rgba(244,63,94,0.1)',
          borderRadius: 6, padding: "12px 16px",
          display: "flex", gap: 10, alignItems: "center"
        }}>
          <span style={{ fontSize: 18 }}>{saveStatus === 'success' ? '✓' : '✗'}</span>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: saveStatus === 'success' ? '#10b981' : '#f43f5e' }}>
              {saveStatus === 'success' ? 'Success' : 'Error'}
            </div>
            <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 2 }}>{saveMessage}</div>
          </div>
        </div>
      )}

      {/* Suggestion Banner */}
      {suggestion && (
        <div style={{
          border: `1px solid ${suggestion.border}`,
          backgroundColor: suggestion.bg,
          borderRadius: 6, padding: "14px 18px",
          display: "flex", gap: 12, alignItems: "center"
        }}>
          <span style={{ fontSize: 22 }}>{suggestion.icon}</span>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: suggestion.color, fontFamily: "Syne, sans-serif" }}>
              Recommended Action: {suggestion.label}
            </div>
            <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 2 }}>{suggestion.text}</div>
          </div>
        </div>
      )}

      {/* Step Tabs */}
      <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
        {STEPS.map(s => {
          const stepQs = questions.filter(q => q.step === s.num);
          const done = stepQs.length > 0 && stepQs.every(q => answers[q.id]);
          const active = activeStep === s.num;
          const hasQs = stepQs.length > 0;
          return (
            <button
              key={s.num}
              type="button"
              onClick={() => setActiveStep(s.num)}
              style={{
                display: "flex", alignItems: "center", gap: 6,
                padding: "6px 12px", borderRadius: 4, fontSize: 10, fontWeight: 700,
                fontFamily: "inherit", cursor: hasQs ? "pointer" : "default",
                border: active ? "1px solid #38bdf8" : "1px solid #1e3a5f",
                backgroundColor: active ? "rgba(56,189,248,0.08)" : "#0a1628",
                color: active ? "#38bdf8" : done ? "#10b981" : "#64748b",
                opacity: hasQs ? 1 : 0.4,
              }}
            >
              {done ? "✓" : s.icon} STEP {s.num}: {s.label.toUpperCase()}
            </button>
          );
        })}
      </div>

      {/* Questions Panel */}
      <div style={{ backgroundColor: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 6, padding: 20 }}>
        <h4 style={{ fontSize: 12, fontWeight: 700, color: "#f1f5f9", fontFamily: "Syne, sans-serif",
                     textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>
          {STEPS[activeStep - 1]?.icon} Step {activeStep}: {STEPS[activeStep - 1]?.label}
        </h4>

        {activeStep === 1 && (
          <div style={{ fontSize: 11, color: "#94a3b8", lineHeight: 1.6, marginBottom: 16 }}>
            <p><strong style={{ color: "#e2e8f0" }}>Alert:</strong> {alert?.title}</p>
            <p><strong style={{ color: "#e2e8f0" }}>Description:</strong> {alert?.description || "No description provided."}</p>
            {alert?.process_tree && (
              <div style={{ marginTop: 10, backgroundColor: "#060b14", padding: 10, borderRadius: 4, fontFamily: "monospace", fontSize: 10 }}>
                <div style={{ color: "#475569", marginBottom: 4 }}>PROCESS TREE:</div>
                {alert.process_tree.split("\n").map((l, i) => <div key={i} style={{ color: "#cbd5e1" }}>{l}</div>)}
              </div>
            )}
            {alert?.ioc_list && (
              <div style={{ marginTop: 10 }}>
                <strong style={{ color: "#e2e8f0" }}>IOCs:</strong>
                <div style={{ fontFamily: "monospace", fontSize: 10, color: "#fb923c", marginTop: 4 }}>{alert.ioc_list}</div>
              </div>
            )}
          </div>
        )}

        {stepQuestions.length === 0 && activeStep !== 1 && (
          <p style={{ fontSize: 11, color: "#475569" }}>No specific questions for this step and alert category.</p>
        )}

        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {stepQuestions.map(q => (
            <div key={q.id} style={{
              backgroundColor: "#060b14", border: "1px solid #1e3a5f",
              borderRadius: 4, padding: "12px 16px"
            }}>
              <div style={{ fontSize: 12, color: "#e2e8f0", marginBottom: 10, lineHeight: 1.5 }}>
                {q.label}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                {["yes", "no", "unknown"].map(val => (
                  <button
                    key={val}
                    type="button"
                    onClick={() => setAnswer(q.id, val)}
                    style={{
                      padding: "6px 16px", borderRadius: 3,
                      fontSize: 10, fontWeight: 700,
                      fontFamily: "inherit", cursor: "pointer",
                      textTransform: "uppercase",
                      border: answers[q.id] === val
                        ? `1px solid ${val === "yes" ? "#10b981" : val === "no" ? "#f43f5e" : "#f59e0b"}`
                        : "1px solid #1e3a5f",
                      backgroundColor: answers[q.id] === val
                        ? val === "yes" ? "rgba(16,185,129,0.15)" : val === "no" ? "rgba(244,63,94,0.15)" : "rgba(245,158,11,0.15)"
                        : "transparent",
                      color: answers[q.id] === val
                        ? val === "yes" ? "#10b981" : val === "no" ? "#f43f5e" : "#f59e0b"
                        : "#64748b",
                    }}
                  >
                    {val === "yes" ? "✓ Yes" : val === "no" ? "✗ No" : "? Unknown"}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Navigation */}
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 16 }}>
          <button type="button" style={btnSecondary} onClick={() => setActiveStep(s => Math.max(1, s - 1))} disabled={activeStep === 1}>← Previous</button>
          {activeStep < 6
            ? <button type="button" style={btnPrimary} onClick={() => setActiveStep(s => Math.min(6, s + 1))}>Next →</button>
            : <button type="button" style={btnPrimary} onClick={saveValidation} disabled={saving}>{saving ? "Saving…" : "Save Checklist"}</button>
          }
        </div>
      </div>

      {/* TP/FP Outcome Selection (shown after validation is complete) */}
      {validationComplete && (
        <div style={{ backgroundColor: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 6, padding: 20 }}>
          <h4 style={{ fontSize: 12, fontWeight: 700, color: "#f1f5f9", fontFamily: "Syne, sans-serif",
                       textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 16 }}>
            Step 7: Outcome Assessment
          </h4>
          
          <div style={{ marginBottom: 16 }}>
            <p style={{ fontSize: 11, color: "#94a3b8", lineHeight: 1.6, marginBottom: 12 }}>
              Based on your validation analysis, classify this alert as a True Positive (actual security event), 
              False Positive (benign activity), or mark it as Unclear if you need further investigation.
            </p>
          </div>

          {suggestion && (
            <div style={{
              border: `1px solid ${suggestion.border}`,
              backgroundColor: suggestion.bg,
              borderRadius: 6, padding: "12px 14px",
              display: "flex", gap: 10, alignItems: "flex-start",
              marginBottom: 16
            }}>
              <span style={{ fontSize: 18, marginTop: 2 }}>{suggestion.icon}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: suggestion.color }}>
                  System Recommendation: {suggestion.label}
                </div>
                <div style={{ fontSize: 10, color: "#94a3b8", marginTop: 4 }}>{suggestion.text}</div>
              </div>
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 12 }}>
            {[
              { id: 'fp', label: 'False Positive', icon: '✅', color: '#10b981', bg: 'rgba(16,185,129,0.15)', border: 'rgba(16,185,129,0.4)' },
              { id: 'unclear', label: 'Unclear', icon: '❓', color: '#f59e0b', bg: 'rgba(245,158,11,0.15)', border: 'rgba(245,158,11,0.4)' },
              { id: 'tp', label: 'True Positive', icon: '⚠️', color: '#f43f5e', bg: 'rgba(244,63,94,0.15)', border: 'rgba(244,63,94,0.4)' },
            ].map(outcome => (
              <button
                key={outcome.id}
                type="button"
                onClick={() => submitOutcome(outcome.id)}
                disabled={submittingOutcome}
                style={{
                  display: "flex", flexDirection: "column", alignItems: "center", gap: 8,
                  padding: 16, borderRadius: 6,
                  border: selectedOutcome === outcome.id ? `2px solid ${outcome.color}` : `1px solid ${outcome.border}`,
                  backgroundColor: selectedOutcome === outcome.id ? outcome.bg : 'rgba(0,0,0,0.2)',
                  color: outcome.color,
                  cursor: submittingOutcome ? 'not-allowed' : 'pointer',
                  opacity: submittingOutcome ? 0.6 : 1,
                  fontSize: 11, fontWeight: 700, fontFamily: "inherit",
                  transition: 'all 0.2s ease'
                }}
              >
                <span style={{ fontSize: 20 }}>{outcome.icon}</span>
                <span>{outcome.label}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Analyst Notes */}
      <div style={{ backgroundColor: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 6, padding: 16 }}>
        <label style={labelStyle}>Analyst Notes</label>
        <textarea
          style={{ width: "100%", backgroundColor: "#060b14", border: "1px solid #1e3a5f", borderRadius: 4,
                   color: "#e2e8f0", padding: 10, fontSize: 12, fontFamily: "monospace", outline: "none", resize: "vertical" }}
          rows={3}
          placeholder="Document triage observations, investigated systems, supporting evidence..."
          value={notes}
          onChange={e => setNotes(e.target.value)}
        />
      </div>

      {/* Dynamic Owner Email */}
      <div style={{ backgroundColor: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 6, padding: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <label style={labelStyle}>Auto-Generated Owner Confirmation Message</label>
          <button type="button" style={btnSecondary}
            onClick={() => navigator.clipboard.writeText(ownerEmail)}>
            Copy to Clipboard
          </button>
        </div>
        <textarea
          style={{ width: "100%", backgroundColor: "#060b14", border: "1px solid #1e3a5f",
                   borderRadius: 4, color: "#94a3b8", padding: 10, fontSize: 11,
                   fontFamily: "monospace", outline: "none", resize: "vertical" }}
          rows={18}
          readOnly
          value={ownerEmail}
        />
      </div>
    </div>
  );
}

const btnPrimary = {
  backgroundColor: "#0ea5e9", color: "#fff", border: "none", borderRadius: 4,
  padding: "8px 18px", fontSize: 11, fontWeight: 700, letterSpacing: "0.08em",
  textTransform: "uppercase", cursor: "pointer", fontFamily: "inherit",
};
const btnSecondary = {
  backgroundColor: "#1e3a5f", color: "#7dd3fc", border: "1px solid #1e5a8f",
  borderRadius: 4, padding: "6px 14px", fontSize: 10, fontWeight: 700,
  cursor: "pointer", fontFamily: "inherit", textTransform: "uppercase",
};
const labelStyle = {
  fontSize: 10, fontWeight: 700, color: "#475569",
  textTransform: "uppercase", letterSpacing: "0.1em", display: "block", marginBottom: 6,
};
