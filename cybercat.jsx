import React, { useState, useEffect, useRef } from "react";

// ── Claude API ────────────────────────────────────────────────────────────────
const CLAUDE_MODEL = "claude-sonnet-4-6";

const SYSTEM_PROMPT = `You are Cyber Cat, an elite AI-powered cybersecurity analyst and incident responder. You work alongside security operations center (SOC) analysts to triage alerts, analyze logs, generate incident documentation, and provide threat intelligence.

Your personality: Sharp, precise, no-nonsense — but never condescending. You communicate like a senior analyst who has seen it all. You use clear, structured output with bold for critical findings and bullet points for lists. You are concise but thorough.

Your expertise covers:
- Log analysis (Windows Event Logs, Syslog, O365, firewall, EDR, SIEM)
- Threat intelligence (IPs, domains, file hashes, TTPs)
- MITRE ATT&CK framework
- Incident response lifecycle (Detection → Containment → Eradication → Recovery)
- Malware analysis and IOC identification
- Writing SOC communications (escalation emails, close-out notes, informational alerts)
- Incident playbook generation

Always flag critical findings clearly. When analyzing logs, classify each finding as: ✅ Benign | ⚠️ Suspicious | 🚨 Malicious. Provide concrete next steps.

REDACTION NOTICE: Logs submitted for analysis have been processed by a client-side PII redaction engine prior to submission. Sensitive fields — including usernames, hostnames, internal IP addresses, email addresses, SIDs, customer identifiers, and session tokens — are replaced with consistent numbered tokens such as [USER_001], [HOST_001], [IP_001], [EMAIL_001], [SID_001], [DOMAIN_001], etc.

Important guidance for working with redacted logs:
- Tokens are consistent within a log — the same token always represents the same original value. Use this to reason about relationships (e.g. [USER_001] authenticating to [HOST_001] is meaningful).
- Do not flag tokenized or missing field values as gaps, anomalies, or errors in the log data — they are intentional redactions.
- Focus your analysis entirely on the activity, behavior, event sequences, and threat indicators present in the log.
- Treat tokens as opaque identifiers — analyze what the entity did, not what it is called.
- event.original and signal.reason fields are always fully redacted — do not reference their absence in your analysis.`;




// ── Settings System ───────────────────────────────────────────────────────────
const SETTINGS_DEFAULTS = {
  analystName:  "John Smith",
  analystTitle: "Security Analyst",
  orgName:      "Acme Security Operations",
};

function loadSettings() {
  try {
    const stored = localStorage.getItem("cybercat_settings");
    return stored ? { ...SETTINGS_DEFAULTS, ...JSON.parse(stored) } : { ...SETTINGS_DEFAULTS };
  } catch { return { ...SETTINGS_DEFAULTS }; }
}

function saveSettings(s) {
  try { localStorage.setItem("cybercat_settings", JSON.stringify(s)); } catch {}
}

function useSettings() {
  const [settings, setSettingsState] = useState(loadSettings);
  const updateSettings = (updates) => {
    const next = { ...settings, ...updates };
    setSettingsState(next);
    saveSettings(next);
  };
  const resetSettings = () => {
    setSettingsState({ ...SETTINGS_DEFAULTS });
    saveSettings({ ...SETTINGS_DEFAULTS });
  };
  return [settings, updateSettings, resetSettings];
}

// ── Settings Modal ────────────────────────────────────────────────────────────
function SettingsModal({ settings, onUpdate, onReset, onClose }) {
  const [local, setLocal] = useState({ ...settings });
  const changed = JSON.stringify(local) !== JSON.stringify(settings);

  const save = () => { onUpdate(local); onClose(); };

  return (
    <div style={{position:"fixed",inset:0,background:"rgba(10,20,30,0.65)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center",padding:"1rem"}}>
      <div style={{background:"var(--ap-white)",borderRadius:"12px",width:"100%",maxWidth:"460px",boxShadow:"0 8px 32px rgba(26,43,60,0.22)",overflow:"hidden"}}>
        {/* Header */}
        <div style={{background:"linear-gradient(135deg,var(--ap-navy) 0%,#243c4f 100%)",borderBottom:"3px solid var(--ap-blue)",padding:"1rem 1.25rem",display:"flex",alignItems:"center",justifyContent:"space-between"}}>
          <div>
            <div style={{fontFamily:"'Montserrat',sans-serif",fontWeight:700,color:"var(--ap-white)",fontSize:"0.9rem",letterSpacing:"0.04em"}}>
              &#9881;&#65039; Settings
            </div>
            <div style={{fontSize:"0.68rem",color:"rgba(255,255,255,0.5)",letterSpacing:"0.08em",textTransform:"uppercase",marginTop:"2px"}}>
              Analyst Identity &amp; Preferences
            </div>
          </div>
          <button onClick={onClose} style={{background:"none",border:"none",color:"rgba(255,255,255,0.5)",fontSize:"1.2rem",cursor:"pointer",lineHeight:1}}>&#10005;</button>
        </div>

        {/* Body */}
        <div style={{padding:"1.25rem",display:"flex",flexDirection:"column",gap:"1rem"}}>
          <div style={{fontSize:"0.72rem",fontWeight:700,color:"var(--ap-text-light)",textTransform:"uppercase",letterSpacing:"0.08em",borderBottom:"1px solid var(--ap-border)",paddingBottom:"0.4rem"}}>
            Analyst Identity
          </div>
          <div style={{fontSize:"0.75rem",color:"var(--ap-text-mid)"}}>
            These values are used in email sign-offs, communications templates, and Claude prompts.
          </div>

          {[
            { label: "Full Name",     key: "analystName",  placeholder: "John Smith" },
            { label: "Title",         key: "analystTitle", placeholder: "Security Analyst" },
            { label: "Organization",  key: "orgName",      placeholder: "Acme Security Operations" },
          ].map(({ label, key, placeholder }) => (
            <div key={key} style={{display:"flex",flexDirection:"column",gap:"0.3rem"}}>
              <label style={{fontSize:"0.72rem",fontWeight:600,color:"var(--ap-text-mid)",textTransform:"uppercase",letterSpacing:"0.06em"}}>{label}</label>
              <input
                style={{background:"var(--ap-offwhite)",border:"1px solid var(--ap-border)",borderRadius:"6px",padding:"0.55rem 0.75rem",fontSize:"0.82rem",color:"var(--ap-text)",fontFamily:"'Montserrat',sans-serif",outline:"none"}}
                value={local[key]}
                placeholder={placeholder}
                onChange={e => setLocal(p => ({ ...p, [key]: e.target.value }))}
              />
            </div>
          ))}

          <div style={{display:"flex",gap:"0.5rem",marginTop:"0.25rem"}}>
            <button onClick={save} disabled={!changed}
              style={{flex:1,background:"var(--ap-blue)",color:"var(--ap-white)",border:"none",borderRadius:"6px",padding:"0.65rem",fontFamily:"'Montserrat',sans-serif",fontWeight:700,fontSize:"0.8rem",cursor:"pointer",opacity:changed?1:0.5,letterSpacing:"0.04em"}}>
              Save Settings
            </button>
            <button onClick={() => { onReset(); onClose(); }}
              style={{background:"none",border:"1px solid var(--ap-border)",borderRadius:"6px",padding:"0.65rem 1rem",fontFamily:"'Montserrat',sans-serif",fontWeight:600,fontSize:"0.78rem",cursor:"pointer",color:"var(--ap-text-mid)"}}>
              Reset
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Threat Hunt Sanitizer ─────────────────────────────────────────────────────
// Allowlist of field paths whose VALUES are safe to send to Claude for hunt generation.
// Everything else gets its value stripped to "" after redaction runs.
const HUNT_VALUE_ALLOWLIST = new Set([
  // Event metadata
  "@timestamp", "event.action", "event.code", "event.category", "event.description",
  "event.outcome", "event.provider", "event.kind", "event.type", "event.severity",
  "event.module", "event.dataset", "event.risk_score", "event.risk_score_norm",
  // Process — behavioral, not identity
  "process.name", "process.parent.name", "process.command_line",
  "process.executable", "process.args", "process.args_count",
  "process.parent.executable", "process.title",
  // Windows event
  "winlog.event_id", "winlog.channel", "winlog.provider_name",
  "winlog.keywords", "winlog.level", "winlog.opcode", "winlog.outcome",
  "winlog.event_data.TaskName", "winlog.event_data.AllowedToDelegateTo",
  // PowerShell
  "powershell.command.name", "powershell.command.type",
  "powershell.engine.version", "powershell.process.executable_version",
  // Network / firewall
  "network.transport", "network.protocol", "network.direction", "network.iana_number",
  "destination.port", "source.port",
  "fortinet.firewall.attack", "fortinet.firewall.attackid", "fortinet.firewall.severity",
  "fortinet.firewall.action", "fortinet.firewall.subtype", "fortinet.firewall.type",
  "fortinet.firewall.crscore", "fortinet.firewall.crlevel", "fortinet.firewall.srccountry",
  "fortinet.firewall.dstcountry", "fortinet.firewall.policytype",
  // Threat intel scores — preserve for hunt context
  "threat.tactic.name", "threat.technique.name", "threat.technique.subtechnique.id",
  "threat.framework", "stix.confidence", "stix.indicator_types",
  "criminalip.source.issues", "criminalip.destination.issues",
  "threat.source.indicator", "threat.destination.indicator",
  // Hashes — always preserve
  "hash.md5", "hash.sha1", "hash.sha256",
  "email.attachments.file.hash.md5", "email.attachments.file.hash.sha256",
  "related.hash",
  // Alert metadata
  "rule.name", "rule.description", "rule.category", "rule.id", "rule.ruleset",
  "signal.status", "signal.depth",
  "m365_defender.incident.alert.title", "m365_defender.incident.alert.severity",
  "m365_defender.incident.alert.status", "m365_defender.incident.alert.detection_source",
  "m365_defender.alerts.severity", "m365_defender.alerts.status",
  "m365_defender.alerts.investigationState", "m365_defender.alerts.mitreTechniques",
  "m365_defender.classification", "m365_defender.determination",
  // O365 / auth outcome
  "event.outcome", "o365.audit.ResultStatus", "o365.audit.LogonError",
  "o365.audit.ErrorNumber", "o365.audit.UserType", "o365.audit.RecordType",
  "o365.audit.ExtendedProperties",
  // Device posture / Duo
  "cisco_duo.auth.factor", "cisco_duo.auth.reason", "cisco_duo.auth.result",
  "cisco_duo.auth.trusted_endpoint_status", "cisco_duo.auth.event_type",
  "cisco_duo.auth.access_device.is_encryption_enabled",
  "cisco_duo.auth.access_device.is_firewall_enabled",
  "cisco_duo.auth.access_device.is_password_set",
  // Darktrace scoring
  "darktrace.model_breach_alert.device_score", "darktrace.model_breach_alert.pb_score",
  "darktrace.model_breach_alert.model.behaviour",
  "darktrace.model_breach_alert.triggered_components",
  // Observer / log source type
  "observer.product", "observer.vendor", "observer.type",
  "host.os.family", "host.os.type", "host.type",
  // Geo — useful for hunt pivot context
  "source.geo.country_name", "source.geo.country_iso_code",
  "destination.geo.country_name", "destination.geo.country_iso_code",
  // Proofpoint threat scoring
  "proofpoint_tap.message_delivered.impostor_score",
  "proofpoint_tap.message_delivered.malware_score",
  "proofpoint_tap.message_delivered.phish_score",
  "proofpoint_tap.message_delivered.spam_score",
  "proofpoint_tap.message_delivered.threat_info_map",
  "proofpoint_tap.message_delivered.classification",
  // Email sender — IOC
  "email.from.address", "email.subject", "email.attachments",
  // Log level / severity
  "log.level", "log.syslog",
]);

// Walk a parsed JSON object and strip values not on the allowlist
function stripNonAllowedValues(obj, path) {
  path = path || "";
  if (Array.isArray(obj)) {
    return obj.map((item, i) => stripNonAllowedValues(item, path + "[" + i + "]"));
  }
  if (obj !== null && typeof obj === "object") {
    const out = {};
    for (const key of Object.keys(obj)) {
      const fullKey = path ? path + "." + key : key;
      const normalizedKey = normalizeArrayPath(fullKey);
      if (HUNT_VALUE_ALLOWLIST.has(fullKey) || HUNT_VALUE_ALLOWLIST.has(normalizedKey)) {
        // Preserve this field's value as-is
        out[key] = obj[key];
      } else if (obj[key] !== null && typeof obj[key] === "object") {
        // Recurse — may have allowed children
        out[key] = stripNonAllowedValues(obj[key], fullKey);
      } else {
        // Strip the value — field structure is visible, value is not
        out[key] = typeof obj[key] === "string" ? "" :
                   typeof obj[key] === "number" ? 0 :
                   typeof obj[key] === "boolean" ? false :
                   Array.isArray(obj[key]) ? [] : "";
      }
    }
    return out;
  }
  return obj;
}

// Main hunt sanitizer — runs redaction then strips remaining values
function sanitizeForHunt(rawInput) {
  // Step 1: Run full redaction engine (field redaction + pattern sweep)
  const { redacted, tokenMap, wasJSON } = redactLog(rawInput);

  if (!wasJSON) {
    // Plain text — just run pattern sweep, no value stripping possible
    return { sanitized: redacted, tokenMap, wasJSON: false, fieldCount: 0 };
  }

  // Step 2: Re-parse the redacted JSON and strip non-allowlisted values
  try {
    const parsed = JSON.parse(redacted);
    const stripped = stripNonAllowedValues(parsed, "");
    const sanitized = JSON.stringify(stripped, null, 2);
    // Count how many top-level fields were preserved vs stripped
    const totalFields = Object.keys(parsed).length;
    return { sanitized, tokenMap, wasJSON: true, totalFields };
  } catch {
    return { sanitized: redacted, tokenMap, wasJSON: true, totalFields: 0 };
  }
}

// ── Redaction notice prepended to every log submitted to Claude ───────────────
// Token type → human-readable entity description for Option 3 token map
const TOKEN_TYPE_LABELS = {
  "USER":             "a user account",
  "HOST":             "an internal hostname",
  "DOMAIN":           "a Windows or network domain",
  "IP":               "an internal IP address",
  "EMAIL":            "an email address",
  "SID":              "a Windows Security Identifier",
  "LOGON_ID":         "a logon session identifier",
  "USER_ID":          "a user identifier",
  "HOST_ID":          "a host identifier",
  "AGENT_ID":         "an agent or sensor identifier",
  "ORG":              "an organization name",
  "ORG_ID":           "an organization identifier",
  "ORG_NUM":          "an organization number",
  "TENANT_ID":        "a cloud tenant identifier",
  "SESSION_ID":       "a session identifier",
  "TOKEN_ID":         "an authentication token identifier",
  "DEVICE_ID":        "a device identifier",
  "TXN_ID":           "a transaction identifier",
  "ALERT_ID":         "an alert identifier",
  "INCIDENT_ID":      "an incident identifier",
  "INCIDENT_NAME":    "an incident name",
  "DETECTOR_ID":      "a detector or sensor identifier",
  "MSG_ID":           "a message identifier",
  "MAILBOX_ID":       "a mailbox identifier",
  "REQUEST_ID":       "a request identifier",
  "EVENT_ID":         "an event identifier",
  "ACTIVITY_ID":      "an activity correlation identifier",
  "PROFILE_ID":       "a profile identifier",
  "PROFILE":          "a profile name",
  "CLUSTER_ID":       "a cluster identifier",
  "ACTOR_ID":         "an actor identifier",
  "TARGET_ID":        "a target entity identifier",
  "AUTHN_ID":         "an authentication request identifier",
  "PROC_ID":          "a process instance identifier",
  "PROC_TITLE":       "a process window title",
  "PS_ID":            "a PowerShell session identifier",
  "PS_PIPELINE_ID":   "a PowerShell pipeline identifier",
  "PS_RUNSPACE_ID":   "a PowerShell runspace identifier",
  "TASK":             "a scheduled task name",
  "VDOM":             "a firewall virtual domain",
  "POLICY_ID":        "a firewall policy identifier",
  "OBSERVER":         "a network observer or sensor name",
  "OBSERVER_IP":      "a network observer IP address",
  "SERIAL_NUM":       "a device serial number",
  "LOG_SRC":          "a log source address",
  "GROUP":            "a user group name",
  "DELEGATE_TARGET":  "a delegation target",
  "ISP":              "an ISP or organization name",
  "GEO_CITY":         "a geographic city",
  "GEO_COUNTRY":      "a geographic country",
  "GEO_CONTINENT":    "a geographic continent",
  "GEO_LAT":          "a geographic latitude",
  "GEO_LON":          "a geographic longitude",
  "PP_GUID":          "a Proofpoint message GUID",
  "QUEUE_ID":         "a mail queue identifier",
  "XDR_EVENT_ID":     "an XDR event identifier",
  "PARSER_ID":        "a parser identifier",
  "SRC_NAME":         "a source entity name",
  "SRC_ID":           "a source entity identifier",
  "SUBJECT":          "a subject entity (file or process)",
  "SUBJECT_ID":       "a subject entity identifier",
  "PLUGIN_ID":        "a plugin or sensor identifier",
  "SERVICE_ID":       "a service identifier",
  "DEVICE_ID":        "a device identifier",
  "BREACH_ID":        "a Darktrace breach identifier",
  "RULE_ID":          "a rule identifier",
  "AWS_ACCOUNT_ID":   "an AWS account identifier",
  "PRODUCT_ARN":      "an AWS product ARN",
  "FINDING_ID":       "an AWS Security Hub finding identifier",
  "GENERATOR_ID":     "a finding generator identifier",
  "RESOURCE_ID":      "an AWS resource identifier",
  "RESOURCE_NAME":    "an AWS resource name",
  "OWNER_ID":         "a resource owner identifier",
  "S1_ACCOUNT_ID":    "a SentinelOne account identifier",
  "S1_SITE_ID":       "a SentinelOne site identifier",
  "S1_SITE":          "a SentinelOne site name",
  "S1_GROUP_ID":      "a SentinelOne group identifier",
  "S1_GROUP":         "a SentinelOne group name",
  "S1_MGMT_ID":       "a SentinelOne management identifier",
  "S1_SCOPE_ID":      "a SentinelOne scope identifier",
  "CORRELATION_ID":        "a correlation identifier",
  "SERVICE_PRINCIPAL_ID":  "an Azure service principal identifier",
  "SERVICE_PRINCIPAL_NAME":"an Azure service principal name",
  "CREDENTIAL_ID":         "a credential identifier",
  "TOKEN_ISSUER":          "a token issuer name",
  "APP_ID":                "an application identifier",
  "CERT_ISSUER":      "a certificate issuer",
  "CERT_SUBJECT":     "a certificate subject",
  "CERT_SERIAL":      "a certificate serial number",
  "SERVER_ADDR":      "a server address",
  "SERVER_DOMAIN":    "a server domain",
  "CLIENT_ADDR":      "a client address",
  "USER_KEY":         "a user key identifier",
  "DOC_ID":           "a document identifier",
  "NODE_ID":          "a node identifier",
  "REDACTED_RAW_LOG": "the original raw log (fully redacted)",
  "REDACTED_SIGNAL_REASON": "the alert description (fully redacted for PII)",
};

// Build the token map section for Option 3
function buildTokenMapSection(tokenMap) {
  if (!tokenMap || Object.keys(tokenMap).length === 0) return "";
  // Group tokens by type prefix for a clean summary
  const lines = Object.keys(tokenMap).map(token => {
    const typeMatch = token.match(/^\[([A-Z_]+)_\d+\]$/);
    const type = typeMatch ? typeMatch[1] : "UNKNOWN";
    const label = TOKEN_TYPE_LABELS[type] || "a redacted value";
    return token + " = " + label;
  });
  return "--- TOKEN MAP ---\n" +
    lines.join("\n") +
    "\nNote: Original values are withheld for privacy. Token types indicate the category of each redacted value.\n";
}

function buildRedactedPrompt(logContent, instruction, tokenMap) {
  const notice = "[REDACTION NOTICE: This log has been processed by a PII redaction engine. " +
    "Sensitive fields have been replaced with consistent numbered tokens (e.g. [USER_001], " +
    "[HOST_001], [IP_001], [EMAIL_001]). The same token always represents the same original " +
    "value within this log. Analyze activity and behavior only — do not flag tokenized fields " +
    "as missing or anomalous.]\n\n";
  const tokenSection = tokenMap ? buildTokenMapSection(tokenMap) + "\n" : "";
  return instruction + "\n\n" + notice + tokenSection + "--- LOG START ---\n" + logContent + "\n--- LOG END ---";
}

async function callClaude(messages, onChunk, signal) {
  // In local dev (localhost) route through proxy; in artifact route directly
  const isLocal = typeof window !== "undefined" &&
    (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1");
  const endpoint = isLocal ? "/api/claude" : "https://api.anthropic.com/v1/messages";
  const baseHeaders = { "Content-Type": "application/json" };
  const body = { model: "claude-sonnet-4-6", max_tokens: 2500, messages, stream: true };
  if (!isLocal) body.system = SYSTEM_PROMPT;
  const res = await fetch(endpoint, {
    method: "POST",
    headers: baseHeaders,
    signal,
    body: JSON.stringify(isLocal ? { ...body, system: SYSTEM_PROMPT } : body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `HTTP ${res.status}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let full = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const lines = decoder.decode(value).split("\n");
    for (const line of lines) {
      if (!line.startsWith("data: ")) continue;
      const data = line.slice(6).trim();
      if (data === "[DONE]") continue;
      try {
        const evt = JSON.parse(data);
        if (evt.type === "content_block_delta" && evt.delta?.text) {
          full += evt.delta.text;
          onChunk(full);
        }
      } catch {}
    }
  }
  return full;
}



// ── Token map display helper ─────────────────────────────────────────────────
function truncateTokenValue(val) {
  if (!val) return val;
  // Fully redacted field content — show clean placeholder
  if (val.trim().startsWith("{") || val.trim().startsWith("[{")) return "{...JSON redacted...}";
  // ARNs — trim to service level
  if (val.startsWith("arn:aws:")) {
    const parts = val.split(":");
    return parts.slice(0, 5).join(":") + ":...";
  }
  // Full UUIDs/GUIDs — show first segment only
  if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(val)) {
    return val.substring(0, 8) + "-…";
  }
  // General — 80 chars max with ellipsis
  if (val.length > 80) return val.substring(0, 77) + "…";
  return val;
}

// ── PII Redaction Engine (Windows / ArmorPoint Schema) ───────────────────────

const REDACT_FIELDS = {
  "user.name":                           "USER",
  "user.domain":                         "DOMAIN",
  "user.id":                             "USER_ID",
  "user.lower_case":                     "USER",
  "related.user":                        "USER",
  "winlog.event_data.SubjectUserName":   "USER",
  "winlog.event_data.SubjectDomainName": "DOMAIN",
  "winlog.event_data.SubjectUserSid":    "SID",
  "winlog.event_data.SubjectLogonId":    "LOGON_ID",
  "host.name":                           "HOST",
  "winlog.computer_name":                "HOST",
  "ArmorPoint.agent.Hostname":           "HOST",
  "winlog.event_data.FQDN":             "HOST",
  "customer.name":                       "ORG",
  "customer.number":                     "ORG_NUM",
  "ArmorPoint.event.customerID":         "ORG_ID",
  "ArmorPoint.agent.ProfileId":          "PROFILE_ID",
  "ArmorPoint.agent.ProfileName":        "PROFILE",
  "ArmorPoint.agent.AgentUUID":          "AGENT_ID",
  "elastic_agent.id":                    "AGENT_ID",
  "winlog.logon.id":                     "LOGON_ID",
  "winlog.event_data.ClientProcessId":   "PID",
  "winlog.event_data.ParentProcessId":   "PID",
  "_id":                                 "DOC_ID",
  "_nodeId":                             "NODE_ID",
  // User Activity schema additions
  "ArmorPoint.agent.Domain":             "DOMAIN",
  "winlog.caller_computer_name":         "HOST",
  "winlog.event_data.TargetUserName":    "USER",
  "winlog.event_data.TargetDomainName":  "DOMAIN",
  "winlog.event_data.TargetSid":         "SID",
  "winlog.event_data.AllowedToDelegateTo": "DELEGATE_TARGET",
  // winlog.event_data.TaskName preserved — task name is behavioral context, not PII
  // event.message is freeform — pattern sweep handles inline PII automatically
  // ── O365 Login schema ──────────────────────────────────────────────────────
  "user.email":                               "EMAIL",
  "user.key":                                 "USER_KEY",
  // source.ip, source.as.organization.name, source.geo.* preserved — needed for login analysis (impossible travel, geo anomalies, etc.)
  // O365 audit fields
  "o365.audit.DevicePropertiesFlat.SessionId":"SESSION_ID",
  "event.id":                                 "EVENT_ID",
  // ── Microsoft Defender schema ───────────────────────────────────────────────
  "cloud.account.id":                                       "TENANT_ID",
  "email.to.address":                                       "EMAIL",
  "m365_defender.incident.alert.tenant_id":                 "TENANT_ID",
  "m365_defender.incident.alert.id":                        "ALERT_ID",
  "m365_defender.incident.alert.incident_id":               "INCIDENT_ID",
  "m365_defender.incident.alert.provider_alert_id":         "ALERT_ID",
  "m365_defender.incident.alert.detector_id":               "DETECTOR_ID",
  // related.ip and source.ip preserved — needed for threat intel analysis
  // related.user already covered by existing "related.user" entry above
  // evidence array — wildcard path matches any index
  "m365_defender.incident.alert.evidence[].network_message_id": "MSG_ID",
  // ── Okta Authentication schema ──────────────────────────────────────────────
  // User identity
  "client.user.full_name":                                    "USER",
  "client.user.id":                                           "USER_ID",
  "client.user.name":                                         "USER",
  "source.user.full_name":                                    "USER",
  "source.user.id":                                           "USER_ID",
  "source.user.name":                                         "USER",
  "user.full_name":                                           "USER",
  "user.name":                                                "USER",
  // Okta actor (the authenticated principal)
  "okta.actor.alternate_id":                                  "USER",
  "okta.actor.display_name":                                  "USER",
  "okta.actor.id":                                            "ACTOR_ID",
  // Okta target (the resource/user being acted upon) — wildcard for array
  "okta.target[].alternate_id":                               "USER",
  "okta.target[].display_name":                               "USER",
  "okta.target[].id":                                         "TARGET_ID",
  // Session / device identifiers
  "okta.authentication_context.external_session_id":          "SESSION_ID",
  "okta.debug_context.debug_data.device_fingerprint":         "DEVICE_ID",
  "okta.debug_context.debug_data.flattened.deviceFingerprint":"DEVICE_ID",
  "okta.debug_context.debug_data.flattened.authnRequestId":   "AUTHN_ID",
  "okta.debug_context.debug_data.flattened.requestId":        "REQUEST_ID",
  "okta.debug_context.debug_data.flattened.dtHash":           "DEVICE_ID",
  "okta.debug_context.debug_data.request_id":                 "REQUEST_ID",
  "okta.transaction.id":                                      "TXN_ID",
  "okta.uuid":                                                "EVENT_ID",
  // Cluster / agent IDs
  "cluster.uuid":                                             "CLUSTER_ID",
  "cluster_uuid":                                             "CLUSTER_ID",
  "elasticsearch.cluster.id":                                 "CLUSTER_ID",
  // ip_chain geo preserved — ip_chain IPs preserved for threat intel
  // okta.security_context.* preserved — ISP/proxy detection has threat intel value
  // client.ip, source.ip, related.ip preserved — needed for analysis
  // all geo fields preserved — location context needed for auth anomaly detection
  // ── Cisco Duo schema ────────────────────────────────────────────────────────
  // User identity
  "user.email":                              "EMAIL",
  "user.id":                                 "USER_ID",
  "user.name":                               "USER",
  "source.user.email":                       "EMAIL",
  "source.user.id":                          "USER_ID",
  "source.user.name":                        "USER",
  "source.user.group.name":                  "GROUP",
  // Duo auth identity
  "cisco_duo.auth.email":                    "EMAIL",
  "cisco_duo.auth.txid":                     "TXN_ID",
  // access_device and auth_device location, posture, and factor data preserved
  // cisco_duo.auth.application.* preserved — app context needed for analysis
  // cisco_duo.auth.auth_device.name preserved — device type not PII
  // ── Fortigate Firewall schema ────────────────────────────────────────────────
  // Internal infrastructure identifiers
  "observer.name":                           "OBSERVER",
  "observer.serial_number":                  "SERIAL_NUM",
  "ArmorPoint.observer.ip":                  "OBSERVER_IP",
  "ArmorPoint.observer.port":                "OBSERVER_PORT",
  "log.source.address":                      "LOG_SRC",
  // Fortigate internal session/policy identifiers
  "fortinet.firewall.poluuid":               "POLICY_ID",
  "fortinet.firewall.incidentserialno":      "INCIDENT_ID",
  "fortinet.firewall.sessionid":             "SESSION_ID",
  "fortinet.firewall.vd":                    "VDOM",
  // All IPs, geo, threat intel, criminalip, maxmind, whois, stix preserved —
  // this is network/threat intel data needed for firewall analysis
  // ── Windows PowerShell Event Log schema ─────────────────────────────────────
  // Destination user
  "destination.user.domain":             "DOMAIN",
  "destination.user.name":               "USER",
  // Source user (domain variant — complements existing source.user.name)
  "source.user.domain":                  "DOMAIN",
  // Process session identifiers
  "process.entity_id":                   "PROC_ID",
  "process.title":                       "PROC_TITLE",
  // PowerShell session identifiers
  "powershell.id":                       "PS_ID",
  "powershell.pipeline_id":              "PS_PIPELINE_ID",
  "powershell.runspace_id":              "PS_RUNSPACE_ID",
  // winlog user and session
  "winlog.user.identifier":              "SID",
  "winlog.activity_id":                  "ACTIVITY_ID",
  // powershell.command.invocation_details[].value preserved — command content
  // needed for analysis; pattern sweep handles any inline user paths
  // process.args[], process.command_line, process.executable preserved with
  // path redaction via pattern sweep (C:\Users\username -> C:\Users\[USER_001])
  // ── Global cross-schema redactions ──────────────────────────────────────────
  // event.original — raw unparsed log line, may contain all PII in unstructured
  // form that pattern sweep cannot fully catch; structured fields above provide
  // everything needed for analysis so this is safe to fully redact
  "event.original":                      "REDACTED_RAW_LOG",
  // signal.reason — fully redacted due to PII leakage risk (usernames, hostnames
  // embedded in alert descriptions); event.action and event.description provide
  // sufficient context for log type identification and analysis
  "signal.reason":                       "REDACTED_SIGNAL_REASON",
  // ── ArmorXDR / Cybereason EDR (Windows Event Log) schema ───────────────────
  "armorpoint.parser.id":              "PARSER_ID",
  "armorxdr.event.id":                 "XDR_EVENT_ID",
  "armorxdr.user.id":                  "USER_ID",
  "event.customerID":                  "ORG_ID",
  "host.hostname":                     "HOST",
  "host.id":                           "HOST_ID",
  "host.domain":                       "DOMAIN",
  "host.ip":                           "IP",
  // process.path and process.parent.path preserved — pattern sweep handles
  // any embedded usernames (C:\Users\username -> C:\Users\[USER_001])
  // ── Cybereason EDR / Malware Detection schema ──────────────────────────────
  "_source.organization.name":              "ORG",
  "_source.organization.id":               "ORG_ID",
    // _source.events.subject.name preserved — file/entity name, threat intel context
    // _source.events.subject.external_id preserved — external threat intel reference
    // _source.events.subject.plugin_id preserved — sensor/plugin context
    // _source.events.subject.service_id preserved — service context
  "_source.events.source.name":            "SRC_NAME",
  "_source.events.source.id":              "SRC_ID",
    // _source.events.subjects[].name preserved — subject entity names, file context
  // _source.events.subject.hashes preserved — threat intel
  // _source.rule.name, event.*, observer.*, fileset.* preserved — alert context
  // Machine/Path in file reputation table — pattern sweep handles embedded usernames
  // ── O365 Exchange Mailbox Audit schema ─────────────────────────────────────
  "o365.audit.AppAccessContext.AADSessionId":  "SESSION_ID",
  "o365.audit.AppAccessContext.UniqueTokenId": "TOKEN_ID",
  "o365.audit.Parameters.ForwardingAddress":   "EMAIL",
  "o365.audit.Parameters.Identity":            "MAILBOX_ID",
  "o365.audit.RequestId":                      "REQUEST_ID",
  "o365.audit.SessionId":                      "SESSION_ID",
  "o365.audit.TokenObjectId":                  "TOKEN_ID",
  "o365.audit.TokenTenantId":                  "TENANT_ID",
  "o365.audit.UserId":                         "USER",
  "o365.audit.UserKey":                        "USER_KEY",
  "o365.audit.ObjectId":                       "MAILBOX_ID",
  "organization.id":                           "ORG_ID",
  "organization.name":                         "ORG",
  "client.address":                            "CLIENT_ADDR",
  "client.ip":                                 "IP",
  "server.address":                            "SERVER_ADDR",
  "server.domain":                             "SERVER_DOMAIN",
  "session.id":                                "SESSION_ID",
  "token.id":                                  "TOKEN_ID",
  "related.hosts":                             "HOST",
  // o365.audit.Parameters.DeliverToMailboxAndForward preserved — boolean flag
  // o365.audit.ResultStatus/RecordType/UserType/ExternalAccess preserved — alert metadata
  // source.*/criminalip.*/maxmind.*/whois.*/threat.* preserved — threat intel
  // ── Microsoft Defender (Identity/User Evidence variant) schema ──────────────
  "m365_defender.incident.alert.evidence[].display_name":                        "USER",
  "m365_defender.incident.alert.evidence[].primary_address":                     "EMAIL",
  "m365_defender.incident.alert.evidence[].upn":                                 "USER",
  "m365_defender.incident.alert.evidence[].user_account.account_name":           "USER",
  "m365_defender.incident.alert.evidence[].user_account.azure_ad_user_id":       "USER_ID",
  "m365_defender.incident.alert.evidence[].user_account.domain_name":            "DOMAIN",
  "m365_defender.incident.alert.evidence[].user_account.user_principal_name":    "USER",
  "m365_defender.incident.alert.evidence[].user_account.user_sid":               "SID",
  "m365_defender.incident.alert.evidence[].user_account.display_name":           "USER",
  // evidence[].verdict, remediation_status, odata_type preserved — analytical
  // m365_defender.incident.alert.* metadata preserved — title, severity, status etc.
  // threat.tactic.name preserved — MITRE context
  // ── Microsoft Defender Alerts (flat format) schema ──────────────────────────
  "m365_defender.alerts.entities.accountName":       "USER",
  "m365_defender.alerts.entities.mailboxAddress":    "EMAIL",
  "m365_defender.alerts.entities.mailboxDisplayName":"USER",
  "m365_defender.alerts.entities.userSid":           "SID",
  "m365_defender.alerts.incidentId":                 "INCIDENT_ID",
  "m365_defender.alerts.providerAlertId":            "ALERT_ID",
  "m365_defender.alerts.detectorId":                 "DETECTOR_ID",
  "m365_defender.incidentId":                        "INCIDENT_ID",
  "m365_defender.incidentName":                      "INCIDENT_NAME",
  // m365_defender.alerts.entities.entityType/verdict/remediationStatus preserved
  // m365_defender.alerts.mitreTechniques[] preserved — MITRE context
  // m365_defender.alerts.severity/status/investigationState/detectionSource preserved
  // m365_defender.classification/determination/status/incidentUri preserved
  // threat.framework/technique.name preserved — MITRE context
  // rule.description preserved — rule context
  // cloud.provider preserved
  // ── Darktrace Model Breach Alert schema ─────────────────────────────────────
  "darktrace.model_breach_alert.device.hostname":        "HOST",
  "darktrace.model_breach_alert.device.sid":             "DEVICE_ID",
  "darktrace.model_breach_alert.pbid":                   "BREACH_ID",
  "darktrace.model_breach_alert.model.edited.by":        "USER",
  "darktrace.model_breach_alert.triggered_components[].ip": "IP",
  "rule.uuid":                                           "RULE_ID",
  // darktrace.model_breach_alert.device.type_label/first_seen/last_seen preserved
  // darktrace.model_breach_alert.device_score/pb_score preserved — anomaly scores
  // darktrace.model_breach_alert.model.* preserved — model config and behavior
  // darktrace.model_breach_alert.triggered_components[].metric.* preserved
  // darktrace.model_breach_alert.triggered_components[].triggered_filters.* preserved
  // darktrace.model_breach_alert.breach_url.* preserved — portal link
  // rule.name/description/category/author/version preserved — rule context
  // event.risk_score/risk_score_norm/severity preserved — critical scoring
  // Pattern sweep handles any IPs or hostnames embedded in filter trigger values
  // ── AWS Security Hub / GuardDuty schema ─────────────────────────────────────
  // AWS account & identity
  "aws.securityhub_findings.aws_account_id":                                          "AWS_ACCOUNT_ID",
  "aws.securityhub_findings.company.name":                                            "ORG",
  "aws.securityhub_findings.generator.id":                                            "GENERATOR_ID",
  "aws.securityhub_findings.product.arn":                                             "PRODUCT_ARN",
  "aws.securityhub_findings.product.fields.aws/securityhub/FindingId":               "FINDING_ID",
  "aws.securityhub_findings.product.fields.aws/guardduty/service/detectorId":        "DETECTOR_ID",
  // IAM resource identity — wildcard array path
  "aws.securityhub_findings.resources[].Details.AwsIamAccessKey.PrincipalId":        "USER_ID",
  "aws.securityhub_findings.resources[].Details.AwsIamAccessKey.PrincipalName":      "USER",
  "aws.securityhub_findings.resources[].Id":                                          "RESOURCE_ID",
  "aws.securityhub_findings.resources[].Owner.Id":                                    "OWNER_ID",
  // Top-level resource fields
  "resource.id":                                                                       "RESOURCE_ID",
  "resource.name":                                                                     "RESOURCE_NAME",
  // aws.securityhub_findings.action.* preserved — API call, remote IP, geo, org (threat intel)
  // aws.securityhub_findings.severity.*/provider_fields.severity.* preserved — critical
  // aws.securityhub_findings.title/description preserved — alert context
  // aws.securityhub_findings.types[]/workflow.*/record_state preserved — status/classification
  // aws.securityhub_findings.region/cloud.region/cloud.provider preserved — infra context
  // aws.securityhub_findings.resources[].Type/Partition/Region/CloudProvider preserved
  // aws.securityhub_findings.resources[].Details.AwsIamAccessKey.PrincipalType preserved
  // all guardduty remoteIpDetails fields preserved — threat intel
  // rule.*/resource.type/result.evaluation/url.* preserved — analytical
  // ── AWS Security Hub / GuardDuty (behavioral profiling variant) ─────────────
  "aws.securityhub_findings.resources[].Owner.Account.Id":                           "OWNER_ID",
  "aws.securityhub_findings.product.fields.aws/guardduty/service/additionalInfo/profiledBehavior/frequentProfiledUserNamesAccountProfiling": "USER",
  // All other additionalInfo.profiledBehavior/unusualBehavior/userAgent fields preserved
  // — behavioral baselines, ASNs, API names, user agent strings (no direct PII)
  // ── SentinelOne OCSF schema ─────────────────────────────────────────────────
  // Device identity
  "device.owner.name":                                       "USER",
  "device.uid":                                              "DEVICE_ID",
  "device.agent.uid":                                        "AGENT_ID",
  "device.agent.uuid":                                       "AGENT_ID",
  // Evidence actor user
  "evidences[].actor.user.name":                             "USER",
  "evidences[].actor.user.uid":                              "USER_ID",
  "evidences[].actor.user.uid_alt":                          "USER_ID",
  "evidences[].actor.user.account.name":                     "ORG",
  // Evidence process user
  "evidences[].process.user.name":                           "USER",
  "evidences[].process.user.uid":                            "USER_ID",
  "evidences[].process.user.uid_alt":                        "USER_ID",
  "evidences[].process.user.display_name":                   "USER",
  "evidences[].process.user.domain":                         "DOMAIN",
  "evidences[].process.user.account.name":                   "ORG",
  // Evidence file owner
  "evidences[].process.file.owner.name":                     "USER",
  "evidences[].process.file.owner.uid":                      "USER_ID",
  "evidences[].process.file.owner.uid_alt":                  "USER_ID",
  "evidences[].process.file.owner.account.name":             "ORG",
  // Certificate identifiers
  "evidences[].process.file.signature.certificate.issuer":   "CERT_ISSUER",
  "evidences[].process.file.signature.certificate.subject":  "CERT_SUBJECT",
  "evidences[].process.file.signature.certificate.serial_number": "CERT_SERIAL",
  // Evidence user
  "evidences[].user.name":                                   "USER",
  "evidences[].user.uid":                                    "USER_ID",
  "evidences[].user.uid_alt":                                "USER_ID",
  "evidences[].user.account.name":                           "ORG",
  // Evidence resource owner
  "evidences[].resources[].owner.name":                      "USER",
  "evidences[].resources[].owner.uid":                       "USER_ID",
  "evidences[].resources[].owner.uid_alt":                   "USER_ID",
  "evidences[].resources[].owner.account.name":              "ORG",
  // Top-level resource owner
  "resources[].owner.name":                                  "USER",
  "resources[].owner.uid":                                   "USER_ID",
  "resources[].owner.uid_alt":                               "USER_ID",
  "resources[].owner.account.name":                          "ORG",
  "resources[].internal_uid":                                "RESOURCE_ID",
  // SentinelOne metadata — account, site, group identifiers
  "resources[].s1_metadata.account_id":                      "S1_ACCOUNT_ID",
  "resources[].s1_metadata.account_name":                    "ORG",
  "resources[].s1_metadata.site_id":                         "S1_SITE_ID",
  "resources[].s1_metadata.site_name":                       "S1_SITE",
  "resources[].s1_metadata.group_id":                        "S1_GROUP_ID",
  "resources[].s1_metadata.group_name":                      "S1_GROUP",
  "resources[].s1_metadata.mgmt_id":                         "S1_MGMT_ID",
  "resources[].s1_metadata.scope_id":                        "S1_SCOPE_ID",
  "s1_detection_metadata.account_id":                        "S1_ACCOUNT_ID",
  "s1_detection_metadata.account_name":                      "ORG",
  "s1_detection_metadata.site_id":                           "S1_SITE_ID",
  "s1_detection_metadata.site_name":                         "S1_SITE",
  "s1_detection_metadata.group_id":                          "S1_GROUP_ID",
  "s1_detection_metadata.group_name":                        "S1_GROUP",
  "s1_detection_metadata.mgmt_id":                           "S1_MGMT_ID",
  "s1_detection_metadata.scope_id":                          "S1_SCOPE_ID",
  // Finding identifiers
  "finding_info.uid":                                        "FINDING_ID",
  "finding_info.uid_alt":                                    "FINDING_ID",
  "finding_info.internal_uid":                               "FINDING_ID",
  "metadata.correlation_uid":                                "CORRELATION_ID",
  // finding_info.related_events[].attacks[].tactic/technique preserved — MITRE ATT&CK
  // evidences[].process.cmd_line/file.hashes/name/path preserved — threat intel
  // evidences[].process.file.signature.state_id/algorithm preserved — analytical
  // observables[].value preserved — IOC values (IPs, hashes, domains)
  // device.os.*/analytic.*/metadata.product.* preserved — context
  // severity_id/confidence_id/verdict_id/status_id preserved — scoring
  // ── Azure AD Sign-in Logs (Event Hub) schema ────────────────────────────────
  // Azure identifiers
  "azure.correlation_id":                                              "CORRELATION_ID",
  "azure.resource.id":                                                 "RESOURCE_ID",
  "azure.tenant_id":                                                   "TENANT_ID",
  "azure.signinlogs.caller_ip_address":                                "IP",
  "azure.signinlogs.identity":                                         "USER",
  // Sign-in properties — identity
  "azure.signinlogs.properties.alternate_sign_in_name":               "USER",
  "azure.signinlogs.properties.app_id":                                "APP_ID",
  "azure.signinlogs.properties.app_owner_tenant_id":                   "TENANT_ID",
  "azure.signinlogs.properties.app_service_principal_id":              "SERVICE_PRINCIPAL_ID",
  "azure.signinlogs.properties.correlation_id":                        "CORRELATION_ID",
  "azure.signinlogs.properties.device_detail.device_id":               "DEVICE_ID",
  "azure.signinlogs.properties.federated_credential_id":               "CREDENTIAL_ID",
  "azure.signinlogs.properties.global_secure_access_ip_address":       "IP",
  "azure.signinlogs.properties.home_tenant_id":                        "TENANT_ID",
  "azure.signinlogs.properties.home_tenant_name":                      "ORG",
  "azure.signinlogs.properties.id":                                    "EVENT_ID",
  "azure.signinlogs.properties.ip_address_from_resource_provider":     "IP",
  "azure.signinlogs.properties.original_request_id":                   "REQUEST_ID",
  "azure.signinlogs.properties.resource_id":                           "RESOURCE_ID",
  "azure.signinlogs.properties.resource_owner_tenant_id":              "TENANT_ID",
  "azure.signinlogs.properties.resource_service_principal_id":         "SERVICE_PRINCIPAL_ID",
  "azure.signinlogs.properties.resource_tenant_id":                    "TENANT_ID",
  "azure.signinlogs.properties.service_principal_credential_key_id":   "CREDENTIAL_ID",
  "azure.signinlogs.properties.service_principal_credential_thumbprint": "CERT_SERIAL",
  "azure.signinlogs.properties.service_principal_id":                  "SERVICE_PRINCIPAL_ID",
  "azure.signinlogs.properties.service_principal_name":                "SERVICE_PRINCIPAL_NAME",
  "azure.signinlogs.properties.session_id":                            "SESSION_ID",
  "azure.signinlogs.properties.sign_in_identifier":                    "USER",
  "azure.signinlogs.properties.source_app_client_id":                  "APP_ID",
  "azure.signinlogs.properties.tenant_id":                             "TENANT_ID",
  "azure.signinlogs.properties.token_issuer_name":                     "TOKEN_ISSUER",
  "azure.signinlogs.properties.unique_token_identifier":               "TOKEN_ID",
  "azure.signinlogs.properties.user_display_name":                     "USER",
  "azure.signinlogs.properties.user_id":                               "USER_ID",
  "azure.signinlogs.properties.user_principal_name":                   "USER",
  // Related entities
  "related.entity":                                                    "USER",
  "source.address":                                                    "IP",
  // Preserved: app_display_name, auth_protocol/requirement, ASN, client_app_used,
  // conditional_access_status, cross_tenant_access_type, device_detail.browser/OS/
  // is_compliant/is_managed, risk_*, network_location_details[].network_type,
  // sign_in_event_types, token_issuer_type, resource_display_name, status.error_code,
  // azure.resource.provider, azure-eventhub.*, geo.*, source.geo.*, threat intel fields
  // ── O365 Unusual Login (_source wrapper variant) schema ────────────────────
  // Common fields re-mapped under _source wrapper
  "_source.user.name":                           "USER",
  "_source.user.domain":                         "DOMAIN",
  "_source.user.id":                             "USER_ID",
  "_source.user.email":                          "EMAIL",
  "_source.customer.name":                       "ORG",
  "_source.customer.number":                     "ORG_NUM",
  "_source.host.name":                           "HOST",
  "_source.host.id":                             "HOST_ID",
  "_source.client.address":                      "CLIENT_ADDR",
  "_source.client.ip":                           "IP",
  "_source.elastic_agent.id":                    "AGENT_ID",
  "_source.related.user":                        "USER",
  "_source.related.hosts":                       "HOST",
  "_source.organization.id":                     "ORG_ID",
  "_source.event.id":                            "EVENT_ID",
  // Agent fields under _source
  "_source.agent.name":                          "AGENT_NAME",
  "_source.agent.id":                            "AGENT_ID",
  "_source.agent.ephemeral_id":                  "AGENT_ID",
  // O365 audit fields under _source
  "_source.o365.audit.ActorIpAddress":           "IP",
  "_source.o365.audit.Actor[].ID":               "ACTOR_ID",
  "_source.o365.audit.Target[].ID":              "TARGET_ID",
  "_source.o365.audit.IntraSystemId":            "SESSION_ID",
  "_source.o365.audit.InterSystemsId":           "SESSION_ID",
  "_source.o365.audit.ActorContextId":           "ACTOR_ID",
  "_source.o365.audit.TargetContextId":          "TARGET_ID",
  "_source.o365.audit.ApplicationId":            "APP_ID",
  "_source.o365.audit.UserId":                   "USER",
  "_source.o365.audit.UserKey":                  "USER_KEY",
  "_source.o365.audit.ObjectId":                 "MAILBOX_ID",
  "_source.o365.audit.DevicePropertiesFlat.SessionId": "SESSION_ID",
  // Elasticsearch highlight fields — contain raw PII from matching documents
  "highlight.user.name":                         "USER",
  "highlight.related.user":                      "USER",
  // source.ip/geo.* and threat intel fields preserved under _source wrapper
  // _source.o365.audit.Actor[].Type/Target[].Type preserved — entity type context
  // _source.o365.audit.LogonError/ResultStatus/ErrorNumber preserved — auth context
  // _source.o365.audit.DevicePropertiesFlat.OS/BrowserType/IsCompliant preserved
  // highlight.event.code[] preserved — analytical
  // ── Proofpoint TAP schema ────────────────────────────────────────────────────
  "email.to.address":                                        "EMAIL",
  "email.message_id":                                        "MSG_ID",
  "proofpoint_tap.guid":                                     "PP_GUID",
  "proofpoint_tap.message_delivered.qid":                    "QUEUE_ID",
  "proofpoint_tap.message_delivered.recipient":              "EMAIL",
  "proofpoint_tap.message_delivered.to_addresses":           "EMAIL",
  // email.from.address preserved — phishing sender is a critical IOC
  // email.subject preserved — pattern sweep handles any embedded PII
  // proofpoint_tap.message_delivered.header.from preserved — sender evidence
  // email.attachments[].file.hash.* preserved — threat intel
  // email.attachments[].file.mime_type/name preserved — analytical
  // proofpoint_tap.message_delivered.*_score preserved — threat scoring
  // proofpoint_tap.message_delivered.threat_info_map.* preserved — threat intel
  // proofpoint_tap.message_delivered.policy_routes/modules_run preserved — analytical
  // source.*/criminalip.*/maxmind.*/whois.*/threat.* preserved — threat intel

  // hash.md5/sha1/sha256 preserved — threat intel, never redact
  // signal.reason covered by pattern sweep — preserves alert context
};

function createTokenRegistry() {
  const registry = {};
  const counters = {};
  return {
    get(type, value) {
      const key = type + "::" + value;
      if (!registry[key]) {
        counters[type] = (counters[type] || 0) + 1;
        const idx = String(counters[type]).padStart(3, "0");
        registry[key] = "[" + type + "_" + idx + "]";
      }
      return registry[key];
    },
    getMap() {
      return Object.entries(registry).reduce((acc, [k, v]) => {
        const val = k.split("::").slice(1).join("::");
        acc[v] = val;
        return acc;
      }, {});
    }
  };
}

function normalizeArrayPath(path) {
  // Convert array-indexed path like "foo[0].bar" to wildcard "foo[].bar"
  // so REDACT_FIELDS can match regardless of array index
  return path.replace(/\[\d+\]/g, "[]");
}

function redactObject(obj, registry, path) {
  path = path || "";
  if (Array.isArray(obj)) {
    return obj.map(function(item, i) { return redactObject(item, registry, path + "[" + i + "]"); });
  }
  if (obj !== null && typeof obj === "object") {
    const out = {};
    for (const key of Object.keys(obj)) {
      const val = obj[key];
      const fullKey = path ? path + "." + key : key;
      const normalizedKey = normalizeArrayPath(fullKey);
      const tokenType = REDACT_FIELDS[fullKey] || REDACT_FIELDS[normalizedKey];
      if (tokenType) {
        if (Array.isArray(val)) {
          out[key] = val.map(function(v) { return v ? registry.get(tokenType, String(v)) : v; });
        } else {
          out[key] = val ? registry.get(tokenType, String(val)) : val;
        }
      } else {
        out[key] = redactObject(val, registry, fullKey);
      }
    }
    return out;
  }
  return obj;
}

function redactStringPatterns(text, registry) {
  if (typeof text !== "string") return text;
  let out = text;
  // Windows user profile path — preserve path, redact username only
  out = out.replace(/([Cc]:[\\\/][Uu]sers[\\\/])([^\\/\s"',]+)/g, function(m, prefix, username) {
    return prefix + registry.get("USER", username);
  });
  // UNC paths \\HOSTNAME\share
  out = out.replace(/\\\\([A-Za-z0-9._-]+)(\\[^\s"',]*)?/g, function(m, host, rest) {
    return "\\\\" + registry.get("HOST", host) + (rest || "");
  });
  // SAM account DOMAIN\username — carefully exclude known Windows system paths
  // to prevent over-redaction of paths like WINDOWS\System32\WindowsPowerShell
  const SYSTEM_PATH_SEGMENTS = new Set([
    "windows","system32","syswow64","sysnative","system","drivers","etc",
    "windowspowershell","powershell","powershell.exe","cmd","cmd.exe",
    "wscript","cscript","mshta","rundll32","regsvr32","svchost","lsass",
    "services","explorer","taskmgr","notepad","calc","msiexec","wmic",
    "programfiles","programfilesx86","programdata","commonfiles",
    "microsoftshared","microsoftoffice","windowsnt","currentversion",
    "v1.0","v2.0","v3.0","v4.0","v4.0.30319","v6.3","x86","x64","amd64",
    "wbem","inetsrv","microsoft","windows","windowsdefender","securityhealth",
    "softwaremicrosoftwindows","run","currentversionrun","policies",
    "software","wow6432node","classes","clsid","interface",
    "appdata","local","locallow","roaming","temp","tmp",
    "desktop","downloads","documents","pictures","music","videos",
    "assembly","gac","gac_32","gac_64","gac_msil","dotnet","framework","framework64",
    "packages","node_modules","bin","obj","debug","release","public","default","allusers",
    "users","programfiles","programfiles(x86)","programdata",
  ]);
  out = out.replace(/\b([A-Za-z0-9_.-]+)\\([A-Za-z0-9._-]+)\b/g, function(m, domain, user) {
    // Skip if either segment is a known Windows system path component
    if (SYSTEM_PATH_SEGMENTS.has(domain.toLowerCase()) ||
        SYSTEM_PATH_SEGMENTS.has(user.toLowerCase())) return m;
    // Skip version-like segments e.g. v1.0, 4.0.30319
    if (/^v?\d+[\d.]*$/.test(domain) || /^v?\d+[\d.]*$/.test(user)) return m;
    // Skip if looks like a file extension pair e.g. powershell.exe
    if (/\.[a-zA-Z]{2,4}$/.test(user)) return m;
    // Skip if user segment looks like a GUID, filename with dashes, or long path component
    if (/^[a-f0-9]{8}-[a-f0-9]{4}/i.test(user)) return m;
    if ((user.match(/-/g) || []).length >= 2) return m;
    // Skip registry hives
    if (/^HK(LM|CU|CR|U|CC)$/i.test(domain)) return m;
    return registry.get("DOMAIN", domain) + "\\" + registry.get("USER", user);
  });
  // Internal RFC 1918 IPs
  out = out.replace(/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g, function(m) {
    return registry.get("IP", m);
  });
  // External IPs are preserved — needed for threat intel and geo analysis
  // Email addresses
  out = out.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, function(m) {
    return registry.get("EMAIL", m);
  });
  // Windows SIDs
  out = out.replace(/\bS-1(-\d+){2,}\b/g, function(m) {
    return registry.get("SID", m);
  });
  return out;
}

function redactLog(rawInput) {
  const registry = createTokenRegistry();

  // Helper to redact a single parsed JSON object
  function redactSingleJSON(parsed) {
    const cleaned = redactObject(parsed, registry);
    return JSON.stringify(cleaned, function(key, val) {
      if (typeof val === "string") return redactStringPatterns(val, registry);
      return val;
    }, 2);
  }

  // Try single valid JSON first (most common case — no change in behavior)
  try {
    const parsed = JSON.parse(rawInput);
    // JSON array of logs e.g. [{...},{...}]
    if (Array.isArray(parsed)) {
      const redactedLogs = parsed.map(item =>
        typeof item === "object" && item !== null
          ? redactSingleJSON(item)
          : redactStringPatterns(String(item), registry)
      );
      return { redacted: redactedLogs.join("\n\n"), tokenMap: registry.getMap(), logCount: parsed.length };
    }
    // Single JSON object
    return { redacted: redactSingleJSON(parsed), tokenMap: registry.getMap(), logCount: 1 };
  } catch (_) {}

  // Not valid JSON — try to split into multiple JSON objects
  // Match top-level {...} blocks (handles newline-separated or blank-line-separated logs)
  const jsonBlocks = [];
  let depth = 0, start = -1, inStr = false, esc = false;
  for (let i = 0; i < rawInput.length; i++) {
    const c = rawInput[i];
    if (esc) { esc = false; continue; }
    if (c === "\\") { esc = true; continue; }
    if (c === "\"" && !esc) { inStr = !inStr; continue; }
    if (inStr) continue;
    if (c === "{") { if (depth === 0) start = i; depth++; }
    else if (c === "}") {
      depth--;
      if (depth === 0 && start >= 0) {
        jsonBlocks.push(rawInput.slice(start, i + 1));
        start = -1;
      }
    }
  }

  if (jsonBlocks.length > 1) {
    // Multiple JSON objects found — redact each with the shared registry
    const redactedBlocks = jsonBlocks.map(block => {
      try {
        const parsed = JSON.parse(block);
        return redactSingleJSON(parsed);
      } catch {
        return redactStringPatterns(block, registry);
      }
    });
    // Also redact any plain text between/around the JSON blocks
    return { redacted: redactedBlocks.join("\n\n"), tokenMap: registry.getMap(), logCount: jsonBlocks.length };
  }

  if (jsonBlocks.length === 1) {
    // Single JSON block extracted from surrounding text
    try {
      const parsed = JSON.parse(jsonBlocks[0]);
      return { redacted: redactSingleJSON(parsed), tokenMap: registry.getMap(), logCount: 1 };
    } catch {}
  }

  // Pure plain text — pattern sweep only
  return { redacted: redactStringPatterns(rawInput, registry), tokenMap: registry.getMap(), logCount: 0 };
}



// ── Smart Email Template Engine ──────────────────────────────────────────────

// ── Field extractor — reads dot-notation paths from parsed JSON ───────────────
function extractField(obj, path) {
  if (!obj || !path) return null;
  const parts = path.replace(/\[(\d+)\]/g, ".$1").split(".");
  let cur = obj;
  for (const part of parts) {
    if (cur === null || cur === undefined) return null;
    cur = cur[part];
  }
  if (cur === null || cur === undefined || cur === "") return null;
  if (Array.isArray(cur)) return cur[0] || null;
  return String(cur);
}

// ── Format helpers ────────────────────────────────────────────────────────────
function formatTimestamp(ts) {
  if (!ts) return null;
  try {
    return new Date(ts).toLocaleString("en-US", {
      month: "short", day: "numeric", year: "numeric",
      hour: "2-digit", minute: "2-digit", timeZoneName: "short"
    });
  } catch { return ts; }
}

// ── Log type detector ─────────────────────────────────────────────────────────
function detectLogType(parsed) {
  if (!parsed || typeof parsed !== "object") return null;
  // O365 login — has o365.audit or ml.distance fields
  // O365 Exchange mailbox audit — has Parameters/forwarding fields
  if (parsed.o365 && parsed.o365.audit && parsed.o365.audit.Parameters) return "o365_exchange";
  // O365 login _source wrapper variant
  if (parsed._source && parsed._source.o365) return "o365_login";
  // O365 login — has o365.audit or ml.distance fields
  if (parsed.o365 || (parsed.ml && parsed.ml.distance)) return "o365_login";
  // Microsoft Defender
  if (parsed.m365_defender) {
    // Flat alerts format
    if (parsed.m365_defender.alerts) return "defender_alerts";
    // Identity/user evidence variant
    const alert = parsed.m365_defender.incident && parsed.m365_defender.incident.alert;
    const evidence = alert && alert.evidence;
    if (evidence && Array.isArray(evidence) && evidence.some(e => e.user_account)) return "defender_identity";
    return "defender";
  }
  // Okta
  if (parsed.okta) return "okta";
  // Cisco Duo
  if (parsed.cisco_duo) return "cisco_duo";
  // Fortigate
  if (parsed.fortinet) return "fortigate";
  // PowerShell Windows event
  if (parsed.powershell) return "windows_powershell";
  // Azure AD Sign-in Logs
  if (parsed.azure && parsed.azure.signinlogs) return "azure_signin";
  // SentinelOne OCSF
  if (parsed.s1_detection_metadata || parsed.finding_info) return "sentinelone";
  // AWS Security Hub / GuardDuty
  if (parsed.aws && parsed.aws.securityhub_findings) return "aws_securityhub";
  // Darktrace — has darktrace field
  if (parsed.darktrace) return "darktrace";
  // Proofpoint TAP — has proofpoint_tap field
  if (parsed.proofpoint_tap) return "proofpoint_tap";
  // Cybereason EDR — _source wrapper with events and organization fields
  if (parsed._source && parsed._source.events) return "cybereason";
  // Windows event log — distinguish scheduled task vs process creation by event ID
  if (parsed.winlog) {
    const eid = String(parsed.winlog.event_id || "");
    // 4698 = task created, 4702 = task updated, 4700 = task enabled, 4701 = task disabled
    if (["4698","4702","4700","4701"].includes(eid)) return "windows_scheduled_task";
    return "windows_event";
  }
  return "unknown";
}

// ── Template definitions ──────────────────────────────────────────────────────
const SMART_TEMPLATES = {
  o365_login: {
    label: "O365 Unusual Login Location",
    subject: (fields) => `Security Alert | O365 Unusual Login | ${fields.customer || "Client"} | ${new Date().toLocaleDateString()}`,
    fields: {
      user:      "user.name",
      sourceIp:  "source.ip",
      city:      "source.geo.city_name",
      country:   "source.geo.country_name",
      time:      "@timestamp",
      miles:     "ml.distance.miles",
      customer:  "customer.name",
    },
    body: (f) =>
`Hello,

${getSettings().orgName} has observed an O365 Unusual Login for the following user.

User: ${f.user || "[user not found]"}
Source IP: ${f.sourceIp || "[IP not found]"}
Location: ${f.city || "[city not found]"}, ${f.country || "[country not found]"}
Time: ${f.time ? formatTimestamp(f.time) : "[time not found]"}
Distance from typical location: ${f.miles || "[distance not found]"} miles

We observed the following user logging in from a location that was not typical and had not previously appeared in the user's history. We wanted to reach out to confirm if this activity was expected. If you have any questions or concerns, please feel free to ask. We are here to help.

Regards,
${analystName} - ${analystTitle}`,
  },

  fortigate: {
    label: "Fortigate Firewall Threat Activity",
    subject: (fields) => `Security Alert | Fortigate Firewall Threat | ${fields.customer || "Client"} | ${new Date().toLocaleDateString()}`,
    fields: {
      customer:    "customer.name",
      attack:      "fortinet.firewall.attack",
      action:      "fortinet.firewall.action",
      sourceIp:    "source.ip",
      srcCountry:  "source.geo.country_name",
      destIp:      "destination.ip",
      destPort:    "destination.port",
      protocol:    "network.transport",
      time:        "@timestamp",
    },
    body: (f) =>
`Hello,

${getSettings().orgName} has observed the following Fortigate Firewall Threat Activity.

Customer: ${f.customer || "[customer not found]"}
Alert: ${f.attack || "[alert not found]"}
Action: ${f.action || "[action not found]"}
Source IP: ${f.sourceIp || "[source IP not found]"}
Source Country: ${f.srcCountry || "[country not found]"}
Destination IP: ${f.destIp || "[destination IP not found]"}
Destination Port: ${f.destPort || "[port not found]"}
Protocol: ${f.protocol || "[protocol not found]"}
Time: ${f.time ? formatTimestamp(f.time) : "[time not found]"}

${getSettings().orgName} has detected suspicious network activity originating from an external source targeting your environment. The activity has been flagged by the firewall's intrusion detection system. If this is not an expected activity, we would recommend adding this IP to your block list if it is not related to your business operations. If you have any questions or concerns, please let us know. We are more than happy to assist.

Regards,
${analystName} - ${analystTitle}`,
  },

  windows_scheduled_task: {
    label: "Suspicious Scheduled Task",
    subject: (fields) => `Security Alert | Suspicious Scheduled Task | ${fields.customer || "Client"} | ${new Date().toLocaleDateString()}`,
    fields: {
      customer:  "customer.name",
      reason:    "event.action",
      description: "event.description",
      hostname:  "host.name",
      taskName:  "winlog.event_data.TaskName",
      cmdline:   "process.command_line",
      subject:   "winlog.event_data.SubjectUserName",
      eventId:   "winlog.event_id",
      time:      "@timestamp",
    },
    body: (f) =>
`Hello,

${getSettings().orgName} has observed the following Suspicious Scheduled Task Activity.

Customer: ${f.customer || "[customer not found]"}
Alert: ${f.reason || "[alert not found]"}
Hostname: ${f.hostname || "[hostname not found]"}
Task Name: ${f.taskName || "[task name not found]"}
Command Line: ${f.cmdline || "[command line not found]"}
Subject User: ${f.subject || "[user not found]"}
Event ID: ${f.eventId || "[event ID not found]"}
Time: ${f.time ? formatTimestamp(f.time) : "[time not found]"}

${getSettings().orgName} has detected a scheduled task event on the above-mentioned host that has triggered a security alert. Scheduled tasks are commonly used by threat actors to establish persistence on an endpoint. We wanted to bring this to your attention and confirm whether this task was expected or authorized. If you have any questions or concerns, please let us know. We are more than happy to assist.

Regards,
${analystName} - ${analystTitle}`,
  },

  windows_event: {
    label: "Suspicious Process Execution",
    subject: (fields) => `Security Alert | Suspicious Process Execution | ${fields.customer || "Client"} | ${new Date().toLocaleDateString()}`,
    fields: {
      customer:    "customer.name",
      reason:      "event.action",
      description: "event.description",
      hostname:    "host.name",
      process:     "process.name",
      cmdline:     "process.command_line",
      parent:      "process.parent.name",
      executable:  "process.executable",
      eventId:     "winlog.event_id",
      time:        "@timestamp",
    },
    body: (f) =>
`Hello,

${getSettings().orgName} has observed the following Suspicious Process Execution Activity.

Customer: ${f.customer || "[customer not found]"}
Alert: ${f.reason || "[alert not found]"}
Hostname: ${f.hostname || "[hostname not found]"}
Process: ${f.process || "[process not found]"}
Command Line: ${f.cmdline || "[command line not found]"}
Parent Process: ${f.parent || "[parent process not found]"}
Executable: ${f.executable || "[executable not found]"}
Event ID: ${f.eventId || "[event ID not found]"}
Time: ${f.time ? formatTimestamp(f.time) : "[time not found]"}

${getSettings().orgName} has detected a process execution event on the above-mentioned host that has triggered a security alert. This activity may indicate unauthorized or suspicious behavior on the endpoint. We wanted to bring this to your attention and confirm whether this activity was expected. If you have any questions or concerns, please let us know. We are more than happy to assist.

Regards,
${analystName} - ${analystTitle}`,
  },
};

// ── Template engine — parses log, detects type, extracts fields, builds email ─
function buildSmartEmail(rawLog) {
  let parsed;
  try { parsed = JSON.parse(rawLog); }
  catch { return { error: "Could not parse log as JSON. Please paste a valid JSON log." }; }

  const logType = detectLogType(parsed);
  const template = SMART_TEMPLATES[logType];

  if (!template) {
    // No template — return lightweight metadata for AI subject suggestion fallback
    return {
      noTemplate: true,
      logType,
      label: logType !== "unknown" ? logType.split("_").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ") : "Unknown",
      meta: {
        reason:   extractField(parsed, "event.action") || extractField(parsed, "event.description") || extractField(parsed, "rule.name") || "",
        action:   extractField(parsed, "event.action")    || "",
        provider: extractField(parsed, "event.provider")  || extractField(parsed, "observer.product") || "",
        customer: extractField(parsed, "customer.name")   || "",
        time:     extractField(parsed, "@timestamp")      || "",
      },
    };
  }

  // Extract all fields defined in the template
  const extracted = {};
  for (const [key, path] of Object.entries(template.fields)) {
    extracted[key] = extractField(parsed, path);
  }

  // Find any missing fields for analyst review
  const missing = Object.entries(extracted)
    .filter(([, v]) => !v)
    .map(([k]) => template.fields[k]);

  return {
    logType,
    label: template.label,
    subject: template.subject(extracted),
    body: template.body(extracted),
    extracted,
    missing,
  };
}


// ── Custom Redaction Engine ───────────────────────────────────────────────────
function applyCustomRedactions(text, customRules) {
  if (!customRules || customRules.length === 0) return text;
  let out = text;
  customRules.forEach(rule => {
    if (!rule.value || !rule.value.trim()) return;
    const escaped = rule.value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    out = out.replace(new RegExp(escaped, "g"), rule.token);
  });
  return out;
}

function CustomRedactionPanel({ text, onRedact }) {
  const [fieldInput, setFieldInput] = React.useState("");
  const [rules, setRules] = React.useState([]);
  const [counter, setCounter] = React.useState(1);
  const [showPanel, setShowPanel] = React.useState(false);
  const [matchCount, setMatchCount] = React.useState(null);

  const handleAdd = () => {
    const val = fieldInput.trim();
    if (!val || !text) return;
    const escaped = val.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const matches = (text.match(new RegExp(escaped, "g")) || []).length;
    if (matches === 0) { setMatchCount(0); return; }
    const token = "[CUSTOM_" + String(counter).padStart(3, "0") + "]";
    const newRules = [...rules, { id: Date.now(), value: val, token, matches }];
    setRules(newRules);
    setCounter(c => c + 1);
    setFieldInput("");
    setMatchCount(null);
    if (onRedact) onRedact(newRules);
  };

  const handleRemove = (id) => {
    const newRules = rules.filter(r => r.id !== id);
    setRules(newRules);
    if (onRedact) onRedact(newRules);
  };

  const handleInputChange = (val) => {
    setFieldInput(val);
    setMatchCount(null);
    if (!val.trim() || !text) return;
    const escaped = val.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    setMatchCount((text.match(new RegExp(escaped, "g")) || []).length);
  };

  return (
    <div style={{borderTop:"1px solid var(--ap-border)",marginTop:"0.25rem",paddingTop:"0.5rem"}}>
      <button onClick={() => setShowPanel(v => !v)}
        style={{background:"none",border:"none",color:"var(--ap-blue-dark)",fontWeight:600,fontSize:"0.72rem",cursor:"pointer",padding:0,display:"flex",alignItems:"center",gap:"0.3rem"}}>
        {showPanel ? "▲" : "▼"} {rules.length > 0 ? "Custom redactions (" + rules.length + " active)" : "Add custom redaction"}
      </button>
      {showPanel && (
        <div style={{display:"flex",flexDirection:"column",gap:"0.5rem",marginTop:"0.5rem"}}>
          <div style={{fontSize:"0.72rem",color:"var(--ap-text-mid)"}}>
            Type a specific value visible in the preview to redact all occurrences. Use ✕ to remove a rule.
          </div>
          <div style={{display:"flex",gap:"0.4rem",alignItems:"center"}}>
            <input
              style={{flex:1,background:"var(--ap-white)",border:"1px solid "+(matchCount===0?"var(--ap-danger)":"var(--ap-border)"),
                borderRadius:"5px",padding:"0.45rem 0.75rem",fontSize:"0.78rem",
                fontFamily:"'Source Code Pro',monospace",color:"var(--ap-text)",outline:"none"}}
              placeholder="Value to redact (e.g. acme-corp-9876, tenant-id-abc)..."
              value={fieldInput}
              onChange={e => handleInputChange(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter") handleAdd(); }}
            />
            {fieldInput.trim() && matchCount !== null && (
              <span style={{fontSize:"0.7rem",fontWeight:600,whiteSpace:"nowrap",
                color:matchCount===0?"var(--ap-danger)":"var(--ap-success)"}}>
                {matchCount===0 ? "No matches" : matchCount+" match"+(matchCount!==1?"es":"")}
              </span>
            )}
            <button onClick={handleAdd} disabled={!fieldInput.trim()||matchCount===0}
              style={{background:"var(--ap-blue)",color:"var(--ap-white)",border:"none",borderRadius:"5px",
                padding:"0.45rem 0.875rem",fontSize:"0.75rem",fontWeight:600,cursor:"pointer",
                fontFamily:"'Montserrat',sans-serif",opacity:(!fieldInput.trim()||matchCount===0)?0.4:1}}>
              Redact
            </button>
          </div>
          {rules.length > 0 && (
            <div style={{display:"flex",flexDirection:"column",gap:"0.3rem"}}>
              {rules.map(rule => (
                <div key={rule.id} style={{display:"flex",alignItems:"center",gap:"0.5rem",
                  background:"var(--ap-white)",border:"1px solid var(--ap-border)",
                  borderRadius:"5px",padding:"0.35rem 0.6rem",fontSize:"0.72rem"}}>
                  <span style={{fontFamily:"monospace",color:"var(--ap-blue-dark)",fontWeight:600}}>{rule.token}</span>
                  <span style={{color:"var(--ap-text-mid)"}}>←</span>
                  <span style={{fontFamily:"monospace",color:"var(--ap-text)",flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{rule.value}</span>
                  <span style={{color:"var(--ap-text-light)",fontSize:"0.68rem"}}>{rule.matches} replaced</span>
                  <button onClick={() => handleRemove(rule.id)}
                    style={{background:"none",border:"none",color:"var(--ap-text-light)",cursor:"pointer",fontSize:"0.75rem",padding:"0 2px",lineHeight:1}}>✕</button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Markdown renderer (no external dep) ──────────────────────────────────────
function MD({ children }) {
  if (!children) return null;
  let text = children;
  const codeBlocks = [];
  text = text.replace(/```(?:[a-zA-Z]*)\n([\s\S]*?)```/g, function(m, code) {
    const idx = codeBlocks.length;
    codeBlocks.push(code.trimEnd());
    return "\u0000CODE" + idx + "\u0000";
  });
  text = text.replace(/^`{1,3}\s*$/gm, "");
  text = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  text = text.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/`([^`\n]{1,200})`/g, "<code>$1</code>");
  text = text.replace(/^### (.+)$/gm, "<h3>$1</h3>");
  text = text.replace(/^## (.+)$/gm, "<h2>$1</h2>");
  text = text.replace(/^# (.+)$/gm, "<h1>$1</h1>");
  const lines = text.split("\n");
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed) { out.push(""); i++; continue; }
    if (/^<[huo]|^\u0000CODE/.test(trimmed)) { out.push(line); i++; continue; }
    if (/^[-*] /.test(trimmed)) {
      const items = [];
      while (i < lines.length && /^[-*] /.test(lines[i].trim())) {
        items.push("<li>" + lines[i].trim().replace(/^[-*] /, "") + "</li>");
        i++;
      }
      out.push("<ul>" + items.join("") + "</ul>");
      continue;
    }
    if (/^\d+\. /.test(trimmed)) {
      const items = [];
      while (i < lines.length && /^\d+\. /.test(lines[i].trim())) {
        items.push("<li>" + lines[i].trim().replace(/^\d+\. /, "") + "</li>");
        i++;
      }
      out.push("<ol>" + items.join("") + "</ol>");
      continue;
    }
    out.push(trimmed);
    i++;
  }
  let result = out.join("\n").split("\n\n").map(function(block) {
    const b = block.trim();
    if (!b) return "";
    if (/^<[huo]|^\u0000CODE/.test(b)) return b;
    return "<p>" + b.replace(/\n/g, "<br/>") + "</p>";
  }).join("\n");
  codeBlocks.forEach(function(code, idx) {
    const escaped = code.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    result = result.replace("\u0000CODE" + idx + "\u0000", "<pre><code>" + escaped + "</code></pre>");
  });
  return <div className="md" dangerouslySetInnerHTML={{ __html: result }} />;
}

// ── Copy helper ───────────────────────────────────────────────────────────────
function useCopy() {
  const [msg, setMsg] = useState("");
  const copy = (text) => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
          setMsg("Copied!");
          setTimeout(() => setMsg(""), 2000);
        }).catch(() => fallbackCopy(text));
      } else {
        fallbackCopy(text);
      }
    } catch {
      fallbackCopy(text);
    }
  };
  const fallbackCopy = (text) => {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.cssText = "position:fixed;left:-9999px;top:-9999px";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      setMsg("Copied!");
    } catch {
      setMsg("Copy failed");
    }
    setTimeout(() => setMsg(""), 2000);
  };
  return [msg, copy];
}

// ── Shared components ─────────────────────────────────────────────────────────
function ResultBox({ content, onCopy, label = "Copy" }) {
  if (!content) return null;
  return (
    <div className="result-box">
      <MD>{content}</MD>
      <button className="copy-btn" onClick={() => onCopy(content)}>{label}</button>
    </div>
  );
}

function Spinner() {
  return <span className="spinner" />;
}

// ── Sections ──────────────────────────────────────────────────────────────────


// ── Threat Intel Enrichment Helpers ──────────────────────────────────────────
const PRIVATE_IP_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|::1$|fc|fd)/;

function extractExternalIPs(text) {
  const matches = text.match(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g) || [];
  return [...new Set(matches.filter(ip => !PRIVATE_IP_RE.test(ip)))].slice(0, 5);
}

function extractHashes(text) {
  const sha256 = [...new Set(text.match(/\b[a-fA-F0-9]{64}\b/g) || [])];
  const md5    = [...new Set(text.match(/\b[a-fA-F0-9]{32}\b/g) || [])];
  const sha1   = [...new Set(text.match(/\b[a-fA-F0-9]{40}\b/g) || [])];
  // Prefer SHA256, fallback to SHA1, then MD5 — limit to 3 total
  return [...sha256, ...sha1, ...md5].slice(0, 3);
}

async function enrichIP(ip) {
  try {
    const res = await fetch("/api/abuseipdb?ip=" + encodeURIComponent(ip) + "&maxAgeInDays=90");
    if (!res.ok) return null;
    const data = await res.json();
    const s = data.summary || {};
    return { ip, score: s.abuse_confidence, reports: s.total_reports, isp: s.isp, country: s.country, is_tor: s.is_tor };
  } catch { return null; }
}

async function enrichHash(hash) {
  try {
    const res = await fetch("/api/virustotal?type=hash&value=" + encodeURIComponent(hash));
    if (!res.ok) return null;
    const data = await res.json();
    const s = data.summary || {};
    return { hash, malicious: s.malicious, total: s.total, tags: s.tags || [], detections: (s.detections || []).slice(0, 3) };
  } catch { return null; }
}

function buildEnrichmentContext(ipResults, hashResults) {
  if (!ipResults.length && !hashResults.length) return "";
  let ctx = "\n\n--- THREAT INTELLIGENCE ENRICHMENT ---\n";
  ctx += "(Automatically gathered before analysis — use this to inform your findings)\n\n";

  if (ipResults.length > 0) {
    ctx += "IP Reputation (AbuseIPDB):\n";
    ipResults.forEach(r => {
      if (!r) return;
      const risk = r.score > 50 ? "HIGH RISK" : r.score > 10 ? "SUSPICIOUS" : "CLEAN";
      ctx += "  " + r.ip + " — " + risk + " (" + r.score + "% abuse confidence, " + r.reports + " reports)";
      if (r.isp) ctx += " | ISP: " + r.isp;
      if (r.country) ctx += " | Country: " + r.country;
      if (r.is_tor) ctx += " | ⚠️ TOR EXIT NODE";
      ctx += "\n";
    });
  }

  if (hashResults.length > 0) {
    ctx += "\nHash Reputation (VirusTotal):\n";
    hashResults.forEach(r => {
      if (!r) return;
      const risk = r.malicious > 5 ? "MALICIOUS" : r.malicious > 0 ? "SUSPICIOUS" : "CLEAN";
      ctx += "  " + r.hash.substring(0, 16) + "... — " + risk + " (" + r.malicious + "/" + r.total + " detections)";
      if (r.detections && r.detections.length > 0) ctx += " | Engines: " + r.detections.map(d => d.engine).join(", ");
      ctx += "\n";
    });
  }

  ctx += "--- END THREAT INTELLIGENCE ---";
  return ctx;
}

function LogAnalysis({ copy, onSendToPlaybook }) {
  const [logs, setLogs] = useState("");
  const [result, setResult] = useState("");
  const [loading, setLoading] = useState(false);
  const [tokenMap, setTokenMap] = useState(null);
  const [showTokenMap, setShowTokenMap] = useState(false);
  const [preview, setPreview] = useState(null);
  const [showPreview, setShowPreview] = useState(false);
  const [customRules, setCustomRules] = useState([]);
  const [enrichment, setEnrichment] = useState(null);  // { ipResults, hashResults, loading }
  const abortRef = useRef(null);

  const isLocal = typeof window !== "undefined" &&
    (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1");

  const clear = () => {
    setLogs(""); setResult(""); setTokenMap(null);
    setShowTokenMap(false); setPreview(null); setShowPreview(false);
    setCustomRules([]); setEnrichment(null);
  };

  const handleInput = (val) => {
    setLogs(val);
    setResult(""); setPreview(null); setTokenMap(null);
    if (!val.trim()) return;
    const { redacted, tokenMap: tMap, wasJSON, logCount } = redactLog(val);
    setTokenMap(Object.keys(tMap).length > 0 ? tMap : null);
    setPreview({ content: redacted, wasJSON, logCount });
  };

  const analyze = async () => {
    if (!logs.trim()) return;
    setLoading(true); setResult(""); setEnrichment(null);
    abortRef.current = new AbortController();
    try {
      const { redacted: baseRedacted, tokenMap: tMap } = redactLog(logs);
      const redacted = applyCustomRedactions(baseRedacted, customRules);
      setTokenMap(Object.keys(tMap).length > 0 ? tMap : null);
      setPreview({ content: redacted, wasJSON: true });

      // ── Parallel threat intel enrichment (local only) ───────────────────────
      let enrichCtx = "";
      if (isLocal) {
        const ips    = extractExternalIPs(redacted);
        const hashes = extractHashes(redacted);
        if (ips.length > 0 || hashes.length > 0) {
          setEnrichment({ loading: true, ips, hashes, ipResults: [], hashResults: [] });
          const [ipResults, hashResults] = await Promise.all([
            Promise.all(ips.map(ip => enrichIP(ip))),
            Promise.all(hashes.map(h => enrichHash(h))),
          ]);
          const validIPs    = ipResults.filter(Boolean);
          const validHashes = hashResults.filter(Boolean);
          setEnrichment({ loading: false, ips, hashes, ipResults: validIPs, hashResults: validHashes });
          enrichCtx = buildEnrichmentContext(validIPs, validHashes);
        }
      }

      // ── Build instruction string cleanly ────────────────────────────────────
      const instruction = [
        "Analyze these logs. Identify the log type and classify the overall finding as:",
        "\u2705 Benign | \u26a0\ufe0f Suspicious | \ud83d\udea8 Malicious.",
        "",
        "Immediately after the classification line, provide a concise Activity Summary using exactly this format:",
        "",
        "**Activity Summary**",
        "**Who:** [the user, account, or entity involved — use token if redacted, note if not available]",
        "**What:** [what activity occurred in plain language — one to two sentences]",
        "**When:** [timestamp from the log — note if not available]",
        "**Where:** [host, network segment, service, or system affected — use token if redacted]",
        "**Why:** [why this is significant — threat context, risk, or technique in plain language]",
        "",
        "Keep each field to two lines maximum. If a value is not present in the log, write \"Not available in log\" — do not guess or infer.",
        "",
        enrichCtx ? "THREAT INTELLIGENCE DATA is included below the log. Incorporate it into your Activity Summary and Findings where relevant — reference specific IPs or hashes by their token and note their threat status." : "",
        "",
        "After the Activity Summary, provide the detailed Findings:",
        "1. What activity was observed — explain the behavior clearly",
        "2. Why it is significant — context, risk, and potential impact",
        "3. Key indicators — specific fields, values, or patterns that drove the classification",
        "",
        "Do NOT provide remediation steps or next steps — remediation is handled separately by the IR Playbook Generator.",
        "If the finding is Suspicious or Malicious, end with a single line: \"\ud83d\udccb Remediation recommended — use the IR Playbook Generator for response steps.\"",
      ].filter(l => l !== null).join("\n");

      await callClaude(
        [{ role: "user", content: buildRedactedPrompt(redacted + enrichCtx, instruction, tMap) }],
        setResult,
        abortRef.current.signal
      );
    } catch (e) { if (e.name !== "AbortError") setResult(`Error: ${e.message}`); }
    finally { setLoading(false); }
  };


  return (
    <div className="section">
      <h2 className="section-title">Log Analysis</h2>
      <label className="field-label">Paste any log data</label>
      <textarea
        className="textarea"
        placeholder="Paste O365, Windows Event, firewall, EDR logs..."
        value={logs}
        onChange={e => handleInput(e.target.value)}
      />

      {preview && (
        <div style={{background:"var(--ap-blue-pale)",border:"1px solid rgba(63,186,234,0.3)",borderLeft:"3px solid var(--ap-blue)",borderRadius:"6px",padding:"0.75rem 1rem",fontSize:"0.8rem"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <span style={{fontWeight:600,color:"var(--ap-navy)"}}>
              &#128737;&#65039; {tokenMap ? Object.keys(tokenMap).length + " value" + (Object.keys(tokenMap).length !== 1 ? "s" : "") + " redacted" : "Pattern sweep applied"} &mdash; {preview.logCount > 1 ? preview.logCount + " logs detected" : preview.wasJSON ? "JSON" : "plain text"}
            </span>
            <div style={{display:"flex",gap:"0.75rem",alignItems:"center"}}>
              {tokenMap && (
                <button onClick={() => setShowTokenMap(v => !v)} style={{background:"none",border:"none",color:"var(--ap-blue-dark)",fontWeight:600,fontSize:"0.72rem",cursor:"pointer"}}>
                  {showTokenMap ? "Hide tokens ▲" : "Show tokens ▼"}
                </button>
              )}
              <button onClick={() => setShowPreview(v => !v)} style={{background:"none",border:"none",color:"var(--ap-blue-dark)",fontWeight:600,fontSize:"0.72rem",cursor:"pointer"}}>
                {showPreview ? "Hide preview ▲" : "Preview redacted ▼"}
              </button>
            </div>
          </div>

          {showTokenMap && tokenMap && (
            <table style={{width:"100%",borderCollapse:"collapse",fontSize:"0.75rem",marginTop:"0.5rem"}}>
              <thead>
                <tr>
                  <th style={{textAlign:"left",padding:"2px 6px",color:"var(--ap-text-mid)",borderBottom:"1px solid var(--ap-border)"}}>Token</th>
                  <th style={{textAlign:"left",padding:"2px 6px",color:"var(--ap-text-mid)",borderBottom:"1px solid var(--ap-border)"}}>Original value</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(tokenMap).map(([token, val]) => (
                  <tr key={token}>
                    <td style={{padding:"2px 6px",fontFamily:"monospace",color:"var(--ap-blue-dark)",fontWeight:600}}>{token}</td>
                    <td style={{padding:"2px 6px",color:"var(--ap-text)",fontFamily:"monospace",wordBreak:"break-word",maxWidth:"260px"}}>{truncateTokenValue(val)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {showPreview && (
            <pre style={{marginTop:"0.5rem",background:"var(--ap-white)",border:"1px solid var(--ap-border)",borderRadius:"4px",padding:"0.6rem",fontSize:"0.72rem",overflowX:"auto",maxHeight:"200px",overflowY:"auto",color:"var(--ap-text)",fontFamily:"'Source Code Pro',monospace",whiteSpace:"pre-wrap",wordBreak:"break-word"}}>
              {applyCustomRedactions(preview.content, customRules)}
            </pre>
          )}
          <CustomRedactionPanel
            text={preview ? applyCustomRedactions(preview.content, customRules) : ""}
            onRedact={setCustomRules}
          />
        </div>
      )}

      <div className="btn-row">
        <button className="btn" onClick={analyze} disabled={loading || !logs.trim()}>
          {loading ? <><Spinner /> Analyzing...</> : "Analyze Logs"}
        </button>
        <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)",width:"auto",padding:"0.55rem 1rem"}} onClick={clear} disabled={!logs && !result}>Clear</button>
      </div>

      {enrichment && (
        <div style={{background:"rgba(39,174,96,0.06)",border:"1px solid rgba(39,174,96,0.25)",borderLeft:"3px solid #27ae60",borderRadius:"6px",padding:"0.65rem 1rem",fontSize:"0.8rem"}}>
          <div style={{fontWeight:600,color:"var(--ap-navy)",marginBottom:"0.4rem"}}>
            {enrichment.loading
              ? <><Spinner /> Gathering threat intelligence...</>
              : "\uD83D\uDD0E Threat Intel Enrichment — included in analysis"}
          </div>
          {!enrichment.loading && (
            <div style={{display:"flex",flexDirection:"column",gap:"0.25rem"}}>
              {enrichment.ipResults.map(r => r && (
                <div key={r.ip} style={{fontSize:"0.75rem",display:"flex",gap:"0.75rem",alignItems:"center"}}>
                  <span style={{fontFamily:"monospace",color:"var(--ap-navy)",fontWeight:600,minWidth:"120px"}}>{r.ip}</span>
                  <span style={{color: r.score > 50 ? "var(--ap-danger)" : r.score > 10 ? "var(--ap-warn)" : "#27ae60", fontWeight:600}}>
                    {r.score > 50 ? "HIGH RISK" : r.score > 10 ? "SUSPICIOUS" : "CLEAN"} ({r.score}%)
                  </span>
                  {r.isp && <span style={{color:"var(--ap-text-light)"}}>{r.isp}</span>}
                  {r.is_tor && <span style={{color:"var(--ap-danger)",fontWeight:600}}>⚠️ TOR</span>}
                </div>
              ))}
              {enrichment.hashResults.map(r => r && (
                <div key={r.hash} style={{fontSize:"0.75rem",display:"flex",gap:"0.75rem",alignItems:"center"}}>
                  <span style={{fontFamily:"monospace",color:"var(--ap-navy)",fontWeight:600,minWidth:"120px"}}>{r.hash.substring(0,16)}...</span>
                  <span style={{color: r.malicious > 5 ? "var(--ap-danger)" : r.malicious > 0 ? "var(--ap-warn)" : "#27ae60", fontWeight:600}}>
                    {r.malicious > 5 ? "MALICIOUS" : r.malicious > 0 ? "SUSPICIOUS" : "CLEAN"} ({r.malicious}/{r.total})
                  </span>
                  {r.detections && r.detections.length > 0 && <span style={{color:"var(--ap-text-light)"}}>{r.detections.map(d => d.engine).join(", ")}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {result && onSendToPlaybook && (
        <button
          onClick={() => { onSendToPlaybook(result); }}
          style={{background:"var(--ap-navy)",border:"none",borderRadius:"6px",color:"var(--ap-blue)",
            fontFamily:"'Montserrat',sans-serif",fontWeight:600,fontSize:"0.78rem",
            padding:"0.55rem 1.1rem",cursor:"pointer",letterSpacing:"0.03em",width:"100%"}}>
          &#128203; Generate IR Playbook from this Analysis
        </button>
      )}
      <ResultBox content={result} onCopy={copy} label="Copy Results" />
    </div>
  );
}



function CsvAnalysis({ copy }) {
  const [result, setResult] = useState("");
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState("");
  const [tokenMap, setTokenMap] = useState(null);
  const [showTokenMap, setShowTokenMap] = useState(false);

  const clear = () => { setResult(""); setTokenMap(null); setShowTokenMap(false); setFileName(""); };

  const handleFile = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setFileName(file.name); setLoading(true); setResult(""); setTokenMap(null);
    const text = await file.text();
    try {
      // Run PII redaction on CSV content before submitting to Claude
      // CSV is treated as plain text — pattern sweep catches inline PII,
      // and any JSON-embedded fields within cells are handled by redactLog
      const { redacted, tokenMap: tMap } = redactLog(text.slice(0, 8000));
      setTokenMap(Object.keys(tMap).length > 0 ? tMap : null);
      await callClaude(
        [{ role: "user", content: buildRedactedPrompt(redacted, "Analyze this CSV data for anomalies, suspicious patterns, or security-relevant findings. Identify key columns.", tMap) }],
        setResult
      );
    } catch (err) { setResult(`Error: ${err.message}`); }
    finally { setLoading(false); }
  };

  return (
    <div className="section border-top">
      <h2 className="section-title">CSV Analysis</h2>
      <label className="file-label">
        <span>{fileName || "Choose CSV file"}</span>
        <input type="file" accept=".csv" onChange={handleFile} style={{ display: "none" }} />
      </label>
      {tokenMap && (
        <div style={{background:"var(--ap-blue-pale)",border:"1px solid rgba(63,186,234,0.3)",borderLeft:"3px solid var(--ap-blue)",borderRadius:"6px",padding:"0.75rem 1rem",fontSize:"0.8rem"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom: showTokenMap ? "0.5rem" : 0}}>
            <span style={{fontWeight:600,color:"var(--ap-navy)"}}>🛡️ PII Redacted — {Object.keys(tokenMap).length} value{Object.keys(tokenMap).length !== 1 ? "s" : ""} masked before submission</span>
            <button onClick={() => setShowTokenMap(v => !v)} style={{background:"none",border:"none",color:"var(--ap-blue-dark)",fontWeight:600,fontSize:"0.75rem",cursor:"pointer"}}>
              {showTokenMap ? "Hide map ▲" : "Show map ▼"}
            </button>
          </div>
          {showTokenMap && (
            <table style={{width:"100%",borderCollapse:"collapse",fontSize:"0.75rem"}}>
              <thead>
                <tr>
                  <th style={{textAlign:"left",padding:"2px 6px",color:"var(--ap-text-mid)",borderBottom:"1px solid var(--ap-border)"}}>Token</th>
                  <th style={{textAlign:"left",padding:"2px 6px",color:"var(--ap-text-mid)",borderBottom:"1px solid var(--ap-border)"}}>Original value</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(tokenMap).map(([token, val]) => (
                  <tr key={token}>
                    <td style={{padding:"2px 6px",fontFamily:"monospace",color:"var(--ap-blue-dark)",fontWeight:600}}>{token}</td>
                    <td style={{padding:"2px 6px",color:"var(--ap-text)",fontFamily:"monospace",wordBreak:"break-word",maxWidth:"260px"}}>{truncateTokenValue(val)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
      {(fileName || result) && <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)"}} onClick={clear}>Clear</button>}
      {loading && <div className="loading-text"><Spinner /> Analyzing CSV...</div>}
      <ResultBox content={result} onCopy={copy} label="Copy Results" />
    </div>
  );
}


// ── IOC Extractor ─────────────────────────────────────────────────────────────
const IOC_PATTERNS = {
  "External IPs":   { regex: /\b(?!10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, color: "#e74c3c" },
  "Internal IPs":   { regex: /\b(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b/g, color: "#e67e22" },
  "Domains":        { regex: /\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|fr|br|nl|eu|info|biz|co|gov|mil|edu|onion|xyz|top|club|site|online|store|live|app|dev)\b/gi, color: "#9b59b6" },
  "SHA256 Hashes":  { regex: /\b[a-fA-F0-9]{64}\b/g, color: "#27ae60" },
  "MD5 Hashes":     { regex: /\b[a-fA-F0-9]{32}\b/g, color: "#16a085" },
  "SHA1 Hashes":    { regex: /\b[a-fA-F0-9]{40}\b/g, color: "#1abc9c" },
  "URLs":           { regex: /https?:\/\/[^\s"'<>\]\[)]+/g, color: "#2980b9" },
  "Email Addresses":{ regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, color: "#8e44ad" },
  "Registry Keys":  { regex: /HK(?:LM|CU|CR|U|CC)\\[^\n"'<>]+/g, color: "#d35400" },
  "File Paths":     { regex: /[A-Za-z]:\\[^\n"'<>]+/g, color: "#7f8c8d" },
  "CVEs":           { regex: /CVE-\d{4}-\d{4,7}/gi, color: "#c0392b" },
};

function extractIOCs(text) {
  const results = {};
  for (const [type, { regex }] of Object.entries(IOC_PATTERNS)) {
    const matches = [...new Set(text.match(new RegExp(regex.source, regex.flags)) || [])];
    // Filter out false positives — version numbers, short sequences
    const filtered = matches.filter(m => {
      if (type === "MD5 Hashes" && /^[0-9.]+$/.test(m)) return false;
      if (type === "Domains" && m.split(".").length < 2) return false;
      return true;
    });
    if (filtered.length > 0) results[type] = filtered;
  }
  return results;
}

function IOCExtractor({ copy }) {
  const [input, setInput] = useState("");
  const [iocs, setIOCs] = useState(null);
  const [copied, setCopied] = useState("");
  const [lookupResults, setLookupResults] = useState({});
  const [lookingUp, setLookingUp] = useState({});

  const isLocal = typeof window !== "undefined" &&
    (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1");

  const extract = () => {
    if (!input.trim()) return;
    setIOCs(extractIOCs(input));
    setLookupResults({});
  };

  const clear = () => { setInput(""); setIOCs(null); setCopied(""); setLookupResults({}); setLookingUp({}); };

  const copyOne = (val) => {
    copy(val);
    setCopied(val);
    setTimeout(() => setCopied(""), 2000);
  };

  const copyAll = () => {
    if (!iocs) return;
    const lines = Object.entries(iocs).flatMap(([type, vals]) =>
      vals.map(v => type + "\t" + v)
    );
    copy("Type\tIndicator\n" + lines.join("\n"));
  };

  const exportCSV = () => {
    if (!iocs) return;
    const rows = Object.entries(iocs).flatMap(([type, vals]) =>
      vals.map(v => '"' + type + '","' + v.replace(/"/g, '""') + '"')
    );
    const csv = "Type,Indicator\n" + rows.join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "cybercat_iocs.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  // Determine what lookup to run per IOC type
  const getLookupType = (iocType) => {
    if (iocType === "External IPs" || iocType === "Internal IPs") return "ip";
    if (iocType === "Domains") return "domain";
    if (iocType === "SHA256 Hashes" || iocType === "MD5 Hashes" || iocType === "SHA1 Hashes") return "hash";
    if (iocType === "URLs") return "url";
    return null;
  };

  const runLookup = async (iocType, val) => {
    const lookupType = getLookupType(iocType);
    if (!lookupType || !isLocal) return;
    const key = val;
    setLookingUp(p => ({ ...p, [key]: true }));
    try {
      let result = null;
      if (lookupType === "ip") {
        const res = await fetch("/api/abuseipdb?ip=" + encodeURIComponent(val));
        if (res.ok) { const d = await res.json(); result = { source: "AbuseIPDB", ...d.summary }; }
      } else {
        const res = await fetch("/api/virustotal?type=" + lookupType + "&value=" + encodeURIComponent(val));
        if (res.ok) { const d = await res.json(); result = { source: "VirusTotal", ...d.summary }; }
      }
      setLookupResults(p => ({ ...p, [key]: result }));
    } catch (e) {
      setLookupResults(p => ({ ...p, [key]: { error: e.message } }));
    } finally {
      setLookingUp(p => ({ ...p, [key]: false }));
    }
  };

  const renderLookupResult = (val) => {
    const r = lookupResults[val];
    if (!r) return null;
    if (r.error) return <span style={{fontSize:"0.68rem",color:"var(--ap-danger)"}}>Error</span>;
    if (r.source === "AbuseIPDB") {
      const risk = r.abuse_confidence > 50 ? "HIGH" : r.abuse_confidence > 10 ? "SUSPICIOUS" : "CLEAN";
      const color = r.abuse_confidence > 50 ? "var(--ap-danger)" : r.abuse_confidence > 10 ? "var(--ap-warn)" : "#27ae60";
      return (
        <span style={{fontSize:"0.68rem",fontWeight:600,color}}>
          {risk} {r.abuse_confidence}% | {r.isp || r.country || ""}
        </span>
      );
    }
    if (r.source === "VirusTotal") {
      const risk = r.malicious > 5 ? "MALICIOUS" : r.malicious > 0 ? "SUSPICIOUS" : "CLEAN";
      const color = r.malicious > 5 ? "var(--ap-danger)" : r.malicious > 0 ? "var(--ap-warn)" : "#27ae60";
      return (
        <span style={{fontSize:"0.68rem",fontWeight:600,color}}>
          {risk} {r.malicious}/{r.total}
        </span>
      );
    }
    return null;
  };

  const totalCount = iocs ? Object.values(iocs).reduce((s, v) => s + v.length, 0) : 0;

  return (
    <div className="section border-top">
      <h2 className="section-title">IOC Extractor</h2>
      <label className="field-label">Paste log analysis output or raw log</label>
      <textarea className="textarea" placeholder="Paste Claude's analysis output or any log text containing IPs, hashes, domains, URLs, registry keys..." value={input} onChange={e => setInput(e.target.value)} style={{minHeight:"100px"}}/>
      <div className="btn-row">
        <button className="btn" onClick={extract} disabled={!input.trim()}>Extract IOCs</button>
        <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)",width:"auto",padding:"0.55rem 1rem"}} onClick={clear} disabled={!input && !iocs}>Clear</button>
      </div>

      {iocs && totalCount === 0 && (
        <div style={{background:"var(--ap-offwhite)",border:"1px solid var(--ap-border)",borderRadius:"6px",padding:"0.75rem 1rem",fontSize:"0.85rem",color:"var(--ap-text-light)",textAlign:"center"}}>
          No indicators found in the provided text.
        </div>
      )}

      {iocs && totalCount > 0 && (
        <div style={{display:"flex",flexDirection:"column",gap:"0.75rem"}}>
          <div style={{background:"var(--ap-navy)",borderRadius:"6px",padding:"0.6rem 1rem",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <span style={{color:"var(--ap-blue)",fontWeight:600,fontSize:"0.8rem",letterSpacing:"0.04em"}}>
              &#128269; {totalCount} indicator{totalCount !== 1 ? "s" : ""} extracted
            </span>
            <div style={{display:"flex",gap:"0.5rem"}}>
              <button onClick={copyAll} style={{background:"none",border:"1px solid rgba(63,186,234,0.4)",borderRadius:"4px",color:"var(--ap-blue)",fontSize:"0.7rem",fontWeight:600,padding:"3px 10px",cursor:"pointer"}}>Copy All</button>
              <button onClick={exportCSV} style={{background:"none",border:"1px solid rgba(63,186,234,0.4)",borderRadius:"4px",color:"var(--ap-blue)",fontSize:"0.7rem",fontWeight:600,padding:"3px 10px",cursor:"pointer"}}>Export CSV</button>
            </div>
          </div>

          {Object.entries(iocs).map(([type, vals]) => {
            const canLookup = isLocal && getLookupType(type) !== null;
            return (
              <div key={type} style={{background:"var(--ap-offwhite)",border:"1px solid var(--ap-border)",borderRadius:"6px",overflow:"hidden"}}>
                <div style={{background:"rgba(26,43,60,0.06)",borderBottom:"1px solid var(--ap-border)",padding:"0.4rem 0.875rem",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <span style={{fontFamily:"'Montserrat',sans-serif",fontSize:"0.72rem",fontWeight:700,textTransform:"uppercase",letterSpacing:"0.08em",color:"var(--ap-text-mid)"}}>
                    {type} <span style={{color:"var(--ap-blue)",marginLeft:"4px"}}>{vals.length}</span>
                  </span>
                  <button onClick={() => copy(vals.join("\n"))} style={{background:"none",border:"none",color:"var(--ap-blue-dark)",fontSize:"0.7rem",fontWeight:600,cursor:"pointer"}}>Copy all</button>
                </div>
                {vals.map((val, i) => (
                  <div key={i} style={{display:"flex",alignItems:"center",padding:"0.45rem 0.875rem",borderBottom: i < vals.length-1 ? "1px solid var(--ap-border)" : "none",gap:"0.5rem",flexWrap:"wrap"}}>
                    <span style={{fontFamily:"'Source Code Pro',monospace",fontSize:"0.78rem",color:"var(--ap-text)",wordBreak:"break-all",flex:1}}>{val}</span>
                    {renderLookupResult(val) && <span style={{flexShrink:0}}>{renderLookupResult(val)}</span>}
                    <div style={{display:"flex",gap:"0.3rem",flexShrink:0}}>
                      {canLookup && !lookupResults[val] && (
                        <button onClick={() => runLookup(type, val)} disabled={lookingUp[val]}
                          style={{background:"rgba(63,186,234,0.1)",border:"1px solid rgba(63,186,234,0.3)",borderRadius:"4px",color:"var(--ap-blue-dark)",fontSize:"0.68rem",fontWeight:600,padding:"2px 7px",cursor:"pointer"}}>
                          {lookingUp[val] ? <Spinner /> : "\uD83D\uDD0E Lookup"}
                        </button>
                      )}
                      <button onClick={() => copyOne(val)} style={{background: copied === val ? "rgba(39,174,96,0.1)" : "none",border:"1px solid " + (copied === val ? "rgba(39,174,96,0.3)" : "var(--ap-border)"),borderRadius:"4px",color: copied === val ? "#27ae60" : "var(--ap-text-light)",fontSize:"0.68rem",fontWeight:600,padding:"2px 8px",cursor:"pointer",transition:"all 0.2s"}}>
                        {copied === val ? "Copied!" : "Copy"}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ThreatIntel({ copy }) {
  const [indicator, setIndicator] = useState("");
  const [vtResult, setVtResult] = useState(null);
  const [abResult, setAbResult] = useState(null);
  const [aiResult, setAiResult] = useState("");
  const [loading, setLoading] = useState(false);
  const [phase, setPhase] = useState(""); // "vt" | "ab" | "ai" | ""
  const [error, setError] = useState("");

  const clear = () => {
    setIndicator(""); setVtResult(null); setAbResult(null);
    setAiResult(""); setLoading(false); setPhase(""); setError("");
  };

  // Detect indicator type
  const detectType = (val) => {
    const v = val.trim();
    if (/^[a-fA-F0-9]{64}$/.test(v)) return "hash";
    if (/^[a-fA-F0-9]{40}$/.test(v)) return "hash";
    if (/^[a-fA-F0-9]{32}$/.test(v)) return "hash";
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)) return "ip";
    if (/^https?:\/\//i.test(v)) return "url";
    if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(v)) return "domain";
    return "unknown";
  };

  const isLocal = typeof window !== "undefined" &&
    (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1");

  const lookup = async () => {
    if (!indicator.trim()) return;
    setLoading(true); setVtResult(null); setAbResult(null); setAiResult(""); setError("");
    const val = indicator.trim();
    const type = detectType(val);
    let vtData = null, abData = null;

    // ── Step 1: VirusTotal ──────────────────────────────────────────────────
    if (isLocal && type !== "unknown") {
      try {
        setPhase("vt");
        const params = new URLSearchParams({ type: type === "hash" ? "hash" : type, value: val });
        const res = await fetch("/api/virustotal?" + params);
        if (res.ok) { vtData = await res.json(); setVtResult(vtData); }
        else {
          const err = await res.json().catch(() => ({}));
          if (err.error && err.error.includes("not configured")) {
            setVtResult({ unavailable: true });
          }
        }
      } catch { setVtResult({ unavailable: true }); }
    }

    // ── Step 2: AbuseIPDB (IPs only) ───────────────────────────────────────
    if (isLocal && type === "ip") {
      try {
        setPhase("ab");
        const res = await fetch("/api/abuseipdb?ip=" + encodeURIComponent(val));
        if (res.ok) { abData = await res.json(); setAbResult(abData); }
        else {
          const err = await res.json().catch(() => ({}));
          if (err.error && err.error.includes("not configured")) {
            setAbResult({ unavailable: true });
          }
        }
      } catch { setAbResult({ unavailable: true }); }
    }

    // ── Step 3: Claude analysis ────────────────────────────────────────────
    setPhase("ai");
    try {
      let contextBlock = "";
      if (vtData && vtData.summary) {
        const s = vtData.summary;
        contextBlock += "VirusTotal Results:\n" +
          "  Malicious detections: " + s.malicious + "/" + s.total + "\n" +
          "  Suspicious: " + s.suspicious + "\n" +
          "  Reputation score: " + s.reputation + "\n" +
          (s.country ? "  Country: " + s.country + "\n" : "") +
          (s.as_owner ? "  AS Owner: " + s.as_owner + "\n" : "") +
          (s.tags && s.tags.length ? "  Tags: " + s.tags.join(", ") + "\n" : "") +
          (s.detections && s.detections.length
            ? "  Top detections: " + s.detections.map(d => d.engine + " (" + d.result + ")").join(", ") + "\n"
            : "") + "\n";
      }
      if (abData && abData.summary) {
        const s = abData.summary;
        contextBlock += "AbuseIPDB Results:\n" +
          "  Abuse confidence score: " + s.abuse_confidence + "%\n" +
          "  Total reports: " + s.total_reports + "\n" +
          "  Country: " + (s.country || "unknown") + "\n" +
          "  ISP: " + (s.isp || "unknown") + "\n" +
          "  Usage type: " + (s.usage_type || "unknown") + "\n" +
          (s.is_tor ? "  ⚠️ TOR exit node\n" : "") +
          (s.last_reported_at ? "  Last reported: " + s.last_reported_at + "\n" : "") + "\n";
      }
      const prompt = "Perform a threat intelligence assessment for this indicator: " + val +
        " (type: " + type + ")\n\n" +
        (contextBlock ? "External intelligence gathered:\n" + contextBlock : "") +
        "Based on" + (contextBlock ? " the above data and" : "") + " your training knowledge, provide:\n" +
        "1. Overall threat verdict (Malicious / Suspicious / Clean / Unknown)\n" +
        "2. Known threat actor associations or malware families if applicable\n" +
        "3. Context on why this indicator is significant\n" +
        "4. Recommended immediate actions\n" +
        "5. Suggested hunting queries or pivot points";
      await callClaude([{ role: "user", content: prompt }], setAiResult);
    } catch (e) { setError("Claude error: " + e.message); }
    finally { setLoading(false); setPhase(""); }
  };

  const isMalicious = vtResult && vtResult.summary && vtResult.summary.malicious > 0;
  const isClean = vtResult && vtResult.summary && vtResult.summary.malicious === 0 && vtResult.summary.suspicious === 0;
  const abuseScore = abResult && abResult.summary ? abResult.summary.abuse_confidence : null;

  return (
    <div className="section">
      <h2 className="section-title">Threat Intelligence</h2>
      <label className="field-label">Indicator (IP, domain, hash, URL)</label>
      <input className="input" placeholder="e.g. 185.220.101.45, evil.com, abc123...sha256"
        value={indicator} onChange={e => setIndicator(e.target.value)}
        onKeyDown={e => e.key === "Enter" && lookup()} />

      <div className="btn-row">
        <button className="btn" onClick={lookup} disabled={loading || !indicator.trim()}>
          {loading
            ? <><Spinner /> {phase === "vt" ? "VirusTotal..." : phase === "ab" ? "AbuseIPDB..." : "Analyzing..."}</>
            : "🔍 Threat Intel Lookup"}
        </button>
        <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)",width:"auto",padding:"0.55rem 1rem"}} onClick={clear} disabled={!indicator && !vtResult && !aiResult}>Clear</button>
      </div>

      {!isLocal && (
        <div style={{background:"#fff8e6",border:"1px solid #f0ad4e",borderLeft:"3px solid #f0ad4e",borderRadius:"6px",padding:"0.65rem 1rem",fontSize:"0.78rem",color:"#7a5800"}}>
          ⚠️ Running in artifact mode — VirusTotal and AbuseIPDB require the local deployment. Claude analysis only.
        </div>
      )}

      {error && (
        <div style={{background:"#fff3f3",border:"1px solid var(--ap-danger)",borderLeft:"3px solid var(--ap-danger)",borderRadius:"6px",padding:"0.65rem 1rem",fontSize:"0.78rem",color:"var(--ap-danger)"}}>
          {error}
        </div>
      )}

      {/* VirusTotal results card */}
      {vtResult && !vtResult.unavailable && vtResult.summary && (
        <div style={{background: isMalicious ? "rgba(231,76,60,0.06)" : isClean ? "rgba(39,174,96,0.06)" : "var(--ap-offwhite)",
          border:"1px solid " + (isMalicious ? "rgba(231,76,60,0.3)" : isClean ? "rgba(39,174,96,0.3)" : "var(--ap-border)"),
          borderLeft:"3px solid " + (isMalicious ? "var(--ap-danger)" : isClean ? "var(--ap-success)" : "var(--ap-text-light)"),
          borderRadius:"6px",padding:"0.75rem 1rem"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"0.5rem"}}>
            <span style={{fontWeight:700,fontSize:"0.78rem",color:"var(--ap-navy)",fontFamily:"'Montserrat',sans-serif",textTransform:"uppercase",letterSpacing:"0.06em"}}>
              VirusTotal
            </span>
            <span style={{fontWeight:700,fontSize:"0.82rem",color: isMalicious ? "var(--ap-danger)" : isClean ? "var(--ap-success)" : "var(--ap-warn)"}}>
              {vtResult.summary.malicious}/{vtResult.summary.total} detections
            </span>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"0.3rem 1rem",fontSize:"0.78rem",marginTop:"0.25rem"}}>
            {vtResult.summary.country && (
              <div><span style={{color:"var(--ap-text-light)",fontSize:"0.68rem",textTransform:"uppercase",letterSpacing:"0.06em"}}>Country</span><div style={{color:"var(--ap-text)",fontWeight:500}}>{vtResult.summary.country}</div></div>
            )}
            {vtResult.summary.as_owner && (
              <div><span style={{color:"var(--ap-text-light)",fontSize:"0.68rem",textTransform:"uppercase",letterSpacing:"0.06em"}}>ASN Owner</span><div style={{color:"var(--ap-text)",fontWeight:500}}>{vtResult.summary.as_owner}</div></div>
            )}
            {vtResult.summary.reputation !== undefined && (
              <div><span style={{color:"var(--ap-text-light)",fontSize:"0.68rem",textTransform:"uppercase",letterSpacing:"0.06em"}}>Reputation</span><div style={{color:vtResult.summary.reputation < 0 ? "var(--ap-danger)" : "var(--ap-success)",fontWeight:600}}>{vtResult.summary.reputation}</div></div>
            )}
            {vtResult.summary.last_analysis_date && (
              <div><span style={{color:"var(--ap-text-light)",fontSize:"0.68rem",textTransform:"uppercase",letterSpacing:"0.06em"}}>Last Scanned</span><div style={{color:"var(--ap-text)",fontWeight:500}}>{vtResult.summary.last_analysis_date.substring(0,10)}</div></div>
            )}
          </div>
          {vtResult.summary.tags && vtResult.summary.tags.length > 0 && (
            <div style={{display:"flex",gap:"0.3rem",flexWrap:"wrap",marginTop:"0.4rem"}}>
              {vtResult.summary.tags.slice(0,5).map(t => (
                <span key={t} style={{background:"rgba(63,186,234,0.12)",color:"var(--ap-blue-dark)",padding:"2px 8px",borderRadius:"10px",fontSize:"0.68rem",fontWeight:600}}>{t}</span>
              ))}
              {vtResult.summary.is_tor && <span style={{background:"rgba(231,76,60,0.12)",color:"var(--ap-danger)",padding:"2px 8px",borderRadius:"10px",fontSize:"0.68rem",fontWeight:600}}>⚠️ TOR</span>}
            </div>
          )}
          {vtResult.summary.detections && vtResult.summary.detections.length > 0 && (
            <div style={{marginTop:"0.5rem",padding:"0.4rem 0.6rem",background:"rgba(231,76,60,0.06)",borderRadius:"4px",fontSize:"0.72rem",color:"var(--ap-danger)"}}>
              <strong>Flagged by:</strong> {vtResult.summary.detections.slice(0,6).map(d => d.engine).join(", ")}
              {vtResult.summary.detections.length > 6 && <span style={{color:"var(--ap-text-light)"}}> +{vtResult.summary.detections.length - 6} more</span>}
            </div>
          )}
        </div>
      )}

      {/* AbuseIPDB results card */}
      {abResult && !abResult.unavailable && abResult.summary && (
        <div style={{background: abuseScore > 50 ? "rgba(231,76,60,0.06)" : abuseScore > 10 ? "rgba(230,126,34,0.06)" : "rgba(39,174,96,0.06)",
          border:"1px solid " + (abuseScore > 50 ? "rgba(231,76,60,0.3)" : abuseScore > 10 ? "rgba(230,126,34,0.3)" : "rgba(39,174,96,0.3)"),
          borderLeft:"3px solid " + (abuseScore > 50 ? "var(--ap-danger)" : abuseScore > 10 ? "var(--ap-warn)" : "var(--ap-success)"),
          borderRadius:"6px",padding:"0.75rem 1rem"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"0.5rem"}}>
            <span style={{fontWeight:700,fontSize:"0.78rem",color:"var(--ap-navy)",fontFamily:"'Montserrat',sans-serif",textTransform:"uppercase",letterSpacing:"0.06em"}}>
              AbuseIPDB
            </span>
            <span style={{fontWeight:700,fontSize:"0.82rem",
              color: abuseScore > 50 ? "var(--ap-danger)" : abuseScore > 10 ? "var(--ap-warn)" : "var(--ap-success)"}}>
              {abuseScore}% abuse confidence
            </span>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"0.3rem 1rem",fontSize:"0.78rem",marginTop:"0.25rem"}}>
            <div><span style={{color:"var(--ap-text-light)",fontSize:"0.68rem",textTransform:"uppercase",letterSpacing:"0.06em"}}>Total Reports</span><div style={{color:"var(--ap-text)",fontWeight:600}}>{abResult.summary.total_reports}</div></div>
            {abResult.summary.isp && <div><span style={{color:"var(--ap-text-light)",fontSize:"0.68rem",textTransform:"uppercase",letterSpacing:"0.06em"}}>ISP</span><div style={{color:"var(--ap-text)",fontWeight:500}}>{abResult.summary.isp}</div></div>}
            {abResult.summary.usage_type && <div><span style={{color:"var(--ap-text-light)",fontSize:"0.68rem",textTransform:"uppercase",letterSpacing:"0.06em"}}>Usage Type</span><div style={{color:"var(--ap-text)",fontWeight:500}}>{abResult.summary.usage_type}</div></div>}
            {abResult.summary.country && <div><span style={{color:"var(--ap-text-light)",fontSize:"0.68rem",textTransform:"uppercase",letterSpacing:"0.06em"}}>Country</span><div style={{color:"var(--ap-text)",fontWeight:500}}>{abResult.summary.country}</div></div>}
            {abResult.summary.domain && <div><span style={{color:"var(--ap-text-light)",fontSize:"0.68rem",textTransform:"uppercase",letterSpacing:"0.06em"}}>Domain</span><div style={{color:"var(--ap-text)",fontWeight:500}}>{abResult.summary.domain}</div></div>}
            {abResult.summary.last_reported_at && <div><span style={{color:"var(--ap-text-light)",fontSize:"0.68rem",textTransform:"uppercase",letterSpacing:"0.06em"}}>Last Reported</span><div style={{color:"var(--ap-text)",fontWeight:500}}>{abResult.summary.last_reported_at.substring(0,10)}</div></div>}
          </div>
          {abResult.summary.is_tor && (
            <div style={{marginTop:"0.4rem"}}>
              <span style={{background:"rgba(231,76,60,0.12)",color:"var(--ap-danger)",padding:"2px 8px",borderRadius:"10px",fontSize:"0.68rem",fontWeight:600}}>⚠️ TOR Exit Node</span>
            </div>
          )}
        </div>
      )}

      {/* Claude AI analysis */}
      {aiResult && <ResultBox content={aiResult} onCopy={copy} label="Copy Intel" />}
    </div>
  );
}

function Playbook({ copy, externalInput, onExternalInputUsed }) {
  const { useEffect, useRef } = React;

  const PHASES = [
    { id: 1, label: "Identification",  icon: "🔍",
      prompt: "Generate ONLY Phase 1 — Identification of an incident response playbook.\n\nInclude:\n- Detection indicators and alert triage steps\n- Log sources to review\n- Initial scope assessment\n- Key questions to answer during identification\n\nBe specific and technical. Use bullet points." },
    { id: 2, label: "Containment",     icon: "🛡️",
      prompt: "Generate ONLY Phase 2 — Containment of an incident response playbook.\n\nInclude:\n- Immediate short-term containment actions\n- Long-term containment strategies\n- Evidence preservation steps\n- Isolation procedures\n\nBe specific and technical. Use bullet points." },
    { id: 3, label: "Eradication",     icon: "🧹",
      prompt: "Generate ONLY Phase 3 — Eradication of an incident response playbook.\n\nInclude:\n- Remove threat artifacts and malicious files\n- Patch or remediate the root cause\n- Registry and persistence cleanup\n- Verification that eradication is complete\n\nBe specific and technical. Use bullet points." },
    { id: 4, label: "Recovery",        icon: "🔄",
      prompt: "Generate ONLY Phase 4 — Recovery of an incident response playbook.\n\nInclude:\n- Steps to restore affected systems safely\n- Validation and monitoring during recovery\n- Return to normal operations criteria\n- Post-recovery verification checks\n\nBe specific and technical. Use bullet points." },
    { id: 5, label: "Lessons Learned", icon: "📋",
      prompt: "Generate ONLY Phase 5 — Lessons Learned of an incident response playbook.\n\nInclude:\n- Post-incident review checklist\n- Root cause analysis\n- Recommended detection improvements\n- Documentation and reporting requirements\n- Process improvement recommendations\n\nBe specific and technical. Use bullet points." },
  ];

  const [details, setDetails] = useState("");
  const [phases, setPhases] = useState({});
  const [expanded, setExpanded] = useState({});
  const [currentPhase, setCurrentPhase] = useState(0);
  const [generating, setGenerating] = useState(false);
  const abortRef = useRef(null);
  const stoppedRef = useRef(false);

  useEffect(() => {
    if (externalInput) {
      setDetails(externalInput);
      setPhases({}); setExpanded({}); setCurrentPhase(0); setGenerating(false);
      stoppedRef.current = false;
      if (onExternalInputUsed) onExternalInputUsed();
    }
  }, [externalInput]);

  const clear = () => {
    if (abortRef.current) abortRef.current.abort();
    stoppedRef.current = true;
    setDetails(""); setPhases({}); setExpanded({});
    setCurrentPhase(0); setGenerating(false);
  };

  const toggleExpand = (id) => setExpanded(v => ({ ...v, [id]: !v[id] }));

  const expandAll = () => {
    const all = {};
    PHASES.forEach(p => { all[p.id] = true; });
    setExpanded(all);
  };

  const stop = () => {
    stoppedRef.current = true;
    if (abortRef.current) abortRef.current.abort();
    setGenerating(false);
    setCurrentPhase(0);
  };

  const generate = async () => {
    if (!details.trim()) return;
    setPhases({}); setExpanded({}); setGenerating(true);
    stoppedRef.current = false;
    abortRef.current = new AbortController();

    for (const phase of PHASES) {
      // Check stop flag at start of each phase — catches between-phase stops
      if (stoppedRef.current || abortRef.current.signal.aborted) {
        setGenerating(false); setCurrentPhase(0); return;
      }

      setCurrentPhase(phase.id);
      setPhases(prev => ({ ...prev, [phase.id]: { content: "", status: "generating" } }));
      setExpanded(prev => ({ ...prev, [phase.id]: true }));

      const prompt = "Incident type: " + details + "\n\n" + phase.prompt;

      try {
        await callClaude(
          [{ role: "user", content: prompt }],
          (chunk) => {
            setPhases(prev => ({ ...prev, [phase.id]: { content: chunk, status: "generating" } }));
          },
          abortRef.current.signal
        );

        // Only mark done if we weren't stopped mid-stream
        if (!stoppedRef.current) {
          setPhases(prev => ({ ...prev, [phase.id]: { ...prev[phase.id], status: "done" } }));
          setTimeout(() => {
            setExpanded(prev => ({ ...prev, [phase.id]: false }));
          }, 2500);
        }
      } catch (e) {
        if (e.name === "AbortError" || stoppedRef.current) {
          // Mark the partial phase as stopped rather than error
          setPhases(prev => {
            const existing = prev[phase.id];
            if (existing && existing.content) {
              return { ...prev, [phase.id]: { ...existing, status: "done" } };
            }
            const updated = { ...prev };
            delete updated[phase.id];
            return updated;
          });
          setGenerating(false); setCurrentPhase(0); return;
        }
        setPhases(prev => ({ ...prev, [phase.id]: { content: "Error: " + e.message, status: "error" } }));
      }
    }

    setGenerating(false);
    setCurrentPhase(0);
  };

  const copyFull = () => {
    const full = PHASES
      .filter(p => phases[p.id] && phases[p.id].content)
      .map(p => "## Phase " + p.id + ": " + p.label + "\n\n" + phases[p.id].content)
      .join("\n\n---\n\n");
    copy("IR Playbook: " + details + "\n\n" + full);
  };

  const allDone = PHASES.every(p => phases[p.id] && phases[p.id].status === "done");
  const anyDone = PHASES.some(p => phases[p.id] && phases[p.id].content);

  const STATUS_ICON  = { generating: "⏳", done: "✅", error: "❌" };
  const STATUS_COLOR = { generating: "var(--ap-blue)", done: "#27ae60", error: "var(--ap-danger)" };

  return (
    <div className="section border-top">
      <h2 className="section-title">IR Playbook Generator</h2>
      <label className="field-label">Describe the incident type</label>
      <textarea className="textarea"
        placeholder="e.g. Ransomware on Windows endpoint, O365 account compromise, lateral movement detected... (or click Generate IR Playbook from Log Analysis to auto-fill)"
        value={details} onChange={e => setDetails(e.target.value)} />

      {generating && (
        <div style={{background:"var(--ap-offwhite)",border:"1px solid var(--ap-border)",borderRadius:"6px",padding:"0.6rem 1rem",fontSize:"0.8rem"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"0.4rem"}}>
            <span style={{fontWeight:600,color:"var(--ap-navy)"}}>
              &#9203; Phase {currentPhase} of 5 — {PHASES[currentPhase-1] && PHASES[currentPhase-1].label}
            </span>
            <button onClick={stop} style={{background:"none",border:"1px solid var(--ap-danger)",borderRadius:"4px",color:"var(--ap-danger)",fontSize:"0.7rem",fontWeight:600,padding:"2px 8px",cursor:"pointer"}}>
              &#9646;&#9646; Stop
            </button>
          </div>
          <div style={{display:"flex",gap:"4px"}}>
            {PHASES.map(p => (
              <div key={p.id} style={{flex:1,height:"6px",borderRadius:"3px",
                background: p.id < currentPhase ? "#27ae60" : p.id === currentPhase ? "var(--ap-blue)" : "var(--ap-border)",
                transition:"background 0.3s"}} />
            ))}
          </div>
        </div>
      )}

      <div className="btn-row">
        {!generating ? (
          <button className="btn" onClick={generate} disabled={!details.trim()}>
            &#9654; Generate IR Playbook
          </button>
        ) : (
          <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)"}} onClick={stop}>
            &#9646;&#9646; Stop Generation
          </button>
        )}
        {anyDone && !generating && (
          <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)",width:"auto",padding:"0.55rem 1rem"}} onClick={expandAll}>
            Expand All
          </button>
        )}
        <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)",width:"auto",padding:"0.55rem 1rem"}} onClick={clear} disabled={!details && !anyDone}>Clear</button>
      </div>

      {PHASES.map(phase => {
        const state    = phases[phase.id];
        const isExpanded   = expanded[phase.id];
        const isPending    = !state;
        const isGenerating = state && state.status === "generating";
        const isDone       = state && state.status === "done";

        if (isPending && !generating && !anyDone) return null;

        return (
          <div key={phase.id} style={{border:"1px solid var(--ap-border)",borderRadius:"8px",overflow:"hidden",opacity:isPending?0.45:1,transition:"opacity 0.3s"}}>
            <div
              onClick={() => !isPending && toggleExpand(phase.id)}
              style={{background:isGenerating?"var(--ap-blue-pale)":isDone?"rgba(39,174,96,0.06)":"var(--ap-offwhite)",
                borderBottom:isExpanded?"1px solid var(--ap-border)":"none",
                padding:"0.65rem 1rem",display:"flex",alignItems:"center",justifyContent:"space-between",
                cursor:isPending?"default":"pointer",userSelect:"none",transition:"background 0.2s"}}>
              <div style={{display:"flex",alignItems:"center",gap:"0.6rem"}}>
                <span style={{fontSize:"0.9rem"}}>{phase.icon}</span>
                <span style={{fontFamily:"'Montserrat',sans-serif",fontWeight:700,fontSize:"0.82rem",color:"var(--ap-navy)"}}>
                  Phase {phase.id} — {phase.label}
                </span>
                {state && (
                  <span style={{fontSize:"0.8rem",color:STATUS_COLOR[state.status]}}>
                    {STATUS_ICON[state.status]}
                  </span>
                )}
                {isPending && <span style={{fontSize:"0.7rem",color:"var(--ap-text-light)",fontWeight:500}}>pending</span>}
                {isGenerating && <span style={{fontSize:"0.7rem",color:"var(--ap-blue)",fontWeight:600}}>live</span>}
              </div>
              {!isPending && (
                <div style={{display:"flex",alignItems:"center",gap:"0.5rem"}}>
                  {isDone && (
                    <button onClick={e => { e.stopPropagation(); copy("## Phase " + phase.id + ": " + phase.label + "\n\n" + state.content); }}
                      style={{background:"none",border:"1px solid var(--ap-border)",borderRadius:"4px",color:"var(--ap-text-mid)",fontSize:"0.68rem",fontWeight:600,padding:"2px 8px",cursor:"pointer"}}>
                      Copy
                    </button>
                  )}
                  <span style={{color:"var(--ap-text-light)",fontSize:"0.75rem"}}>{isExpanded?"▲":"▼"}</span>
                </div>
              )}
            </div>
            {isExpanded && state && state.content && (
              <div style={{padding:"0.875rem 1rem",fontSize:"0.85rem",lineHeight:"1.65",color:"var(--ap-text)",background:"var(--ap-white)",maxWidth:"100%",overflow:"hidden"}}>
                <MD>{state.content}</MD>
              </div>
            )}
          </div>
        );
      })}

      {allDone && (
        <button className="btn" onClick={copyFull} style={{background:"var(--ap-navy)",color:"var(--ap-blue)",border:"none"}}>
          &#128203; Copy Full IR Playbook
        </button>
      )}
    </div>
  );
}

function SmartEmail({ copy, rawLog }) {
  const [log, setLog] = useState(rawLog || "");
  const [result, setResult] = useState(null);
  const [aiReview, setAiReview] = useState("");
  const [loadingAI, setLoadingAI] = useState(false);
  const [editedBody, setEditedBody] = useState("");
  const [editedSubject, setEditedSubject] = useState("");
  const [isEditing, setIsEditing] = useState(false);
  const [suggestedSubjects, setSuggestedSubjects] = useState([]);
  const [loadingSubjects, setLoadingSubjects] = useState(false);
  const [chosenSubject, setChosenSubject] = useState("");

  const generate = () => {
    if (!log.trim()) return;
    const res = buildSmartEmail(log);
    setResult(res);
    setEditedBody(res.body || "");
    setEditedSubject(res.subject || "");
    setAiReview("");
    setIsEditing(false);
    setSuggestedSubjects([]);
    setChosenSubject("");
  };

  const suggestSubjects = async () => {
    if (!result || !result.noTemplate) return;
    setLoadingSubjects(true);
    setSuggestedSubjects([]);
    setChosenSubject("");
    const { meta } = result;
    const parts = [];
    if (meta.reason)   parts.push("Alert: " + meta.reason);
    if (meta.action)   parts.push("Action: " + meta.action);
    if (meta.provider) parts.push("Source: " + meta.provider);
    if (meta.customer) parts.push("Customer: " + meta.customer);
    if (meta.time)     parts.push("Time: " + formatTimestamp(meta.time));
    const context = parts.join(" | ");
    const prompt = "You are a SOC analyst assistant. Based on this security alert metadata, suggest exactly 3 professional email subject lines. "
      + "Format your response as a JSON array of 3 strings only — no explanation, no markdown, no extra text.\n\n"
      + "Alert context: " + context + "\n\n"
      + "Subject format: \"Security Alert | [Alert Type] | [Customer] | [Date]\"\n"
      + "Today: " + new Date().toLocaleDateString();
    try {
      let raw = "";
      await callClaude([{ role: "user", content: prompt }], (chunk) => { raw = chunk; });
      const cleaned = raw.replace(/```json|```/g, "").trim();
      const parsed = JSON.parse(cleaned);
      if (Array.isArray(parsed) && parsed.length > 0) {
        setSuggestedSubjects(parsed.slice(0, 3));
      } else {
        setSuggestedSubjects(["Could not parse suggestions — please type subject manually."]);
      }
    } catch (e) {
      setSuggestedSubjects(["Error: " + e.message]);
    } finally {
      setLoadingSubjects(false);
    }
  };

  const buildFallbackEmail = (subject) => {
    setChosenSubject(subject);
    setEditedSubject(subject);
    const { meta } = result;
    const alertLine = meta.reason
      ? "${getSettings().orgName} has observed the following security alert: " + meta.reason + "."
      : "${getSettings().orgName} has observed the following security alert.";
    const actionLine  = meta.action   ? "\nAction: " + meta.action   : "";
    const sourceLine  = meta.provider ? "\nSource: " + meta.provider : "";
    const timeLine    = meta.time     ? "\nTime: "   + formatTimestamp(meta.time) : "";
    const body = "Hello,\n\n" + alertLine + actionLine + sourceLine + timeLine
      + "\n\nWe wanted to bring this activity to your attention and confirm whether it was expected. "
      + "If you have any questions or concerns, please let us know. We are more than happy to assist."
      + "\n\nRegards,\n" + getSettings().analystName + " - " + getSettings().analystTitle + "";
    setEditedBody(body);
  };

  const runAIReview = async () => {
    if (!log.trim()) return;
    setLoadingAI(true);
    setAiReview("");
    try {
      const { redacted, tokenMap: aiTMap } = redactLog(log);
      const prompt = buildRedactedPrompt(redacted, "You are reviewing a pre-written security alert email. Based on the redacted log below, provide a brief 2-3 sentence analytical commentary that could be appended to the email — describe the risk level, any notable context, and whether the activity warrants urgent follow-up. Keep it professional and concise.", aiTMap)
        + "\n\nDraft email:\n" + editedBody;
      await callClaude([{ role: "user", content: prompt }], setAiReview);
    } catch (e) {
      setAiReview("Error: " + e.message);
    } finally {
      setLoadingAI(false);
    }
  };

  const finalEmail = aiReview
    ? editedBody + "\n\n--- AI Review Note ---\n" + aiReview
    : editedBody;

  return (
    <div className="section">
      <h2 className="section-title">Smart Email Generator</h2>
      <label className="field-label">Paste log (JSON)</label>
      <textarea className="textarea" placeholder="Paste your O365, Windows, Fortigate, Defender, Okta, or Duo log here..." value={log} onChange={e => setLog(e.target.value)} style={{minHeight:"120px"}}/>
      <div className="btn-row">
        <button className="btn" onClick={generate} disabled={!log.trim()}>Generate Email</button>
        <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)",width:"auto",padding:"0.55rem 1rem"}} onClick={() => { setLog(""); setResult(null); setAiReview(""); setEditedBody(""); setEditedSubject(""); setSuggestedSubjects([]); setChosenSubject(""); setIsEditing(false); }} disabled={!log && !result}>Clear</button>
      </div>

      {result && result.error && (
        <div style={{background:"#fff3f3",border:"1px solid #f5c6c6",borderLeft:"3px solid var(--ap-danger)",borderRadius:"6px",padding:"0.75rem 1rem",fontSize:"0.85rem",color:"var(--ap-danger)"}}>
          ⚠️ {result.error}
        </div>
      )}

      {result && result.noTemplate && !chosenSubject && (
        <div style={{display:"flex",flexDirection:"column",gap:"0.75rem"}}>
          <div style={{background:"var(--ap-offwhite)",border:"1px solid var(--ap-border)",borderLeft:"3px solid #f0ad4e",borderRadius:"6px",padding:"0.75rem 1rem",fontSize:"0.85rem"}}>
            <div style={{fontWeight:600,color:"var(--ap-navy)",marginBottom:"0.25rem"}}>
              No template available for: <span style={{color:"var(--ap-blue-dark)"}}>{result.label}</span>
            </div>
            <div style={{color:"var(--ap-text-mid)",fontSize:"0.8rem"}}>
              Claude can suggest 3 subject line options based on the alert metadata. No full log data will be sent — only the alert name, action, source, and customer fields.
            </div>
          </div>
          <button className="btn" onClick={suggestSubjects} disabled={loadingSubjects}>
            {loadingSubjects ? <><Spinner /> Generating subject suggestions...</> : "\u2709\uFE0F Suggest Subject Lines"}
          </button>
          {suggestedSubjects.length > 0 && (
            <div style={{display:"flex",flexDirection:"column",gap:"0.5rem"}}>
              <label className="field-label">Select a subject line</label>
              {suggestedSubjects.map((s, i) => (
                <button key={i} onClick={() => buildFallbackEmail(s)}
                  style={{background:"var(--ap-white)",border:"1px solid var(--ap-border)",borderRadius:"6px",padding:"0.6rem 0.9rem",fontSize:"0.82rem",color:"var(--ap-text)",cursor:"pointer",textAlign:"left"}}>
                  {s}
                </button>
              ))}
              <div style={{fontSize:"0.75rem",color:"var(--ap-text-light)"}}>
                Or type your own subject after selecting one to edit it.
              </div>
            </div>
          )}
        </div>
      )}

      {((result && !result.error && !result.noTemplate) || (result && result.noTemplate && chosenSubject)) && (
        <div style={{display:"flex",flexDirection:"column",gap:"0.75rem"}}>
          <div style={{background:"var(--ap-navy)",borderRadius:"6px",padding:"0.6rem 1rem",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <span style={{color:"var(--ap-blue)",fontWeight:600,fontSize:"0.8rem",letterSpacing:"0.04em"}}>
              {result.noTemplate ? "AI-assisted — " + result.label : result.label}
            </span>
            {result.noTemplate && (
              <button onClick={() => setChosenSubject("")} style={{background:"none",border:"none",color:"rgba(255,255,255,0.5)",fontSize:"0.72rem",cursor:"pointer"}}>&larr; Back</button>
            )}
            {result.missing && result.missing.length > 0 && (
              <span style={{color:"#f0ad4e",fontSize:"0.72rem",fontWeight:600}}>
                &#9888; {result.missing.length} field{result.missing.length !== 1 ? "s" : ""} not found
              </span>
            )}
          </div>

          {result.missing && result.missing.length > 0 && (
            <div style={{background:"#fff8e6",border:"1px solid #f0ad4e",borderRadius:"6px",padding:"0.6rem 0.9rem",fontSize:"0.78rem",color:"#7a5800"}}>
              <strong>Fields not found:</strong> {result.missing.join(", ")} — please fill in manually.
            </div>
          )}

          <div>
            <label className="field-label">Subject</label>
            <input className="input" value={editedSubject} onChange={e => setEditedSubject(e.target.value)} style={{marginTop:"0.3rem"}}/>
          </div>

          <div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"0.3rem"}}>
              <label className="field-label">Email Body</label>
              <button onClick={() => setIsEditing(v => !v)} style={{background:"none",border:"none",color:"var(--ap-blue-dark)",fontWeight:600,fontSize:"0.72rem",cursor:"pointer"}}>
                {isEditing ? "Done editing" : "Edit \u270F\uFE0F"}
              </button>
            </div>
            {isEditing ? (
              <textarea className="textarea" value={editedBody} onChange={e => setEditedBody(e.target.value)} style={{minHeight:"220px",fontFamily:"monospace",fontSize:"0.82rem"}}/>
            ) : (
              <div style={{background:"var(--ap-offwhite)",border:"1px solid var(--ap-border)",borderRadius:"6px",padding:"0.875rem 1rem",fontSize:"0.85rem",lineHeight:"1.7",whiteSpace:"pre-wrap",fontFamily:"monospace"}}>
                {editedBody}
              </div>
            )}
          </div>

          <div style={{display:"flex",gap:"0.5rem"}}>
            <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)"}} onClick={runAIReview} disabled={loadingAI}>
              {loadingAI ? <><Spinner /> AI Review...</> : "\uD83E\uDD16 AI Review"}
            </button>
            <button className="btn" onClick={() => copy(editedSubject + "\n\n" + finalEmail)}>
              Copy Email
            </button>
          </div>

          {aiReview && (
            <div style={{background:"var(--ap-blue-pale)",border:"1px solid rgba(63,186,234,0.3)",borderLeft:"3px solid var(--ap-blue)",borderRadius:"6px",padding:"0.875rem 1rem",fontSize:"0.85rem",lineHeight:"1.65"}}>
              <div style={{fontWeight:600,color:"var(--ap-navy)",marginBottom:"0.4rem",fontSize:"0.78rem",textTransform:"uppercase",letterSpacing:"0.06em"}}>&#128737; AI Review (redacted log used)</div>
              <MD>{aiReview}</MD>
            </div>
          )}
        </div>
      )}
    </div>
  );
}


function TokenMapBanner({ tokenMap, showMap, setShowMap }) {
  if (!tokenMap || Object.keys(tokenMap).length === 0) return null;
  return (
    <div style={{background:"var(--ap-blue-pale)",border:"1px solid rgba(63,186,234,0.3)",borderLeft:"3px solid var(--ap-blue)",borderRadius:"6px",padding:"0.75rem 1rem",fontSize:"0.8rem"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:showMap?"0.5rem":0}}>
        <span style={{fontWeight:600,color:"var(--ap-navy)"}}>&#128737; PII Redacted — {Object.keys(tokenMap).length} value{Object.keys(tokenMap).length!==1?"s":""} masked before submission</span>
        <button onClick={()=>setShowMap(v=>!v)} style={{background:"none",border:"none",color:"var(--ap-blue-dark)",fontWeight:600,fontSize:"0.75rem",cursor:"pointer"}}>
          {showMap?"Hide map ▲":"Show map ▼"}
        </button>
      </div>
      {showMap && (
        <table style={{width:"100%",borderCollapse:"collapse",fontSize:"0.75rem"}}>
          <thead>
            <tr>
              <th style={{textAlign:"left",padding:"2px 6px",color:"var(--ap-text-mid)",borderBottom:"1px solid var(--ap-border)"}}>Token</th>
              <th style={{textAlign:"left",padding:"2px 6px",color:"var(--ap-text-mid)",borderBottom:"1px solid var(--ap-border)"}}>Original value</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(tokenMap).map(([token,val])=>(
              <tr key={token}>
                <td style={{padding:"2px 6px",fontFamily:"monospace",color:"var(--ap-blue-dark)",fontWeight:600}}>{token}</td>
                <td style={{padding:"2px 6px",color:"var(--ap-text)",fontFamily:"monospace",wordBreak:"break-word",maxWidth:"260px"}}>{truncateTokenValue(val)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}


// ── Threat Hunt Query Generator ───────────────────────────────────────────────
function ThreatHuntQuery({ copy }) {
  const [finding, setFinding] = useState("");
  const [language, setLanguage] = useState("kql");
  const [result, setResult] = useState("");
  const [loading, setLoading] = useState(false);
  const [sanitized, setSanitized] = useState(null);
  const [tokenMap, setTokenMap] = useState(null);
  const [showPreview, setShowPreview] = useState(false);
  const [showTokenMap, setShowTokenMap] = useState(false);
  const [customRules, setCustomRules] = useState([]);

  const clear = () => {
    setFinding(""); setResult(""); setSanitized(null);
    setTokenMap(null); setShowPreview(false); setShowTokenMap(false);
    setCustomRules([]);
  };

  const LANGUAGE_LABELS = {
    kql:   "KQL (Elastic / Sentinel)",
    spl:   "SPL (Splunk)",
    sigma: "Sigma (Generic)",
  };

  const handleInput = (val) => {
    setFinding(val);
    setResult(""); setSanitized(null); setTokenMap(null);
    if (!val.trim()) return;
    const { sanitized: s, tokenMap: tMap, wasJSON } = sanitizeForHunt(val);
    setSanitized({ content: s, wasJSON });
    setTokenMap(Object.keys(tMap).length > 0 ? tMap : null);
  };

  const generate = async () => {
    if (!finding.trim()) return;
    setLoading(true); setResult("");
    const { sanitized: rawS, tokenMap: tMap } = sanitizeForHunt(finding);
    const s = applyCustomRedactions(rawS, customRules);
    const instruction = LANGUAGE_LABELS[language] + " Threat Hunt Query Generator.\n\n" +
      "Based on the following sanitized log data, generate comprehensive threat hunting queries. " +
      "Sensitive field values have been removed or redacted — focus on field structure, " +
      "event types, behavioral patterns, and preserved analytical values.\n\n" +
      "Provide:\n" +
      "1. Primary hunt query — clearly formatted and ready to paste into the SIEM\n" +
      "2. What the query hunts for (2-3 sentences)\n" +
      "3. Expected false positives to watch for\n" +
      "4. 2-3 recommended follow-up pivot queries with brief explanations\n" +
      "5. Relevant MITRE ATT&CK techniques if applicable";
    const prompt = buildRedactedPrompt(s, instruction, tMap);
    try {
      await callClaude([{ role: "user", content: prompt }], setResult);
    } catch (e) { setResult("Error: " + e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="section border-top">
      <h2 className="section-title">Threat Hunt Query Generator</h2>

      <label className="field-label">Query language</label>
      <div style={{display:"flex",gap:"0.4rem",marginBottom:"0.25rem"}}>
        {Object.entries(LANGUAGE_LABELS).map(([key, label]) => (
          <button key={key} onClick={() => setLanguage(key)}
            style={{
              flex:1, padding:"0.5rem 0.4rem", borderRadius:"6px", border:"1px solid",
              borderColor: language === key ? "var(--ap-blue)" : "var(--ap-border)",
              background: language === key ? "var(--ap-blue)" : "var(--ap-white)",
              color: language === key ? "var(--ap-white)" : "var(--ap-text-mid)",
              fontFamily:"'Montserrat',sans-serif", fontSize:"0.72rem", fontWeight:600,
              cursor:"pointer", transition:"all 0.15s", letterSpacing:"0.03em",
            }}>
            {key.toUpperCase()}
          </button>
        ))}
      </div>
      <div style={{fontSize:"0.72rem",color:"var(--ap-text-light)",marginBottom:"0.5rem"}}>{LANGUAGE_LABELS[language]}</div>

      <label className="field-label">Paste log or describe finding</label>
      <textarea className="textarea" value={finding} onChange={e => handleInput(e.target.value)}
        placeholder="Paste a full log (JSON or plain text), a portion of a log, or describe a finding. Example: Base64-encoded PowerShell (T1059.001), Scheduled task creation (T1053.005), C2 outbound connection (T1071)"
        style={{minHeight:"120px"}} />

      {sanitized && (
        <div style={{background:"var(--ap-blue-pale)",border:"1px solid rgba(63,186,234,0.3)",borderLeft:"3px solid var(--ap-blue)",borderRadius:"6px",padding:"0.65rem 1rem",fontSize:"0.8rem"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <span style={{fontWeight:600,color:"var(--ap-navy)"}}>
              &#128737;&#65039; {sanitized.wasJSON ? "Log sanitized — values stripped, field structure preserved" : "Plain text — pattern sweep applied"}
            </span>
            <div style={{display:"flex",gap:"0.5rem"}}>
              {tokenMap && (
                <button onClick={() => setShowTokenMap(v => !v)} style={{background:"none",border:"none",color:"var(--ap-blue-dark)",fontWeight:600,fontSize:"0.72rem",cursor:"pointer"}}>
                  {showTokenMap ? "Hide tokens ▲" : "Show tokens ▼"}
                </button>
              )}
              <button onClick={() => setShowPreview(v => !v)} style={{background:"none",border:"none",color:"var(--ap-blue-dark)",fontWeight:600,fontSize:"0.72rem",cursor:"pointer"}}>
                {showPreview ? "Hide preview ▲" : "Preview sanitized ▼"}
              </button>
            </div>
          </div>
          {showTokenMap && tokenMap && (
            <table style={{width:"100%",borderCollapse:"collapse",fontSize:"0.75rem",marginTop:"0.5rem"}}>
              <thead>
                <tr>
                  <th style={{textAlign:"left",padding:"2px 6px",color:"var(--ap-text-mid)",borderBottom:"1px solid var(--ap-border)"}}>Token</th>
                  <th style={{textAlign:"left",padding:"2px 6px",color:"var(--ap-text-mid)",borderBottom:"1px solid var(--ap-border)"}}>Original value</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(tokenMap).map(([token, val]) => (
                  <tr key={token}>
                    <td style={{padding:"2px 6px",fontFamily:"monospace",color:"var(--ap-blue-dark)",fontWeight:600}}>{token}</td>
                    <td style={{padding:"2px 6px",color:"var(--ap-text)",fontFamily:"monospace",wordBreak:"break-word",maxWidth:"260px"}}>{truncateTokenValue(val)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {showPreview && (
            <pre style={{marginTop:"0.5rem",background:"var(--ap-white)",border:"1px solid var(--ap-border)",borderRadius:"4px",padding:"0.6rem",fontSize:"0.72rem",overflowX:"auto",maxHeight:"180px",overflowY:"auto",color:"var(--ap-text)"}}>
              {applyCustomRedactions(sanitized.content, customRules)}
            </pre>
          )}
          <CustomRedactionPanel
            text={sanitized ? applyCustomRedactions(sanitized.content, customRules) : ""}
            onRedact={setCustomRules}
          />
        </div>
      )}

      <div className="btn-row">
        <button className="btn" onClick={generate} disabled={loading || !finding.trim()}>
          {loading ? <><Spinner /> Generating...</> : "Generate Hunt Query"}
        </button>
        <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)",width:"auto",padding:"0.55rem 1rem"}} onClick={clear} disabled={!finding && !result}>Clear</button>
      </div>

      {result && (
        <div style={{display:"flex",flexDirection:"column",gap:"0.5rem"}}>
          <div style={{background:"var(--ap-navy)",borderRadius:"6px 6px 0 0",padding:"0.5rem 1rem",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <span style={{color:"var(--ap-blue)",fontWeight:600,fontSize:"0.78rem",letterSpacing:"0.04em",fontFamily:"'Montserrat',sans-serif"}}>{LANGUAGE_LABELS[language]} Query</span>
            <button onClick={() => copy(result)} style={{background:"none",border:"1px solid rgba(63,186,234,0.4)",borderRadius:"4px",color:"var(--ap-blue)",fontSize:"0.7rem",fontWeight:600,padding:"3px 10px",cursor:"pointer"}}>Copy</button>
          </div>
          <div style={{background:"var(--ap-blue-pale)",border:"1px solid rgba(63,186,234,0.3)",borderTop:"none",borderLeft:"3px solid var(--ap-blue)",borderRadius:"0 0 6px 6px",padding:"0.875rem 1rem",fontSize:"0.85rem",lineHeight:"1.65",color:"var(--ap-text)",minHeight:"120px",overflow:"hidden",maxWidth:"100%"}}>
            <div style={{overflowX:"auto",maxWidth:"100%"}}>
              <MD>{result}</MD>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}



// Global settings getter for use in non-component contexts
function getSettings() {
  try {
    const stored = localStorage.getItem("cybercat_settings");
    return stored ? { ...SETTINGS_DEFAULTS, ...JSON.parse(stored) } : { ...SETTINGS_DEFAULTS };
  } catch { return { ...SETTINGS_DEFAULTS }; }
}

// ── Email Templates ───────────────────────────────────────────────────────────
function getEmailTemplates() {
  const s = getSettings();
  return {
    standard: {
      label: "Standard Informational",
      prompt: function(d) {
        return "Draft a Standard Informational Email. Detail the specific behavior and activity observed from the alert and inquire if the activity is expected. " +
          "Template: Hello, " + s.orgName + " has alerted us regarding [insert alert name]. [insert behavior details]. " +
          "We wanted to verify whether this activity was expected. Please feel free to reach out to us if you have any further questions or concerns. " +
          "We are more than happy to help. Regards, " + s.analystName + " - " + s.analystTitle + ".\n\nIncident details: " + d;
      }
    },
    edr: {
      label: "Cybereason EDR Alert",
      prompt: function(d) {
        return "Draft an EDR Solution Email. Detail specific activity and behavior observed via the alert. " +
          "Template: Hello, we have been alerted by " + s.orgName + " about a Malware Detection by Anti-Malware on device: [insert device name]. " +
          "File: [file name]. File Path: [file path]. Status: [file status]. The file was automatically quarantined by Cybereason and will be removed in 30 days. " +
          "We just wanted to bring this activity to your attention in case this file was expected on the device. " +
          "Please let us know if you have any questions or concerns we are happy to assist. " +
          "Regards, " + s.analystName + " - " + s.analystTitle + ".\n\nIncident details: " + d;
      }
    },
    pup: {
      label: "Potentially Unwanted Program",
      prompt: function(d) {
        return "Draft a PUP Removal Email. Detail the process observed, the specific activity, and threat intelligence status (Malicious or Suspicious). " +
          "Template: Hello, " + s.orgName + " has identified a Potentially Unwanted Program (PUP) on [system]. " +
          "Process: [process]. Path: [path]. Activity: [activity]. [explain and describe the process and identify the known PUP software associated]. " +
          "We recommend performing a full disk scan and quarantining any components of this software that are found. " +
          "Recommend a manual removal process for potentially unwanted programs. " +
          "If you have any further questions or concerns regarding this activity please feel free to reach out to us. " +
          "We are happy to help. Regards, " + s.analystName + " - " + s.analystTitle + ".\n\nIncident details: " + d;
      }
    },
  };
}
const EMAIL_TEMPLATES = getEmailTemplates();

function Communications({ copy }) {
  const [template, setTemplate] = useState("standard");

  // Email state
  const [details, setDetails] = useState("");
  const [emailResult, setEmailResult] = useState("");
  const [loadingEmail, setLoadingEmail] = useState(false);
  const [emailTokenMap, setEmailTokenMap] = useState(null);
  const [showEmailMap, setShowEmailMap] = useState(false);
  const [emailPreview, setEmailPreview] = useState(null);
  const [showEmailPreview, setShowEmailPreview] = useState(false);
  const [emailCustomRules, setEmailCustomRules] = useState([]);

  // Incident state
  const [incidentCtx, setIncidentCtx] = useState("");
  const [summary, setSummary] = useState("");
  const [escalation, setEscalation] = useState("");
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [loadingEscalation, setLoadingEscalation] = useState(false);
  const [incidentTokenMap, setIncidentTokenMap] = useState(null);
  const [showIncidentMap, setShowIncidentMap] = useState(false);
  const [incidentPreview, setIncidentPreview] = useState(null);
  const [showIncidentPreview, setShowIncidentPreview] = useState(false);
  const [incidentCustomRules, setIncidentCustomRules] = useState([]);

  // Close-out state
  const [closeoutCtx, setCloseoutCtx] = useState("");
  const [closeout, setCloseout] = useState("");
  const [loadingCloseout, setLoadingCloseout] = useState(false);
  const [closeoutTokenMap, setCloseoutTokenMap] = useState(null);
  const [showCloseoutMap, setShowCloseoutMap] = useState(false);
  const [closeoutPreview, setCloseoutPreview] = useState(null);
  const [showCloseoutPreview, setShowCloseoutPreview] = useState(false);
  const [closeoutCustomRules, setCloseoutCustomRules] = useState([]);

  // Live redaction handlers — run on every keystroke
  const handleEmailInput = (val) => {
    setDetails(val); setEmailResult(""); setEmailPreview(null); setEmailTokenMap(null);
    if (!val.trim()) return;
    const { redacted, tokenMap: tMap, wasJSON } = redactLog(val);
    setEmailTokenMap(Object.keys(tMap).length > 0 ? tMap : null);
    setEmailPreview({ content: redacted, wasJSON });
  };

  const handleIncidentInput = (val) => {
    setIncidentCtx(val); setSummary(""); setEscalation(""); setIncidentPreview(null); setIncidentTokenMap(null);
    if (!val.trim()) return;
    const { redacted, tokenMap: tMap, wasJSON } = redactLog(val);
    setIncidentTokenMap(Object.keys(tMap).length > 0 ? tMap : null);
    setIncidentPreview({ content: redacted, wasJSON });
  };

  const handleCloseoutInput = (val) => {
    setCloseoutCtx(val); setCloseout(""); setCloseoutPreview(null); setCloseoutTokenMap(null);
    if (!val.trim()) return;
    const { redacted, tokenMap: tMap, wasJSON } = redactLog(val);
    setCloseoutTokenMap(Object.keys(tMap).length > 0 ? tMap : null);
    setCloseoutPreview({ content: redacted, wasJSON });
  };

  // Generation functions
  const genEmail = async () => {
    if (!details.trim()) return;
    setLoadingEmail(true); setEmailResult("");
    try {
      const { redacted: baseR1, tokenMap: tMap } = redactLog(details);
      const redacted = applyCustomRedactions(baseR1, emailCustomRules);
      setEmailTokenMap(Object.keys(tMap).length > 0 ? tMap : null);
      const templates = getEmailTemplates(); // refresh with current settings
      await callClaude([{ role: "user", content: templates[template].prompt(redacted) }], setEmailResult);
    } catch (e) { setEmailResult("Error: " + e.message); }
    finally { setLoadingEmail(false); }
  };

  const genSummary = async () => {
    if (!incidentCtx.trim()) return;
    setLoadingSummary(true); setSummary("");
    try {
      const { redacted: baseR2, tokenMap: tMap } = redactLog(incidentCtx);
      const redacted = applyCustomRedactions(baseR2, incidentCustomRules);
      setIncidentTokenMap(Object.keys(tMap).length > 0 ? tMap : null);
      await callClaude([{ role: "user", content: buildRedactedPrompt(redacted, "Write a concise incident summary. Bold the type, impact, and status. Use bullets for timeline.", tMap) }], setSummary);
    } catch (e) { setSummary("Error: " + e.message); }
    finally { setLoadingSummary(false); }
  };

  const genEscalation = async () => {
    if (!incidentCtx.trim()) return;
    setLoadingEscalation(true); setEscalation("");
    try {
      const { redacted: baseR3, tokenMap: tMap } = redactLog(incidentCtx);
      const redacted = applyCustomRedactions(baseR3, incidentCustomRules);
      setIncidentTokenMap(Object.keys(tMap).length > 0 ? tMap : null);
      await callClaude([{ role: "user", content: buildRedactedPrompt(redacted, "Draft an escalation email for this incident. Include usernames, filenames, systems, hashes where available. Bold critical info.", tMap) }], setEscalation);
    } catch (e) { setEscalation("Error: " + e.message); }
    finally { setLoadingEscalation(false); }
  };

  const genCloseout = async () => {
    if (!closeoutCtx.trim()) return;
    setLoadingCloseout(true); setCloseout("");
    try {
      const { redacted: baseR4, tokenMap: tMap } = redactLog(closeoutCtx);
      const redacted = applyCustomRedactions(baseR4, closeoutCustomRules);
      setCloseoutTokenMap(Object.keys(tMap).length > 0 ? tMap : null);
      await callClaude([{ role: "user", content: buildRedactedPrompt(redacted, "Write brief close-out notes for this alert. Omit PII. Classify the activity (benign/suspicious/malicious), state what was found, and confirm no further action needed or list follow-up items.", tMap) }], setCloseout);
    } catch (e) { setCloseout("Error: " + e.message); }
    finally { setLoadingCloseout(false); }
  };

  // Reusable live preview banner
  const PreviewBanner = ({ preview, tokenMap, showMap, setShowMap, showPreview, setShowPreview }) => {
    if (!preview) return null;
    return (
      <div style={{background:"var(--ap-blue-pale)",border:"1px solid rgba(63,186,234,0.3)",borderLeft:"3px solid var(--ap-blue)",borderRadius:"6px",padding:"0.65rem 1rem",fontSize:"0.8rem"}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <span style={{fontWeight:600,color:"var(--ap-navy)"}}>
            &#128737;&#65039; {tokenMap ? Object.keys(tokenMap).length + " value" + (Object.keys(tokenMap).length !== 1 ? "s" : "") + " redacted" : "Pattern sweep applied"} &mdash; {preview.wasJSON ? "JSON" : "plain text"}
          </span>
          <div style={{display:"flex",gap:"0.6rem",alignItems:"center"}}>
            {tokenMap && (
              <button onClick={() => setShowMap(v => !v)} style={{background:"none",border:"none",color:"var(--ap-blue-dark)",fontWeight:600,fontSize:"0.72rem",cursor:"pointer"}}>
                {showMap ? "Hide tokens ▲" : "Show tokens ▼"}
              </button>
            )}
            <button onClick={() => setShowPreview(v => !v)} style={{background:"none",border:"none",color:"var(--ap-blue-dark)",fontWeight:600,fontSize:"0.72rem",cursor:"pointer"}}>
              {showPreview ? "Hide preview ▲" : "Preview redacted ▼"}
            </button>
          </div>
        </div>
        {showMap && tokenMap && (
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:"0.75rem",marginTop:"0.5rem"}}>
            <thead>
              <tr>
                <th style={{textAlign:"left",padding:"2px 6px",color:"var(--ap-text-mid)",borderBottom:"1px solid var(--ap-border)"}}>Token</th>
                <th style={{textAlign:"left",padding:"2px 6px",color:"var(--ap-text-mid)",borderBottom:"1px solid var(--ap-border)"}}>Original value</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(tokenMap).map(([token, val]) => (
                <tr key={token}>
                  <td style={{padding:"2px 6px",fontFamily:"monospace",color:"var(--ap-blue-dark)",fontWeight:600}}>{token}</td>
                  <td style={{padding:"2px 6px",color:"var(--ap-text)",fontFamily:"monospace",wordBreak:"break-word",maxWidth:"260px"}}>{truncateTokenValue(val)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {showPreview && (
          <pre style={{marginTop:"0.5rem",background:"var(--ap-white)",border:"1px solid var(--ap-border)",borderRadius:"4px",padding:"0.6rem",fontSize:"0.72rem",overflowX:"auto",maxHeight:"180px",overflowY:"auto",color:"var(--ap-text)",fontFamily:"'Source Code Pro',monospace",whiteSpace:"pre-wrap",wordBreak:"break-word"}}>
            {preview.content}
          </pre>
        )}
      </div>
    );
  };

  return (
    <div className="section">
      <h2 className="section-title">Communications</h2>

      <div className="subsection">
        <h3 className="subsection-title">Informational Email</h3>
        <label className="field-label">Template</label>
        <select className="select" value={template} onChange={e => setTemplate(e.target.value)}>
          {Object.entries(getEmailTemplates()).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
        <label className="field-label">Incident details</label>
        <textarea className="textarea" placeholder="Alert type, system affected, detected behavior..." value={details} onChange={e => handleEmailInput(e.target.value)} />
        <PreviewBanner preview={emailPreview} tokenMap={emailTokenMap} showMap={showEmailMap} setShowMap={setShowEmailMap} showPreview={showEmailPreview} setShowPreview={setShowEmailPreview} />
        {emailPreview && <CustomRedactionPanel text={emailPreview.content} onRedact={setEmailCustomRules} />}
        <div className="btn-row">
          <button className="btn" onClick={genEmail} disabled={loadingEmail || !details.trim()}>
            {loadingEmail ? <><Spinner /> Generating...</> : "Generate " + EMAIL_TEMPLATES[template].label}
          </button>
          <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)",width:"auto",padding:"0.55rem 1rem"}} onClick={() => { setDetails(""); setEmailResult(""); setEmailTokenMap(null); setEmailPreview(null); setShowEmailMap(false); setShowEmailPreview(false); }} disabled={!details && !emailResult}>Clear</button>
        </div>
        <ResultBox content={emailResult} onCopy={copy} label="Copy Email" />
      </div>

      <div className="subsection border-top">
        <h3 className="subsection-title">Incident Summary & Escalation</h3>
        <textarea className="textarea" placeholder="General incident context..." value={incidentCtx} onChange={e => handleIncidentInput(e.target.value)} />
        <PreviewBanner preview={incidentPreview} tokenMap={incidentTokenMap} showMap={showIncidentMap} setShowMap={setShowIncidentMap} showPreview={showIncidentPreview} setShowPreview={setShowIncidentPreview} />
        {incidentPreview && <CustomRedactionPanel text={incidentPreview.content} onRedact={setIncidentCustomRules} />}
        <div className="btn-row">
          <button className="btn btn-half" onClick={genSummary} disabled={loadingSummary || !incidentCtx.trim()}>
            {loadingSummary ? <><Spinner /> ...</> : "Summary"}
          </button>
          <button className="btn btn-half" onClick={genEscalation} disabled={loadingEscalation || !incidentCtx.trim()}>
            {loadingEscalation ? <><Spinner /> ...</> : "Escalation Email"}
          </button>
          <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)",gridColumn:"1/-1"}} onClick={() => { setIncidentCtx(""); setSummary(""); setEscalation(""); setIncidentTokenMap(null); setIncidentPreview(null); setShowIncidentMap(false); setShowIncidentPreview(false); }} disabled={!incidentCtx && !summary && !escalation}>Clear</button>
        </div>
        <ResultBox content={summary} onCopy={copy} label="Copy Summary" />
        <ResultBox content={escalation} onCopy={copy} label="Copy Escalation" />
      </div>

      <div className="subsection border-top">
        <h3 className="subsection-title">Close-Out Notes</h3>
        <textarea className="textarea" placeholder="Details for close-out..." value={closeoutCtx} onChange={e => handleCloseoutInput(e.target.value)} />
        <PreviewBanner preview={closeoutPreview} tokenMap={closeoutTokenMap} showMap={showCloseoutMap} setShowMap={setShowCloseoutMap} showPreview={showCloseoutPreview} setShowPreview={setShowCloseoutPreview} />
        {closeoutPreview && <CustomRedactionPanel text={closeoutPreview.content} onRedact={setCloseoutCustomRules} />}
        <div className="btn-row">
          <button className="btn" onClick={genCloseout} disabled={loadingCloseout || !closeoutCtx.trim()}>
            {loadingCloseout ? <><Spinner /> Generating...</> : "Generate Close-Out Notes"}
          </button>
          <button className="btn" style={{background:"rgba(26,43,60,0.08)",color:"var(--ap-navy)",border:"1px solid var(--ap-border)",width:"auto",padding:"0.55rem 1rem"}} onClick={() => { setCloseoutCtx(""); setCloseout(""); setCloseoutTokenMap(null); setCloseoutPreview(null); setShowCloseoutMap(false); setShowCloseoutPreview(false); }} disabled={!closeoutCtx && !closeout}>Clear</button>
        </div>
        <ResultBox content={closeout} onCopy={copy} label="Copy Notes" />
      </div>
    </div>
  );
}


function Chat() {
  const [history, setHistory] = useState([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [history, loading]);

  const send = async () => {
    const text = input.trim();
    if (!text) return;
    const userMsg = { role: "user", content: text };
    const newHistory = [...history, userMsg];
    setHistory(newHistory);
    setInput("");
    setLoading(true);
    let streamed = "";
    setHistory(h => [...h, { role: "assistant", content: "", streaming: true }]);
    try {
      await callClaude(
        newHistory.map(m => ({ role: m.role === "assistant" ? "assistant" : "user", content: m.content })),
        (chunk) => {
          streamed = chunk;
          setHistory(h => h.map((m, i) => i === h.length - 1 ? { ...m, content: chunk } : m));
        }
      );
      setHistory(h => h.map((m, i) => i === h.length - 1 ? { role: "assistant", content: streamed } : m));
    } catch (e) {
      setHistory(h => h.map((m, i) => i === h.length - 1 ? { role: "assistant", content: `Error: ${e.message}` } : m));
    }
    finally { setLoading(false); }
  };

  return (
    <div className="section border-top">
      <h2 className="section-title">Ask the Cyber Cat</h2>
      <div className="chat-box">
        {history.length === 0 && (
          <div className="chat-empty">Ask Cyber Cat anything — threat analysis, MITRE techniques, remediation steps...</div>
        )}
        {history.map((m, i) => (
          <div key={i} className={`chat-msg ${m.role}`}>
            <div className="chat-label">{m.role === "user" ? "You" : "🐱 Cyber Cat"}</div>
            <MD>{m.content}</MD>
          </div>
        ))}
        {loading && (
          <div className="chat-msg assistant">
            <div className="chat-label">🐱 Cyber Cat</div>
            <span className="typing-dots"><span /><span /><span /></span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>
      <div style={{display:"flex",justifyContent:"flex-end",marginBottom:"-0.25rem"}}>
        <button onClick={() => setHistory([])} disabled={history.length === 0} style={{background:"none",border:"none",color:"var(--ap-text-light)",fontSize:"0.72rem",fontWeight:600,cursor:"pointer",padding:"0"}}>Clear chat</button>
      </div>
      <div className="chat-input-row">
        <input
          className="chat-input"
          placeholder="Ask a follow-up question..."
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && !e.shiftKey && send()}
        />
        <button className="chat-send" onClick={send} disabled={loading || !input.trim()}>Send</button>
      </div>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [copyMsg, copy] = useCopy();
  const [resetKey, setResetKey] = useState(0);
  const [playbookInput, setPlaybookInput] = useState("");
  const [settings, updateSettings, resetSettings] = useSettings();
  const [showSettings, setShowSettings] = useState(false);

  const newCase = () => {
    if (window.confirm("Start a new case? This will clear all fields and results.")) {
      setResetKey(k => k + 1);
      setPlaybookInput("");
    }
  };

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&family=Source+Code+Pro:wght@400;600&display=swap');

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        :root {
          --ap-navy: #1a2b3c;
          --ap-navy-mid: #243c4f;
          --ap-navy-light: #2e4d63;
          --ap-blue: #3fbaea;
          --ap-blue-dark: #2d9fd0;
          --ap-blue-pale: #e8f6fd;
          --ap-white: #ffffff;
          --ap-offwhite: #f4f7fa;
          --ap-border: #d0dde8;
          --ap-text: #1a2b3c;
          --ap-text-mid: #4a6278;
          --ap-text-light: #7a96aa;
          --ap-success: #27ae60;
          --ap-warn: #e67e22;
          --ap-danger: #e74c3c;
        }

        body {
          font-family: 'Montserrat', sans-serif;
          background: var(--ap-offwhite);
          color: var(--ap-text);
          min-height: 100vh;
        }

        .app {
          min-height: 100vh;
          background: var(--ap-offwhite);
          padding: 0 0 4rem;
        }

        header {
          background: linear-gradient(135deg, var(--ap-navy) 0%, var(--ap-navy-mid) 60%, var(--ap-navy-light) 100%);
          padding: 1.75rem 2rem;
          display: flex;
          align-items: center;
          gap: 1.25rem;
          border-bottom: 3px solid var(--ap-blue);
          margin-bottom: 2rem;
        }

        .logo-mark {
          width: 64px; height: 60px;
          flex-shrink: 0;
          display: flex; align-items: center; justify-content: center;
        }

        .logo-text {}
        .logo {
          font-family: 'Montserrat', sans-serif;
          font-size: 1.6rem;
          font-weight: 700;
          color: var(--ap-white);
          letter-spacing: 0.04em;
          line-height: 1;
        }
        .logo span { color: var(--ap-blue); }

        .logo-sub {
          font-size: 0.72rem;
          color: rgba(255,255,255,0.5);
          letter-spacing: 0.12em;
          text-transform: uppercase;
          margin-top: 3px;
          font-weight: 500;
        }

        .columns {
          max-width: 1300px;
          margin: 0 auto;
          padding: 0 1.5rem;
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 1.5rem;
        }

        @media (max-width: 900px) { .columns { grid-template-columns: 1fr; } }

        .card {
          background: var(--ap-white);
          border: 1px solid var(--ap-border);
          border-radius: 12px;
          padding: 1.75rem;
          box-shadow: 0 2px 12px rgba(26,43,60,0.07);
          min-width: 0;
          overflow: hidden;
        }

        .section { display: flex; flex-direction: column; gap: 0.75rem; }
        .section + .section { margin-top: 1.75rem; }
        .border-top { border-top: 1px solid var(--ap-border); padding-top: 1.75rem; margin-top: 0.5rem; }

        .section-title {
          font-family: 'Montserrat', sans-serif;
          font-size: 0.95rem;
          font-weight: 700;
          color: var(--ap-navy);
          letter-spacing: 0.04em;
          text-transform: uppercase;
          padding-bottom: 0.4rem;
          border-bottom: 2px solid var(--ap-blue);
          display: inline-block;
          margin-bottom: 0.25rem;
        }

        .subsection { display: flex; flex-direction: column; gap: 0.6rem; }
        .subsection-title {
          font-size: 0.78rem;
          font-weight: 600;
          color: var(--ap-text-mid);
          text-transform: uppercase;
          letter-spacing: 0.1em;
        }

        .field-label {
          font-size: 0.72rem;
          font-weight: 600;
          color: var(--ap-text-light);
          text-transform: uppercase;
          letter-spacing: 0.09em;
        }

        .textarea, .input, .select {
          width: 100%;
          background: var(--ap-offwhite);
          border: 1px solid var(--ap-border);
          border-radius: 6px;
          color: var(--ap-text);
          font-family: 'Montserrat', sans-serif;
          font-size: 0.875rem;
          padding: 0.625rem 0.75rem;
          outline: none;
          transition: border-color 0.2s, box-shadow 0.2s;
          resize: vertical;
        }
        .textarea { min-height: 110px; }
        .textarea:focus, .input:focus, .select:focus {
          border-color: var(--ap-blue);
          box-shadow: 0 0 0 3px rgba(63,186,234,0.15);
          background: var(--ap-white);
        }
        .select { appearance: none; cursor: pointer; }
        ::placeholder { color: var(--ap-text-light); opacity: 1; }

        .file-label {
          display: block;
          background: var(--ap-offwhite);
          border: 1.5px dashed var(--ap-border);
          border-radius: 6px;
          padding: 0.85rem;
          font-size: 0.85rem;
          color: var(--ap-text-light);
          cursor: pointer;
          text-align: center;
          transition: border-color 0.2s, background 0.2s;
          font-weight: 500;
        }
        .file-label:hover { border-color: var(--ap-blue); background: var(--ap-blue-pale); color: var(--ap-blue-dark); }

        .btn {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 0.4rem;
          background: var(--ap-blue);
          border: none;
          border-radius: 6px;
          color: var(--ap-white);
          font-family: 'Montserrat', sans-serif;
          font-size: 0.82rem;
          font-weight: 600;
          letter-spacing: 0.04em;
          padding: 0.6rem 1.2rem;
          cursor: pointer;
          transition: background 0.2s, transform 0.1s;
          width: 100%;
        }
        .btn:hover:not(:disabled) { background: var(--ap-blue-dark); }
        .btn:active:not(:disabled) { transform: scale(0.98); }
        .btn:disabled { opacity: 0.45; cursor: not-allowed; }
        .btn-row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
        .btn-half { width: 100%; }

        .result-box {
          background: var(--ap-blue-pale);
          border: 1px solid rgba(63,186,234,0.3);
          border-left: 3px solid var(--ap-blue);
          border-radius: 6px;
          padding: 0.875rem 1rem;
          font-size: 0.85rem;
          line-height: 1.65;
          color: var(--ap-text);
        }

        .copy-btn {
          display: inline-block;
          margin-top: 0.6rem;
          background: none;
          border: none;
          color: var(--ap-blue-dark);
          font-size: 0.75rem;
          font-family: 'Montserrat', sans-serif;
          font-weight: 600;
          cursor: pointer;
          opacity: 0.8;
          padding: 0;
          letter-spacing: 0.04em;
        }
        .copy-btn:hover { opacity: 1; text-decoration: underline; }

        .md h1, .md h2, .md h3 { color: var(--ap-navy); font-size: 0.9rem; margin: 0.5rem 0 0.25rem; font-weight: 700; }
        .md pre { background: rgba(26,43,60,0.06); border: 1px solid var(--ap-border); border-radius: 4px; padding: 0.6rem 0.75rem; margin: 0.4rem 0; overflow-x: auto; max-width: 100%; box-sizing: border-box; }
        .md pre code { background: none; padding: 0; font-size: 0.78rem; color: var(--ap-navy); white-space: pre; word-break: normal; display: block; }
        .md ol { padding-left: 1.25rem; }
        .md ol li { margin: 0.2rem 0; }
        .md strong { color: var(--ap-navy); font-weight: 700; }
        .md code { background: rgba(63,186,234,0.15); padding: 0.1em 0.4em; border-radius: 3px; font-family: 'Source Code Pro', monospace; font-size: 0.82em; color: var(--ap-navy-mid); }
        .md ul { padding-left: 1.25rem; }
        .md li { margin: 0.2rem 0; }
        .md p { margin: 0.35rem 0; }

        .chat-box {
          background: var(--ap-offwhite);
          border: 1px solid var(--ap-border);
          border-radius: 8px;
          padding: 1rem;
          height: 340px;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          scrollbar-width: thin;
          scrollbar-color: var(--ap-border) transparent;
        }

        .chat-empty { color: var(--ap-text-light); font-size: 0.85rem; text-align: center; margin: auto; }

        .chat-msg { display: flex; flex-direction: column; gap: 0.2rem; max-width: 88%; }
        .chat-msg.user { align-self: flex-end; }
        .chat-msg.assistant { align-self: flex-start; }

        .chat-label { font-size: 0.68rem; font-weight: 600; color: var(--ap-text-light); margin-bottom: 2px; letter-spacing: 0.06em; text-transform: uppercase; }
        .chat-msg.user .chat-label { text-align: right; }

        .chat-msg.user .md, .chat-msg.user > * {
          background: var(--ap-navy);
          color: var(--ap-white);
          border-radius: 10px 10px 2px 10px;
          padding: 0.55rem 0.85rem;
          font-size: 0.875rem;
        }
        .chat-msg.user .md p { color: var(--ap-white); }
        .chat-msg.assistant .md, .chat-msg.assistant > * {
          background: var(--ap-white);
          border: 1px solid var(--ap-border);
          border-radius: 10px 10px 10px 2px;
          padding: 0.55rem 0.85rem;
          font-size: 0.875rem;
          color: var(--ap-text);
        }

        .typing-dots { display: inline-flex; gap: 4px; padding: 0.55rem 0.85rem; background: var(--ap-white); border: 1px solid var(--ap-border); border-radius: 10px 10px 10px 2px; }
        .typing-dots span {
          width: 6px; height: 6px; border-radius: 50%; background: var(--ap-blue);
          animation: bounce 1s infinite;
        }
        .typing-dots span:nth-child(2) { animation-delay: 0.15s; }
        .typing-dots span:nth-child(3) { animation-delay: 0.3s; }
        @keyframes bounce { 0%,80%,100% { transform: translateY(0); opacity: 0.35; } 40% { transform: translateY(-5px); opacity: 1; } }

        .chat-input-row { display: flex; gap: 0.5rem; margin-top: 0.4rem; }
        .chat-input {
          flex: 1;
          background: var(--ap-white);
          border: 1px solid var(--ap-border);
          border-radius: 6px;
          color: var(--ap-text);
          font-family: 'Montserrat', sans-serif;
          font-size: 0.875rem;
          padding: 0.6rem 0.75rem;
          outline: none;
          transition: border-color 0.2s, box-shadow 0.2s;
        }
        .chat-input:focus { border-color: var(--ap-blue); box-shadow: 0 0 0 3px rgba(63,186,234,0.15); }
        .chat-send {
          background: var(--ap-navy);
          border: none;
          border-radius: 6px;
          color: var(--ap-white);
          font-family: 'Montserrat', sans-serif;
          font-size: 0.8rem;
          font-weight: 600;
          padding: 0.6rem 1.1rem;
          cursor: pointer;
          transition: background 0.2s;
          white-space: nowrap;
        }
        .chat-send:hover:not(:disabled) { background: var(--ap-navy-light); }
        .chat-send:disabled { opacity: 0.4; cursor: not-allowed; }

        .loading-text {
          display: flex; align-items: center; gap: 0.5rem;
          font-size: 0.8rem; color: var(--ap-text-light);
          font-weight: 500;
        }

        .spinner {
          display: inline-block;
          width: 13px; height: 13px;
          border: 2px solid rgba(63,186,234,0.3);
          border-top-color: var(--ap-blue);
          border-radius: 50%;
          animation: spin 0.7s linear infinite;
          flex-shrink: 0;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        .toast {
          position: fixed; bottom: 1.5rem; right: 1.5rem;
          background: var(--ap-navy);
          border-left: 3px solid var(--ap-blue);
          border-radius: 6px;
          color: var(--ap-white);
          font-family: 'Montserrat', sans-serif;
          font-size: 0.8rem;
          font-weight: 600;
          padding: 0.65rem 1.2rem;
          box-shadow: 0 4px 16px rgba(26,43,60,0.2);
          z-index: 999;
          animation: fadeIn 0.2s ease;
        }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>

      <div className="app">
        <header>
          <div className="logo-mark">
            <div style={{width:"56px",height:"56px",background:"var(--ap-blue)",borderRadius:"10px",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"1.6rem",flexShrink:0}}>
              🐱
            </div>
          </div>
          <div className="logo-text">
            <div className="logo">Cyber<span>Cat</span></div>
            <div className="logo-sub">AI-powered triage & incident response</div>
          </div>
          <div style={{display:"flex",gap:"0.5rem",marginLeft:"auto"}}>
            <button onClick={() => setShowSettings(true)} style={{background:"rgba(63,186,234,0.12)",border:"1px solid rgba(63,186,234,0.35)",borderRadius:"6px",color:"var(--ap-blue)",fontFamily:"'Montserrat',sans-serif",fontWeight:600,fontSize:"0.78rem",padding:"0.55rem 1.1rem",cursor:"pointer",letterSpacing:"0.04em",transition:"background 0.2s"}}>
              &#9881;&#65039; Settings
            </button>
            <button onClick={newCase} style={{background:"rgba(63,186,234,0.12)",border:"1px solid rgba(63,186,234,0.35)",borderRadius:"6px",color:"var(--ap-blue)",fontFamily:"'Montserrat',sans-serif",fontWeight:600,fontSize:"0.78rem",padding:"0.55rem 1.1rem",cursor:"pointer",letterSpacing:"0.04em",transition:"background 0.2s"}}>
              &#8635; New Case
            </button>
          </div>
        </header>
        {showSettings && (
          <SettingsModal
            settings={settings}
            onUpdate={updateSettings}
            onReset={resetSettings}
            onClose={() => setShowSettings(false)}
          />
        )}

        <div className="columns">
          <div className="card" key={"left-" + resetKey}>
            <LogAnalysis copy={copy} onSendToPlaybook={setPlaybookInput} />
            <CsvAnalysis copy={copy} />
            <IOCExtractor copy={copy} />
            <ThreatHuntQuery copy={copy} />
            <Chat />
          </div>
          <div className="card" key={"right-" + resetKey}>
            <ThreatIntel copy={copy} />
            <Playbook copy={copy} externalInput={playbookInput} onExternalInputUsed={() => setPlaybookInput("")} />
            <SmartEmail copy={copy} />
            <Communications copy={copy} />
          </div>
        </div>
      </div>

      {copyMsg && <div className="toast">{copyMsg}</div>}
    </>
  );
}
