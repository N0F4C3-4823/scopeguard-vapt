const state = {
  page: "overview",
  selectedId: new URLSearchParams(location.search).get("assessment"),
  eventSource: null,
  detail: null,
  wizard: null,
  resultFilters: { search: "", status: "all" },
};

const phases = [
  "Preflight", "Dependencies", "Scope Validation", "Discovery", "Service Enumeration",
  "Security Checks", "Evidence Verification", "AI Triage", "Report Generation", "Packaging", "Complete",
];
const stageGroups = [
  { label: "Preparing environment", phases: ["Preflight", "Dependencies"] },
  { label: "Checking targets", phases: ["Scope Validation"] },
  { label: "Discovering services", phases: ["Discovery", "Service Enumeration"] },
  { label: "Running security checks", phases: ["Security Checks"] },
  { label: "Validating evidence", phases: ["Evidence Verification"] },
  { label: "Analyzing results", phases: ["AI Triage"] },
  { label: "Generating reports", phases: ["Report Generation", "Packaging"] },
  { label: "Completed", phases: ["Complete"] },
];
const assessmentTypeLabels = {
  external_unauthenticated: "External network assessment — unauthenticated",
  internal_unauthenticated: "Internal network assessment — unauthenticated",
  internal_authenticated: "Internal network assessment — authenticated",
  custom_hybrid: "Custom / hybrid assessment",
};
const assessmentTypes = [
  {
    id: "external_unauthenticated",
    title: "External network assessment",
    subtitle: "Unauthenticated",
    description: "Checks systems reachable from outside your organization without login credentials.",
  },
  {
    id: "internal_unauthenticated",
    title: "Internal network assessment",
    subtitle: "Unauthenticated",
    description: "Checks systems visible from an authorized internal network without credentials.",
  },
  {
    id: "internal_authenticated",
    title: "Internal network assessment",
    subtitle: "Authenticated",
    description: "Adds approved credentials and internal access to the assessment context.",
  },
  {
    id: "custom_hybrid",
    title: "Custom / hybrid assessment",
    subtitle: "Flexible scope",
    description: "Combines approved external and internal capabilities for a defined engagement.",
  },
];
const pageMeta = {
  overview: ["Workspace / Dashboard", "Assessment dashboard"],
  "new-assessment": ["Workspace / New assessment", "Create an assessment"],
  "active-assessments": ["Workspace / Active", "Active assessments"],
  history: ["Workspace / Assessments", "Assessment history"],
  findings: ["Workspace / Findings", "Findings"],
  evidence: ["Workspace / Evidence", "Evidence explorer"],
  reports: ["Workspace / Reports", "Reports & downloads"],
  "local-ai": ["System / Local AI", "Local AI controls"],
  tools: ["System / Dependencies", "Tools & dependencies"],
  settings: ["System / Settings", "Settings"],
  assessment: ["Workspace / Assessment", "Assessment workspace"],
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
}[char]));
const toArray = (value) => Array.isArray(value) ? value : (value ? [value] : []);
const formatDate = (value) => value ? new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "—";
const formatBytes = (value) => {
  if (!Number.isFinite(Number(value))) return "Unavailable";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
};
const statusBadge = (status) => `<span class="status-badge status-${escapeHtml(status)}" role="status">${escapeHtml(String(status).replaceAll("_", " "))}</span>`;
const api = async (path, options = {}) => {
  const response = await fetch(path, { headers: { "Content-Type": "application/json", ...(options.headers || {}) }, ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
};
const toast = (message) => {
  const element = $("#toast");
  element.textContent = message;
  element.classList.add("show");
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => element.classList.remove("show"), 3400);
};

function metric(label, value, hint, className = "metric-blue") {
  return `<div class="metric-card ${className}"><div class="label">${escapeHtml(label)}</div><div class="metric">${escapeHtml(value)}</div><div class="hint">${escapeHtml(hint)}</div></div>`;
}
function healthRow(label, value, good) {
  return `<div class="evidence-item"><span class="status-indicator ${good ? "success" : "warning"}" aria-hidden="true"></span><div><strong>${escapeHtml(label)}</strong><div class="small muted">${escapeHtml(value)}</div></div></div>`;
}
function setPage(page) {
  state.page = page;
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.page === page));
  const [breadcrumb, title] = pageMeta[page] || pageMeta.overview;
  $("#breadcrumb").textContent = breadcrumb;
  $("#page-title").textContent = title;
  $("#sidebar").classList.remove("open");
  const params = new URLSearchParams(location.search);
  if (page === "assessment" && state.selectedId) params.set("assessment", state.selectedId);
  else params.delete("assessment");
  history.replaceState({}, "", `${location.pathname}${params.toString() ? `?${params}` : ""}`);
  renderPage().catch((error) => {
    $("#app").innerHTML = `<div class="callout danger" role="alert"><strong>We could not load this screen.</strong><br>${escapeHtml(error.message)}</div>`;
  });
}
async function renderPage() {
  if (state.page === "overview") return renderOverview();
  if (state.page === "new-assessment") return renderNewAssessment();
  if (state.page === "assessment") return renderAssessment(state.selectedId);
  if (state.page === "active-assessments") return renderActive();
  if (state.page === "history") return renderHistory();
  if (state.page === "findings") return renderFindings();
  if (state.page === "evidence") return renderEvidence();
  if (state.page === "reports") return renderReports();
  if (state.page === "local-ai") return renderAI();
  if (state.page === "tools") return renderTools();
  return renderSettings();
}

function distribution(data) {
  const values = [
    ["Confirmed findings", data.confirmed_findings, "#b44452"],
    ["Verified negatives", data.verified_negatives, "#21805d"],
    ["Not applicable", data.not_applicable, "#9a681c"],
    ["Inconclusive", data.inconclusive, "#7b8797"],
  ];
  const max = Math.max(1, ...values.map((item) => item[1]));
  return `<div class="tree">${values.map(([label, value, color]) => `<div><div class="progress-meta"><span>${label}</span><strong>${value}</strong></div><div class="progress"><span style="width:${Math.max(3, value / max * 100)}%;background:${color}"></span></div></div>`).join("")}</div>`;
}
function recentTable(rows) {
  if (!rows.length) return `<div class="empty"><strong>No assessments yet</strong>Create a controlled local assessment to see persisted results here.</div>`;
  return `<div class="table-wrap"><table><thead><tr><th>Assessment</th><th>Targets</th><th>Type</th><th>Status</th><th>Created</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>${rows.map((row) => `<tr><td><strong>${escapeHtml(row.name)}</strong>${row.client_name ? `<div class="small muted">${escapeHtml(row.client_name)}</div>` : `<div class="small muted">${escapeHtml(row.id)}</div>`}</td><td>${row.target_count}</td><td><span class="small">${escapeHtml(assessmentTypeLabels[row.assessment_type] || row.assessment_type)}</span></td><td>${statusBadge(row.status)}</td><td>${formatDate(row.created_at)}</td><td><button class="button button-quiet button-small" data-open-assessment="${escapeHtml(row.id)}">Open</button></td></tr>`).join("")}</tbody></table></div>`;
}
async function renderOverview() {
  const [data, dependency] = await Promise.all([api("/api/overview"), api("/api/dependencies")]);
  $("#app").innerHTML = `
    <div class="page-intro"><div><h2>Welcome to ScopeGuard</h2><p>Build an authorized scope, choose the right assessment context, and follow the evidence-backed result through to export.</p></div><div class="page-intro-actions"><span class="tag">Local only · no default targets</span><button class="button button-primary" data-page="new-assessment">＋ Start an assessment</button></div></div>
    <section class="cards">
      ${metric("Assessments", data.total_assessments, "persisted locally", "metric-blue")}
      ${metric("Targets assessed", data.total_targets, "across stored runs", "metric-slate")}
      ${metric("Confirmed findings", data.confirmed_findings, "deterministic evidence", "metric-red")}
      ${metric("Verified negatives", data.verified_negatives, "complete checks only", "metric-green")}
      ${metric("Inconclusive", data.inconclusive, "uncertainty preserved", "metric-amber")}
    </section>
    <section class="grid-2">
      <div class="panel"><div class="panel-header"><div><h2>Recent assessments</h2><p>Open an assessment to see activity, results, evidence, and reports.</p></div><button class="button button-link" data-page="history">View all</button></div>${recentTable(data.recent)}</div>
      <div class="panel"><div class="panel-header"><div><h2>Result distribution</h2><p>Stored classifications across all assessments.</p></div></div>${distribution(data)}<div class="callout" style="margin-top:18px">FOUND and NOT_FOUND are produced by deterministic evidence rules. NA and INCONCLUSIVE remain visible instead of being forced into a conclusion.</div></div>
    </section>
    <section class="grid-3">
      <div class="panel"><div class="panel-header"><div><h2>System health</h2><p>Local dependencies and runtime.</p></div></div><div class="tree">${healthRow("Backend", "Healthy", true)}${healthRow("Python", dependency.python, true)}${healthRow("WSL", dependency.wsl ? "Detected" : "Not detected", dependency.wsl)}${healthRow("Ollama", dependency.ollama.reachable ? "Reachable" : "Unavailable", dependency.ollama.reachable)}</div></div>
      <div class="panel"><div class="panel-header"><div><h2>Decision quality</h2><p>Honest state totals.</p></div></div><div class="tree">${healthRow("Not applicable", data.not_applicable, true)}${healthRow("Execution errors", data.error_assessments, data.error_assessments === 0)}${healthRow("Running now", data.running_assessments, data.running_assessments === 0)}</div></div>
      <div class="panel"><div class="panel-header"><div><h2>Start safely</h2><p>A guided first run takes four steps.</p></div></div><div class="callout success">Use <code>fixture://mixed</code> to explore the complete workflow without probing a network.</div><button class="button button-primary" style="margin-top:15px" data-page="new-assessment">Create assessment</button></div>
    </section>`;
}

function defaultWizard() {
  return { step: 1, name: "", clientName: "", description: "", targets: "", excludes: "", type: "external_unauthenticated", profile: "controlled_fixture", authorizationNote: "", capabilities: [], permissions: [], credentials: false, authorized: false, llm: false, screenshots: true };
}
function renderNewAssessment() {
  if (!state.wizard) state.wizard = defaultWizard();
  const wizard = state.wizard;
  $("#app").innerHTML = `<div class="wizard">
    <div class="page-intro"><div><h2>Create an assessment</h2><p>Move through the setup in plain language. You can go back before starting without losing your entries.</p></div><span class="tag">Step ${wizard.step} of 4</span></div>
    <div class="stepper" aria-label="Assessment setup progress">
      ${[[1,"Details","Name and context"],[2,"Targets","Authorized scope"],[3,"Assessment type","Testing context"],[4,"Review & start","Final confirmation"]].map(([number,title,description]) => `<button type="button" class="step ${number === wizard.step ? "active" : ""} ${number < wizard.step ? "complete" : ""}" data-wizard-step="${number}" aria-current="${number === wizard.step ? "step" : "false"}"><span class="step-number">${number < wizard.step ? "✓" : number}</span><span class="step-title">${title}</span><span class="step-description">${description}</span></button>`).join("")}
    </div>
    <form id="assessment-form" novalidate>
      <select id="assessment-type" class="visually-hidden" aria-label="Assessment type">${assessmentTypes.map((item) => `<option value="${item.id}" ${item.id === wizard.type ? "selected" : ""}>${item.title} — ${item.subtitle}</option>`).join("")}</select>
      <select id="profile" class="visually-hidden" aria-label="Execution profile"><option value="controlled_fixture" ${wizard.profile === "controlled_fixture" ? "selected" : ""}>Controlled local fixture</option><option value="authorized_external" ${wizard.profile === "authorized_external" ? "selected" : ""}>Authorized external network</option></select>
      <section class="panel wizard-panel" data-wizard-panel="1" ${wizard.step === 1 ? "" : "hidden"}>
        <h2>Name the engagement</h2><p class="panel-lead">Give the run enough context to be recognizable in history and reports. Only the name is required.</p>
        <div class="form-grid"><div class="form-field full"><label for="assessment-name">Assessment name <span aria-hidden="true">*</span></label><input id="assessment-name" value="${escapeHtml(wizard.name)}" maxlength="120" placeholder="Example: Q4 network perimeter review" required /><span class="helper">Use a name your team will understand later.</span></div><div class="form-field"><label for="client-name">Client or project <span class="muted">optional</span></label><input id="client-name" value="${escapeHtml(wizard.clientName)}" maxlength="120" placeholder="Example: Northwind production" /></div><div class="form-field"><label for="description">Description <span class="muted">optional</span></label><input id="description" value="${escapeHtml(wizard.description)}" maxlength="1000" placeholder="Short engagement context" /></div></div>
        <div class="callout danger wizard-error" data-wizard-error="1" role="alert" hidden></div><div class="form-actions"><span></span><div class="right"><button class="button button-primary" type="button" data-wizard-next="2">Continue <span aria-hidden="true">→</span></button></div></div>
      </section>
      <section class="panel wizard-panel" data-wizard-panel="2" ${wizard.step === 2 ? "" : "hidden"}>
        <h2>Define the authorized scope</h2><p class="panel-lead">Add only the addresses and names you have permission to assess. Nothing is discovered or added automatically.</p>
        <div class="form-field"><label for="targets">Targets <span aria-hidden="true">*</span></label><textarea id="targets" placeholder="fixture://mixed\n192.0.2.10\napp.example.test\n2001:db8::10\n192.0.2.0/28">${escapeHtml(wizard.targets)}</textarea><span class="helper">One IPv4, IPv6, hostname, bounded CIDR, or controlled fixture per line. Commas also work.</span></div>
        <div class="form-field" style="margin-top:16px"><label for="target-file">Upload a target list <span class="muted">optional</span></label><input id="target-file" class="file-input" type="file" accept=".txt,.csv,text/plain,text/csv" /><span class="helper">The file is read locally into this draft; the backend validates the final scope.</span></div>
        <div id="target-preview" class="target-preview" aria-live="polite"></div>
        <div class="form-grid" style="margin-top:17px"><div class="form-field"><label for="excludes">Exclusions <span class="muted">optional</span></label><input id="excludes" value="${escapeHtml(wizard.excludes)}" placeholder="One exact target per line" /><span class="helper">Excluded values are removed before the scope manifest is written.</span></div><div class="form-field"><label>Scope rule</label><div class="callout">The final effective scope is recorded before execution and cannot silently expand.</div></div></div>
        <div class="callout danger wizard-error" data-wizard-error="2" role="alert" hidden></div><div class="form-actions"><button class="button" type="button" data-wizard-prev="1">← Back</button><div class="right"><button class="button button-primary" type="button" data-wizard-next="3">Continue <span aria-hidden="true">→</span></button></div></div>
      </section>
      <section class="panel wizard-panel" data-wizard-panel="3" ${wizard.step === 3 ? "" : "hidden"}>
        <h2>Choose the testing context</h2><p class="panel-lead">This selection guides per-condition applicability. It never grants access, adds targets, or turns missing capabilities into findings.</p>
        <div class="profile-grid">${assessmentTypes.map((item) => `<button type="button" class="profile-card ${wizard.type === item.id ? "selected" : ""}" data-select-type="${item.id}" aria-pressed="${wizard.type === item.id}"><input class="profile-radio" type="radio" name="assessment-type-card" value="${item.id}" ${wizard.type === item.id ? "checked" : ""} tabindex="-1" /><h3>${item.title}<br><span class="muted">${item.subtitle}</span></h3><p>${item.description}</p></button>`).join("")}</div>
        <details class="details"><summary>Advanced capabilities and permissions</summary><div class="form-grid" style="margin-top:16px"><div class="form-field"><label>Available capabilities</label><label class="checkline"><input id="cap-internal" type="checkbox" value="internal_vantage" ${wizard.capabilities.includes("internal_vantage") ? "checked" : ""} /> <span>Authorized internal vantage point</span></label><label class="checkline"><input id="cap-layer2" type="checkbox" value="layer2_access" ${wizard.capabilities.includes("layer2_access") ? "checked" : ""} /> <span>Layer-2 access</span></label><label class="checkline"><input id="cap-wireless" type="checkbox" value="wireless_adapter" ${wizard.capabilities.includes("wireless_adapter") ? "checked" : ""} /> <span>Wireless adapter and proximity</span></label><label class="checkline"><input id="cap-egress" type="checkbox" value="egress_vantage" ${wizard.capabilities.includes("egress_vantage") ? "checked" : ""} /> <span>Approved egress vantage</span></label><label class="checkline"><input id="cap-inventory" type="checkbox" value="asset_inventory" ${wizard.capabilities.includes("asset_inventory") ? "checked" : ""} /> <span>Authorized asset inventory</span></label></div><div class="form-field"><label>Explicit permissions</label><label class="checkline"><input id="perm-segmentation" type="checkbox" value="segmentation_testing" ${wizard.permissions.includes("segmentation_testing") ? "checked" : ""} /> <span>Segmentation testing</span></label><label class="checkline"><input id="perm-layer2" type="checkbox" value="layer2_testing" ${wizard.permissions.includes("layer2_testing") ? "checked" : ""} /> <span>Layer-2 testing</span></label><label class="checkline"><input id="perm-egress" type="checkbox" value="egress_testing" ${wizard.permissions.includes("egress_testing") ? "checked" : ""} /> <span>Egress testing</span></label><label class="checkline"><input id="perm-inventory" type="checkbox" value="inventory_access" ${wizard.permissions.includes("inventory_access") ? "checked" : ""} /> <span>Inventory access</span></label><label class="checkline"><input id="perm-wireless" type="checkbox" value="wireless_testing" ${wizard.permissions.includes("wireless_testing") ? "checked" : ""} /> <span>Wireless testing</span></label><label class="checkline"><input id="perm-policy" type="checkbox" value="credential_policy_testing" ${wizard.permissions.includes("credential_policy_testing") ? "checked" : ""} /> <span>Credential policy testing</span></label></div></div></details>
        <div class="form-field" style="margin-top:19px"><label for="profile-visible">Run mode</label><select id="profile-visible"><option value="controlled_fixture" ${wizard.profile === "controlled_fixture" ? "selected" : ""}>Controlled local fixture — safe development run</option><option value="authorized_external" ${wizard.profile === "authorized_external" ? "selected" : ""}>Authorized target — written authorization required</option></select><span class="helper">External mode is blocked unless the entered scope and authorization record pass backend validation.</span></div>
        <div class="callout danger wizard-error" data-wizard-error="3" role="alert" hidden></div><div class="form-actions"><button class="button" type="button" data-wizard-prev="2">← Back</button><div class="right"><button class="button button-primary" type="button" data-wizard-next="4">Continue <span aria-hidden="true">→</span></button></div></div>
      </section>
      <section class="panel wizard-panel" data-wizard-panel="4" ${wizard.step === 4 ? "" : "hidden"}>
        <h2>Review and start</h2><p class="panel-lead">Confirm the engagement context before the scope is locked. The backend remains authoritative for validation.</p>
        <div id="review-summary" class="review-grid"></div>
        <div class="form-grid"><div class="form-field"><label for="authorization-note">Authorization record <span aria-hidden="true">*</span></label><input id="authorization-note" value="${escapeHtml(wizard.authorizationNote)}" maxlength="500" placeholder="Fixture authorization or written approval reference" /><span class="helper">This is retained with the assessment audit record.</span></div><div class="form-field"><label>Execution posture</label><div class="callout">40 registered security checks are evaluated independently. Not applicable and inconclusive conditions remain explicit.</div></div><div class="form-field full"><label class="checkline"><input id="authorized" type="checkbox" ${wizard.authorized ? "checked" : ""} /> <span>I confirm these targets are authorized and within the permitted assessment scope.</span></label><label class="checkline"><input id="credentials-available" type="checkbox" ${wizard.credentials ? "checked" : ""} /> <span>Approved credentials are available for this assessment context.</span></label><label class="checkline"><input id="llm-enabled" type="checkbox" ${wizard.llm ? "checked" : ""} /> <span>Enable optional Local AI explanations when Ollama is healthy.</span></label><label class="checkline"><input id="screenshots" type="checkbox" ${wizard.screenshots ? "checked" : ""} /> <span>Generate command/output POC PNGs for valid FOUND and NOT_FOUND evidence.</span></label></div></div>
        <div id="form-error" class="callout danger wizard-error" data-wizard-error="4" role="alert" hidden></div>
        <div class="form-actions"><button class="button" type="button" data-wizard-prev="3">← Back</button><div class="right"><button class="button button-primary" type="submit">Create assessment</button></div></div>
      </section>
    </form></div>`;
  bindWizard();
  updateScopePreview();
  updateReviewSummary();
}
function bindWizard() {
  $("#assessment-form").addEventListener("submit", createAssessment);
  $("#targets").addEventListener("input", updateScopePreview);
  $("#excludes").addEventListener("input", updateScopePreview);
  $("#assessment-name").addEventListener("input", () => { state.wizard.name = $("#assessment-name").value; });
  $("#client-name").addEventListener("input", () => { state.wizard.clientName = $("#client-name").value; });
  $("#description").addEventListener("input", () => { state.wizard.description = $("#description").value; });
  $("#authorization-note").addEventListener("input", () => { state.wizard.authorizationNote = $("#authorization-note").value; });
  $("#profile-visible").addEventListener("change", (event) => { state.wizard.profile = event.target.value; $("#profile").value = event.target.value; });
  $("#target-file").addEventListener("change", async (event) => { const file = event.target.files?.[0]; if (!file) return; $("#targets").value = await file.text(); updateScopePreview(); });
  $$('input[type="checkbox"]', $("#assessment-form")).forEach((input) => input.addEventListener("change", captureWizardOptions));
}
function captureWizardOptions() {
  const wizard = state.wizard;
  wizard.targets = $("#targets")?.value || wizard.targets;
  wizard.excludes = $("#excludes")?.value || wizard.excludes;
  wizard.type = $("#assessment-type")?.value || wizard.type;
  wizard.profile = $("#profile-visible")?.value || wizard.profile;
  wizard.authorizationNote = $("#authorization-note")?.value || wizard.authorizationNote;
  wizard.authorized = Boolean($("#authorized")?.checked);
  wizard.credentials = Boolean($("#credentials-available")?.checked);
  wizard.llm = Boolean($("#llm-enabled")?.checked);
  wizard.screenshots = Boolean($("#screenshots")?.checked);
  wizard.capabilities = $$('[id^="cap-"]:checked').map((element) => element.value);
  wizard.permissions = $$('[id^="perm-"]:checked').map((element) => element.value);
}
function setWizardStep(step) {
  captureWizardOptions();
  state.wizard.step = step;
  renderNewAssessment();
  const heading = $(`[data-wizard-panel="${step}"] h2`);
  if (heading) heading.focus?.();
}
function showWizardError(message, selector) {
  const error = $(`[data-wizard-panel="${state.wizard.step}"] [data-wizard-error]`) || $("#form-error");
  if (error) { error.textContent = message; error.hidden = false; }
  if (selector) { const field = $(selector); if (field) { field.setAttribute("aria-invalid", "true"); field.focus(); } }
}
function clearWizardError() { $$(".wizard-error").forEach((error) => { error.textContent = ""; error.hidden = true; }); $$('[aria-invalid="true"]').forEach((field) => field.removeAttribute("aria-invalid")); }
function splitTargets(value) { return String(value || "").split(/\n|,/).map((item) => item.trim()).filter(Boolean); }
function isValidTarget(value) {
  if (/^fixture:\/\/[A-Za-z0-9._-]+$/.test(value)) return true;
  if (/^[0-9a-f:.]+\/[0-9]{1,3}$/i.test(value)) return true;
  if (/^[0-9a-f:.]+$/i.test(value) && value.includes(":")) return true;
  if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(value)) return true;
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value);
}
function targetAnalysis() {
  const values = splitTargets($("#targets")?.value || state.wizard?.targets);
  const normalized = values.map((value) => value.toLowerCase());
  const excludes = new Set(splitTargets($("#excludes")?.value || state.wizard?.excludes).map((value) => value.toLowerCase()));
  const seen = new Set();
  const entries = values.map((value, index) => { const duplicate = seen.has(normalized[index]); seen.add(normalized[index]); return { value, valid: isValidTarget(value), duplicate, excluded: excludes.has(normalized[index]) }; });
  return { entries, valid: entries.filter((item) => item.valid && !item.excluded && !item.duplicate), invalid: entries.filter((item) => !item.valid), duplicates: entries.filter((item) => item.duplicate), excludes };
}
function updateScopePreview() {
  const preview = $("#target-preview");
  if (!preview) return;
  captureWizardOptions();
  const result = targetAnalysis();
  if (!result.entries.length) { preview.innerHTML = `<div class="callout">No targets entered yet. The initial scope is empty.</div>`; updateReviewSummary(); return; }
  const chips = result.entries.map((item) => `<span class="target-chip ${item.valid ? "" : "invalid"}">${escapeHtml(item.value)}${item.excluded ? `<span class="tiny">excluded</span>` : ""}${item.duplicate ? `<span class="tiny">duplicate</span>` : ""}<button type="button" class="chip-remove" data-remove-target="${encodeURIComponent(item.value)}" aria-label="Remove ${escapeHtml(item.value)}">×</button></span>`).join("");
  const message = result.invalid.length ? `<div class="callout warning"><strong>${result.invalid.length} target${result.invalid.length === 1 ? "" : "s"} need attention.</strong> Check the highlighted value${result.invalid.length === 1 ? "" : "s"} before continuing.</div>` : `<div class="callout success"><strong>${result.valid.length} effective target${result.valid.length === 1 ? "" : "s"} ready.</strong> ${result.duplicates.length} duplicate${result.duplicates.length === 1 ? "" : "s"}; ${result.excludes.size} exclusion${result.excludes.size === 1 ? "" : "s"}.</div>`;
  preview.innerHTML = `<div class="target-summary">${chips}</div>${message}`;
  updateReviewSummary();
}
function updateReviewSummary() {
  const summary = $("#review-summary");
  if (!summary) return;
  captureWizardOptions();
  const result = targetAnalysis();
  const capabilities = state.wizard.capabilities.length ? state.wizard.capabilities.join(", ") : "None declared";
  summary.innerHTML = `<div class="review-item"><div class="review-label">Assessment</div><div class="review-value">${escapeHtml(state.wizard.name || "Unnamed assessment")}</div></div><div class="review-item"><div class="review-label">Targets</div><div class="review-value">${result.valid.length} effective · ${result.entries.length} entered</div></div><div class="review-item"><div class="review-label">Assessment type</div><div class="review-value">${escapeHtml(assessmentTypeLabels[state.wizard.type])}</div></div><div class="review-item"><div class="review-label">Checks enabled</div><div class="review-value">40 registered security checks</div></div><div class="review-item"><div class="review-label">Capabilities</div><div class="review-value">${escapeHtml(capabilities)}</div></div><div class="review-item"><div class="review-label">Intensity</div><div class="review-value">Bounded, non-destructive defaults</div></div><div class="review-item full"><div class="review-label">Authorization</div><div class="review-value">${state.wizard.authorized ? "Operator confirmation recorded" : "Confirmation still required"}</div></div>`;
}
function validateWizardStep(step) {
  clearWizardError();
  captureWizardOptions();
  if (step === 1 && !state.wizard.name.trim()) { showWizardError("Give this assessment a name before continuing.", "#assessment-name"); return false; }
  if (step === 2) { const analysis = targetAnalysis(); if (!analysis.entries.length) { showWizardError("Add at least one authorized target before continuing.", "#targets"); return false; } if (analysis.invalid.length) { showWizardError("One or more targets need attention. Correct the highlighted values before continuing.", "#targets"); return false; } }
  if (step === 3 && !assessmentTypes.some((item) => item.id === state.wizard.type)) { showWizardError("Choose an assessment type before continuing."); return false; }
  if (step === 4) { if (!state.wizard.authorized) { showWizardError("Confirm that the targets are authorized and within scope.", "#authorized"); return false; } if (state.wizard.profile === "authorized_external" && !state.wizard.authorizationNote.trim()) { showWizardError("Add the written authorization reference for an authorized target assessment.", "#authorization-note"); return false; } }
  return true;
}
async function createAssessment(event) {
  event.preventDefault();
  if (!validateWizardStep(4)) return;
  const wizard = state.wizard;
  const submit = $("#assessment-form button[type=submit]");
  submit.disabled = true; submit.textContent = "Creating…";
  try {
    const assessment = await api("/api/assessments", { method: "POST", body: JSON.stringify({
      name: wizard.name.trim(), client_name: wizard.clientName.trim(), description: wizard.description.trim(),
      targets: splitTargets(wizard.targets), excludes: splitTargets(wizard.excludes), authorized: true,
      authorization_note: wizard.authorizationNote.trim(), profile: wizard.profile, assessment_type: wizard.type,
      capabilities: wizard.capabilities, permissions: wizard.permissions, credentials_available: wizard.credentials,
      llm_enabled: wizard.llm, evidence_screenshots: wizard.screenshots,
    }) });
    state.selectedId = assessment.id; state.wizard = null; localStorage.setItem("scopeguard:lastAssessment", assessment.id); toast("Assessment created. Review the scope, then start when ready."); setPage("assessment");
  } catch (error) { submit.disabled = false; submit.textContent = "Create assessment"; showWizardError(error.message); }
}

function phaseIndex(phase) { return Math.max(0, phases.indexOf(phase)); }
function stageClass(group, detail) {
  const current = phaseIndex(detail.current_phase);
  const last = Math.max(...group.phases.map(phaseIndex));
  const first = Math.min(...group.phases.map(phaseIndex));
  if (detail.status === "COMPLETED" || current > last) return "done";
  if (detail.status === "FAILED" && current >= first && current <= last) return "failed";
  if (current >= first && current <= last) return "current";
  return current > last ? "done" : "";
}
function stageLabel(stage, detail) {
  const className = stageClass(stage, detail);
  if (className === "done") return "Completed";
  if (className === "current") return detail.status === "PAUSED" ? "Paused" : detail.status;
  if (className === "failed") return "Failed";
  return "Pending";
}
function currentActivity(detail) {
  const latest = [...(detail.recent_events || [])].reverse()[0];
  if (latest?.message) return latest.message;
  if (detail.current_target || detail.current_testcase) return `Checking ${detail.current_testcase || "security conditions"} on ${detail.current_target || "the selected target"}.`;
  return detail.status === "COMPLETED" ? "Assessment complete. Evidence and reports are ready." : "Preparing the assessment.";
}
function stageList(detail) {
  return `<div class="stage-list">${stageGroups.map((stage) => { const cls = stageClass(stage, detail); return `<div class="stage ${cls}"><span class="stage-icon">${cls === "done" ? "✓" : cls === "failed" ? "!" : cls === "current" ? "•" : "·"}</span><span>${stage.label}</span><span class="muted" style="margin-left:auto">${stageLabel(stage, detail)}</span></div>`; }).join("")}</div>`;
}
function eventLog(events) {
  if (!events?.length) return "No activity recorded yet.";
  return events.slice(-18).map((event) => `<div class="event-line"><span class="event-time">${escapeHtml(event.created_at.slice(11, 19))}</span> <span class="event-status">${escapeHtml(event.event)}</span> ${escapeHtml(event.message)}</div>`).join("");
}
function lastCommand(detail) { const last = [...(detail.recent_events || [])].reverse().find((event) => event.payload?.command); return last?.payload?.command || "Waiting for an evidence-producing command."; }
function resultMatches(result) {
  const query = state.resultFilters.search.toLowerCase();
  return (!query || [result.target, result.target_label, result.testcase_id, result.testcase_name, result.status].some((value) => String(value || "").toLowerCase().includes(query))) && (state.resultFilters.status === "all" || result.status === state.resultFilters.status);
}
function resultsTable(results, id) {
  const filtered = results.filter(resultMatches);
  if (!results.length) return `<div class="empty"><strong>Results will appear here</strong>Start the assessment to populate the persisted 40-case result set.</div>`;
  if (!filtered.length) return `<div class="empty"><strong>No matching results</strong>Adjust the search or status filter.</div>`;
  return `<div class="table-wrap"><table><thead><tr><th>Target</th><th>Security check</th><th>Result</th><th>Severity</th><th>Evidence</th><th><span class="sr-only">Details</span></th></tr></thead><tbody>${filtered.map((result) => { const pocs = toArray(result.poc_paths_json); return `<tr class="result-row" data-result-id="${result.id}" tabindex="0"><td><strong>${escapeHtml(result.target_label)}</strong><div class="small muted">${escapeHtml(result.target)}</div></td><td><strong>${escapeHtml(result.testcase_id)}</strong><div class="small muted">${escapeHtml(result.testcase_name)}</div></td><td>${statusBadge(result.status)}</td><td>${escapeHtml(result.severity)}</td><td>${pocs.length ? pocs.map((path) => `<a href="#" class="small" data-preview="${encodeURIComponent(path)}" data-assessment="${id}">${escapeHtml(path.split("/").pop())}</a>`).join("<br>") : `<span class="small muted">${escapeHtml(result.failure_reason || result.applicability || "No POC")}</span>`}</td><td><span class="row-action">View details →</span></td></tr>`; }).join("")}</tbody></table></div>`;
}
async function renderAssessment(id) {
  if (!id) return setPage("history");
  const detail = await api(`/api/assessments/${encodeURIComponent(id)}`); state.detail = detail;
  if (["QUEUED", "RUNNING", "PAUSED"].includes(detail.status)) subscribe(id); else stopSubscription(id);
  const percent = detail.total_units ? Math.round(detail.completed_units / detail.total_units * 100) : 0;
  const active = ["QUEUED", "RUNNING", "PAUSED"].includes(detail.status);
  const terminal = ["COMPLETED", "FAILED", "CANCELLED"].includes(detail.status);
  $("#app").innerHTML = `<div class="page-intro"><div><h2>${escapeHtml(detail.name)}</h2><p>${escapeHtml(assessmentTypeLabels[detail.assessment_type] || detail.assessment_type)} · ${detail.target_count} target${detail.target_count === 1 ? "" : "s"} · Created ${formatDate(detail.created_at)}</p></div><div class="page-intro-actions"><button class="button button-link" data-page="history">← All assessments</button></div></div>
    <section class="assessment-hero"><div class="hero-top"><div><h2>${detail.status === "COMPLETED" ? "Assessment complete" : detail.status === "FAILED" ? "Assessment needs attention" : "Assessment in progress"}</h2><p>${escapeHtml(currentActivity(detail))}</p></div><span class="hero-status ${detail.status === "FAILED" ? "danger" : ""}">${escapeHtml(detail.status)}</span></div><div class="progress ${active && detail.completed_units === 0 ? "indeterminate" : ""}"><span style="width:${percent}%"></span></div><div class="progress-meta"><span>${detail.completed_units} of ${detail.total_units} checks complete</span><strong>${percent}%</strong></div></section>
    <div class="button-row" style="margin-bottom:16px">${detail.status === "DRAFT" ? `<button class="button button-primary" data-control="start">Start assessment</button>` : ""}${detail.status === "RUNNING" || detail.status === "QUEUED" ? `<button class="button" data-control="pause">Pause safely</button>` : ""}${detail.status === "PAUSED" ? `<button class="button button-primary" data-control="resume">Resume assessment</button>` : ""}${active ? `<button class="button button-danger" data-control="cancel">Cancel assessment</button>` : ""}${terminal ? `<a class="button button-primary" href="/api/assessments/${id}/export/zip">Download complete report</a><a class="button button-quiet" href="/api/assessments/${id}/export/csv">Testcase CSV</a>` : `<span class="tag">Downloads appear after completion</span>`}</div>
    ${terminal && detail.status === "COMPLETED" ? `<div class="callout success" style="margin-bottom:16px"><strong>Your assessment is ready.</strong> Review findings and evidence below, then download the verified ZIP report.</div>` : ""}
    <section class="live-stats">${liveStat("FOUND", detail.found_count, "Confirmed", "metric-red")}${liveStat("NOT FOUND", detail.not_found_count, "Verified", "metric-green")}${liveStat("NA", detail.na_count, "Not applicable", "metric-amber")}${liveStat("INCONCLUSIVE", detail.inconclusive_count, "Limitations retained", "metric-slate")}${liveStat("Applicable", detail.applicable_count, "Eligible conditions", "metric-blue")}${liveStat("Errors", detail.error_count, "Execution errors", "metric-red")}</section>
    <section class="grid-2"><div class="panel"><div class="panel-header"><div><h2>Activity</h2><p>Structured progress from the persisted assessment lifecycle.</p></div></div>${stageList(detail)}<div class="current-activity" style="margin-top:15px"><div class="activity-label">Current activity</div><p>${escapeHtml(currentActivity(detail))}</p></div><details class="technical-details"><summary>Technical details</summary><div class="command-box"><span class="prompt">$</span> ${escapeHtml(lastCommand(detail))}</div><div id="event-log" class="event-log">${eventLog(detail.recent_events)}</div></details></div><div class="panel"><div class="panel-header"><div><h2>Scope and context</h2><p>Locked when execution begins.</p></div></div><div class="tree">${healthRow("Assessment type", assessmentTypeLabels[detail.assessment_type] || detail.assessment_type, true)}${healthRow("Authorized targets", detail.target_count, true)}${healthRow("Capabilities", toArray(detail.capabilities).join(", ") || "None declared", true)}${healthRow("Authorization", detail.authorized ? "Confirmed" : "Missing", detail.authorized)}</div></div></section>
    <section class="panel" style="margin-top:16px"><div class="panel-header"><div><h2>Results and evidence</h2><p>Every target has one row for each of the 40 registered security checks. Select a row for plain-language details.</p></div><div class="panel-actions"><span class="small muted">${detail.results.length} rows</span></div></div><div class="filter-bar"><label class="sr-only" for="result-search">Search results</label><input id="result-search" placeholder="Search target or testcase" value="${escapeHtml(state.resultFilters.search)}" /><label class="sr-only" for="result-status">Filter by result</label><select id="result-status"><option value="all">All results</option>${["FOUND", "NOT_FOUND", "NA", "INCONCLUSIVE"].map((status) => `<option value="${status}" ${state.resultFilters.status === status ? "selected" : ""}>${status.replaceAll("_", " ")}</option>`).join("")}</select><span class="small muted">NA means not applicable. INCONCLUSIVE means the evidence could not establish a conclusion.</span></div><div id="results-table">${resultsTable(detail.results, id)}</div></section>`;
  $$('[data-control]').forEach((button) => button.addEventListener("click", () => controlAssessment(id, button.dataset.control)));
  $("#result-search")?.addEventListener("input", (event) => { state.resultFilters.search = event.target.value; $("#results-table").innerHTML = resultsTable(detail.results, id); bindResultRows(id); });
  $("#result-status")?.addEventListener("change", (event) => { state.resultFilters.status = event.target.value; $("#results-table").innerHTML = resultsTable(detail.results, id); bindResultRows(id); });
  bindResultRows(id);
}
function liveStat(label, value, hint, className) { return `<div class="live-stat ${className}"><div class="label">${label}</div><strong>${value}</strong><div class="small muted">${hint}</div></div>`; }
function bindResultRows(id) { $$(".result-row").forEach((row) => { row.addEventListener("click", (event) => { if (!event.target.closest("a")) openResultDetail(id, Number(row.dataset.resultId)); }); row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openResultDetail(id, Number(row.dataset.resultId)); } }); }); }
async function controlAssessment(id, action) { try { await api(`/api/assessments/${id}/${action}`, { method: "POST" }); toast(`${action === "cancel" ? "Cancellation" : action.charAt(0).toUpperCase() + action.slice(1)} requested`); await renderAssessment(id); } catch (error) { toast(error.message); } }
function openModal(content) { $("#modal-content").innerHTML = content; $("#modal").hidden = false; $(".modal-close")?.focus(); }
function closeModal() { $("#modal").hidden = true; }
function openResultDetail(assessmentId, resultId, results = state.detail?.results) {
  const result = results?.find((item) => item.id === resultId); if (!result) return;
  const pocs = toArray(result.poc_paths_json); const evidence = toArray(result.evidence_paths_json);
  openModal(`<h2 id="modal-title">${escapeHtml(result.testcase_name)}</h2><p class="muted small">${escapeHtml(result.target_label)} · Testcase ${escapeHtml(result.testcase_id)}</p><div class="modal-grid" style="margin-top:18px"><div class="modal-section"><h3>Result</h3><p>${statusBadge(result.status)}</p><p style="margin-top:9px">${escapeHtml(result.failure_reason || result.applicability || "Deterministic result recorded.")}</p></div><div class="modal-section"><h3>Evidence</h3><p>${pocs.length ? `${pocs.length} POC image${pocs.length === 1 ? "" : "s"} available.` : "No POC is created for this status."}</p><p class="small muted" style="margin-top:7px">Validation: ${escapeHtml(result.validation_state)}</p></div></div><div class="modal-section" style="margin-top:14px"><h3>What was observed</h3><p>${escapeHtml(result.output_preview || "No command output preview was stored for this result.")}</p></div>${result.command ? `<details class="details" open><summary>Original command and output</summary><div class="command-box"><span class="prompt">$</span> ${escapeHtml(result.command)}\n\n${escapeHtml(result.output_preview || "")}</div></details>` : ""}<div class="button-row" style="margin-top:17px">${pocs.map((path) => `<button class="button button-primary button-small" data-modal-preview="${encodeURIComponent(path)}" data-assessment="${assessmentId}">Preview POC</button><a class="button button-quiet button-small" href="/api/assessments/${assessmentId}/evidence/${path}" download>Download POC</a>`).join("")}<button class="button button-quiet button-small" data-copy="${encodeURIComponent(result.command || pocs[0] || "")}">Copy reference</button></div><p class="small muted" style="margin-top:14px">Supporting files: ${escapeHtml(evidence.join("; ") || "Applicability record")}</p>`);
}
function openPreview(assessmentId, encodedPath) { const path = decodeURIComponent(encodedPath); openModal(`<h2 id="modal-title">Evidence preview</h2><p class="muted small">The PNG contains only the original command and actual captured output.</p><img class="preview-image" src="/api/assessments/${assessmentId}/evidence/${path}" alt="Evidence command and output POC" /><div class="button-row" style="margin-top:15px"><a class="button button-primary button-small" href="/api/assessments/${assessmentId}/evidence/${path}" download>Download POC</a><button class="button button-quiet button-small" data-copy="${encodeURIComponent(path)}">Copy evidence path</button></div><p class="small muted" style="margin-top:12px">${escapeHtml(path)}</p>`); }

async function renderActive() { const data = await api("/api/assessments"); const active = data.assessments.filter((row) => ["QUEUED", "RUNNING", "PAUSED"].includes(row.status)); $("#app").innerHTML = `<div class="page-intro"><div><h2>Active assessments</h2><p>Return to an assessment without interrupting its persisted lifecycle.</p></div></div><div class="panel">${active.length ? recentTable(active) : `<div class="empty"><strong>No active assessments</strong>Start a new authorized assessment when you are ready.</div>`}</div>`; }
async function renderHistory() { const data = await api("/api/assessments"); $("#app").innerHTML = `<div class="page-intro"><div><h2>Assessment history</h2><p>Every run is retained locally with its scope authorization, result rows, and evidence references.</p></div><button class="button button-primary" data-page="new-assessment">＋ New assessment</button></div><div class="panel"><div class="filter-bar"><label class="sr-only" for="history-search">Search history</label><input id="history-search" placeholder="Search assessments" /><select id="history-status"><option value="all">All statuses</option><option value="COMPLETED">Completed</option><option value="RUNNING">Running</option><option value="FAILED">Failed</option><option value="CANCELLED">Cancelled</option></select></div><div id="history-table">${recentTable(data.assessments)}</div></div>`; const update = () => { const query = $("#history-search").value.toLowerCase(); const status = $("#history-status").value; const rows = data.assessments.filter((row) => (!query || `${row.name} ${row.client_name || ""} ${row.id}`.toLowerCase().includes(query)) && (status === "all" || row.status === status)); $("#history-table").innerHTML = recentTable(rows); }; $("#history-search").addEventListener("input", update); $("#history-status").addEventListener("change", update); }
async function renderFindings() { const data = await api("/api/assessments"); const rows = []; for (const assessment of data.assessments) { const result = await api(`/api/assessments/${assessment.id}/results`); result.results.filter((row) => row.status === "FOUND").forEach((row) => rows.push({ ...row, assessment_name: assessment.name, assessment_results: result.results })); } $("#app").innerHTML = `<div class="page-intro"><div><h2>Findings</h2><p>Only deterministic FOUND results appear here. Local AI can explain evidence but cannot create or change a finding.</p></div></div><div class="panel">${rows.length ? `<div class="table-wrap"><table><thead><tr><th>Assessment</th><th>Target</th><th>Security check</th><th>Severity</th><th>Evidence</th></tr></thead><tbody>${rows.map((row) => `<tr class="finding-row" data-result-id="${row.id}" data-assessment="${row.assessment_id}"><td>${escapeHtml(row.assessment_name)}</td><td>${escapeHtml(row.target)}</td><td><strong>${escapeHtml(row.testcase_id)}</strong><div class="small muted">${escapeHtml(row.testcase_name)}</div></td><td>${escapeHtml(row.severity)}</td><td>${toArray(row.poc_paths_json).map((path) => `<a href="#" data-preview="${encodeURIComponent(path)}" data-assessment="${row.assessment_id}">Preview POC</a>`).join("<br>") || "—"}</td></tr>`).join("")}</tbody></table></div>` : `<div class="empty"><strong>No confirmed findings</strong>Completed checks with FOUND status will appear here.</div>`}</div>`; $$(".finding-row").forEach((row) => row.addEventListener("click", (event) => { if (!event.target.closest("a")) { const finding = rows.find((item) => item.id === Number(row.dataset.resultId)); if (finding) openResultDetail(row.dataset.assessment, finding.id, finding.assessment_results); } })); }
async function renderEvidence() { const data = await api("/api/assessments"); $("#app").innerHTML = `<div class="page-intro"><div><h2>Evidence explorer</h2><p>Open an assessment to move from target to testcase to the stored POC and original command evidence.</p></div></div><div class="panel"><div class="tree">${data.assessments.length ? data.assessments.map((assessment) => `<div class="tree-node"><strong>${escapeHtml(assessment.name)}</strong><div class="small muted">${escapeHtml(assessment.id)} · ${assessment.target_count} target${assessment.target_count === 1 ? "" : "s"} · ${escapeHtml(assessment.status)}</div><div class="tree-child"><button class="button button-quiet button-small" data-open-assessment="${assessment.id}">Open assessment evidence →</button></div></div>`).join("") : `<div class="empty"><strong>No evidence roots yet</strong>Create and complete an assessment to populate this explorer.</div>`}</div></div>`; }
async function renderReports() { const data = await api("/api/assessments"); $("#app").innerHTML = `<div class="page-intro"><div><h2>Reports and downloads</h2><p>Reports are generated from persisted results and checked for complete testcase coverage before download.</p></div></div><div class="panel"><div class="table-wrap"><table><thead><tr><th>Assessment</th><th>Status</th><th>Coverage</th><th>Verified files</th><th>Downloads</th></tr></thead><tbody>${data.assessments.length ? data.assessments.map((row) => `<tr><td><strong>${escapeHtml(row.name)}</strong><div class="small muted">${escapeHtml(row.id)}</div></td><td>${statusBadge(row.status)}</td><td>${row.completed_units} / ${row.total_units}</td><td><span class="small" data-export-info="${row.id}">${row.status === "COMPLETED" ? "Checking…" : "Available after completion"}</span></td><td><div class="button-row">${row.status === "COMPLETED" ? `<a class="button button-primary button-small" href="/api/assessments/${row.id}/export/zip">Complete ZIP</a><a class="button button-quiet button-small" href="/api/assessments/${row.id}/export/csv">CSV</a>` : "—"}</div></td></tr>`).join("") : `<tr><td colspan="5"><div class="empty"><strong>No reports available</strong>Complete an assessment to generate verified exports.</div></td></tr>`}</tbody></table></div></div>`; for (const row of data.assessments.filter((item) => item.status === "COMPLETED")) { try { const info = await api(`/api/assessments/${row.id}/exports`); const text = info.files.map((file) => `${file.name} · ${formatBytes(file.bytes)}`).join(" · "); const target = $(`[data-export-info="${row.id}"]`); if (target) target.textContent = text; } catch (error) { const target = $(`[data-export-info="${row.id}"]`); if (target) target.textContent = "Export verification unavailable"; } } }
async function renderAI() { const status = await api("/api/ollama/status"); $("#app").innerHTML = `<div class="page-intro"><div><h2>Local AI</h2><p>Optional secondary analysis only. It cannot set classifications, execute commands, expand scope, or rewrite evidence.</p></div><span class="tag">No classification authority</span></div><section class="grid-2"><div class="panel"><div class="panel-header"><div><h2>Runtime status</h2><p>Endpoint and exact model readiness.</p></div>${statusBadge(status.ready ? "COMPLETED" : "INCONCLUSIVE")}</div><div class="tree">${healthRow("Endpoint", status.url, status.reachable)}${healthRow("Model", status.model, status.model_available)}${healthRow("Memory", status.memory_sufficient ? "Within safe threshold" : "Below safe threshold", status.memory_sufficient)}${healthRow("Authority", "Secondary explanation only", true)}</div><p class="small muted" style="margin-top:12px">${escapeHtml(status.message || "")}</p><button id="ai-health-test" class="button button-primary" ${status.ready ? "" : "disabled"}>Run health test</button><div id="ai-health-result" class="small muted" style="margin-top:10px" role="status"></div></div><div class="panel"><div class="panel-header"><div><h2>AI boundary</h2><p>Evidence references are validated before storage.</p></div></div><div class="callout">The model receives bounded evidence excerpts. Unsupported claims and hallucinated observation IDs are rejected, while the deterministic backend remains authoritative.</div></div></section>`; const button = $("#ai-health-test"); button?.addEventListener("click", async () => { button.disabled = true; $("#ai-health-result").textContent = "Running sequential local inference…"; try { const result = await api("/api/ollama/health-test", { method: "POST" }); $("#ai-health-result").textContent = `Validated response received from ${result.model}.`; } catch (error) { $("#ai-health-result").textContent = error.message; } finally { button.disabled = false; } }); }
async function renderTools() { const [data, matrix] = await Promise.all([api("/api/dependencies"), api("/api/capability-matrix")]); $("#app").innerHTML = `<div class="page-intro"><div><h2>Tools and dependencies</h2><p>Check the local execution environment without installing packages silently.</p></div></div><section class="grid-2"><div class="panel"><div class="panel-header"><div><h2>Environment</h2><p>${escapeHtml(data.platform)}</p></div></div><div class="tree">${healthRow("Python", data.python, true)}${healthRow("WSL", data.wsl ? "Detected" : "Not detected", data.wsl)}${healthRow("Available memory", data.available_memory_bytes ? `${Math.round(data.available_memory_bytes / 1024 / 1024)} MiB` : "Unknown", true)}${healthRow("Free disk", `${Math.round(data.available_disk_bytes / 1024 / 1024 / 1024)} GiB`, true)}</div></div><div class="panel"><div class="panel-header"><div><h2>Tool inventory</h2><p>Detected on this host.</p></div></div><div class="tree">${Object.entries(data.tools).map(([name, item]) => healthRow(name, item.available ? "Available" : "Not installed", item.available)).join("")}</div></div></section><section class="panel" style="margin-top:16px"><div class="panel-header"><div><h2>Adapter coverage</h2><p>Use the machine-readable matrix for condition-level detail.</p></div>${statusBadge(`${matrix.live_execution_adapters} LIVE`)}</div><div class="metric-grid"><div class="metric"><span>Registered</span><strong>${matrix.registered_testcases}</strong></div><div class="metric"><span>Live command adapters</span><strong>${matrix.live_execution_adapters}</strong></div><div class="metric"><span>Capability-only</span><strong>${matrix.capability_only_testcases}</strong></div></div><p class="small muted" style="margin-top:13px">Capability-only conditions remain explicitly gated until an authorized internal, Layer-2, wireless, inventory, egress, or credential-policy sensor is available.</p></section>`; }
async function renderSettings() { $("#app").innerHTML = `<div class="page-intro"><div><h2>Settings</h2><p>Local-only defaults, advanced diagnostics, and evidence integrity controls.</p></div></div><section class="grid-2"><div class="panel"><div class="panel-header"><div><h2>Assessment defaults</h2><p>Safe behavior is the default.</p></div></div><div class="tree">${healthRow("Control interface", "127.0.0.1", true)}${healthRow("Scope", "Operator-provided only", true)}${healthRow("Classification", "Deterministic backend predicates", true)}${healthRow("Evidence", "Original output and SHA-256 hashes", true)}</div></div><div class="panel"><div class="panel-header"><div><h2>Advanced tools</h2><p>Open only when needed.</p></div></div><div class="button-row"><button class="button button-quiet" data-page="tools">Tools & dependencies</button><button class="button button-quiet" data-page="local-ai">Local AI status</button></div><details class="details"><summary>Evidence policy</summary><p class="small muted" style="margin-top:12px">POC PNGs contain only the original executed command and actual captured output. NA and INCONCLUSIVE results never create misleading negative POCs.</p></details></div></section>`; }

function stopSubscription(id) { if (state.eventSource && (!id || state.eventSource.assessmentId === id)) { state.eventSource.close(); state.eventSource = null; } }
function subscribe(id) { if (state.eventSource?.assessmentId === id) return; stopSubscription(); const source = new EventSource(`/api/assessments/${id}/events`); source.assessmentId = id; source.onmessage = async () => { if (source !== state.eventSource) return; if (state.page === "assessment" && state.selectedId === id) await renderAssessment(id); }; source.onerror = () => { if (source === state.eventSource) { source.close(); state.eventSource = null; toast("Live updates paused; refresh to reconnect."); } }; state.eventSource = source; }

document.addEventListener("click", async (event) => {
  const pageTarget = event.target.closest("[data-page]");
  if (pageTarget) { event.preventDefault(); setPage(pageTarget.dataset.page); return; }
  const openAssessment = event.target.closest("[data-open-assessment]");
  if (openAssessment) { event.preventDefault(); state.selectedId = openAssessment.dataset.openAssessment; localStorage.setItem("scopeguard:lastAssessment", state.selectedId); setPage("assessment"); return; }
  const wizardNext = event.target.closest("[data-wizard-next]");
  if (wizardNext) { event.preventDefault(); const next = Number(wizardNext.dataset.wizardNext); if (validateWizardStep(next - 1)) setWizardStep(next); return; }
  const wizardPrev = event.target.closest("[data-wizard-prev]");
  if (wizardPrev) { event.preventDefault(); setWizardStep(Number(wizardPrev.dataset.wizardPrev)); return; }
  const wizardStep = event.target.closest("[data-wizard-step]");
  if (wizardStep) { event.preventDefault(); const step = Number(wizardStep.dataset.wizardStep); if (step <= state.wizard.step || validateWizardStep(step - 1)) setWizardStep(step); return; }
  const typeCard = event.target.closest("[data-select-type]");
  if (typeCard) { event.preventDefault(); state.wizard.type = typeCard.dataset.selectType; $("#assessment-type").value = state.wizard.type; renderNewAssessment(); return; }
  const removeTarget = event.target.closest("[data-remove-target]");
  if (removeTarget) { event.preventDefault(); const value = decodeURIComponent(removeTarget.dataset.removeTarget); const remaining = splitTargets($("#targets").value).filter((item) => item !== value); $("#targets").value = remaining.join("\n"); updateScopePreview(); return; }
  const preview = event.target.closest("[data-preview]");
  if (preview) { event.preventDefault(); openPreview(preview.dataset.assessment, preview.dataset.preview); return; }
  const modalPreview = event.target.closest("[data-modal-preview]");
  if (modalPreview) { event.preventDefault(); openPreview(modalPreview.dataset.assessment, modalPreview.dataset.modalPreview); return; }
  const resultRow = event.target.closest(".result-row");
  if (resultRow && !event.target.closest("a")) { event.preventDefault(); openResultDetail(resultRow.dataset.assessment || state.selectedId, Number(resultRow.dataset.resultId)); return; }
  const copy = event.target.closest("[data-copy]");
  if (copy) { event.preventDefault(); const value = decodeURIComponent(copy.dataset.copy); try { await navigator.clipboard.writeText(value); toast("Copied to clipboard"); } catch { toast("Clipboard access is unavailable; select the reference manually."); } return; }
  if (event.target.closest("[data-close-modal]")) closeModal();
});
$("#menu-toggle").addEventListener("click", () => { const sidebar = $("#sidebar"); const open = sidebar.classList.toggle("open"); $("#menu-toggle").setAttribute("aria-expanded", String(open)); });
document.addEventListener("keydown", (event) => { if (event.key === "Escape" && !$("#modal").hidden) closeModal(); });

async function bootstrap() {
  try { await api("/api/health"); $("#backend-health").textContent = "Backend healthy"; } catch { $("#backend-health").textContent = "Backend unavailable"; }
  const queryAssessment = new URLSearchParams(location.search).get("assessment");
  if (queryAssessment) { state.selectedId = queryAssessment; state.page = "assessment"; }
  else { state.page = "overview"; }
  setPage(state.page);
}
bootstrap();
