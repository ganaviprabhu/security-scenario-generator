#!/usr/bin/env node
/**
 * Security Test Scenario Generator
 * --------------------------------
 * Reads a bounded requirements document (plain text, one requirement per line
 * or bullet) and generates security test scenarios mapped to a FIXED set of
 * security categories.
 *
 * Usage:
 *   node security-scenario-generator.js <path-to-requirements.txt>
 *
 * Output:
 *   - reports/<source-name>_<timestamp>.html  <- styled, human-readable report
 *   - reports/<source-name>_<timestamp>.md    <- plain markdown version (same data)
 *   - a short summary printed to the console
 *
 * Change detection:
 *   Each source document's content is hashed. If you run the script again on
 *   a document that hasn't changed since its last report, no new report is
 *   written - the script just points you back at the existing one. This
 *   keeps reports/ from filling up with identical reports for the same
 *   unchanged file. Edit the document (even by one character) and it will
 *   generate a fresh report again.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ---------------------------------------------------------------------------
// 1. FIXED SECURITY CATEGORY TAXONOMY
//    This list must stay fixed. Every scenario generated MUST be tagged
//    with one of these categories only - nothing outside this list.
// ---------------------------------------------------------------------------
const CATEGORIES = [
  "Authentication",
  "Authorization / Access Control",
  "Input Validation / Injection",
  "Data Protection",
  "Session Management",
  "Error Handling & Logging",
  "API / Interface Security",
  "Configuration & Deployment Security",
];

// ---------------------------------------------------------------------------
// 2. KEYWORD -> CATEGORY MAPPING
//    Simple rule-based detection. Add more keywords as you encounter them.
// ---------------------------------------------------------------------------
const KEYWORD_RULES = [
  { keywords: ["log in", "login", "password", "credentials", "sign in"], category: "Authentication" },
  { keywords: ["admin", "role", "permission", "access to", "only admin"], category: "Authorization / Access Control" },
  { keywords: ["upload", "file", "input", "search", "filter", "enter"], category: "Input Validation / Injection" },
  { keywords: ["credit card", "payment", "personal data", "sensitive", "email"], category: "Data Protection" },
  { keywords: ["session", "token", "logged in", "timeout", "expire"], category: "Session Management" },
  { keywords: ["error", "invalid", "error message", "logs", "log file", "exception"], category: "Error Handling & Logging" },
  { keywords: ["api", "endpoint", "returns a list", "request"], category: "API / Interface Security" },
  { keywords: ["config", "configuration", "connection details", "api key", "default"], category: "Configuration & Deployment Security" },
];

// ---------------------------------------------------------------------------
// 3. CATEGORY PREFIXES (for Test Case IDs, e.g. AUTH-01, INPUT-02)
// ---------------------------------------------------------------------------
const CATEGORY_PREFIXES = {
  "Authentication": "AUTH",
  "Authorization / Access Control": "AUTHZ",
  "Input Validation / Injection": "INPUT",
  "Data Protection": "DATA",
  "Session Management": "SESS",
  "Error Handling & Logging": "ERR",
  "API / Interface Security": "API",
  "Configuration & Deployment Security": "CONFIG",
};

// ---------------------------------------------------------------------------
// 4. SCENARIO TEMPLATES PER CATEGORY
//    Each category defines a short title, a numbered list of test steps,
//    and the expected (secure) result - the building blocks of a proper
//    test case: Test Case ID - Category - Test Scenario - Steps - Expected
//    Result. All templates take the matched requirement text so the case
//    stays traceable back to the line that triggered it.
// ---------------------------------------------------------------------------
const SCENARIO_TEMPLATES = {
  "Authentication": {
    title: () => "Verify login authentication cannot be bypassed or brute-forced",
    steps: (req) => [
      "Navigate to the login page covered by this requirement.",
      "Attempt to log in with incorrect credentials.",
      "Repeat the failed login attempt several times in quick succession.",
      "Attempt to open the account/dashboard directly without logging in.",
    ],
    expectedResult: () =>
      "Invalid credentials are rejected on every attempt; repeated failures trigger a lockout or throttling response; the account/dashboard is not reachable without a valid, successful login.",
  },
  "Authorization / Access Control": {
    title: () => "Verify non-admin accounts cannot reach admin-only functionality",
    steps: (req) => [
      "Log in using a regular (non-admin) account.",
      "Attempt to navigate directly to the admin-only page or feature URL.",
      "If an API backs the feature, attempt to call it directly with the non-admin account's session.",
    ],
    expectedResult: () =>
      "The non-admin account is denied access (e.g. 403/redirect) to the admin-only page, feature, and any underlying API - no admin data or controls are exposed.",
  },
  "Input Validation / Injection": {
    title: () => "Verify the input field rejects malicious or malformed data",
    steps: (req) => [
      "Locate the input field this requirement refers to.",
      "Submit a script/HTML payload (e.g. <script>alert(1)</script>) into the field.",
      "Submit a SQL-like string (e.g. ' OR '1'='1) into the field.",
      "Submit an oversized value and, if applicable, a disguised file type.",
    ],
    expectedResult: () =>
      "Every malicious or malformed input is rejected or safely sanitized. No script executes, no database error surfaces, and the application does not misbehave or crash.",
  },
  "Data Protection": {
    title: () => "Verify sensitive data is protected in transit, at rest, and in output",
    steps: (req) => [
      "Identify the sensitive data referenced by this requirement.",
      "Inspect network traffic while submitting/retrieving that data to confirm it is sent over HTTPS/TLS.",
      "Inspect the database/storage layer to confirm the data is encrypted at rest.",
      "Check API responses, URLs, and application logs for the same data appearing in plaintext.",
    ],
    expectedResult: () =>
      "The sensitive data is encrypted in transit and at rest, and never appears unmasked in responses, URLs, or logs.",
  },
  "Session Management": {
    title: () => "Verify the session expires and cannot be reused after logout",
    steps: (req) => [
      "Log in and note the active session/token.",
      "Remain idle until the stated timeout period has elapsed.",
      "Attempt to perform an authenticated action using the now-idle session.",
      "Log out, then attempt to reuse the same session/token for a request.",
    ],
    expectedResult: () =>
      "The session is invalidated once the timeout is reached, and the logged-out token is rejected on reuse - no action succeeds with an expired or logged-out session.",
  },
  "Error Handling & Logging": {
    title: () => "Verify error responses don't leak internal system details",
    steps: (req) => [
      "Trigger the erroneous/invalid condition described by this requirement (e.g. wrong password, bad input).",
      "Record the exact error message shown to the end user.",
      "Cross-check the same event in the application/server logs.",
    ],
    expectedResult: () =>
      "The user-facing error message is generic and free of stack traces, internal paths, or system details; any sensitive diagnostic detail stays server-side in the logs only.",
  },
  "API / Interface Security": {
    title: () => "Verify the API endpoint enforces rate limiting and access control",
    steps: (req) => [
      "Identify the API endpoint this requirement refers to.",
      "Send a burst of rapid, repeated requests to the endpoint.",
      "Call the endpoint without a valid authentication token or with an unauthorized account.",
    ],
    expectedResult: () =>
      "Excessive requests are throttled or rate-limited; unauthenticated or unauthorized calls are rejected with an appropriate error rather than returning data.",
  },
  "Configuration & Deployment Security": {
    title: () => "Verify configuration secrets are not stored or exposed in plaintext",
    steps: (req) => [
      "Locate the configuration file(s) or environment settings referenced by this requirement.",
      "Check whether secrets (API keys, connection strings, credentials) are stored in plaintext.",
      "Check whether the configuration file is reachable via the web server or committed to a public repository.",
    ],
    expectedResult: () =>
      "Secrets are not stored in plaintext, are excluded from version control, and the configuration file is not publicly accessible.",
  },
};

// ---------------------------------------------------------------------------
// 5. ONE-LINE RATIONALE TEMPLATES PER CATEGORY
// ---------------------------------------------------------------------------
const RATIONALE_TEMPLATES = {
  "Authentication": () => "This requirement involves user login, so authentication bypass and brute-force protection must be verified.",
  "Authorization / Access Control": () => "This requirement implies restricted/role-based access, so improper access control could let unauthorized users in.",
  "Input Validation / Injection": () => "This requirement accepts user-supplied input, so unvalidated input could lead to injection or malicious file risks.",
  "Data Protection": () => "This requirement involves sensitive or personal data, so exposure or weak protection must be tested.",
  "Session Management": () => "This requirement involves session/login state, so improper session handling could allow session hijacking or fixation.",
  "Error Handling & Logging": () => "This requirement involves error messages, so verbose errors could leak sensitive internal information.",
  "API / Interface Security": () => "This requirement involves an API endpoint, so lack of rate limiting or abuse controls could be exploited.",
  "Configuration & Deployment Security": () => "This requirement involves stored configuration/secrets, so insecure storage could expose credentials.",
};

// ---------------------------------------------------------------------------
// 6. SUGGESTED MANUAL SCENARIO FOR AN UNCOVERED CATEGORY
//    Shown in the report so a category with zero matches isn't just a
//    silent gap - it comes with a starting point for a manual test.
// ---------------------------------------------------------------------------
const GAP_SUGGESTIONS = {
  "Authentication": "Manually verify login lockout, password reset flow, and multi-factor enforcement, since no requirement line triggered this category.",
  "Authorization / Access Control": "Manually verify that role checks are enforced server-side, not just hidden in the UI.",
  "Input Validation / Injection": "Manually test every user-facing input field for injection and oversized/malformed payloads.",
  "Data Protection": "Manually confirm what counts as sensitive data in this system and verify it's encrypted at rest and in transit.",
  "Session Management": "Manually verify session expiry, logout invalidation, and token reuse across the application.",
  "Error Handling & Logging": "Manually trigger error conditions across the app and check responses/logs for leaked internal details.",
  "API / Interface Security": "Manually check all API endpoints for rate limiting, auth enforcement, and input validation.",
  "Configuration & Deployment Security": "Check that API keys, database connection strings, and other secrets aren't stored in plaintext in config files, environment dumps, or client-accessible bundles.",
};

// ---------------------------------------------------------------------------
// 6. PARSE THE REQUIREMENTS DOCUMENT
// ---------------------------------------------------------------------------
function parseRequirements(rawText) {
  return rawText
    .split("\n")
    .map((line) => line.replace(/^\s*[\d]+[\.\)]\s*/, "").trim()) // strip "1. " numbering
    .filter((line) => line.length > 0 && !line.toLowerCase().startsWith("project"));
}

// ---------------------------------------------------------------------------
// 7. DETECT MATCHING CATEGORIES FOR A SINGLE REQUIREMENT LINE
// ---------------------------------------------------------------------------
function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function containsKeyword(text, keyword) {
  // \b word-boundary match so short keywords (e.g. "log") don't match
  // inside unrelated words (e.g. "login"). Works for multi-word phrases too.
  const pattern = new RegExp(`\\b${escapeRegExp(keyword)}\\b`, "i");
  return pattern.test(text);
}

function detectCategories(requirementLine) {
  const matched = [];
  for (const rule of KEYWORD_RULES) {
    const hit = rule.keywords.some((kw) => containsKeyword(requirementLine, kw));
    if (hit) matched.push(rule.category);
  }
  return matched;
}

// ---------------------------------------------------------------------------
// 8. MAIN GENERATION LOGIC
//    Ensures 5-8 scenarios, prioritising coverage across DIFFERENT categories
//    before adding a second scenario to any single category.
// ---------------------------------------------------------------------------
function generateScenarios(requirements, minScenarios = 5, maxScenarios = 8) {
  // Map: category -> list of {requirement} that matched it
  const categoryHits = {};
  for (const cat of CATEGORIES) categoryHits[cat] = [];

  for (const req of requirements) {
    const cats = detectCategories(req);
    for (const cat of cats) {
      categoryHits[cat].push(req);
    }
  }

  const scenarios = [];
  const categoryCounters = {};
  for (const cat of CATEGORIES) categoryCounters[cat] = 0;

  function buildScenario(cat, req) {
    categoryCounters[cat] += 1;
    const template = SCENARIO_TEMPLATES[cat];
    const idNum = String(categoryCounters[cat]).padStart(2, "0");
    return {
      testCaseId: `${CATEGORY_PREFIXES[cat]}-${idNum}`,
      category: cat,
      requirement: req,
      title: template.title(req),
      steps: template.steps(req),
      expectedResult: template.expectedResult(req),
      rationale: RATIONALE_TEMPLATES[cat](),
    };
  }

  // Pass 1: one scenario per category that has at least one hit (coverage first)
  for (const cat of CATEGORIES) {
    if (categoryHits[cat].length > 0 && scenarios.length < maxScenarios) {
      scenarios.push(buildScenario(cat, categoryHits[cat][0]));
    }
  }

  // Pass 2: if below minimum, add extra scenarios from categories with multiple hits
  let i = 1;
  while (scenarios.length < minScenarios) {
    let addedAny = false;
    for (const cat of CATEGORIES) {
      if (categoryHits[cat].length > i && scenarios.length < maxScenarios) {
        scenarios.push(buildScenario(cat, categoryHits[cat][i]));
        addedAny = true;
      }
    }
    if (!addedAny) break; // no more hits available anywhere
    i++;
  }

  return scenarios;
}

// ---------------------------------------------------------------------------
// 9. COVERAGE SUMMARY
// ---------------------------------------------------------------------------
function buildCoverageSummary(scenarios) {
  const counts = {};
  for (const cat of CATEGORIES) counts[cat] = 0;
  for (const s of scenarios) counts[s.category]++;

  return CATEGORIES.map((cat) => ({
    category: cat,
    covered: counts[cat] > 0,
    count: counts[cat],
  }));
}

// ---------------------------------------------------------------------------
// 10. MARKDOWN REPORT (kept for scripting/diffing/plain-text use)
// ---------------------------------------------------------------------------
function buildMarkdownReport(scenarios, coverage) {
  let md = "# Security Test Scenario Report\n\n";

  md += "## 1. Security Test Cases\n\n";
  md += "| Test Case ID | Category | Test Scenario | Steps | Expected Result |\n";
  md += "|---|---|---|---|---|\n";
  scenarios.forEach((s) => {
    const stepsCell = s.steps.map((step, i) => `${i + 1}. ${step}`).join("<br>");
    md += `| ${s.testCaseId} | ${s.category} | ${s.title} | ${stepsCell} | ${s.expectedResult} |\n`;
  });

  md += "\n## 2. Coverage Summary\n\n";
  md += "| Category | Covered? | # Scenarios |\n";
  md += "|----------|----------|-------------|\n";
  coverage.forEach((c) => {
    md += `| ${c.category} | ${c.covered ? "Yes" : "No"} | ${c.count} |\n`;
  });

  const coveredCount = coverage.filter((c) => c.covered).length;
  md += `\n**Overall coverage: ${coveredCount}/${CATEGORIES.length} categories covered.**\n`;

  return md;
}

// ---------------------------------------------------------------------------
// 11. HTML REPORT (the human-readable version)
//     Groups scenarios by category, quotes the source requirement, and
//     calls out any category with zero matches as an explicit gap with a
//     suggested manual scenario - built fresh from whatever CATEGORIES /
//     scenarios / coverage are passed in, so it always reflects the current
//     input document rather than any fixed example.
// ---------------------------------------------------------------------------
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function buildHtmlReport(scenarios, coverage, sourceFileName) {
  const coveredCount = coverage.filter((c) => c.covered).length;
  const total = CATEGORIES.length;
  const generatedAt = new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC";

  const ticksHtml = coverage
    .map(
      (c) =>
        `<div class="tick${c.covered ? " filled" : ""}" title="${escapeHtml(c.category)}${
          c.covered ? "" : " — not covered"
        }"></div>`
    )
    .join("\n          ");

  // Group scenarios by category, preserving CATEGORIES order
  const scenariosByCategory = {};
  for (const cat of CATEGORIES) scenariosByCategory[cat] = [];
  for (const s of scenarios) scenariosByCategory[cat_or(s)].push(s);
  function cat_or(s) { return s.category; }

  const sectionsHtml = CATEGORIES.map((cat) => {
    const items = scenariosByCategory[cat];
    if (items.length > 0) {
      const cardsHtml = items
        .map(
          (s) => `
    <div class="scenario-card">
      <div class="card-top">
        <span class="tc-id">${escapeHtml(s.testCaseId)}</span>
        <h3 class="tc-title">${escapeHtml(s.title)}</h3>
      </div>
      <p class="req-quote">&quot;${escapeHtml(s.requirement)}&quot;</p>
      <p class="field-label">Steps</p>
      <ol class="steps-list">
        ${s.steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("\n        ")}
      </ol>
      <p class="field-label">Expected result</p>
      <p class="expected-result">${escapeHtml(s.expectedResult)}</p>
      <p class="rationale">${escapeHtml(s.rationale)}</p>
    </div>`
        )
        .join("\n");

      return `
  <section class="category-block">
    <div class="cat-heading">
      <h2>${escapeHtml(cat)}</h2>
      <span class="cat-count">${items.length} scenario${items.length > 1 ? "s" : ""}</span>
    </div>${cardsHtml}
  </section>`;
    }

    // Uncovered category -> gap callout instead of an empty section
    const suggestion = GAP_SUGGESTIONS[cat] || "No requirement line matched this category. Add manual test coverage for it.";
    return `
  <section class="gap-block">
    <div class="gap-card">
      <h2>${escapeHtml(cat)} — no matching requirement</h2>
      <p>Nothing in the requirements document mentioned this category, so the generator had no line to build a scenario from. That doesn't mean the risk isn't there — it means the requirements doc is silent on it.</p>
      <p class="gap-suggestion">Suggested manual scenario: ${escapeHtml(suggestion)}</p>
    </div>
  </section>`;
  }).join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Test Scenario Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Spectral:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #F2EFE7;
    --surface: #FFFFFF;
    --ink: #1C2B36;
    --muted: #5C6B75;
    --accent-amber: #B5651D;
    --border: #DCD5C2;
    --tick-fill: #3E6259;
    --tick-empty: #DCD5C2;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #131E27; --surface: #1B2831; --ink: #EAE4D6; --muted: #93A3AC;
      --accent-amber: #E0A458; --border: #2C3C46; --tick-fill: #82BBA6; --tick-empty: #2C3C46;
    }
  }
  :root[data-theme="dark"] {
    --bg: #131E27; --surface: #1B2831; --ink: #EAE4D6; --muted: #93A3AC;
    --accent-amber: #E0A458; --border: #2C3C46; --tick-fill: #82BBA6; --tick-empty: #2C3C46;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--ink); font-family: 'IBM Plex Sans', system-ui, sans-serif; line-height: 1.55; -webkit-font-smoothing: antialiased; }
  .page { max-width: 760px; margin: 0 auto; padding: 64px 24px 96px; }
  header.report-head { margin-bottom: 48px; }
  .file-line { font-family: 'IBM Plex Mono', monospace; font-size: 13px; color: var(--muted); margin: 0 0 18px; word-break: break-all; }
  h1 { font-family: 'Spectral', Georgia, serif; font-weight: 600; font-size: 40px; line-height: 1.15; margin: 0 0 10px; letter-spacing: -0.01em; }
  .dek { font-size: 16px; color: var(--muted); max-width: 60ch; margin: 0; }
  .scoreboard { display: flex; align-items: center; gap: 28px; margin-top: 40px; padding-top: 32px; border-top: 1px solid var(--border); flex-wrap: wrap; }
  .score-num { font-family: 'Spectral', serif; font-size: 56px; font-weight: 600; line-height: 1; white-space: nowrap; }
  .score-num span { font-size: 22px; color: var(--muted); font-weight: 400; }
  .score-detail { flex: 1; min-width: 200px; }
  .score-label { font-size: 14px; color: var(--muted); margin: 0 0 10px; }
  .ticks { display: flex; gap: 6px; flex-wrap: wrap; }
  .tick { width: 28px; height: 10px; border-radius: 2px; background: var(--tick-empty); position: relative; cursor: default; }
  .tick.filled { background: var(--tick-fill); }
  .tick[title]:hover::after { content: attr(title); position: absolute; bottom: 16px; left: 50%; transform: translateX(-50%); background: var(--ink); color: var(--bg); font-size: 11px; padding: 4px 8px; border-radius: 4px; white-space: nowrap; z-index: 2; }
  section.category-block { margin-top: 40px; padding-top: 32px; border-top: 1px solid var(--border); }
  .cat-heading { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 18px; }
  .cat-heading h2 { font-family: 'Spectral', serif; font-weight: 600; font-size: 21px; margin: 0; }
  .cat-count { font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: var(--muted); white-space: nowrap; }
  .scenario-card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 20px 22px; margin-bottom: 14px; }
  .scenario-card:last-child { margin-bottom: 0; }
  .card-top { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; margin-bottom: 12px; }
  .tc-id { font-family: 'IBM Plex Mono', monospace; font-size: 12px; font-weight: 500; color: var(--surface); background: var(--tick-fill); padding: 2px 8px; border-radius: 3px; white-space: nowrap; }
  .tc-title { font-family: 'IBM Plex Sans', sans-serif; font-weight: 600; font-size: 15.5px; margin: 0; }
  .req-quote { font-family: 'Spectral', serif; font-style: italic; font-size: 14px; color: var(--muted); margin: 0 0 16px; padding-left: 14px; border-left: 2px solid var(--border); }
  .field-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); margin: 0 0 6px; }
  .steps-list { margin: 0 0 16px; padding-left: 20px; font-size: 14.5px; }
  .steps-list li { margin-bottom: 5px; }
  .steps-list li:last-child { margin-bottom: 0; }
  .expected-result { font-size: 14.5px; margin: 0 0 14px; padding: 10px 12px; background: color-mix(in srgb, var(--tick-fill) 10%, var(--surface)); border-left: 2px solid var(--tick-fill); border-radius: 3px; }
  .rationale { font-size: 12.5px; color: var(--muted); margin: 0; font-style: italic; }
  .gap-block { margin-top: 40px; padding-top: 32px; border-top: 1px solid var(--border); }
  .gap-card { border: 1px dashed var(--accent-amber); border-radius: 6px; padding: 20px 22px; background: color-mix(in srgb, var(--accent-amber) 8%, var(--surface)); }
  .gap-card h2 { font-family: 'Spectral', serif; font-weight: 600; font-size: 21px; margin: 0 0 10px; color: var(--accent-amber); }
  .gap-card p { margin: 0 0 12px; font-size: 15px; }
  .gap-card p:last-child { margin-bottom: 0; }
  .gap-suggestion { font-size: 13.5px; color: var(--muted); }
  footer { margin-top: 56px; padding-top: 24px; border-top: 1px solid var(--border); font-size: 12.5px; color: var(--muted); }
  @media (max-width: 520px) {
    h1 { font-size: 30px; }
    .scoreboard { flex-direction: column; align-items: flex-start; gap: 16px; }
    .score-num { font-size: 44px; }
  }
</style>
</head>
<body>
<div class="page">

  <header class="report-head">
    <p class="file-line">source: ${escapeHtml(sourceFileName)} — generated ${escapeHtml(generatedAt)}</p>
    <h1>Security Test Scenario Report</h1>
    <p class="dek">Test scenarios mapped from the requirements document to a fixed set of ${total} security categories, so gaps in coverage are visible at a glance.</p>

    <div class="scoreboard">
      <div class="score-num">${coveredCount}<span>/${total}</span></div>
      <div class="score-detail">
        <p class="score-label">Categories covered</p>
        <div class="ticks">
          ${ticksHtml}
        </div>
      </div>
    </div>
  </header>
${sectionsHtml}

  <footer>
    ${coveredCount} of ${total} categories covered from the supplied requirements. Uncovered categories are flagged above with a suggested manual scenario — add a matching line to the requirements document to have the generator pick it up automatically next time.
  </footer>

</div>
</body>
</html>
`;
}

// ---------------------------------------------------------------------------
// 12. OUTPUT FILE NAMING
//     Every run gets its own report files instead of overwriting the last
//     one. The name is built from the source document's name plus a
//     timestamp, so re-running against the same document twice still
//     produces two distinct reports. If somehow both name AND timestamp
//     collide (e.g. two runs in the same second), a numeric suffix is
//     added so nothing already on disk is ever overwritten.
// ---------------------------------------------------------------------------
const REPORTS_DIR = "reports";
const INDEX_PATH = path.join(REPORTS_DIR, ".report-index.json");

// ---------------------------------------------------------------------------
// CHANGE DETECTION
//     Tracks the content hash of the last report generated for each source
//     document (by filename). If the same document is run again unchanged,
//     we skip writing a new report and just point back at the last one.
// ---------------------------------------------------------------------------
function hashContent(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function loadIndex() {
  if (!fs.existsSync(INDEX_PATH)) return {};
  try {
    return JSON.parse(fs.readFileSync(INDEX_PATH, "utf-8"));
  } catch {
    // Corrupt or unreadable index - start fresh rather than crash the run.
    return {};
  }
}

function saveIndex(index) {
  fs.writeFileSync(INDEX_PATH, JSON.stringify(index, null, 2), "utf-8");
}

function slugify(name) {
  return name
    .toLowerCase()
    .replace(/\.[^/.]+$/, "")     // strip file extension
    .replace(/[^a-z0-9]+/g, "-")  // non-alphanumeric -> hyphen
    .replace(/^-+|-+$/g, "");     // trim leading/trailing hyphens
}

function timestampStr(date = new Date()) {
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `_${pad(date.getHours())}-${pad(date.getMinutes())}-${pad(date.getSeconds())}`
  );
}

function buildOutputBaseName(sourceFileName) {
  const base = `${slugify(sourceFileName)}_${timestampStr()}`;
  let candidate = base;
  let counter = 2;
  // Guard against collisions (two runs within the same second, etc.)
  while (
    fs.existsSync(path.join(REPORTS_DIR, `${candidate}.html`)) ||
    fs.existsSync(path.join(REPORTS_DIR, `${candidate}.md`))
  ) {
    candidate = `${base}-${counter}`;
    counter++;
  }
  return candidate;
}

// ---------------------------------------------------------------------------
// 13. ENTRY POINT
// ---------------------------------------------------------------------------
function main() {
  const inputPath = process.argv[2];
  if (!inputPath) {
    console.error("Usage: node security-scenario-generator.js <path-to-requirements.txt>");
    process.exit(1);
  }

  const resolvedPath = path.resolve(inputPath);
  const rawText = fs.readFileSync(resolvedPath, "utf-8");
  const sourceFileName = path.basename(resolvedPath);

  if (!fs.existsSync(REPORTS_DIR)) {
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
  }

  // --- Change detection: skip regenerating if this exact content was
  //     already turned into a report for this source filename. ---
  const contentHash = hashContent(rawText);
  const index = loadIndex();
  const lastRun = index[sourceFileName];

  if (lastRun && lastRun.hash === contentHash && fs.existsSync(lastRun.htmlPath)) {
    console.log(`No changes detected in "${sourceFileName}" since the last report - skipping regeneration.`);
    console.log(`- ${lastRun.mdPath}   (existing, unchanged)`);
    console.log(`- ${lastRun.htmlPath} (existing, unchanged)`);
    return;
  }

  const requirements = parseRequirements(rawText);
  const scenarios = generateScenarios(requirements);
  const coverage = buildCoverageSummary(scenarios);

  const mdReport = buildMarkdownReport(scenarios, coverage);
  const htmlReport = buildHtmlReport(scenarios, coverage, sourceFileName);

  const outputBaseName = buildOutputBaseName(sourceFileName);
  const mdPath = path.join(REPORTS_DIR, `${outputBaseName}.md`);
  const htmlPath = path.join(REPORTS_DIR, `${outputBaseName}.html`);

  fs.writeFileSync(mdPath, mdReport, "utf-8");
  fs.writeFileSync(htmlPath, htmlReport, "utf-8");

  index[sourceFileName] = { hash: contentHash, mdPath, htmlPath, generatedAt: new Date().toISOString() };
  saveIndex(index);

  const coveredCount = coverage.filter((c) => c.covered).length;
  console.log(`Generated ${scenarios.length} scenario(s) across ${coveredCount}/${CATEGORIES.length} categories.`);
  console.log(`- ${mdPath}   (plain text)`);
  console.log(`- ${htmlPath} (open this one in a browser)`);
}

main();
