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
 * Output (every run):
 *   - security-test-report.html   <- styled, human-readable report (open in a browser)
 *   - security-test-report.md     <- plain markdown version (same data)
 *   - a short summary printed to the console
 */

const fs = require("fs");
const path = require("path");

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
// 3. SCENARIO TEMPLATES PER CATEGORY
//    Each template turns a matched requirement into a concrete test.
// ---------------------------------------------------------------------------
const SCENARIO_TEMPLATES = {
  "Authentication": (req) =>
    `Attempt to access the account/dashboard without valid login credentials, and attempt repeated failed logins to check for lockout, based on: "${req}"`,
  "Authorization / Access Control": (req) =>
    `Attempt to access admin-only functionality/data using a non-admin (regular customer) account, based on: "${req}"`,
  "Input Validation / Injection": (req) =>
    `Submit malformed, oversized, or malicious input (e.g. script tags, SQL-like strings, disguised file types) to the relevant field, based on: "${req}"`,
  "Data Protection": (req) =>
    `Verify that sensitive data referenced here is encrypted in transit/at rest and is not exposed in responses, URLs, or logs, based on: "${req}"`,
  "Session Management": (req) =>
    `Verify that the session token expires correctly, cannot be reused after logout, and is invalidated after the stated timeout, based on: "${req}"`,
  "Error Handling & Logging": (req) =>
    `Trigger an invalid/erroneous input scenario and verify the error message does not leak internal system details, based on: "${req}"`,
  "API / Interface Security": (req) =>
    `Send an excessive number of rapid requests to the related endpoint to verify rate limiting / abuse protection is enforced, based on: "${req}"`,
  "Configuration & Deployment Security": (req) =>
    `Verify that sensitive configuration values (keys, connection strings) are not stored in plaintext or exposed in accessible files, based on: "${req}"`,
};

// ---------------------------------------------------------------------------
// 4. ONE-LINE RATIONALE TEMPLATES PER CATEGORY
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
// 5. SUGGESTED MANUAL SCENARIO FOR AN UNCOVERED CATEGORY
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

  // Pass 1: one scenario per category that has at least one hit (coverage first)
  for (const cat of CATEGORIES) {
    if (categoryHits[cat].length > 0 && scenarios.length < maxScenarios) {
      const req = categoryHits[cat][0];
      scenarios.push({
        category: cat,
        requirement: req,
        scenario: SCENARIO_TEMPLATES[cat](req),
        rationale: RATIONALE_TEMPLATES[cat](),
      });
    }
  }

  // Pass 2: if below minimum, add extra scenarios from categories with multiple hits
  let i = 1;
  while (scenarios.length < minScenarios) {
    let addedAny = false;
    for (const cat of CATEGORIES) {
      if (categoryHits[cat].length > i && scenarios.length < maxScenarios) {
        const req = categoryHits[cat][i];
        scenarios.push({
          category: cat,
          requirement: req,
          scenario: SCENARIO_TEMPLATES[cat](req),
          rationale: RATIONALE_TEMPLATES[cat](),
        });
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

  md += "## 1. Security Test Scenarios\n\n";
  md += "| # | Scenario | Category | Rationale |\n";
  md += "|---|----------|----------|-----------|\n";
  scenarios.forEach((s, idx) => {
    md += `| ${idx + 1} | ${s.scenario} | ${s.category} | ${s.rationale} |\n`;
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
      <p class="req-quote">&quot;${escapeHtml(s.requirement)}&quot;</p>
      <p class="field-label">Test scenario</p>
      <p class="scenario-text">${escapeHtml(s.scenario.replace(/, based on:.*$/, ""))}</p>
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
  .req-quote { font-family: 'Spectral', serif; font-style: italic; font-size: 15px; color: var(--muted); margin: 0 0 14px; padding-left: 14px; border-left: 2px solid var(--border); }
  .field-label { font-size: 11px; color: var(--muted); margin: 0 0 4px; }
  .scenario-text { font-size: 15px; margin: 0 0 16px; }
  .rationale { font-size: 13.5px; color: var(--muted); margin: 0; }
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
// 12. ENTRY POINT
// ---------------------------------------------------------------------------
function main() {
  const inputPath = process.argv[2];
  if (!inputPath) {
    console.error("Usage: node security-scenario-generator.js <path-to-requirements.txt>");
    process.exit(1);
  }

  const resolvedPath = path.resolve(inputPath);
  const rawText = fs.readFileSync(resolvedPath, "utf-8");
  const requirements = parseRequirements(rawText);
  const scenarios = generateScenarios(requirements);
  const coverage = buildCoverageSummary(scenarios);

  const mdReport = buildMarkdownReport(scenarios, coverage);
  const htmlReport = buildHtmlReport(scenarios, coverage, path.basename(resolvedPath));

  fs.writeFileSync("security-test-report.md", mdReport, "utf-8");
  fs.writeFileSync("security-test-report.html", htmlReport, "utf-8");

  const coveredCount = coverage.filter((c) => c.covered).length;
  console.log(`Generated ${scenarios.length} scenario(s) across ${coveredCount}/${CATEGORIES.length} categories.`);
  console.log('- security-test-report.md   (plain text)');
  console.log('- security-test-report.html (open this one in a browser)');
}

main();
