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
 *   - Prints a Markdown report to the console
 *   - Also saves the same report to "security-test-report.md"
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
// 5. PARSE THE REQUIREMENTS DOCUMENT
// ---------------------------------------------------------------------------
function parseRequirements(rawText) {
  return rawText
    .split("\n")
    .map((line) => line.replace(/^\s*[\d]+[\.\)]\s*/, "").trim()) // strip "1. " numbering
    .filter((line) => line.length > 0 && !line.toLowerCase().startsWith("project"));
}

// ---------------------------------------------------------------------------
// 6. DETECT MATCHING CATEGORIES FOR A SINGLE REQUIREMENT LINE
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
// 7. MAIN GENERATION LOGIC
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
// 8. COVERAGE SUMMARY
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
// 9. REPORT FORMATTING (Markdown)
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
// 10. ENTRY POINT
// ---------------------------------------------------------------------------
function main() {
  const inputPath = process.argv[2];
  if (!inputPath) {
    console.error("Usage: node security-scenario-generator.js <path-to-requirements.txt>");
    process.exit(1);
  }

  const rawText = fs.readFileSync(path.resolve(inputPath), "utf-8");
  const requirements = parseRequirements(rawText);
  const scenarios = generateScenarios(requirements);
  const coverage = buildCoverageSummary(scenarios);
  const report = buildMarkdownReport(scenarios, coverage);

  console.log(report);
  fs.writeFileSync("security-test-report.md", report, "utf-8");
  console.log('\n(Report also saved to "security-test-report.md")');
}

main();
