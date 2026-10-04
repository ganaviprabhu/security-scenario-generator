#!/usr/bin/env node
/**
 * Security Test Scenario Generator  (v2.2)
 * --------------------------------------
 * Reads a bounded requirements document (.txt, .md, .html, .docx or .pdf; one
 * requirement per line or bullet) and generates security test scenarios mapped to a FIXED set of
 * security categories.
 *
 * Usage:
 *   node security-scenario-generator.js <requirements-file> [--per-category 6]
 *
 * Supported input: .txt  .md  .markdown  .html  .htm  .docx  .pdf
 * (.docx needs: npm install mammoth   |   .pdf needs: npm install pdf-parse)
 *
 * Output:
 *   - reports/<source-name>_<timestamp>.html  <- styled, human-readable report
 *   - reports/<source-name>_<timestamp>.md    <- plain markdown version (same data)
 *   - a short summary printed to the console
 *
 * What changed in v2:
 *   - Every category now has 3 different scenario variants (not 1), so a
 *     single matching requirement can produce several distinct tests.
 *   - EVERY requirement line that matches a category gets its own scenario,
 *     not just the first match.
 *   - Every category you touch gets up to 6 scenarios (default). Use
 *     --per-category 5 for 5 each. There is no overall cap.
 *   - Each scenario starts with a step that quotes the requirement it came
 *     from, so tests stay traceable.
 *   - Change detection now also tracks the generator version and the
 *     --per-category setting, so upgrading the script or changing the limit
 *     regenerates the report instead of saying "no changes detected".
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// Bump this whenever scenario logic changes so old hashes stop matching.
const GENERATOR_VERSION = "2.2.0";
const MAX_PER_CATEGORY = 6; // number of distinct variants written per category
const DEFAULT_LIMITS = { perCategory: 6 };

// ---------------------------------------------------------------------------
// 1. FIXED SECURITY CATEGORY TAXONOMY
//    Every scenario MUST be tagged with one of these categories only.
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
// 4. SCENARIO VARIANTS PER CATEGORY  (3 per category)
//    Each variant = { title, steps[], expectedResult }.
//    A first step quoting the source requirement is added automatically.
// ---------------------------------------------------------------------------
const SCENARIO_VARIANTS = {
  "Authentication": [
    {
      title: "Verify login authentication cannot be bypassed or brute-forced",
      steps: [
        "Navigate to the login page.",
        "Attempt to log in with incorrect credentials.",
        "Repeat the failed login attempt several times in quick succession.",
        "Attempt to open the account/dashboard directly without logging in.",
      ],
      expectedResult:
        "Invalid credentials are rejected on every attempt; repeated failures trigger a lockout or throttling response; the account/dashboard is not reachable without a valid, successful login.",
    },
    {
      title: "Verify password rules are enforced and credentials are never echoed back",
      steps: [
        "Try to set or change a password using an empty value, a very short value, and a common weak password.",
        "Submit a valid password and inspect the response body, URL, and page source.",
        "Check that the password field is masked and that the browser is not told to cache or autofill it unsafely.",
      ],
      expectedResult:
        "Weak or empty passwords are rejected with a clear rule message; passwords never appear in URLs, responses, or page source; the field is masked.",
    },
    {
      title: "Verify account recovery and login errors do not allow account enumeration",
      steps: [
        "Request a password reset for an existing account and for an account that does not exist.",
        "Compare the response text, status code, and response time of both requests.",
        "Open a used or expired reset link and try to use it again.",
      ],
      expectedResult:
        "Both requests return an identical, generic response so attackers cannot tell which accounts exist; used or expired reset links are rejected.",
    },
  ],
  "Authorization / Access Control": [
    {
      title: "Verify non-admin accounts cannot reach admin-only functionality",
      steps: [
        "Log in using a regular (non-admin) account.",
        "Attempt to navigate directly to the admin-only page or feature URL.",
        "If an API backs the feature, call it directly with the non-admin account's session.",
      ],
      expectedResult:
        "The non-admin account is denied access (e.g. 403/redirect) to the admin-only page, feature, and any underlying API - no admin data or controls are exposed.",
    },
    {
      title: "Verify one user cannot read or change another user's data (horizontal access)",
      steps: [
        "Log in as User A and note the ID or reference in a URL or request for one of A's records.",
        "Replace that ID with one belonging to User B and resend the request.",
        "Repeat for a write action (update or delete) on User B's record.",
      ],
      expectedResult:
        "Requests for another user's record are rejected; the server checks ownership on every read and write, not just in the UI.",
    },
    {
      title: "Verify role or privilege values cannot be tampered with by the client",
      steps: [
        "Capture a normal request and look for role, user type, or permission values in the body, cookie, or token.",
        "Modify those values to a higher privilege and resend the request.",
        "Add unexpected fields such as isAdmin=true to a profile update request.",
      ],
      expectedResult:
        "Privilege is determined server-side only; tampered or extra fields are ignored or rejected and no privilege change occurs.",
    },
  ],
  "Input Validation / Injection": [
    {
      title: "Verify the input field rejects malicious or malformed data",
      steps: [
        "Locate the input field this requirement refers to.",
        "Submit a script/HTML payload (e.g. <script>alert(1)</script>) into the field.",
        "Submit a SQL-like string (e.g. ' OR '1'='1) into the field.",
        "Submit an oversized value.",
      ],
      expectedResult:
        "Every malicious or malformed input is rejected or safely sanitized. No script executes, no database error surfaces, and the application does not misbehave or crash.",
    },
    {
      title: "Verify file upload accepts only permitted file types and sizes",
      steps: [
        "Upload a file with a disallowed extension, and one with a double extension (e.g. report.pdf.exe).",
        "Upload a file whose content does not match its extension.",
        "Upload a file larger than the stated limit, and one with a path-like name (e.g. ../../test.txt).",
      ],
      expectedResult:
        "Disallowed, mismatched, oversized, and path-manipulating files are rejected; accepted files are stored safely and are never executed.",
    },
    {
      title: "Verify validation is enforced on the server, not only in the browser",
      steps: [
        "Submit the form normally with invalid data and note the client-side message.",
        "Bypass the browser by sending the same invalid data directly to the server request.",
        "Try special characters, Unicode, null bytes, and extremely long strings.",
      ],
      expectedResult:
        "The server rejects invalid data even when client-side checks are skipped, and handles unusual characters without errors or unexpected behaviour.",
    },
  ],
  "Data Protection": [
    {
      title: "Verify sensitive data is protected in transit, at rest, and in output",
      steps: [
        "Identify the sensitive data referenced by this requirement.",
        "Inspect network traffic while submitting/retrieving that data to confirm it is sent over HTTPS/TLS.",
        "Inspect the database/storage layer to confirm the data is encrypted at rest.",
        "Check API responses, URLs, and application logs for the same data appearing in plaintext.",
      ],
      expectedResult:
        "The sensitive data is encrypted in transit and at rest, and never appears unmasked in responses, URLs, or logs.",
    },
    {
      title: "Verify sensitive data is masked on screen and not cached by the browser",
      steps: [
        "Open the screens that display the sensitive data.",
        "Check whether values are masked or partially hidden (e.g. last 4 digits only).",
        "Check response headers for cache controls, then use the browser back button after logout.",
      ],
      expectedResult:
        "Sensitive values are masked where full display is not needed; pages with sensitive data are not cached and cannot be viewed again after logout.",
    },
    {
      title: "Verify sensitive data does not leak through exports, notifications, or stored copies",
      steps: [
        "Trigger any export, report, email, or notification that includes this data.",
        "Review the content for full, unmasked values.",
        "Check temporary files, backups, and client-side storage (local storage, cookies) for copies of the data.",
      ],
      expectedResult:
        "Exports and notifications contain only the minimum data required, masked where possible; no unprotected copies exist in temporary files or browser storage.",
    },
  ],
  "Session Management": [
    {
      title: "Verify the session expires and cannot be reused after logout",
      steps: [
        "Log in and note the active session/token.",
        "Remain idle until the stated timeout period has elapsed.",
        "Attempt to perform an authenticated action using the now-idle session.",
        "Log out, then attempt to reuse the same session/token for a request.",
      ],
      expectedResult:
        "The session is invalidated once the timeout is reached, and the logged-out token is rejected on reuse - no action succeeds with an expired or logged-out session.",
    },
    {
      title: "Verify session cookies and tokens carry the right security attributes",
      steps: [
        "Log in and inspect the session cookie or token in the browser developer tools.",
        "Check the cookie flags: Secure, HttpOnly, and SameSite.",
        "Check that the token is long, random, and not guessable or based on user details.",
      ],
      expectedResult:
        "Session cookies are set with Secure, HttpOnly, and an appropriate SameSite value; tokens are random and cannot be predicted.",
    },
    {
      title: "Verify a new session is issued at login and concurrent use is controlled",
      steps: [
        "Note the session ID before logging in, then log in and note the session ID again.",
        "Try to use the pre-login session ID after logging in.",
        "Log in from a second browser with the same account and check how the first session behaves.",
      ],
      expectedResult:
        "A new session ID is issued at login and the pre-login ID is rejected (no session fixation); concurrent sessions follow the defined policy.",
    },
  ],
  "Error Handling & Logging": [
    {
      title: "Verify error responses don't leak internal system details",
      steps: [
        "Trigger the erroneous/invalid condition described by this requirement (e.g. wrong password, bad input).",
        "Record the exact error message shown to the end user.",
        "Cross-check the same event in the application/server logs.",
      ],
      expectedResult:
        "The user-facing error message is generic and free of stack traces, internal paths, or system details; any sensitive diagnostic detail stays server-side in the logs only.",
    },
    {
      title: "Verify security-relevant events are logged without recording secrets",
      steps: [
        "Perform a failed login, an access-denied action, and a successful sensitive action.",
        "Locate the matching entries in the application or audit log.",
        "Check each entry for who, what, when, and source, and for any passwords, tokens, or full card numbers.",
      ],
      expectedResult:
        "Each security event is logged with enough detail to investigate it, and no passwords, tokens, or other secrets appear in the log.",
    },
    {
      title: "Verify malformed requests and unhandled exceptions fail safely",
      steps: [
        "Send a malformed request (broken JSON, missing required fields, wrong data types).",
        "Request a page or resource that does not exist, and one that forces a server-side exception if possible.",
        "Review the status codes and response bodies returned.",
      ],
      expectedResult:
        "The application returns a generic error with an appropriate status code, stays available, and reveals no stack trace, framework version, or internal path.",
    },
  ],
  "API / Interface Security": [
    {
      title: "Verify the API endpoint enforces rate limiting and access control",
      steps: [
        "Send a burst of rapid, repeated requests to the endpoint.",
        "Call the endpoint without a valid authentication token.",
        "Call the endpoint with a token belonging to an unauthorized account.",
      ],
      expectedResult:
        "Excessive requests are throttled or rate-limited; unauthenticated or unauthorized calls are rejected with an appropriate error rather than returning data.",
    },
    {
      title: "Verify the API only accepts expected fields and returns only intended data",
      steps: [
        "Send a valid request with extra, unexpected fields added to the body.",
        "Request a list or record and review the response for fields the caller should not see.",
        "Request a record using an ID that belongs to another user.",
      ],
      expectedResult:
        "Unexpected fields are ignored or rejected, responses contain only the fields intended for the caller, and other users' records are not returned.",
    },
    {
      title: "Verify the API rejects unsupported methods and restricts cross-origin access",
      steps: [
        "Call the endpoint with HTTP methods it should not support (e.g. DELETE, PUT, TRACE).",
        "Send a request with an unexpected content type.",
        "Send a request with an Origin header from an untrusted site and review the CORS response headers.",
      ],
      expectedResult:
        "Unsupported methods and content types are rejected; cross-origin access is allowed only for trusted origins.",
    },
  ],
  "Configuration & Deployment Security": [
    {
      title: "Verify configuration secrets are not stored or exposed in plaintext",
      steps: [
        "Locate the configuration file(s) or environment settings referenced by this requirement.",
        "Check whether secrets (API keys, connection strings, credentials) are stored in plaintext.",
        "Check whether the configuration file is reachable via the web server or committed to a public repository.",
      ],
      expectedResult:
        "Secrets are not stored in plaintext, are excluded from version control, and the configuration file is not publicly accessible.",
    },
    {
      title: "Verify default credentials and debug features are disabled",
      steps: [
        "Try the vendor or framework default usernames and passwords on the application and any admin console.",
        "Look for debug pages, test endpoints, sample accounts, and verbose error modes.",
        "Check that directory listing is turned off on the web server.",
      ],
      expectedResult:
        "Default credentials do not work, debug and test features are disabled in the deployed environment, and directory listing is off.",
    },
    {
      title: "Verify HTTPS is enforced and security headers are present",
      steps: [
        "Open the application over plain HTTP and note whether it redirects to HTTPS.",
        "Inspect the response headers for HSTS, Content-Security-Policy, X-Content-Type-Options, and X-Frame-Options.",
        "Check that headers do not reveal server software or version numbers.",
      ],
      expectedResult:
        "HTTP is redirected to HTTPS, key security headers are present, and server version details are not exposed.",
    },
  ],
};

// ---------------------------------------------------------------------------
// 4b. EXTRA SCENARIO VARIANTS (variants 4-6 for every category)
//     Appended to the base list above so each category has 6 distinct tests.
// ---------------------------------------------------------------------------
const EXTRA_VARIANTS = {
  "Authentication": [
    {
      title: "Verify a second authentication factor cannot be skipped, replayed, or guessed",
      steps: [
        "Log in with a correct username and password and stop at the second-factor step.",
        "Try to open an authenticated page directly without completing the second factor.",
        "Reuse a previously valid one-time code, then try many wrong codes in a row.",
        "If no second factor exists, record that as a gap for the security review.",
      ],
      expectedResult:
        "Access is blocked until the second factor is completed; old codes are rejected; repeated wrong codes are throttled or locked out.",
    },
    {
      title: "Verify automated login abuse (credential stuffing) is detected and slowed",
      steps: [
        "Send login attempts for many different usernames using a short list of common passwords.",
        "Send the attempts from a single source in a short period.",
        "Observe whether throttling, CAPTCHA, or temporary blocking is applied.",
      ],
      expectedResult:
        "Automated attempts are throttled or blocked at the source level, and the response gives no hint about which usernames exist.",
    },
    {
      title: "Verify changing a password requires re-authentication and ends other sessions",
      steps: [
        "While logged in, open the change-password function.",
        "Try to change the password without entering the current password.",
        "Change it properly, then try the old password and any other open sessions.",
      ],
      expectedResult:
        "The current password is required, the old password stops working, and other active sessions are ended.",
    },
  ],
  "Authorization / Access Control": [
    {
      title: "Verify pages and endpoints that are not linked in the interface are still protected",
      steps: [
        "Guess or collect URLs that are not linked in the UI, such as /admin, /export, or /api/users.",
        "Request each URL with no login, and again with a low-privilege account.",
        "Compare the responses with those of an authorised account.",
      ],
      expectedResult:
        "Hidden pages and endpoints enforce the same access checks as visible ones and return no data to unauthorised callers.",
    },
    {
      title: "Verify restricted actions are blocked for every HTTP method, not just the one the UI uses",
      steps: [
        "Find a restricted action and note the method the UI uses (for example POST).",
        "Repeat the same request as a low-privilege user using other methods (GET, PUT, DELETE).",
        "Try to reuse a saved link or request from an administrator account.",
      ],
      expectedResult:
        "Access is checked for every method and every caller; saved admin links or requests do not work for other users.",
    },
    {
      title: "Verify permission changes take effect immediately",
      steps: [
        "Log in as a user and keep the session open.",
        "As an administrator, remove that user's role or disable the account.",
        "Use the still-open session to repeat a previously allowed action.",
      ],
      expectedResult:
        "The existing session loses access straight away, and disabled accounts cannot perform any action.",
    },
  ],
  "Input Validation / Injection": [
    {
      title: "Verify stored input is encoded safely wherever it is displayed",
      steps: [
        "Save a script payload in a field that is later shown to other users.",
        "View the saved value as another user, and in any export, email, or report.",
        "Try payloads suited to different display contexts (HTML text, attributes, JavaScript, CSV).",
      ],
      expectedResult:
        "Saved input is shown as plain text in every context; no script runs for any viewer and exports do not execute formulas.",
    },
    {
      title: "Verify query and filter parameters resist SQL, NoSQL, and command injection",
      steps: [
        "Identify search, filter, and sort parameters in the URL or request body.",
        "Send boolean and time-delay payloads (for example ' AND 1=2-- and a sleep payload).",
        "Compare response content, status codes, and response times against a normal request.",
      ],
      expectedResult:
        "Payloads are treated as plain data; responses and timings do not change and no database or system error appears.",
    },
    {
      title: "Verify boundary values and repeated submissions are handled correctly",
      steps: [
        "Submit zero, negative, very large, and non-numeric values where a number is expected.",
        "Submit empty required fields and values at exactly the minimum and maximum length.",
        "Send the same request twice in quick succession.",
      ],
      expectedResult:
        "Out-of-range values are rejected with clear messages, boundary values behave as specified, and duplicate submissions do not create duplicate records or actions.",
    },
  ],
  "Data Protection": [
    {
      title: "Verify transport encryption is correctly configured",
      steps: [
        "Check the TLS version, cipher suites, and certificate validity for every host used.",
        "Try to connect over plain HTTP and with an old protocol version.",
        "Look for pages that load scripts or images over HTTP (mixed content).",
      ],
      expectedResult:
        "Only modern TLS versions are accepted, certificates are valid, HTTP is redirected to HTTPS, and no mixed content is loaded.",
    },
    {
      title: "Verify deleted data is actually removed and not kept longer than allowed",
      steps: [
        "Delete a record that contains personal or sensitive data.",
        "Search for the record in the UI, API, search results, and exports.",
        "Check the stated retention period and how long the data remains in backups and logs.",
      ],
      expectedResult:
        "Deleted data disappears from every interface and is retained only for the documented period.",
    },
    {
      title: "Verify data stores and encryption keys are separated and tightly controlled",
      steps: [
        "Review which accounts and services can read the database or storage holding this data.",
        "Check that the database is not reachable from the public internet.",
        "Check where the encryption keys are kept and who can read them.",
      ],
      expectedResult:
        "Only the accounts that need access have it, data stores are not publicly reachable, and keys are stored apart from the data they protect.",
    },
  ],
  "Session Management": [
    {
      title: "Verify state-changing requests are protected against cross-site request forgery",
      steps: [
        "Capture a state-changing request such as updating a profile or changing a setting.",
        "Replay it from a page on a different origin, and again with the anti-forgery token removed or altered.",
        "Check the SameSite cookie setting and any custom request headers.",
      ],
      expectedResult:
        "Requests without a valid anti-forgery token or from an untrusted origin are rejected and no change is made.",
    },
    {
      title: "Verify session identifiers are never exposed in URLs, logs, or referrer headers",
      steps: [
        "Browse through the application and watch the URLs for session identifiers or tokens.",
        "Check application and proxy logs for tokens.",
        "Follow an external link from a logged-in page and inspect the Referer header.",
      ],
      expectedResult:
        "Session identifiers appear only in secure cookies or headers, and never in URLs, logs, or referrer headers.",
    },
    {
      title: "Verify tampered or replayed tokens are rejected",
      steps: [
        "Capture a valid token (for example a JWT) and change values inside it.",
        "Remove the signature or change the signing algorithm, then send the token.",
        "Replay an old token after a refresh or logout.",
      ],
      expectedResult:
        "Altered, unsigned, and replayed tokens are rejected and no authenticated action succeeds.",
    },
  ],
  "Error Handling & Logging": [
    {
      title: "Verify log entries cannot be forged or tampered with",
      steps: [
        "Submit input containing line breaks and log-like text (for example a fake 'login succeeded' line).",
        "Find the matching entry in the log and check whether it can be mistaken for a real event.",
        "Check who can read, edit, or delete the log files.",
      ],
      expectedResult:
        "User input is encoded in logs so it cannot create fake entries, and logs are readable and writable only by authorised roles.",
    },
    {
      title: "Verify repeated failures and suspicious actions raise alerts",
      steps: [
        "Trigger repeated failed logins and several access-denied actions.",
        "Check whether monitoring or alerting is raised for the pattern.",
        "Confirm how long the related logs are kept.",
      ],
      expectedResult:
        "Suspicious patterns create an alert for the responsible team, and logs are kept long enough for investigation.",
    },
    {
      title: "Verify the system fails securely when a dependency is unavailable",
      steps: [
        "Simulate a failure of a dependency such as the database or an authentication service.",
        "Attempt to log in and to open a protected page during the failure.",
        "Restore the dependency and check the application recovers.",
      ],
      expectedResult:
        "Access is denied (not granted) during the failure, a generic message is shown, and the application recovers without data exposure.",
    },
  ],
  "API / Interface Security": [
    {
      title: "Verify API tokens are validated and limited to the right scope",
      steps: [
        "Call the API with an expired, malformed, and revoked token.",
        "Call an endpoint with a token that lacks the required scope or role.",
        "Check that tokens are not accepted in the query string.",
      ],
      expectedResult:
        "Invalid, expired, revoked, and under-scoped tokens are rejected, and tokens are accepted only in the intended header.",
    },
    {
      title: "Verify the API limits request size, page size, and expensive queries",
      steps: [
        "Request a very large page size and deeply nested or repeated filters.",
        "Send an oversized request body.",
        "Measure response time and server behaviour under these requests.",
      ],
      expectedResult:
        "Limits are applied to page size, body size, and query complexity; the service stays responsive and returns a clear error.",
    },
    {
      title: "Verify old, hidden, or documentation endpoints are not exposed in production",
      steps: [
        "Look for API documentation pages (such as Swagger) and test or debug endpoints.",
        "Try older API versions (for example /v1) and compare their access checks with the current version.",
        "Review response headers for version or technology details.",
      ],
      expectedResult:
        "Documentation and debug endpoints are not public, old versions enforce the same controls, and headers reveal no unnecessary detail.",
    },
  ],
  "Configuration & Deployment Security": [
    {
      title: "Verify components and libraries are up to date and free of known vulnerabilities",
      steps: [
        "Run a dependency scan on the application's libraries and frameworks.",
        "List the open ports and running services on the server.",
        "Check for unused services, sample apps, and outdated server software.",
      ],
      expectedResult:
        "No high-severity known vulnerabilities remain, and only the services the application needs are running.",
    },
    {
      title: "Verify environments are separated and accounts have only the access they need",
      steps: [
        "Check that test or development credentials, data, and endpoints do not exist in production.",
        "Review the permissions of service accounts and the database user.",
        "Check that admin and management interfaces are not reachable from the public internet.",
      ],
      expectedResult:
        "Production is separate from test environments, service accounts use least privilege, and management interfaces are restricted.",
    },
    {
      title: "Verify build files, backups, and source details are not publicly accessible",
      steps: [
        "Request common sensitive paths such as /.git, /.env, backup files (.bak, .zip), and source maps.",
        "Request configuration or status endpoints that should be internal.",
        "Check that the deployed site contains no development files.",
      ],
      expectedResult:
        "Sensitive files and internal endpoints return 403 or 404, and the deployed site contains only what is needed to run it.",
    },
  ],
};

// Combine into the final list: 3 base + 3 extra = 6 variants per category.
for (const cat of Object.keys(EXTRA_VARIANTS)) {
  SCENARIO_VARIANTS[cat] = SCENARIO_VARIANTS[cat].concat(EXTRA_VARIANTS[cat]);
}

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
// 6b. DOCUMENT READERS
//     Turns .txt, .md, .html, .docx and .pdf files into plain text, one
//     requirement per line, ready for parseRequirements().
//     .docx needs the "mammoth" package, .pdf needs "pdf-parse":
//         npm install mammoth pdf-parse
// ---------------------------------------------------------------------------
const SUPPORTED_TYPES = ".txt  .md  .markdown  .html  .htm  .docx  .pdf";

function requirePackage(name, ext) {
  try {
    return require(name);
  } catch {
    throw new Error(
      `Reading ${ext} files needs the "${name}" package, which is not installed.\n` +
        `Run this once in the tool folder, then try again:\n    npm install ${name}`
    );
  }
}

function markdownToText(md) {
  let text = md.replace(/\r\n/g, "\n");
  text = text.replace(/^---\n[\s\S]*?\n---\n/, ""); // front matter
  text = text.replace(/```[\s\S]*?```/g, "").replace(/~~~[\s\S]*?~~~/g, ""); // code blocks

  const out = [];
  for (let line of text.split("\n")) {
    if (/^\s*#{1,6}\s/.test(line)) continue; // headings are labels, not requirements
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) continue; // horizontal rules
    if (/^\s*\|?(\s*:?-{3,}:?\s*\|)+\s*:?-*:?\s*\|?\s*$/.test(line)) continue; // table separator rows

    line = line
      .replace(/^\s*>\s?/, "")
      .replace(/^\s*[-*+]\s+\[[ xX]\]\s+/, "")
      .replace(/^\s*[-*+]\s+/, "")
      .replace(/^\s*\d+[.)]\s+/, "")
      .replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1")
      .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
      .replace(/<[^>]+>/g, "")
      .replace(/(\*\*|__|~~|`|\*)/g, "");

    if (line.includes("|")) {
      line = line.split("|").map((c) => c.trim()).filter(Boolean).join(" - ");
    }
    out.push(line.trim());
  }
  return out.join("\n");
}

function htmlToText(html) {
  return html
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<\/(p|li|div|h[1-6]|tr|ul|ol|table|section|article)>|<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .split("\n")
    .map((l) => l.replace(/\s+/g, " ").trim())
    .join("\n");
}

// PDFs hard-wrap sentences across lines. Join a line onto the previous one
// when the previous line did not finish a sentence and this one clearly
// continues it. Page numbers and page markers are dropped.
function cleanPdfText(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (/^(page\s+)?\d+(\s*(of|\/)\s*\d+)?$/i.test(line)) continue;
    if (/^-+\s*\d+\s*(of|\/)\s*\d+\s*-+$/i.test(line)) continue;
    if (!line) { out.push(""); continue; }
    const prev = out.length ? out[out.length - 1] : "";
    const startsNewItem = /^(\d+[.)]|[-*\u2022\u25CF\u25AA])\s+/.test(line);
    const continues = /^[a-z(,;]/.test(line) || /,$/.test(prev);
    if (prev && !startsNewItem && continues && !/[.!?:;]$/.test(prev)) {
      out[out.length - 1] = prev + " " + line;
    } else {
      out.push(line);
    }
  }
  return out.join("\n");
}

async function readDocx(filePath) {
  const mammoth = requirePackage("mammoth", ".docx");
  const result = await mammoth.extractRawText({ path: filePath });
  return result.value;
}

async function readPdf(filePath) {
  const mod = requirePackage("pdf-parse", ".pdf");
  const buffer = fs.readFileSync(filePath);
  let text;
  try {
  if (typeof mod === "function") {
    text = (await mod(buffer)).text; // pdf-parse 1.x
  } else if (mod.PDFParse) {
    const parser = new mod.PDFParse({ data: buffer }); // pdf-parse 2.x
    try {
      text = (await parser.getText()).text;
    } finally {
      await parser.destroy();
    }
  } else {
    throw new Error("The installed pdf-parse package has an unexpected format. Run: npm install pdf-parse");
  }
  return cleanPdfText(text);
  } catch (err) {
    throw new Error(
      `This PDF could not be read (${err.message}). It may be password-protected or damaged. ` +
        `Try exporting it again, or make sure you installed the latest reader: npm install pdf-parse@latest`
    );
  }
}

async function readDocument(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  let text;
  switch (ext) {
    case "":
    case ".txt":
      text = fs.readFileSync(filePath, "utf-8");
      break;
    case ".md":
    case ".markdown":
      text = markdownToText(fs.readFileSync(filePath, "utf-8"));
      break;
    case ".html":
    case ".htm":
      text = htmlToText(fs.readFileSync(filePath, "utf-8"));
      break;
    case ".docx":
      text = await readDocx(filePath);
      break;
    case ".pdf":
      text = await readPdf(filePath);
      break;
    case ".doc":
      throw new Error('Old .doc files cannot be read. In Word choose File > Save As > "Word Document (.docx)", then run again.');
    default:
      throw new Error(`Unsupported file type "${ext}". Supported types: ${SUPPORTED_TYPES}`);
  }
  if (!text || !text.trim()) {
    throw new Error(
      ext === ".pdf"
        ? "No text could be read from this PDF. It may be a scanned image; export it from the original document or run OCR first."
        : "No text could be read from this file."
    );
  }
  return text;
}

// ---------------------------------------------------------------------------
// 7. PARSE THE REQUIREMENTS DOCUMENT
//    Strips "1. ", "1) ", "- ", "* " and "• " prefixes.
// ---------------------------------------------------------------------------
function parseRequirements(rawText) {
  return rawText
    .split(/\r?\n/)
    .map((line) => line.replace(/^\s*(?:\d+[.)]|[-*\u2022])\s*/, "").trim())
    .filter((line) => line.length > 0 && !line.toLowerCase().startsWith("project"));
}

// ---------------------------------------------------------------------------
// 8. DETECT MATCHING CATEGORIES FOR A SINGLE REQUIREMENT LINE
// ---------------------------------------------------------------------------
function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function containsKeyword(text, keyword) {
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
// 9. MAIN GENERATION LOGIC
//    Every category that has at least one matching requirement gets up to
//    `perCategory` scenarios. Categories with no matching requirement get none
//    and are shown as gaps in the report.
// ---------------------------------------------------------------------------
function generateScenarios(requirements, limits = DEFAULT_LIMITS) {
  const { perCategory } = limits;

  const hits = {};
  for (const cat of CATEGORIES) hits[cat] = [];
  for (const req of requirements) {
    for (const cat of detectCategories(req)) {
      if (!hits[cat].includes(req)) hits[cat].push(req);
    }
  }

  const scenarios = [];
  for (const cat of CATEGORIES) {
    if (hits[cat].length === 0) continue; // uncovered -> shown as a gap in the report

    // Queue order: variant 1 for every matching requirement, then variant 2
    // for every matching requirement, and so on.
    const queue = [];
    for (let v = 0; v < SCENARIO_VARIANTS[cat].length; v++) {
      for (const req of hits[cat]) queue.push({ req, variant: v });
    }

    queue.slice(0, perCategory).forEach((item, i) => {
      const v = SCENARIO_VARIANTS[cat][item.variant];
      scenarios.push({
        testCaseId: `${CATEGORY_PREFIXES[cat]}-${String(i + 1).padStart(2, "0")}`,
        category: cat,
        requirement: item.req,
        title: v.title,
        steps: [`Review the requirement: "${item.req}" and identify the page, field, or endpoint it affects.`, ...v.steps],
        expectedResult: v.expectedResult,
        rationale: RATIONALE_TEMPLATES[cat](),
      });
    });
  }

  return scenarios;
}

// ---------------------------------------------------------------------------
// 10. COVERAGE SUMMARY
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
// 11. MARKDOWN REPORT (kept for scripting/diffing/plain-text use)
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
// 12. HTML REPORT (the human-readable version)
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

  const coverageRowsHtml = coverage
    .map(
      (c) => `
        <tr>
          <td>${escapeHtml(c.category)}</td>
          <td class="${c.covered ? "cov-yes" : "cov-no"}">${c.covered ? "Yes" : "No"}</td>
          <td>${c.count}</td>
        </tr>`
    )
    .join("");

  // Group scenarios by category, preserving CATEGORIES order
  const scenariosByCategory = {};
  for (const cat of CATEGORIES) scenariosByCategory[cat] = [];
  for (const s of scenarios) scenariosByCategory[s.category].push(s);

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
  .coverage-summary { margin-top: 40px; padding-top: 32px; border-top: 1px solid var(--border); }
  .coverage-table { width: 100%; border-collapse: collapse; font-size: 14.5px; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
  .coverage-table th, .coverage-table td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); }
  .coverage-table th { font-family: 'IBM Plex Mono', monospace; font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); font-weight: 500; }
  .coverage-table tr:last-child td { border-bottom: none; }
  .coverage-table td.cov-yes { color: var(--tick-fill); font-weight: 600; }
  .coverage-table td.cov-no { color: var(--accent-amber); font-weight: 600; }
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
    <p class="dek">${scenarios.length} test scenarios mapped from the requirements document to a fixed set of ${total} security categories, so gaps in coverage are visible at a glance.</p>

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

  <section class="coverage-summary">
    <div class="cat-heading">
      <h2>Coverage Summary</h2>
    </div>
    <table class="coverage-table">
      <thead>
        <tr><th>Category</th><th>Covered?</th><th># Scenarios</th></tr>
      </thead>
      <tbody>${coverageRowsHtml}
      </tbody>
    </table>
  </section>
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
// 13. OUTPUT FILE NAMING + CHANGE DETECTION
// ---------------------------------------------------------------------------
const REPORTS_DIR = "reports";
const INDEX_PATH = path.join(REPORTS_DIR, ".report-index.json");

// The hash covers the generator version and limits as well as the document,
// so upgrading the script or changing --min/--max forces a fresh report.
function hashContent(text, limits) {
  return crypto
    .createHash("sha256")
    .update(`${GENERATOR_VERSION}|${limits.perCategory}\n${text}`)
    .digest("hex");
}

function loadIndex() {
  if (!fs.existsSync(INDEX_PATH)) return {};
  try {
    return JSON.parse(fs.readFileSync(INDEX_PATH, "utf-8"));
  } catch {
    return {};
  }
}

function saveIndex(index) {
  fs.writeFileSync(INDEX_PATH, JSON.stringify(index, null, 2), "utf-8");
}

function slugify(name) {
  return name
    .toLowerCase()
    .replace(/\.[^/.]+$/, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
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
// 14. COMMAND-LINE ARGUMENTS
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const args = { inputPath: null, ...DEFAULT_LIMITS };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--per-category") {
      const value = parseInt(argv[++i], 10);
      if (!Number.isInteger(value) || value < 1 || value > MAX_PER_CATEGORY) {
        console.error(`--per-category needs a whole number from 1 to ${MAX_PER_CATEGORY}.`);
        process.exit(1);
      }
      args.perCategory = value;
    } else if (argv[i].startsWith("--")) {
      console.error(`Unknown option ${argv[i]}. Supported: --per-category N (1 to ${MAX_PER_CATEGORY}).`);
      process.exit(1);
    } else if (!args.inputPath) {
      args.inputPath = argv[i];
    }
  }
  return args;
}

// ---------------------------------------------------------------------------
// 15. ENTRY POINT
// ---------------------------------------------------------------------------
async function main() {
  const { inputPath, perCategory } = parseArgs(process.argv);
  const limits = { perCategory };

  if (!inputPath) {
    console.error("Usage: node security-scenario-generator.js <requirements-file> [--per-category 6]");
    process.exit(1);
  }

  const resolvedPath = path.resolve(inputPath);
  if (!fs.existsSync(resolvedPath)) {
    console.error(`File not found: ${resolvedPath}\nCheck the spelling, or run "dir" to list the files in this folder.`);
    process.exit(1);
  }
  const rawText = await readDocument(resolvedPath);
  const sourceFileName = path.basename(resolvedPath);

  if (!fs.existsSync(REPORTS_DIR)) {
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
  }

  const contentHash = hashContent(rawText, limits);
  const index = loadIndex();
  const lastRun = index[sourceFileName];

  if (lastRun && lastRun.hash === contentHash && fs.existsSync(lastRun.htmlPath)) {
    console.log(`No changes detected in "${sourceFileName}" since the last report - skipping regeneration.`);
    console.log(`- ${lastRun.mdPath}   (existing, unchanged)`);
    console.log(`- ${lastRun.htmlPath} (existing, unchanged)`);
    return;
  }

  const requirements = parseRequirements(rawText);
  const scenarios = generateScenarios(requirements, limits);
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
  console.log(`Generated ${scenarios.length} scenario(s) across ${coveredCount}/${CATEGORIES.length} categories (up to ${perCategory} per covered category).`);
  console.log(`- ${mdPath}   (plain text)`);
  console.log(`- ${htmlPath} (open this one in a browser)`);
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});