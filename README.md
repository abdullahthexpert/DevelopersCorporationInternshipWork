# User Management System — Cybersecurity Internship
**DevelopersHub Corporation | Intern: Muhammad Abdullah | ID: DHC 364**

## Overview
A simple Node.js web application used as a target for a 6-week cybersecurity assessment and hardening exercise. The app includes signup, login, profile pages, and a protected API endpoint built with Express.js.

---

## Week 1: Security Assessment

### Vulnerabilities Found

**1. Cross-Site Scripting (XSS)**
- The /profile route rendered user input directly into HTML without escaping
- Injecting a script tag via the ?name= query parameter executed arbitrary JavaScript in the browser
- Risk: Attackers can steal session cookies, redirect users, or perform actions on their behalf

**2. Plain-Text Password Storage**
- User passwords were stored as plain text in the in-memory database
- Risk: A single database leak exposes every user's password, and since people reuse passwords, it compromises their other accounts too

**3. Missing Input Validation**
- The signup route accepted empty fields, invalid emails, and any string as a username
- Risk: Opens the door for stored XSS, injection attacks, and garbage data

### Tools Used
- Browser Developer Tools (manual XSS testing)
- Nmap (port scanning)
- Manual code review

---

## Week 2: Security Fixes

### Packages Installed
- validator, bcrypt, jsonwebtoken, helmet

### Fixes Implemented

**1. Input Validation (validator)**
- Signup now requires a valid email format
- Username must be 3-20 alphanumeric characters
- Password must be at least 6 characters
- Empty fields are rejected at login and signup

**2. Password Hashing (bcrypt)**
- Passwords are hashed with bcrypt (salt rounds: 10) before storage
- Login uses bcrypt.compare() for secure, timing-safe comparison
- Even if the database leaks, passwords cannot be reversed

**3. Token-Based Authentication (jsonwebtoken)**
- On successful login, a JWT token is generated with 1-hour expiry
- Token is signed with a secret key

**4. Secure HTTP Headers (helmet)**
- app.use(helmet()) adds 15+ security headers automatically
- Protects against clickjacking, MIME sniffing, and other header-based attacks

**5. XSS Fix (validator.escape)**
- Profile route now escapes all user-supplied input before rendering
- Script tags are converted to plain text, never executed

---

## Week 3: Advanced Security & Logging

### Security Logging (winston)
Implemented structured JSON logging to both console and security.log

Events logged:
- Application startup
- Successful logins and signups
- Failed login attempts
- Invalid input attempts
- Unauthenticated profile access attempts

### Penetration Testing (Nmap)
Ran a port scan against the local server with: nmap localhost

Results:
- Port 631 - IPP printer service (normal)
- Port 3000 - Node.js app (expected)
- Port 3306 - MySQL (should be firewalled in production)

Finding: Port 3306 is exposed. In production this should be restricted to internal connections only.

### Security Checklist
- [x] Validate all user inputs server-side
- [x] Hash and salt all passwords with bcrypt
- [x] Use token-based authentication (JWT)
- [x] Secure HTTP headers with Helmet.js
- [x] Escape all output to prevent XSS
- [x] Log security events with timestamps
- [x] Scan for open ports with Nmap
- [ ] Use HTTPS in production
- [ ] Move secrets to environment variables
- [ ] Restrict database port access via firewall

---

## Week 4: Advanced Threat Detection & Web Security

### Packages Installed
- express-rate-limit, cors

### Implementations

**1. Rate Limiting (express-rate-limit)**
- Login endpoint: max 5 attempts per 15 minutes per IP
- Global limiter: max 100 requests per minute across all routes
- Blocked IPs receive a 429 Too Many Requests response
- All rate limit violations are logged via winston

**2. CORS Configuration (cors)**
- Restricted to localhost:3000 only
- Allowed methods: GET, POST
- Allowed headers: Content-Type, x-api-key
- Credentials enabled for session support

**3. Content Security Policy (CSP)**
- Configured via helmet's contentSecurityPolicy option
- defaultSrc: self only — blocks external resource loading
- scriptSrc: self only — prevents inline and third-party script injection
- objectSrc: none — blocks Flash and plugin-based attacks
- frameSrc: none — prevents clickjacking via iframes

**4. HTTP Strict Transport Security (HSTS)**
- Configured via helmet's hsts option
- maxAge: 31,536,000 seconds (1 year)
- includeSubDomains: true
- preload: true — eligible for browser HSTS preload lists

**5. API Key Authentication**
- Protected endpoint: GET /api/users
- Requires x-api-key header with valid key
- Returns sanitized user list (no password hashes)
- Unauthorized attempts logged and rejected with 401

**6. Intrusion Detection (Fail2Ban)**
- Installed and configured Fail2Ban on the host system
- Custom jail: nodejs-auth watching security.log
- Triggers on 5 failed login attempts within 15 minutes
- Bans offending IP for 1 hour
- Jail confirmed active via fail2ban-client status nodejs-auth

### Security Checklist Update
- [x] Rate limiting on login and global routes
- [x] CORS restricted to trusted origin
- [x] Content Security Policy configured
- [x] HSTS enforced
- [x] API key authentication on protected endpoints
- [x] Fail2Ban intrusion detection active

---

## Tech Stack
Node.js, Express.js, bcrypt, validator, jsonwebtoken, helmet, winston, express-rate-limit, cors, Fail2Ban

## How to Run
npm install
node server.js

App runs at http://localhost:3000

Protected API: GET http://localhost:3000/api/users
Required header: x-api-key: dhc-intern-api-key-364
---

## Week 5: Ethical Hacking & Exploiting Vulnerabilities

### Tools Used
- SQLMap 1.8.4 (automated SQL injection scanner)
- Burp Suite Community Edition 2026.3.3 (HTTP proxy and request interceptor)
- Manual code review

### SQL Injection — Finding & Fix

**Vulnerable Endpoint Added:** GET /api/search?q=
- Raw string concatenation used to build SQL query directly from user input
- SQLMap confirmed 3 injection types: boolean-based blind, time-based blind, UNION query
- Back-end DBMS identified as SQLite

**SQLMap Finding (before fix):**

Parameter: q (GET)
Type: boolean-based blind
Type: time-based blind
Type: UNION query (3 columns)

**Fix — Prepared Statements:**
- Replaced raw string concatenation with parameterized query using ? placeholder
- User input is now passed as a separate argument, never interpreted as SQL
- SQLMap re-scan after fix: all tested parameters came back clean — not injectable

### CSRF Protection

**Implementation:**
- Used Node.js built-in crypto module to generate 32-byte random tokens
- Token generated server-side on GET /login and stored in session
- Token embedded as hidden field in login form
- POST /login validates submitted token against session token
- Mismatch returns 403 and logs warning with offending IP

**Burp Suite Verification:**
- Intercepted POST /login request via Burp Suite proxy
- Confirmed _csrf token visible in request body alongside credentials
- Requests without valid token are blocked with 403 Forbidden

### Ethical Hacking Report Summary

| # | Vulnerability | Severity | Status |
|---|--------------|----------|--------|
| 1 | SQL Injection on /api/search | Critical | Fixed |
| 2 | CSRF on login form | High | Fixed |
| 3 | Missing rate limiting (Week 4) | High | Fixed |
| 4 | No CORS policy (Week 4) | Medium | Fixed |
| 5 | Missing CSP headers (Week 4) | Medium | Fixed |

### Security Checklist Update
- [x] SQL injection identified with SQLMap
- [x] SQLi fixed with prepared statements
- [x] CSRF tokens implemented on login form
- [x] CSRF protection verified via Burp Suite interception
- [x] HTTP request/response analysis with Burp Suite proxy
---

## Week 6: Advanced Security Audits & Final Deployment

### Tools Used
- Nikto 2.1.5 (web server vulnerability scanner)
- Lynis 3.0.9 (system hardening and compliance audit)
- OWASP ZAP 2.17.0 (automated web application penetration testing)

### Nikto Scan Results

Ran against http://localhost:3000

Findings:
- Cookie connect.sid missing httpOnly flag — Fixed by adding httpOnly: true and sameSite: strict to session config
- Server leaks inodes via ETags — informational, low risk in dev environment
- All other findings were uncommon headers flagged as informational — these are actually our security headers from helmet working correctly (CSP, HSTS, X-Frame-Options, CORS, rate limit headers)

Result: 0 critical vulnerabilities. 1 finding fixed (httpOnly cookie).

### Lynis System Audit Results

Ran: sudo lynis audit system

- Hardening index: 60/100
- Tests performed: 260
- Firewall: active
- Malware scanner: not installed (acceptable for dev environment)
- Security audit module: passed
- Vulnerability scan module: passed

A hardening index of 60 is typical for a development workstation. Production hardening would involve installing a malware scanner, tightening kernel parameters, and enabling full disk encryption.

### OWASP ZAP Automated Scan Results

Target: http://localhost:3000

Alerts found (4):

| Alert | Risk | Notes |
|-------|------|-------|
| CSP: Failure to Define Directive with No Fallback | Medium | Minor CSP gap, non-critical |
| CSP: style-src unsafe-inline | Low | Set intentionally for inline styles |
| Authentication Request Identified | Informational | ZAP detected login form |
| Session Management Response Identified | Informational | ZAP detected session cookies |

No XSS, SQL injection, or critical vulnerabilities detected — confirms that security fixes from Weeks 2-5 are effective.

### OWASP Top 10 Compliance Summary

| # | Risk | Status |
|---|------|--------|
| A01 | Broken Access Control | Mitigated — session auth, profile protection |
| A02 | Cryptographic Failures | Mitigated — bcrypt password hashing |
| A03 | Injection | Mitigated — prepared statements, input validation |
| A04 | Insecure Design | Mitigated — rate limiting, CSRF tokens |
| A05 | Security Misconfiguration | Mitigated — helmet, CSP, HSTS, CORS |
| A06 | Vulnerable Components | Monitored — all packages up to date |
| A07 | Auth & Session Failures | Mitigated — JWT, httpOnly cookies, session management |
| A08 | Software & Data Integrity | Partial — no CI/CD pipeline in dev environment |
| A09 | Security Logging & Monitoring | Mitigated — winston logging, Fail2Ban |
| A10 | SSRF | N/A — no external URL fetching in app |

### Final Security Checklist
- [x] Nikto web server scan completed
- [x] Lynis system audit completed (hardening index: 60/100)
- [x] OWASP ZAP automated scan completed
- [x] httpOnly and sameSite flags added to session cookie
- [x] OWASP Top 10 compliance reviewed
- [x] All critical and high vulnerabilities resolved
- [x] Full security progression documented across 6 weeks
