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
