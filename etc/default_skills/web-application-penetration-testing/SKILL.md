---
name: web-application-penetration-testing
description: Test web apps and APIs with OWASP WSTG, Burp, and TransparentBrowser.
license: MIT
allowed-tools: [pwn, terminal, extrospection]
metadata:
  bundled: true
  references:
    - https://owasp.org/www-project-web-security-testing-guide/
    - https://owasp.org/www-project-application-security-verification-standard/
    - https://owasp.org/www-project-api-security/
    - CWE-79
    - CWE-89
    - CWE-352
---

# Web Application Penetration Testing

Use when the surface is an HTTP app or API. Use `bug-bounty-hunting` when
the rules come from a public program page. Use `penetration-testing` when
the engagement is mixed hosts plus one web app.

## When to use

- "WSTG this app", "OWASP Top 10", "API Top 10"
- auth, session, XSS, CSRF, SSRF, injection, access control
- mobile backend APIs (pair MSTG client work with this skill)

## Methodologies

| Catalog | Role |
|---|---|
| OWASP WSTG | default test cases (info gathering through business logic) |
| OWASP ASVS | verification requirements / coverage checklist |
| OWASP API Security Top 10 | BOLA, BFLA, mass assignment, unbounded resources |
| OWASP Top 10 | executive grouping of findings |
| OWASP MSTG / MASVS | mobile client; APIs still WSTG |
| PTES | wrap the web work in an engagement report |
| CWE | finding IDs (79, 89, 352, 918, 639, 601) |

## Tooling

- `PWN::Plugins::BurpSuite` (preferred) or `Zaproxy`
- `PWN::Plugins::TransparentBrowser` through the proxy
- `PWN::Plugins::Spider`, `OpenAPI`, `Fuzz`
- `PWN::Bounty::LifecycleAuthzReplay` for two-role authz
- `PWN::SAST` on the app repo when source is available

## Procedure

1. Map the app: roles, session mechanism, API surface, CSRF tokens.
2. Walk WSTG info-gathering then config, then identity, then authz.
3. Injection and XSS on every sink Burp or OpenAPI listed. Save requests.
4. Business logic: price, workflow skip, race, mass assignment.
5. Prove each finding with one request/response pair. Read the saved HAR
   or Burp item back.
6. Report by WSTG / ASVS id + CWE.

## Pitfalls

- A crawl with no replay is not a WSTG pass.
- Do not stop at "I will test XSS next time".
- SPA APIs hide in XHR; dump_links plus Burp sitemap, not just HTML.

## Verification

Sitemap or OpenAPI note exists, at least one authenticated test ran, and
each claimed finding cites a saved request and a WSTG/CWE id.
