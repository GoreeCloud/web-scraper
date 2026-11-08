# GoreeCloud Web Scraper — MCP Privacy and Site-Access Operating Boundary

**Status:** Development-only operational guidance. **Checked against source:** November 8, 2026. **Release acceptance:** OPEN. **Scope:** Official served GoreeCloud MCP HTTP runner only, not unrestricted direct Python/SDK use.

## Separation of responsibilities

**GoreeShield governs privacy.** Operators must determine who owns/controls the target, why data is collected, whether people concerned have consented where required, which categories of personal data may be processed, who may see it, and when it must be deleted. The software's URL allowlist is **not** user consent and is **not** authorization to access a third party's information.

**Wardveil governs cybersecurity.** Its remit includes outbound connection authorization, SSRF/redirect and proxy defenses, authentication, TLS, resource limits, browser sandboxing, monitoring and incident response. The safeguards listed below are defense-in-depth, not a guarantee of safe exposure to the internet.

**GoreeCloud Mesh governs approved integration and synchronization.** The available HTTP tool is **not** a verified Mesh interface, production data-transport API or cross-product authorization system.

**GoreeCloud Identity governs production identity and access decisions.** The present optional shared bearer token is not an accepted production SSO, multi-tenant identity or policy audit system.

**GoreeCloud UI governs interfaces.** This backend-only import has no accepted new graphical interface, so no custom UI tokens or false design-compliance claims are made.

## Verified technical defaults in the official served runner

- Outbound HTTP starts at **deny all**; an operator must explicitly supply exact origin allowlists. Public-looking DNS names resolving to local/private networks are rejected; approved IP addresses are pinned at the curl connection. Redirect following, environment-proxy inheritance, unsafe Host routing overrides and disabled TLS verification are forbidden in the served HTTP path. An explicit loopback target authorization remains suitable **only for controlled local development**, not production.
- Browser MCP tools are disabled by default. Unsafe browser compatibility is deliberately limited to loopback listening, but **still lacks complete navigation/subresource/CDP confinement**; do not use it for untrusted websites.
- Per-process served HTTP request limit: **60 admitted calls in a sliding 60-second window**, including attempts rejected later by a target policy, shared across one-shot and persistent-session HTTP tools. Four HTTP calls may run concurrently; eight reusable sessions may be active or starting. These are **not** per-client, distributed or request-per-site quotas.
- The served HTTP path limits outbound request body to **1 MiB** and response body to **4 MiB**; request timeout inputs are 0.1–30 seconds with one attempt and no redirects. Served request headers, cookies, query parameters and basic authentication metadata share a **32 KiB encoded JSON budget**. The complete serialized extraction-result model must fit **256 KiB**, otherwise the request fails with an explicit tool error and does not return partial content.
- These limits do not provide a complete DNS + parsing + transport wall-clock budget, complete remote egress isolation or bounded inbound MCP protocol-message size. Direct-library fetchers retain original compatibility behavior.

## Required operator decisions before sending any request

1. **Scope and purpose:** Record the authorized target origins, data categories, use case, lawful basis and any consent requirements. Avoid credentials, cookies, profile data and personal identifiers unless necessary and explicitly authorized.
2. **Target site policy:** Review robots.txt, access terms, rate requirements and legal/organizational restrictions before initiating collection. The current server **does not automatically enforce robots directives, terms, target-specific crawl delays, consent or usage limits**. Do not use the scraper to bypass logins, CAPTCHA challenges, anti-bot controls or access restrictions.
3. **Minimization:** Prefer exact origin and path targets, limited selectors, minimum data volume and short-lived requests; do not give a model unrestricted navigation just because a local opt-in exists.
4. **Storage and retention:** Determine where outputs, agent transcripts, debugging logs, HTTP cookies, browser network histories and checkpoint data can end up. Set retention and deletion responsibilities in the consuming app; **no cross-host deletion, purge schedule, consent ledger or complete no-logging guarantee has been implemented**.
5. **Secrets and isolation:** Keep bearer tokens and credentials out of URLs, source control, public logs and screenshots. Restrict network egress at the OS/container/VPC layer, authenticate and terminate TLS at a reviewed ingress, and monitor abuse **before** any remote exposure. Current Python resource limits alone are insufficient.
6. **Human release acceptance:** Obtain a review of privacy, security, site authorization, supply-chain licenses, operating-system compatibility, rollback and production identity before a signed Stable release or deployment.

## Testing and release decisions

The controlled local tests intentionally use disposable loopback fixtures without contacting unrelated public websites. Public DNS outcomes may be mocked for negative security controls; mocking **is not** evidence of complete network confinement. Keep [functional/privacy gate #2](https://github.com/GoreeCloud/web-scraper/issues/2) and [security/supply-chain gate #3](https://github.com/GoreeCloud/web-scraper/issues/3) OPEN until independent checks substantiate the missing controls. No production listener, registry publication, deployment, signed release or automatic access to external sites is authorized by this document.
