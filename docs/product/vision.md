# Product vision

PatchPilot is a self-hosted platform that helps people find, prioritize, and close software vulnerabilities with evidence they can trust.

Operators inventory software assets, upload CycloneDX SBOMs, correlate components with vulnerability intelligence, enrich applicable findings with CISA Known Exploited Vulnerabilities (KEV) data, calculate an explainable environmental priority, assign remediation work, record risk acceptance and compensating controls, re-scan, and export operational and executive reports. The system preserves audit history so later reviewers can see what was known, who decided, and which policy produced a score.

PatchPilot is for individual developers, small businesses, nonprofits, engineering teams, and larger organizations that need a private, production-minded workflow rather than a black-box score.

## Principles

- **Useful without AI.** The first usable release and every later release must complete the core journey with AI disabled. Optional AI, if added, may draft explanations or tickets. It must never set authoritative risk scores, and users must supply their own API key or local compatible endpoint.
- **Explainable priority.** Scores are produced by a versioned policy. Each result stores the policy version and contributing factors.
- **Evidence over assertion.** The product records observed facts (this component was in this SBOM; this CVE was listed by this source on this date) separately from calculated conclusions (priority, KEV enrichment, “resolved on rescan”).
- **Tenant isolation.** Work is organization-scoped. Self-hosted does not mean single-check security.
- **No compliance theater.** PatchPilot can support an organization’s vulnerability-management process. It does not grant, prove, or substitute for SOC 2, ISO 27001, FedRAMP, PCI, HIPAA, or any other certification or regulatory compliance.

## Success

A team can go from an empty organization to a newer SBOM that shows whether previous findings were still present, with an export that includes remediation evidence, without depending on a vendor AI or a SaaS scanner account.
