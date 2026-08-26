# Non-goals

This document lists what PatchPilot will **not** do in the first usable release, and claims the product must **not** make.

## Not in the MVP

- Requiring an AI provider, cloud LLM, or hardcoded API key.
- Authoritative risk scores produced by a model.
- Automatic patching, dependency upgrades, or deployment to customer environments.
- SAST, DAST, container image scanning, or runtime IAST as built-in scanners.
- SPDX or non-JSON CycloneDX as first-class upload formats.
- A Go CLI (deferred until the web MVP functions).
- Microservices. Remain a modular monolith until an accepted ADR says otherwise.
- A hosted multi-tenant SaaS control plane operated by the project as the primary delivery model.
- Full enterprise GRC, vendor-risk, or questionnaire modules.
- Claiming that KEV enrichment proves active exploitation against the user’s asset.
- Silent overwrite of vulnerability-intelligence records.
- Cascading deletion of evidentiary data as a convenience.

## Claims the product must not make

PatchPilot must not state or imply, in UI, docs, or exports, that it:

- Certifies SOC 2, ISO 27001, FedRAMP, PCI DSS, HIPAA, CMMC, or any other framework.
- Makes an organization “compliant” by generating a report.
- Proves exploitability in the user’s environment without supporting evidence stored for that finding.
- Proves remediation is complete solely because a ticket was closed or a control was described.
- Guarantees that vulnerability feeds are complete, timely, or legally authoritative.

Operators may use PatchPilot **as part of** their process. The tool records evidence; it does not replace an auditor, certifier, or incident responder.

## Later, only with an explicit decision

Items that might be revisited after MVP, each requiring product agreement and usually an ADR:

- Optional AI drafting with user-supplied keys.
- Additional feed providers.
- Broader SBOM formats.
- CLI, CI upload helpers, or webhooks into customer pipelines.
- Split of worker or API into separately scaled services.
