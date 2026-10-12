# ADR 0040: Controlled Finding latest-observation inspection boundary

- Status: Accepted
- Date: 2026-10-12
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as the selection of one next future Controlled Finding observation
authority: bounded latest-observation inspection. Merge to `main` remains
subject to normal pull-request review. This ADR does not implement that
projection, compose repeated-observation persistence, add a route or
permission, or authorize a Finding lifecycle power.

## Context

[ADR 0035](0035-controlled-finding-creation.md) accepts one creation-only
Finding. [ADR 0036](0036-controlled-finding-operator-api.md) composes owner
`POST /findings` and owner or admin `GET /findings/:findingId`.
[ADR 0037](0037-controlled-finding-target-discovery.md) composes read-only
target discovery. [ADR 0038](0038-controlled-finding-web-workflow.md) is merged
as the nested asset web workflow. Those surfaces are already composed.

[ADR 0039](0039-controlled-finding-repeated-observation.md) accepts one
persistence-only repeated observation of an existing open Finding. That
persistence slice is merged. The additive migration, process-local observation
authority, and atomic repeated-observation transaction exist. Production
registration remains absent. The sealed authority issuer is not a package
export. The writer is not exported from the database package barrel and is not
constructed by production startup. No observation permission, route, web
control, worker, queue, or scheduler exists.

Current public inspection projects the creation observation. Legal repeated
observations are tolerated by the read path and are not part of that
projection. Inspection performs no mutation. Finding `state` remains `open`.
Finding `version` remains 1 under `finding_creation_initial_state_chk`. The
frozen migration count is 25.

ADR 0039 left inspection evolution and operator reachability as separate future
decisions. Selecting one next authority must not silently select the other.
The repository needs that selection recorded before any implementation branch
designs a projection or a command.

`FINDING_REPEATED_OBSERVATION_INVARIANTS.nextSession` remains the tested value
`controlled_finding_repeated_observation_session_3r`. That constant is stale
session bookkeeping from before Session 3-R and branch closure. This ADR leaves
it unchanged. It is not the next activity and it is not authorization.

## Decision

Bounded latest-observation inspection is the next future Controlled Finding
observation authority.

Operator repeated-observation reachability remains deferred. A later ADR is
still required before any caller can invoke repeated-observation persistence.

The selected inspection capability requires a later implementation branch. This
ADR does not make any new behavior reachable. Public inspection remains
creation-observation based until that separate implementation branch is
reviewed, accepted, merged, and production-composed.

Acceptance records the architectural boundary below. It does not grant the
implementation authority to ship the projection, and it does not authorize an
observation command.

## Future projection boundary

The future projection is read-only. It may expose at most the latest legal
repeated observation through one deliberately designed safe projection. It does
not expose complete observation history.

The future projection may expose only:

- Finding identity already authorized through the existing inspection boundary;
- whether the selected projection represents the creation observation or a
  later legal observation;
- the latest observation's recorded timestamp;
- its legal aggregate applicability;
- a safe, tenant-scoped evidence projection;
- constrained component-absence information only when already proven by legal
  persisted state;
- audit-correlated information only when that information does not expose
  internal authority or unrelated tenant data.

The future projection must not expose:

- a complete observation timeline;
- all observation identifiers;
- internal support-row identifiers;
- internal authority tokens or seals;
- foreign-tenant existence;
- raw evidence outside the caller's existing tenant and inspection authority;
- an observation command or command metadata;
- writer reachability;
- lifecycle authority;
- resolution, reopening, suppression, remediation, priority, assignment, or
  scoring behavior.

This ADR does not define a response schema or a public history-list contract.
Concrete API and domain contracts belong to the later implementation slice.

The future projection does not make repeated-observation persistence reachable.
It does not authorize an observation command, route, permission, worker,
scheduler, queue, web control, upload hook, evaluator hook, or automatic
trigger.

## Selection semantics

The later implementation must define, deterministically, all of the following
before the projection can be composed:

- how the latest legal observation is selected;
- timestamp tie handling;
- persisted identity tie handling;
- malformed or illegal persisted-state behavior;
- creation-observation fallback;
- behavior when no repeated observation exists;
- zero-write inspection;
- tenant-scoped indistinguishability for missing and foreign Findings.

The implementation must not rely solely on an ambiguous timestamp ordering. A
timestamp comparison without a defined persisted-identity tie break is not a
legal selection rule.

Malformed or illegal persisted state fails closed. The projection does not
repair it. When no legal repeated observation exists, the projection falls back
to the creation observation. When a legal latest repeated observation exists,
the projection may represent that observation instead of treating every later
row as invisible. Until the implementation branch is production-composed, the
composed public inspection path continues to project the creation observation
only.

Inspection, including this future projection, writes nothing. It inserts no
observation, updates no Finding timestamp, and writes no audit event.

A missing Finding and a foreign Finding remain one public not-found result.
The projection must not reveal that another organization holds the Finding or
any observation.

## Authorization boundary

The future latest-observation projection may build only on existing safe
Finding inspection authority unless a separate ADR accepts a new read
permission. Existing inspection authority is owner or admin
`finding:inspect` on `GET /findings/:findingId`. This ADR does not add a
permission and does not change that route.

This ADR must not reuse any of the following as repeated-observation write
authority:

- `finding:create_controlled`;
- `finding:discover_controlled`;
- `finding:read`;
- `finding:triage`;
- roles or arbitrary membership strings.

No read decision mints write authority. Inspecting a latest observation does
not issue a sealed observation capability, construct the writer, or authorize
`record_finding_repeated_observation`.

## Deferred operator reachability

A later operator-reachability ADR is still required before any caller can
invoke repeated-observation persistence. That later ADR must independently
decide:

- purpose-specific permission design;
- sealed authorization issuance;
- route or command semantics;
- replay behavior;
- concurrency behavior;
- operator feedback;
- audit treatment;
- web availability;
- automation prohibition or allowance.

This ADR does not decide those matters. Operator repeated-observation
reachability is not the implementation successor of this decision.

## Lifecycle boundary

This ADR adopts no Finding lifecycle transition.

- no Finding resolution;
- no reopening;
- no suppression;
- no version increment;
- no remediation effect;
- no automatic state transition.

[ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) section
20 remains unadopted. `affected`, `unaffected`, `unknown`, and
`component_absent` do not change Finding state. Finding state remains `open`
and Finding version remains 1 under the presently implemented persistence
capability.

## Persistence and migration boundary

This ADR authorizes no schema change and no new migration. The 25 frozen
migrations remain unchanged. The repeated-observation migration remains
unchanged.

Support links and observations remain append-only. Creation-observation
evidence remains unchanged. Exact replay remains zero-write. Existing atomicity
and concurrency guarantees remain unchanged. Production registration remains
absent. The writer stays unexported from the database package barrel and is not
constructed by production startup.

## Alternatives considered

### Rejected alternatives

1. **Operator reachability before inspection evolution.** Rejected. A write
   command would become reachable before operators can inspect the latest legal
   aggregate through a reviewed read projection.
2. **Authorizing both inspection and reachability in one ADR.** Rejected. ADR
   0039 kept those decisions separate so one acceptance cannot imply the other.
3. **Full repeated-observation history.** Rejected. A complete timeline exposes
   more observation identity and evidence than the next read needs.
4. **Automatic or scheduled observation.** Rejected. Upload hooks, evaluator
   hooks, workers, queues, and schedulers remain unauthorized.
5. **Lifecycle transition based on observation applicability.** Rejected.
   Applicability is evidence. It is not resolution, reopening, suppression, or
   a version change. ADR 0026 section 20 stays deferred.
6. **Reusing existing broad permissions.** Rejected. Creation, discovery,
   generic read, triage, roles, and membership strings are not
   repeated-observation write authority, and a read grant must not mint a write
   grant.
7. **Treating persistence implementation as implicit production
   authorization.** Rejected. The merged writer remains production uncomposed.
   An implemented transaction is not a route, a permission, or a public
   projection.

## Consequences

Positive:

- Read authority precedes write reachability.
- Operators will eventually be able to inspect the most relevant legal
  aggregate before any production observation command is authorized.
- Full history disclosure is avoided.
- Tenant and evidence boundaries remain reviewable in a later implementation
  slice.

Negative:

- Repeated-observation persistence remains unreachable after this ADR.
- Current production inspection remains creation-based.
- No immediate end-user capability ships.
- Operator reachability requires another future decision.
- Implementation still requires adversarial review.

No migration, dependency, production registration, or startup behavior changes
with this decision.

## Security and tenancy

The future projection uses the organization already bound by safe Finding
inspection. A client-supplied organization id is not authorization. Missing and
foreign Findings stay publicly indistinguishable. The projection must not
disclose another organization's Finding, observation, evidence, or audit
correlation. Internal seals, authority tokens, and support-row identifiers stay
off the projection. No outbound fetch, credential, or new audit writer is
added. This ADR does not broaden tenant or organization authority.

## Operational failure plan

No new runtime path is reachable from this ADR, so production startup gains no
new failure mode and no new operator command. The future implementation must
fail closed on malformed persisted state, write nothing, and keep foreign and
absent Findings indistinguishable. Operators do not insert observations, edit
frozen migrations, or backfill history under this decision. Because the writer
stays uncomposed, production startup still cannot emit `finding.observed`.

## Follow-up

The single implementation successor is Controlled Finding Latest-Observation
Inspection.

Its Work Order must be designed only after this ADR branch passes adversarial
review, acceptance, merge, and main synchronization. That successor designs and
implements the read-only projection inside the boundary above. It does not
implement operator repeated-observation reachability.

`FINDING_REPEATED_OBSERVATION_INVARIANTS.nextSession` stays
`controlled_finding_repeated_observation_session_3r` until a later
implementation change updates that tested bookkeeping constant. Leaving it
unchanged does not select Session 3-R as the next activity.
