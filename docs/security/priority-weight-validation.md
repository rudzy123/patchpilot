# Priority weight validation record

This is the append-only record that discharges [risk register](risk-register.md) R13 for the built-in priority policy decided by [ADR 0045](../adr/0045-deterministic-p1-p4-priority-policy.md). R13 says the weights are product proposals that operators have not validated. Acceptance of ADR 0045 is not that validation.

## Current status

One entry exists, V-0001, prepared on 2026-11-04. No validator has signed it, and the principal architect has not countersigned it. No outcome is recorded. No (engine version, definition hash) pair is validated. R13 stays open, and production composition of priority calculation stays blocked.

## What validation means

Validators judge whether the built-in policy's outputs on the synthetic corpus below are acceptable as the initial operator policy for a PatchPilot deployment. They answer the questions in [Questions for validators](#questions-for-validators) and record one closed outcome.

- Validation does not make priority security truth. It does not establish exploitability, affectedness, compliance, or remediation. Product copy may describe a validated policy only as a "validated operator policy proposal" with its validation date.
- Validation never changes a weight, normalization table, band, or rule. A desired change needs a new policy version and a new entry.
- Validation alone authorizes no composition. Production composition also needs a separate controlled priority activation ADR, which does not exist yet. That ADR, not this record, chooses the composition root and the built-in publication path.

## Record rules

1. **Append-only.** Entries are numbered V-0001, V-0002, and so on. The only permitted edit to an open entry is filling in its sign-off fields once. After sign-off, an entry is never edited or deleted. A correction is a new entry that names the entry it corrects.
2. **Binding.** Each entry binds to exactly one pair: `POLICY_ENGINE_VERSION` and the built-in `policyDefinitionSha256`. Any change to either needs a new entry. An open entry whose pair no longer matches the repository cannot be signed; append a new entry instead.
3. **Fact-assembly binding.** Each entry also records the commit of `assemblePriorityFacts` in `packages/domain/src/risk/fact-assembly.ts`. A change that alters which facts production can assemble does not change the pair. It does invalidate the entry's observations about reachable outputs. The pull request that makes such a change must append a new entry for the same pair before that change is composed.
4. **Closed outcome.** Each signed entry records exactly one outcome:
   - `validated`;
   - `validated_with_residuals`, with each residual listed in the entry;
   - `rejected_new_version_required`. The policy is not used. A new policy version and a new entry follow. The rejected definition is never edited.
5. **Signers.** At least one named operator reviewer who did not author ADR 0045 and who declares that in the entry. The principal architect countersigns. The validator and the countersigner are different people. Record names only, never email addresses, credentials, or contact details.
6. **Synthetic evidence only.** The corpus uses closed fact tokens and integers. It contains no real SBOM, customer data, tenant identifier, component name, vulnerability identifier, or credential. Validators must not substitute real tenant data.
7. **Code mirror.** A later implementation may mirror this record as a constant allowlist of validated pairs. Only entries with outcome `validated` or `validated_with_residuals` may appear on it. Every allowlist change cites its entry ID. Composition must fail closed for any pair not on it. No allowlist exists yet.

## Subject of V-0001

| Field | Value |
| --- | --- |
| Engine version | `@patchpilot/policy-engine@1` (`POLICY_ENGINE_VERSION`) |
| Engine contract | `patchpilot.priority.p1p4/1` |
| Policy schema version | `2` |
| Policy key | `patchpilot.builtin.v0` |
| Policy version | `2` |
| Development seed row ID | `55555555-5555-4555-8555-555555555502` |
| Definition SHA-256 | `7c1815d456ff6dcf9e19c218bcd5eaba73c265abc911027c3f50df41bb8504f7` |
| Canonical definition length | 2205 bytes (UTF-8) |
| Definition source | `packages/policy-engine/src/builtin-definition.ts`, last changed in `146bc01` |
| Fact-assembly source | `packages/domain/src/risk/fact-assembly.ts`, last changed in `c042c67` |
| Repository commit at preparation | `836d4325e34f8bd0431958c2239e35269078f783` |

The definition hash is the lowercase hex SHA-256 of the UTF-8 bytes of `canonicalJson(BUILTIN_PRIORITY_POLICY_DEFINITION)`. This is the same derivation `fingerprintCalculation` uses in `packages/domain/src/risk/calculation.ts`. The policy version number is not part of the hash (ADR 0045 approval item 19). Re-validating a structured clone of the definition, as the writer does with a definition loaded from storage, gives the same hash.

The development seed row ID is listed only to identify the row. Builtin version 2 exists only in the development seed. Production has no built-in publication path.

The built-in numbers under validation, as fixed by ADR 0045:

- Weights: source severity 40, KEV listed 20, environment sensitivity 10, internet exposure 10, business criticality 8, data classification 5, direct dependency 3, fix available 2, finding age 2, advisory withdrawn 0.
- Bands: P1 from 80 (due recommendation 7 days), P2 from 60 (30 days), P3 from 40 (90 days), P4 from 0 (180 days).
- Age buckets: 0 percent below 30 days, 50 percent from 30 days, 100 percent from 90 days.
- Rules: a KEV listing raises the result to at least P2. Escalation is recommended when a KEV listing coincides with observed production or observed internet-facing context.

## How to reproduce

Build the engine, then compute the hash and evaluate each corpus row:

```bash
pnpm install
pnpm --filter @patchpilot/policy-engine build
node --input-type=module -e "
import { createHash } from 'node:crypto';
import { BUILTIN_PRIORITY_POLICY_DEFINITION, canonicalJson } from './packages/policy-engine/dist/index.js';
const json = canonicalJson(BUILTIN_PRIORITY_POLICY_DEFINITION);
console.log(createHash('sha256').update(json.value, 'utf8').digest('hex'));
"
```

For each corpus row, pass the row's facts to `parseFactInput`, then pass the parsed value to `evaluatePriority(BUILTIN_PRIORITY_POLICY_DEFINITION, parsed)`. The input fingerprint in the [fingerprint table](#corpus-input-fingerprints) is the SHA-256 of `canonicalJson({ engineVersion, policyDefinitionSha256, facts })`, where `facts` is the parsed value. That is the fingerprint the calculation writer stores. A matching fingerprint shows that the validator evaluated exactly the recorded facts.

## Synthetic scenario corpus (revision 1)

### Baseline facts

Rows S01 to S18 start from these production-shaped facts and change only the facts listed in the row.

| Fact | Baseline value |
| --- | --- |
| `source_severity` | unavailable |
| `kev_listed` | observed `not_listed_catalog_current` |
| `environment_sensitivity` | observed `production` |
| `internet_exposure` | observed `internal` |
| `business_criticality` | unknown `unspecified` |
| `asset_data_classification` | unknown `unspecified` |
| `direct_dependency` | observed `direct` |
| `fix_available` | unavailable |
| `finding_age_days` | observed `10` |
| `advisory_withdrawn` | observed `not_withdrawn` |

At the recorded fact-assembly commit, `assemblePriorityFacts` always sets `source_severity` and `fix_available` to unavailable, and always observes `finding_age_days`. Maintainer-reviewed advisories carry no severity. Rows S01 to S18 therefore use only fact shapes production can assemble. Rows R01 and R02 are engine-only references with an observed severity. Production cannot reach them today.

### Expected outputs

Scores are in centipoints, as the engine stores them: 100 centipoints equal 1 priority point. Every row was evaluated with the built `@patchpilot/policy-engine@1` and the definition above.

| ID | Scenario | Facts changed from baseline | Weighted | Uplift | Priority | Band | Due days | Escalation reasons | Rule codes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S01 | KEV listed, internet-facing production | KEV `listed_catalog_current`; exposure `internet_facing` | 4300 | 1700 | 60 | P2 | 30 | `kev_production`, `kev_internet_facing` | `kev_minimum_band_raised`, `kev_escalation_recommended` |
| S02 | KEV listed, internal non-production | KEV `listed_catalog_current`; environment `non_production` | 2300 | 3700 | 60 | P2 | 30 | none | `kev_minimum_band_raised`, `kev_escalation_context_not_observed` |
| S03 | KEV listed, internal production | KEV `listed_catalog_current` | 3300 | 2700 | 60 | P2 | 30 | `kev_production` | `kev_minimum_band_raised`, `kev_escalation_recommended` |
| S04 | KEV listed, strongest asset context | KEV `listed_catalog_current`; exposure `internet_facing`; criticality `critical`; classification `restricted`; age 90 | 5800 | 200 | 60 | P2 | 30 | `kev_production`, `kev_internet_facing` | `kev_minimum_band_raised`, `kev_escalation_recommended` |
| S05 | Not KEV listed, no severity, strongest asset context | exposure `internet_facing`; criticality `critical`; classification `restricted`; age 90 | 3800 | 0 | 38 | P4 | 180 | none | `kev_minimum_band_not_triggered`, `kev_escalation_not_triggered` |
| S06 | No canonical CVE, no severity, strongest asset context | KEV unavailable `no_canonical_cve`; exposure `internet_facing`; criticality `critical`; classification `restricted`; age 90 | 3800 | 0 | 38 | P4 | 180 | none | `kev_minimum_band_not_triggered`, `kev_escalation_not_triggered` |
| S07 | Not KEV listed, no severity, weakest asset context | environment `non_production`; criticality `low`; classification `public`; dependency `transitive`; age 0 | 0 | 0 | 0 | P4 | 180 | none | `kev_minimum_band_not_triggered`, `kev_escalation_not_triggered` |
| S08 | All evidence unavailable (engine level) | every fact unavailable; KEV unavailable `no_active_generation` | 0 | 0 | 0 | P4 | 180 | none | `kev_minimum_band_not_triggered`, `kev_escalation_not_triggered` |
| S09 | Stale KEV listing | KEV `listed_catalog_stale`; environment `non_production` | 2300 | 3700 | 60 | P2 | 30 | none | `kev_minimum_band_raised`, `kev_escalation_context_not_observed` |
| S10 | KEV listing with synchronization disabled | KEV `listed_catalog_disabled_with_history`; environment `non_production` | 2300 | 3700 | 60 | P2 | 30 | none | `kev_minimum_band_raised`, `kev_escalation_context_not_observed` |
| S11 | Stale KEV absence | KEV unknown `absent_catalog_stale`; exposure `internet_facing` | 2300 | 0 | 23 | P4 | 180 | none | `kev_minimum_band_not_triggered`, `kev_escalation_not_triggered` |
| S12 | Withdrawn advisory, KEV listed | as S01; withdrawn `withdrawn` | 4300 | 1700 | 60 | P2 | 30 | `kev_production`, `kev_internet_facing` | `kev_minimum_band_raised`, `kev_escalation_recommended` |
| S13 | Withdrawn advisory, not KEV listed | exposure `internet_facing`; withdrawn `withdrawn` | 2300 | 0 | 23 | P4 | 180 | none | `kev_minimum_band_not_triggered`, `kev_escalation_not_triggered` |
| S14 | Age 29 days | age 29 | 1300 | 0 | 13 | P4 | 180 | none | `kev_minimum_band_not_triggered`, `kev_escalation_not_triggered` |
| S15 | Age 30 days | age 30 | 1400 | 0 | 14 | P4 | 180 | none | `kev_minimum_band_not_triggered`, `kev_escalation_not_triggered` |
| S16 | Age 89 days | age 89 | 1400 | 0 | 14 | P4 | 180 | none | `kev_minimum_band_not_triggered`, `kev_escalation_not_triggered` |
| S17 | Age 90 days | age 90 | 1500 | 0 | 15 | P4 | 180 | none | `kev_minimum_band_not_triggered`, `kev_escalation_not_triggered` |
| S18 | KEV listed, context not observed | KEV `listed_catalog_current`; environment unavailable; exposure unknown `unknown` | 2300 | 3700 | 60 | P2 | 30 | none | `kev_minimum_band_raised`, `kev_escalation_context_not_observed` |
| R01 | Engine-only: critical severity, KEV listed, internet-facing production | from S08: severity `critical`; KEV `listed_catalog_current`; environment `production`; exposure `internet_facing` | 8000 | 0 | 80 | P1 | 7 | `kev_production`, `kev_internet_facing` | `kev_minimum_band_already_met`, `kev_escalation_recommended` |
| R02 | Engine-only: critical severity, not KEV listed, internet-facing production | as R01; KEV `not_listed_catalog_current` | 6000 | 0 | 60 | P2 | 30 | none | `kev_minimum_band_not_triggered`, `kev_escalation_not_triggered` |

Per-row explanation codes that validators may check:

- S01 to S04, S12, and S18 report `kev_listed_catalog_current`. S09 reports `kev_listed_catalog_stale`. S10 reports `kev_listed_catalog_disabled_with_history`. S11 reports `kev_absent_catalog_stale`. S06 reports `kev_unavailable_no_canonical_cve`. S08 reports `kev_unavailable_no_active_generation`.
- S14 reports `age_under_30_days`. S15 and S16 report `age_30_to_89_days`. S17 reports `age_90_days_or_more`. S08 reports `age_unavailable`.
- S12 and S13 report `advisory_withdrawn_review_required` with status `informational`.
- R01 and R02 match the ADR 0045 golden cases "P1 sketch Finding A" and "P2 boundary 60" in `packages/policy-engine/src/evaluate.golden.test.ts`.

### Corpus input fingerprints

Evidence summary is the count of observed, unknown, and unavailable facts.

| ID | Evidence summary | Input fingerprint |
| --- | --- | --- |
| S01 | 6 / 2 / 2 | `c8bf1d74505d0d1f759304b1ce26b69b7b0f02637ef3303b6622ad167e7e5a98` |
| S02 | 6 / 2 / 2 | `cab54597a786c8c6b7deaf95de6d0918e475a3e42c4df1214f2509be82cb600e` |
| S03 | 6 / 2 / 2 | `469c13e8e8bad2039f99c504dd720b2a1479ee8c447ad0080327483e789a251e` |
| S04 | 8 / 0 / 2 | `9705c5075e1ca315dddff885e632788bfea14eebe1b46d91c214e5a68cd089c8` |
| S05 | 8 / 0 / 2 | `bee2675034af331bcf710faffae9e53a875ed9d2e5ecf7ef93c4f182acb41e81` |
| S06 | 7 / 0 / 3 | `92bd13356004b39c52af387253d232d851e00ca7c5c8de0989e54bb480d45845` |
| S07 | 8 / 0 / 2 | `6bce85d00a2840b36ab23870cadb76300fb6c45d7c06f9581daa19e276c4f24d` |
| S08 | 0 / 0 / 10 | `103bff93eb31793dd87b69f6bf315be9abb2e233c6c39f591c009a5c45382546` |
| S09 | 6 / 2 / 2 | `1c5f6edaeb6dfac668a4a5b44d90522ae40770298136e8d51a43106a29fa9a09` |
| S10 | 6 / 2 / 2 | `9bf49dd24e38b19726e21ed06cc247d690e5d223344c21c4675885bb85a46223` |
| S11 | 5 / 3 / 2 | `1df1f46d2d16c57a3c386a829fdd1a6b986ae0acaa7752bc96e890133b9aae68` |
| S12 | 6 / 2 / 2 | `45732d3fbf83222a4729177ca14711c94b9a0bad9e2100e0c000c1313281316c` |
| S13 | 6 / 2 / 2 | `59ffa739a607d34588e3ab99f206dad951167c5ee170ffb1ecd44cd0bee99f33` |
| S14 | 6 / 2 / 2 | `eedca271059e540875cf07e79b506e8d228aabf7ea3d92c0e78e1b542dc16479` |
| S15 | 6 / 2 / 2 | `1237fa35abae3940e2fe99840f715fb0fc68a8dd81ca94be8d01469834e49774` |
| S16 | 6 / 2 / 2 | `3dc44237ee2222b893d424d533daf27e3fa981ccb452f5c76e981afde1a936b7` |
| S17 | 6 / 2 / 2 | `2d30d256046b8d3a26f58d260cf612355facd4dfe6311df484805caf41be47f5` |
| S18 | 4 / 3 / 3 | `1f5336f4187642c3d175536d3b5bdb551589199e094a1d9c37ade34da110d713` |
| R01 | 4 / 0 / 6 | `aa11695d584a525109f7adc4460f5c2b5f3c6b55b24e52c5f7d3046f012bdc6e` |
| R02 | 4 / 0 / 6 | `0d6974f4c64727cc959f8b18d573e0eea3e3926aa84a9c370c5178733939ffc8` |

## Observations from the corpus

The corpus tables above are engine outputs. The points below are conclusions drawn from those outputs and from one additional exhaustive evaluation. They are inputs to the validators' judgment, not decisions.

1. **Only P2 and P4 are reachable in production today.** Holding `source_severity` and `fix_available` unavailable, the preparer evaluated all 64,800 combinations of every KEV state, environment, exposure, criticality, classification, dependency, and withdrawal value, with ages 0, 29, 30, 89, 90, and 36500. Every combination with an observed KEV listing scored exactly 60 (P2). Every other combination scored between 0 and 38 (P4). P1 and P3 are unreachable until a source severity fact can be assembled. ADR 0045 describes non-KEV Findings as landing "in P3 or P4"; under production fact assembly they land in P4 only.
2. **The KEV floor hides asset context.** The highest KEV-listed weighted score without severity is 5800 (S04), below the 6000 floor, so the uplift always fills to exactly 60. Asset criticality, data classification, dependency, and age never change a KEV-listed Finding's priority (S01 and S04 both score 60).
3. **The queue separates KEV Findings only by escalation.** Under `compareForRemediationQueue`, S01, S03, and S04 compare equal, and S01 ranks before S02 only because escalation is recommended. Equal rows fall to Finding first observation and Finding ID, which are outside the engine.
4. **Age moves priority by at most 2 points.** Crossing 30 days adds 1 point (S14 to S15) and crossing 90 days adds 1 more (S16 to S17). Age never changes a band in reachable facts.
5. **Stale and disabled listings count as listed.** S09 and S10 equal S02. Stale absence contributes nothing and is reported as unknown (S11), so it is never treated as "not listed".
6. **Withdrawal is informational only.** S12 equals S01 in every output except the withdrawal row's explanation code. S13 equals its non-withdrawn twin at priority 23.
7. **All-unavailable evidence is a completed P4 calculation.** S08 scores 0 (P4) as a result, not as "not calculated". Production assembly always observes age, so a production calculation always has at least one observed fact.
8. **Unobserved context blocks escalation.** S18 is KEV listed with unavailable environment and unknown exposure. It reaches P2 without escalation and reports `kev_escalation_context_not_observed`.

## Questions for validators

Each answer of "no" leads either to a listed residual (`validated_with_residuals`) or to `rejected_new_version_required`.

1. Is a two-band outcome (every KEV-listed Finding P2 at 60, every other Finding P4) acceptable for an initial deployment while source severity is unavailable?
2. Is it acceptable that a non-KEV Finding on an internet-facing, critical, restricted production asset is P4 (S05)?
3. Is the KEV P2 floor acceptable, given that it makes asset context irrelevant to a KEV-listed Finding's priority?
4. Is it acceptable that stale and disabled-with-history listings count as listed (S09, S10)?
5. Are due-date recommendations of 30 days for KEV-listed Findings and 180 days for all others acceptable as recommendations? `Finding.dueAt` is never written.
6. Is it acceptable that withdrawal is a flag only and never lowers priority (S12, S13)?
7. Is it acceptable that queue order among KEV-listed Findings depends only on escalation, then first observation?

## Entry template

```markdown
### V-NNNN

- Prepared on: YYYY-MM-DD
- Corrects: none | V-NNNN
- Engine version:
- Policy key and version:
- Definition SHA-256:
- Fact-assembly commit:
- Corpus revision:
- Reproduced by validator: yes | no, with the commit used
- Validator:
- Validator declares non-authorship of ADR 0045: yes | no
- Validator sign-off date:
- Answers to questions 1 to 7:
- Outcome: validated | validated_with_residuals | rejected_new_version_required
- Residuals:
- Principal architect countersignature:
- Countersignature date:
```

## Entries

### V-0001

- Prepared on: 2026-11-04, during Session 7B (documentation only).
- Corrects: none.
- Engine version: `@patchpilot/policy-engine@1`.
- Policy key and version: `patchpilot.builtin.v0`, version 2.
- Definition SHA-256: `7c1815d456ff6dcf9e19c218bcd5eaba73c265abc911027c3f50df41bb8504f7`.
- Fact-assembly commit: `c042c67`.
- Corpus revision: 1.
- Reproduced by validator: not yet recorded.
- Validator: not yet recorded.
- Validator declares non-authorship of ADR 0045: not yet recorded.
- Validator sign-off date: not yet recorded.
- Answers to questions 1 to 7: not yet recorded.
- Outcome: not yet recorded.
- Residuals: not yet recorded.
- Principal architect countersignature: not yet recorded.
- Countersignature date: not yet recorded.

V-0001 is open and unsigned. Until it carries a validator sign-off, a countersignature, and an outcome of `validated` or `validated_with_residuals`, R13 remains open and no priority calculation may be composed in production.
