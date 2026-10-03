/**
 * Test harness for issuing a capability before an approval write.
 * Not constructed by production startup.
 */

import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import {
  DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
  REVIEWER_CAPABILITY_ISSUANCE_REQUEST_SCHEMA_VERSION,
  REVIEWER_CAPABILITY_LICENSE_CLASSIFICATION,
  REVIEWER_CAPABILITY_LICENSE_POLICY_ID,
  REVIEWER_CAPABILITY_LICENSE_POLICY_VERSION,
  REVIEWER_CAPABILITY_POLICY_ID,
  REVIEWER_CAPABILITY_POLICY_VERSION,
  REVIEWER_CAPABILITY_SOURCE_CLASSIFICATION,
  parseMaintainerReviewedAdvisoryApprovalCommand,
  parseReviewerCapabilityIssuanceRequest,
  prepareDurableApprovalConsumption,
  prepareDurableReviewerCapabilityIssuance,
  type DurableApprovalConsumptionResult,
  type MaintainerReviewedApprovalPersistenceResult,
  type SealedDurableConsumptionCommand,
} from '@patchpilot/vulnerability-intelligence';

import { createDurableReviewerApprovalCapabilityPersistence } from './reviewer-capability-persistence.js';
import { sealDurableIssuerAuthority } from './reviewer-capability-test-seam.js';
import { createMaintainerReviewedAdvisoryApprovalPersistence } from './maintainer-reviewed-advisory-approval-persistence.js';

export type HarnessApprovalResult =
  DurableApprovalConsumptionResult | MaintainerReviewedApprovalPersistenceResult;

export function createApprovalCapabilityHarness(client: PrismaClient): {
  approve(command: unknown): Promise<HarnessApprovalResult>;
  issueConsumption(
    command: unknown,
  ): Promise<
    | { readonly accepted: true; readonly command: SealedDurableConsumptionCommand }
    | { readonly accepted: false; readonly result: HarnessApprovalResult }
  >;
} {
  const capabilities = createDurableReviewerApprovalCapabilityPersistence(client);
  const approvals = createMaintainerReviewedAdvisoryApprovalPersistence(client);
  const capabilityIds = new Map<string, string>();
  const authorizationIds = new Map<string, string>();

  async function ensureCapability(
    command: unknown,
  ): Promise<
    | { readonly accepted: true; readonly capabilityId: string }
    | { readonly accepted: false; readonly result: HarnessApprovalResult }
  > {
    const parsed = parseMaintainerReviewedAdvisoryApprovalCommand(command);
    if (!parsed.accepted) {
      return {
        accepted: false,
        result: await approvals.recordMaintainerReviewedAdvisoryApproval(command),
      };
    }
    const key = JSON.stringify([
      parsed.command.advisoryRevisionId,
      parsed.command.expectedAdvisoryFamilyIdentity,
      parsed.command.expectedContentFingerprint,
      parsed.command.expectedRangeFingerprint,
      parsed.command.expectedNpmPackageIdentity,
      parsed.command.expectedVulnerabilityId,
      parsed.command.authorIdentity,
      parsed.command.reviewerIdentity,
    ]);
    const cached = capabilityIds.get(key);
    if (cached !== undefined) {
      return { accepted: true, capabilityId: cached };
    }
    {
      const requestInput = {
        issuanceRequestSchemaVersion: REVIEWER_CAPABILITY_ISSUANCE_REQUEST_SCHEMA_VERSION,
        capabilityPolicyId: REVIEWER_CAPABILITY_POLICY_ID,
        capabilityPolicyVersion: REVIEWER_CAPABILITY_POLICY_VERSION,
        approvalPolicyId: parsed.command.approvalPolicyId,
        approvalPolicyVersion: parsed.command.approvalPolicyVersion,
        approvalPurpose: parsed.command.approvalPurpose,
        advisoryFamilyIdentity: parsed.command.expectedAdvisoryFamilyIdentity,
        advisoryRevisionId: parsed.command.advisoryRevisionId,
        contentFingerprint: parsed.command.expectedContentFingerprint,
        affectedRangeFingerprint: parsed.command.expectedRangeFingerprint,
        npmPackageIdentity: parsed.command.expectedNpmPackageIdentity,
        vulnerabilityId: parsed.command.expectedVulnerabilityId,
        sourceLicensePolicyId: REVIEWER_CAPABILITY_LICENSE_POLICY_ID,
        sourceLicensePolicyVersion: REVIEWER_CAPABILITY_LICENSE_POLICY_VERSION,
        approvedLicenseClassification: REVIEWER_CAPABILITY_LICENSE_CLASSIFICATION,
        authorIdentity: parsed.command.authorIdentity,
        reviewerIdentity: parsed.command.reviewerIdentity,
        correlationId: parsed.command.correlationId,
        sourceClassification: REVIEWER_CAPABILITY_SOURCE_CLASSIFICATION,
      };
      const request = parseReviewerCapabilityIssuanceRequest(requestInput);
      if (!request.accepted) {
        return {
          accepted: false,
          result: {
            kind: 'rejected',
            code: request.code === 'self_approval' ? 'self_approval' : 'invalid_command',
            effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
          },
        };
      }
      const authorizationId = authorizationIds.get(key) ?? randomUUID();
      authorizationIds.set(key, authorizationId);
      const issuer = sealDurableIssuerAuthority({
        request: request.request,
        authorizationId,
      });
      if (!issuer.accepted) {
        return {
          accepted: false,
          result: {
            kind: 'rejected',
            code: issuer.code,
            effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
          },
        };
      }
      const prepared = prepareDurableReviewerCapabilityIssuance({
        request: request.request,
        issuerAuthority: issuer.issuerAuthority,
      });
      if (!prepared.accepted) {
        return {
          accepted: false,
          result: {
            kind: 'rejected',
            code: prepared.code,
            effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
          },
        };
      }
      const issued = await capabilities.issueDurableReviewerApprovalCapability(prepared.command);
      if (issued.kind === 'immutable_conflict') {
        return {
          accepted: false,
          result: { kind: 'immutable_conflict', effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS },
        };
      }
      if (issued.kind === 'rejected') {
        return { accepted: false, result: issued };
      }
      if (issued.kind !== 'issued' && issued.kind !== 'already_issued') {
        return {
          accepted: false,
          result: {
            kind: 'rejected',
            code: 'internal_failure',
            effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
          },
        };
      }
      capabilityIds.set(key, issued.projection.capabilityPublicId);
      return { accepted: true, capabilityId: issued.projection.capabilityPublicId };
    }
  }

  const api = {
    async issueConsumption(
      command: unknown,
    ): Promise<
      | { readonly accepted: true; readonly command: SealedDurableConsumptionCommand }
      | { readonly accepted: false; readonly result: HarnessApprovalResult }
    > {
      const ensured = await ensureCapability(command);
      if (!ensured.accepted) {
        return ensured;
      }
      const consumption = prepareDurableApprovalConsumption({
        approvalCommand: command,
        capabilityIssuanceId: ensured.capabilityId,
      });
      if (!consumption.accepted) {
        return {
          accepted: false,
          result: {
            kind: 'rejected',
            code: consumption.code,
            effects: DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
          },
        };
      }
      return { accepted: true, command: consumption.command };
    },
    async approve(command: unknown): Promise<HarnessApprovalResult> {
      const consumption = await api.issueConsumption(command);
      if (!consumption.accepted) {
        return consumption.result;
      }
      return capabilities.persistMaintainerReviewedAdvisoryApprovalWithCapability(
        consumption.command,
      );
    },
  };
  return api;
}
