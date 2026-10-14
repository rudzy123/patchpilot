/**
 * Narrow contracts for a later migration, persistence adapter, and
 * deployment-local command. No grant writer, issuer, or production factory.
 */

export {
  INSTANCE_ADVISORY_ACTIVE_GRANT_INVARIANTS,
  INSTANCE_ADVISORY_AUTHORITIES,
  INSTANCE_ADVISORY_AUTHORITY_INVARIANTS,
  INSTANCE_ADVISORY_AUTHORITY_POWERS,
  INSTANCE_ADVISORY_GRANT_EXCLUDED_IDENTITY_FIELDS,
  INSTANCE_ADVISORY_GRANT_IDENTITY_FIELDS,
  INSTANCE_ADVISORY_GRANT_LIFECYCLE_STATES,
  INSTANCE_ADVISORY_ISSUANCE_CLASSIFICATIONS,
  INSTANCE_ADVISORY_PRODUCT_NONAUTHORITY,
  INSTANCE_ADVISORY_REJECTED_AUTHORITIES,
  INSTANCE_ADVISORY_REJECTED_GRANT_LIFECYCLE_STATES,
  INSTANCE_ADVISORY_REJECTED_ISSUANCE_CLASSIFICATIONS,
  INSTANCE_ADVISORY_TENANT_NONAUTHORITY,
  instanceAdvisoryGrantLifecycle,
  isInstanceAdvisoryAuthority,
  isInstanceAdvisoryIssuanceClassification,
  type InstanceAdvisoryAuthority,
  type InstanceAdvisoryGrantLifecycle,
  type InstanceAdvisoryIssuanceClassification,
} from './policy.js';

export {
  INSTANCE_ADVISORY_PRINCIPAL_EXCLUDED_FIELDS,
  INSTANCE_ADVISORY_SEPARATION_RESIDUAL,
  canonicalInstanceAdvisoryPrincipalId,
  compareInstanceAdvisoryPrincipals,
  isCanonicalInstanceAdvisoryPrincipalId,
  type InstanceAdvisoryPrincipalComparison,
} from './identity.js';

export {
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_OUTCOMES,
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
  INSTANCE_ADVISORY_AUTHORITY_OPERATIONS,
  INSTANCE_ADVISORY_PROHIBITED_COMMAND_FIELDS,
  INSTANCE_ADVISORY_USER_ABSENCE_DISCLOSURE,
  isInstanceAdvisoryAuthorityCommandOutcome,
  isInstanceAdvisoryAuthorityOperation,
  parseInstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthorityCommandOutcome,
  type InstanceAdvisoryAuthorityCommandParse,
  type InstanceAdvisoryAuthorityCommandResult,
  type InstanceAdvisoryAuthorityOperation,
} from './command.js';

export {
  INSTANCE_ADVISORY_CONCURRENT_GRANT_CONTRACT,
  INSTANCE_ADVISORY_DISABLEMENT_CONTRACT,
  INSTANCE_ADVISORY_REENABLEMENT_CONTRACT,
  INSTANCE_ADVISORY_REGRANT_CONTRACT,
  INSTANCE_ADVISORY_REVOCATION_CONTRACT,
  INSTANCE_ADVISORY_REVOCATION_REPLAY,
  classifyInstanceAdvisoryAuthorityCommand,
  classifyInstanceAdvisoryConcurrentGrantReread,
  classifyInstanceAdvisoryConcurrentRevocationReread,
  classifyInstanceAdvisoryGrantLifecycleMutation,
  type InstanceAdvisoryAuthoritySnapshot,
  type InstanceAdvisoryCommandDecision,
  type InstanceAdvisoryGrantLifecycleMutation,
  type InstanceAdvisoryRevokedGrantFact,
} from './decision.js';

export {
  INSTANCE_ADVISORY_AUTHORIZATION_EXTERNAL_COLLAPSE,
  INSTANCE_ADVISORY_AUTHORIZATION_READ_OUTCOMES,
  INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
  INSTANCE_ADVISORY_MUTATION_TRANSACTION_REQUIREMENTS,
  classifyInstanceAdvisoryAuthorization,
  collapseInstanceAdvisoryAuthorizationForExternalBoundary,
  parseInstanceAdvisoryAuthorizationReadRequest,
  type InstanceAdvisoryAuthorizationFacts,
  type InstanceAdvisoryAuthorizationReadOutcome,
  type InstanceAdvisoryAuthorizationReadParse,
  type InstanceAdvisoryAuthorizationReadPort,
  type InstanceAdvisoryAuthorizationReadRequest,
  type InstanceAdvisoryAuthorizationReadResult,
} from './authorization.js';

export {
  INSTANCE_ADVISORY_PERSISTENCE_INVARIANTS,
  type InstanceAdvisoryAuthorityCommandPort,
} from './persistence.js';

export {
  INSTANCE_ADVISORY_AUDIT_ACTIONS,
  INSTANCE_ADVISORY_AUDIT_FORBIDDEN_PAYLOAD_FIELDS,
  INSTANCE_ADVISORY_AUDIT_REPLAY,
  INSTANCE_ADVISORY_GRANT_AUDIT_SUBJECT_TYPE,
  INSTANCE_ADVISORY_USER_AUDIT_SUBJECT_TYPE,
  instanceAdvisoryAuditIntent,
  type InstanceAdvisoryAuditAction,
  type InstanceAdvisoryAuditIntent,
} from './audit.js';

export { INSTANCE_ADVISORY_AUTHORITY_EXECUTION_BOUNDARY } from './execution.js';
