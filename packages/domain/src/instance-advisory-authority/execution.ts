/**
 * Caller boundary for the future deployment-local command.
 * Session 1 records the boundary and does not execute it.
 * A caller-supplied object is not authentication.
 */

export const INSTANCE_ADVISORY_AUTHORITY_EXECUTION_BOUNDARY = {
  schemaVersion: 'instance_advisory_authority_execution_boundary_v1',
  classification: 'deployment_local_system_operation',
  implemented: false,
  authenticatedThroughOrganizationSession: false,
  authenticatedThroughOwnerRole: false,
  authenticatedThroughAdminRole: false,
  authenticatedThroughTenantPermission: false,
  authenticatedThroughBrowserCookie: false,
  authenticatedThroughPublicApiToken: false,
  callerSuppliedUserIdIsPrincipal: false,
  infrastructureAccessOutsideTenantAdministration: true,
  permitsExactlyOneStrictOperation: true,
  exposesGenericRepository: false,
  exposesTransactionCallback: false,
  isAdvisoryReviewer: false,
  isInstanceOperator: false,
  isOrganizationOwner: false,
  isApprovalCapabilityIssuer: false,
  missingBoundaryOutcome: 'authority_required',
} as const;
