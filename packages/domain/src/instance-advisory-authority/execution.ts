/**
 * Caller boundary for the deployment-local command.
 * The command executes as the governed system actor.
 * A caller-supplied object is not authentication.
 */

export const INSTANCE_ADVISORY_AUTHORITY_EXECUTION_BOUNDARY = {
  schemaVersion: 'instance_advisory_authority_execution_boundary_v1',
  classification: 'deployment_local_system_operation',
  implemented: true,
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
