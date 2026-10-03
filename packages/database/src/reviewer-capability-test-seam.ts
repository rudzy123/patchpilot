/**
 * Test-only issuer and lifecycle seals.
 * Excluded from the database production build and from package exports.
 * Production package entry points do not re-export these functions.
 */

export {
  sealDurableIssuerAuthority,
  sealDurableLifecycleAuthority,
} from '../../vulnerability-intelligence/dist/matching/reviewer-approval-capability/durable-command.js';
