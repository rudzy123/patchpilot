/**
 * Password hashing and session services are deferred. This package currently
 * hosts the selected Argon2id library and a compatibility test only.
 */
export const packageBoundary = '@patchpilot/auth' as const;
export const passwordHashingLibrary = 'argon2' as const;
