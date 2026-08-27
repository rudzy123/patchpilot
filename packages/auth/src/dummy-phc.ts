/**
 * Fixed server-only Argon2id PHC used for unknown-email login attempts.
 * It belongs to no account, is not an environment variable, is not generated
 * at process start, is never returned to clients, and must never be logged.
 */
export const DUMMY_ARGON2ID_PHC =
  '$argon2id$v=19$m=19456,p=1,t=2$wAfuMzZ5e0/M1YF461YWBA$XcU5YV+Ix8fRIx1DeDaCR7kkeDajckdWmrEnJkcnDyo';
