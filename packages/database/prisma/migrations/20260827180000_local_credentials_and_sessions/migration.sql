-- Session 6 authentication persistence. Forward-only.
-- Does not edit 20260826120000_schema_foundation through 20260827170000_audit_actor_anonymous.

CREATE TYPE "password_hash_algorithm" AS ENUM ('argon2id');

CREATE TYPE "session_authentication_method" AS ENUM ('password');

CREATE TABLE "local_credential" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "password_hash" VARCHAR(255) NOT NULL,
    "password_revision" INTEGER NOT NULL DEFAULT 1,
    "algorithm" "password_hash_algorithm" NOT NULL DEFAULT 'argon2id',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "local_credential_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "local_credential_user_id_key" ON "local_credential"("user_id");

ALTER TABLE "local_credential"
  ADD CONSTRAINT "local_credential_user_id_fkey"
  FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "local_credential"
  ADD CONSTRAINT local_credential_revision_chk CHECK (password_revision >= 1);

ALTER TABLE "local_credential"
  ADD CONSTRAINT local_credential_algorithm_chk CHECK (algorithm = 'argon2id');

ALTER TABLE "local_credential"
  ADD CONSTRAINT local_credential_phc_chk
  CHECK (
    password_hash LIKE '$argon2id$%'
    AND char_length(password_hash) BETWEEN 48 AND 255
  );

CREATE TABLE "session" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "token_hash" CHAR(64) NOT NULL,
    "csrf_token_hash" CHAR(64) NOT NULL,
    "active_organization_id" UUID,
    "authentication_method" "session_authentication_method" NOT NULL DEFAULT 'password',
    "password_revision" INTEGER NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(6) NOT NULL,
    "idle_expires_at" TIMESTAMPTZ(6) NOT NULL,
    "absolute_expires_at" TIMESTAMPTZ(6) NOT NULL,
    "revoked_at" TIMESTAMPTZ(6),
    "revoke_reason" VARCHAR(64),
    "user_agent" VARCHAR(512),

    CONSTRAINT "session_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "session_token_hash_key" ON "session"("token_hash");
CREATE UNIQUE INDEX "session_csrf_token_hash_key" ON "session"("csrf_token_hash");
CREATE INDEX "session_user_idx" ON "session"("user_id");
CREATE INDEX session_idle_cleanup_idx ON "session" ("idle_expires_at") WHERE revoked_at IS NULL;
CREATE INDEX session_absolute_cleanup_idx ON "session" ("absolute_expires_at") WHERE revoked_at IS NULL;
CREATE INDEX session_active_org_idx ON "session" ("active_organization_id") WHERE active_organization_id IS NOT NULL;

ALTER TABLE "session"
  ADD CONSTRAINT "session_user_id_fkey"
  FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "session"
  ADD CONSTRAINT "session_active_organization_id_fkey"
  FOREIGN KEY ("active_organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "session"
  ADD CONSTRAINT session_token_hash_chk CHECK (token_hash ~ '^[a-f0-9]{64}$');

ALTER TABLE "session"
  ADD CONSTRAINT session_csrf_token_hash_chk CHECK (csrf_token_hash ~ '^[a-f0-9]{64}$');

ALTER TABLE "session"
  ADD CONSTRAINT session_revision_chk CHECK (password_revision >= 1);

ALTER TABLE "session"
  ADD CONSTRAINT session_authentication_method_chk CHECK (authentication_method = 'password');

ALTER TABLE "session"
  ADD CONSTRAINT session_absolute_after_created_chk CHECK (absolute_expires_at > created_at);

ALTER TABLE "session"
  ADD CONSTRAINT session_idle_after_created_chk CHECK (idle_expires_at > created_at);

ALTER TABLE "session"
  ADD CONSTRAINT session_idle_within_absolute_chk CHECK (idle_expires_at <= absolute_expires_at);

ALTER TABLE "session"
  ADD CONSTRAINT session_last_seen_window_chk
  CHECK (last_seen_at >= created_at AND last_seen_at <= absolute_expires_at);

ALTER TABLE "session"
  ADD CONSTRAINT session_revoke_consistency_chk
  CHECK (
    (revoked_at IS NULL AND revoke_reason IS NULL)
    OR (revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)
  );

ALTER TABLE "session"
  ADD CONSTRAINT session_revoke_not_before_created_chk
  CHECK (revoked_at IS NULL OR revoked_at >= created_at);

ALTER TABLE "session"
  ADD CONSTRAINT session_revoke_reason_shape_chk
  CHECK (revoke_reason IS NULL OR revoke_reason ~ '^[a-z][a-z0-9_]{0,62}$');

CREATE INDEX membership_user_active_idx ON "membership" ("user_id") WHERE status = 'active';

-- Restore instance-level user attribution. Disable append-only only for this backfill.
ALTER TABLE "audit_event" DISABLE TRIGGER audit_event_append_only;

ALTER TABLE "audit_event" ADD COLUMN "actor_user_id" UUID;

UPDATE "audit_event" AS a
SET "actor_user_id" = m."user_id"
FROM "membership" AS m
WHERE a."actor_membership_id" = m."id"
  AND a."organization_id" = m."organization_id";

ALTER TABLE "audit_event"
  ADD CONSTRAINT "audit_event_actor_user_id_fkey"
  FOREIGN KEY ("actor_user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "audit_event" DROP CONSTRAINT audit_event_actor_scope_chk;

ALTER TABLE "audit_event"
  ADD CONSTRAINT audit_event_actor_scope_chk
  CHECK (
    (
      actor_type = 'anonymous'
      AND actor_user_id IS NULL
      AND organization_id IS NULL
      AND actor_membership_id IS NULL
    )
    OR (
      actor_type = 'user'
      AND actor_user_id IS NOT NULL
      AND organization_id IS NULL
      AND actor_membership_id IS NULL
    )
    OR (
      actor_type = 'user'
      AND actor_user_id IS NOT NULL
      AND organization_id IS NOT NULL
      AND actor_membership_id IS NOT NULL
    )
    OR (
      actor_type = 'system'
      AND actor_user_id IS NULL
      AND actor_membership_id IS NULL
    )
    OR (
      actor_type = 'instance_operator'
      AND actor_user_id IS NULL
      AND actor_membership_id IS NULL
    )
  );

CREATE OR REPLACE FUNCTION patchpilot_audit_actor_membership_user()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  membership_user uuid;
  membership_org uuid;
BEGIN
  IF NEW.actor_membership_id IS NULL THEN
    RETURN NEW;
  END IF;

  SELECT user_id, organization_id
    INTO membership_user, membership_org
    FROM public.membership
    WHERE id = NEW.actor_membership_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit actor membership does not exist'
      USING ERRCODE = 'restrict_violation';
  END IF;

  IF membership_org IS DISTINCT FROM NEW.organization_id THEN
    RAISE EXCEPTION 'audit actor membership organization does not match event organization'
      USING ERRCODE = 'restrict_violation';
  END IF;

  IF membership_user IS DISTINCT FROM NEW.actor_user_id THEN
    RAISE EXCEPTION 'audit actor user does not match membership user'
      USING ERRCODE = 'restrict_violation';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER audit_event_actor_membership_user
  BEFORE INSERT ON "audit_event"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_audit_actor_membership_user();

ALTER TABLE "audit_event" ENABLE TRIGGER audit_event_append_only;
