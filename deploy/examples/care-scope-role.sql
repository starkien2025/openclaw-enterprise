-- Run as the Enterprise migration owner after 0084. The database administrator
-- creates the authenticated occ_care login first, with no role memberships.
BEGIN;

DO $role$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles AS login
    WHERE login.rolname = 'occ_care' AND login.rolcanlogin
      AND NOT (login.rolsuper OR login.rolbypassrls OR login.rolcreaterole
        OR login.rolcreatedb OR login.rolreplication)
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member = login.oid)
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_database
        WHERE datname = pg_catalog.current_database() AND datdba = login.oid
      )
  ) THEN
    RAISE EXCEPTION 'Provision occ_care as an independent, unprivileged login first';
  END IF;
END;
$role$;

GRANT USAGE ON SCHEMA occ TO occ_care;
GRANT EXECUTE ON FUNCTION occ.care_scope_allows(text, text, text) TO occ_care;
GRANT SELECT (id, status, created_at, deleted_at) ON occ.namespaces TO occ_care;
GRANT SELECT (id, namespace_id, name, execution_mode, configuration_id, active_revision_id, created_at)
  ON occ.agents TO occ_care;
GRANT SELECT (id, namespace_id, agent_id, revision_number, admitted_at) ON occ.agent_revisions TO occ_care;
GRANT SELECT (id, namespace_id, created_at) ON occ.configurations TO occ_care;
GRANT SELECT (namespace_id, credential_source_id, owner_principal_id, created_at, revoked_at)
  ON occ.saved_connections TO occ_care;
GRANT SELECT (namespace_id, credential_source_id, actor_id, kind, created_at, expires_at)
  ON occ.authentication_states TO occ_care;
GRANT SELECT (namespace_id, credential_source_id, next_refresh_at) ON occ.connection_token_custody TO occ_care;
GRANT SELECT (id, namespace_id, name, created_at) ON occ.secrets TO occ_care;
GRANT SELECT (id, namespace_id, name, type, state, created_at) ON occ.credential_sources TO occ_care;
GRANT SELECT (namespace_id, credential_source_id, field, secret_id) ON occ.credential_source_secrets TO occ_care;
GRANT SELECT (namespace_id, agent_id, credential_source_id) ON occ.agent_credential_sources TO occ_care;
GRANT SELECT (namespace_id, agent_id, revision_id, binding_id, updated_at) ON occ.credential_deliveries TO occ_care;

COMMIT;
