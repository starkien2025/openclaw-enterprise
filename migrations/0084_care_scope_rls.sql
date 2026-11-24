-- Care IDs are issued by the trusted request broker. The maps have no scoped-role privileges.
CREATE TABLE occ.care_workspace_scope (
  workspace_id text COLLATE "C" PRIMARY KEY CHECK (char_length(workspace_id) BETWEEN 1 AND 128),
  namespace_id text NOT NULL UNIQUE REFERENCES occ.namespaces(id) ON DELETE CASCADE,
  UNIQUE (workspace_id, namespace_id)
);
--> statement-breakpoint
CREATE TABLE occ.care_actor_scope (
  workspace_id text COLLATE "C" NOT NULL REFERENCES occ.care_workspace_scope(workspace_id) ON DELETE CASCADE,
  actor_id text COLLATE "C" NOT NULL CHECK (char_length(actor_id) BETWEEN 1 AND 128),
  principal_id text NOT NULL REFERENCES occ.iam_identities(id) ON DELETE CASCADE,
  PRIMARY KEY (workspace_id, actor_id),
  UNIQUE (workspace_id, principal_id)
);
--> statement-breakpoint
CREATE TABLE occ.care_agent_scope (
  workspace_id text COLLATE "C" NOT NULL,
  actor_id text COLLATE "C" NOT NULL,
  namespace_id text NOT NULL,
  resource_id text NOT NULL,
  PRIMARY KEY (workspace_id, actor_id, resource_id),
  FOREIGN KEY (workspace_id, actor_id) REFERENCES occ.care_actor_scope(workspace_id, actor_id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, namespace_id) REFERENCES occ.care_workspace_scope(workspace_id, namespace_id) ON DELETE CASCADE,
  FOREIGN KEY (namespace_id, resource_id) REFERENCES occ.agents(namespace_id, id) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE occ.care_source_scope (
  workspace_id text COLLATE "C" NOT NULL,
  actor_id text COLLATE "C" NOT NULL,
  namespace_id text NOT NULL,
  resource_id text NOT NULL,
  PRIMARY KEY (workspace_id, actor_id, resource_id),
  FOREIGN KEY (workspace_id, actor_id) REFERENCES occ.care_actor_scope(workspace_id, actor_id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, namespace_id) REFERENCES occ.care_workspace_scope(workspace_id, namespace_id) ON DELETE CASCADE,
  FOREIGN KEY (namespace_id, resource_id) REFERENCES occ.credential_sources(namespace_id, id) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE occ.care_secret_scope (
  workspace_id text COLLATE "C" NOT NULL,
  actor_id text COLLATE "C" NOT NULL,
  namespace_id text NOT NULL,
  resource_id text NOT NULL,
  PRIMARY KEY (workspace_id, actor_id, resource_id),
  FOREIGN KEY (workspace_id, actor_id) REFERENCES occ.care_actor_scope(workspace_id, actor_id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, namespace_id) REFERENCES occ.care_workspace_scope(workspace_id, namespace_id) ON DELETE CASCADE,
  FOREIGN KEY (namespace_id, resource_id) REFERENCES occ.secrets(namespace_id, id) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE FUNCTION occ.care_scope_allows(native_namespace text, resource_kind text, resource_id text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM occ.care_workspace_scope AS workspace
    JOIN occ.care_actor_scope AS actor USING (workspace_id)
    JOIN occ.iam_identities AS principal ON principal.id = actor.principal_id AND principal.kind = 'principal'
    WHERE session_user = 'occ_care'
      AND workspace.workspace_id = current_setting('care.workspace_id', true)
      AND actor.actor_id = current_setting('care.actor_id', true)
      AND workspace.namespace_id = native_namespace
      AND CASE resource_kind
        WHEN 'namespace' THEN true
        WHEN 'actor' THEN principal.id = resource_id
        WHEN 'agent' THEN EXISTS (
          SELECT 1 FROM occ.care_agent_scope AS access
          WHERE access.workspace_id = actor.workspace_id AND access.actor_id = actor.actor_id
            AND access.resource_id = care_scope_allows.resource_id
        )
        WHEN 'configuration' THEN EXISTS (
          SELECT 1 FROM occ.care_agent_scope AS access
          JOIN occ.agents AS agent ON agent.namespace_id = access.namespace_id AND agent.id = access.resource_id
          WHERE access.workspace_id = actor.workspace_id AND access.actor_id = actor.actor_id
            AND agent.configuration_id = care_scope_allows.resource_id
        )
        WHEN 'saved_source' THEN EXISTS (
          SELECT 1 FROM occ.saved_connections AS saved
          WHERE saved.namespace_id = native_namespace
            AND saved.credential_source_id = resource_id AND saved.owner_principal_id = principal.id
        )
        WHEN 'source' THEN EXISTS (
          SELECT 1 FROM occ.care_source_scope AS access
          WHERE access.workspace_id = actor.workspace_id AND access.actor_id = actor.actor_id
            AND access.resource_id = care_scope_allows.resource_id
        ) OR EXISTS (
          SELECT 1 FROM occ.saved_connections AS saved
          WHERE saved.namespace_id = native_namespace
            AND saved.credential_source_id = resource_id AND saved.owner_principal_id = principal.id
        )
        WHEN 'secret' THEN EXISTS (
          SELECT 1 FROM occ.care_secret_scope AS access
          WHERE access.workspace_id = actor.workspace_id AND access.actor_id = actor.actor_id
            AND access.resource_id = care_scope_allows.resource_id
        )
        ELSE false
      END
  );
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION occ.care_scope_allows(text, text, text) FROM PUBLIC;
--> statement-breakpoint
DO $policies$
DECLARE
  protected record;
BEGIN
  FOR protected IN SELECT * FROM (VALUES
    ('namespaces', 'occ.care_scope_allows(id, ''namespace'', id)'),
    ('agents', 'occ.care_scope_allows(namespace_id, ''agent'', id)'),
    ('agent_revisions', 'occ.care_scope_allows(namespace_id, ''agent'', agent_id)'),
    ('configurations', 'occ.care_scope_allows(namespace_id, ''configuration'', id)'),
    ('saved_connections', 'occ.care_scope_allows(namespace_id, ''actor'', owner_principal_id)'),
    ('authentication_states', 'kind = ''oauth_connection'' AND occ.care_scope_allows(namespace_id, ''actor'', actor_id)'),
    ('connection_token_custody', 'occ.care_scope_allows(namespace_id, ''saved_source'', credential_source_id)'),
    ('secrets', 'occ.care_scope_allows(namespace_id, ''secret'', id)'),
    ('credential_sources', 'occ.care_scope_allows(namespace_id, ''source'', id)'),
    ('credential_source_secrets', 'occ.care_scope_allows(namespace_id, ''source'', credential_source_id) AND occ.care_scope_allows(namespace_id, ''secret'', secret_id)'),
    ('agent_credential_sources', 'occ.care_scope_allows(namespace_id, ''agent'', agent_id) AND occ.care_scope_allows(namespace_id, ''source'', credential_source_id)'),
    ('credential_deliveries', 'occ.care_scope_allows(namespace_id, ''agent'', agent_id)')
  ) AS scope(relation_name, predicate)
  LOOP
    EXECUTE format('ALTER TABLE occ.%I ENABLE ROW LEVEL SECURITY', protected.relation_name);
    EXECUTE format('ALTER TABLE occ.%I FORCE ROW LEVEL SECURITY', protected.relation_name);
    -- The native controller preserves its IAM path. Definer triggers run as the schema owner.
    EXECUTE format('CREATE POLICY enterprise_maintenance ON occ.%I TO occ_app, occ_migrator USING (true) WITH CHECK (true)', protected.relation_name);
    EXECUTE format(
      'CREATE POLICY care_scoped_read ON occ.%I FOR SELECT USING (
        CASE WHEN current_user = ''occ_care'' THEN (%s) ELSE false END
      )', protected.relation_name, protected.predicate
    );
  END LOOP;
END;
$policies$;
