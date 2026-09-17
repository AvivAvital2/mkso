DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mkso_i06_owner') THEN
        CREATE ROLE mkso_i06_owner
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOLOGIN NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mkso_i06_broker') THEN
        CREATE ROLE mkso_i06_broker
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOLOGIN NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mkso_i06_runner') THEN
        CREATE ROLE mkso_i06_runner
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOLOGIN NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mkso_i06_private_human'
    ) THEN
        CREATE ROLE mkso_i06_private_human
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOLOGIN NOREPLICATION NOBYPASSRLS;
    END IF;
END
$roles$;

DO $role_invariants$
DECLARE
    required_role text;
BEGIN
    FOREACH required_role IN ARRAY ARRAY[
        'mkso_i06_owner',
        'mkso_i06_broker',
        'mkso_i06_runner',
        'mkso_i06_private_human'
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_roles
            WHERE rolname = required_role
              AND NOT rolsuper
              AND NOT rolcreatedb
              AND NOT rolcreaterole
              AND NOT rolinherit
              AND NOT rolcanlogin
              AND NOT rolreplication
              AND NOT rolbypassrls
        ) THEN
            RAISE EXCEPTION 'role % does not have the frozen attributes', required_role;
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = membership.member
        JOIN pg_catalog.pg_roles AS granted_role ON granted_role.oid = membership.roleid
        WHERE member_role.rolname = ANY (ARRAY[
                  'mkso_i06_owner',
                  'mkso_i06_broker',
                  'mkso_i06_runner',
                  'mkso_i06_private_human'
              ])
          AND granted_role.rolname = ANY (ARRAY[
                  'mkso_i06_owner',
                  'mkso_i06_broker',
                  'mkso_i06_runner',
                  'mkso_i06_private_human'
              ])
    ) THEN
        RAISE EXCEPTION 'runtime roles must not be members of one another';
    END IF;
END
$role_invariants$;

CREATE SCHEMA IF NOT EXISTS mkso_i06 AUTHORIZATION mkso_i06_owner;

DO $schema_owner$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS namespace
        JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = namespace.nspowner
        WHERE namespace.nspname = 'mkso_i06'
          AND owner_role.rolname = 'mkso_i06_owner'
    ) THEN
        RAISE EXCEPTION 'mkso_i06 schema has the wrong owner';
    END IF;
END
$schema_owner$;

REVOKE ALL ON SCHEMA mkso_i06 FROM PUBLIC;
GRANT USAGE ON SCHEMA mkso_i06
    TO mkso_i06_broker, mkso_i06_runner, mkso_i06_private_human;

SET ROLE mkso_i06_owner;

CREATE TABLE IF NOT EXISTS mkso_i06.toolchain_profiles (
    profile_hash text PRIMARY KEY,
    qualification_claim_id text NOT NULL,
    context_manifest_hash text NOT NULL,
    profile_document bytea NOT NULL,
    CONSTRAINT toolchain_profiles_complete_key
        UNIQUE (profile_hash, qualification_claim_id, context_manifest_hash),
    CONSTRAINT toolchain_profiles_profile_hash_format
        CHECK (profile_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT toolchain_profiles_claim_id_format
        CHECK (qualification_claim_id ~ '^[A-Za-z][A-Za-z0-9._:-]{0,127}$'),
    CONSTRAINT toolchain_profiles_context_hash_format
        CHECK (context_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT toolchain_profiles_document_nonempty
        CHECK (octet_length(profile_document) > 0)
);

CREATE TABLE IF NOT EXISTS mkso_i06.toolchain_runs (
    run_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    qualification_claim_id text NOT NULL,
    profile_hash text NOT NULL,
    context_manifest_hash text NOT NULL,
    stage text NOT NULL,
    CONSTRAINT toolchain_runs_complete_key
        UNIQUE (qualification_claim_id, profile_hash, context_manifest_hash),
    CONSTRAINT toolchain_runs_profile_fk
        FOREIGN KEY (profile_hash, qualification_claim_id, context_manifest_hash)
        REFERENCES mkso_i06.toolchain_profiles (
            profile_hash, qualification_claim_id, context_manifest_hash
        ),
    CONSTRAINT toolchain_runs_claim_id_format
        CHECK (qualification_claim_id ~ '^[A-Za-z][A-Za-z0-9._:-]{0,127}$'),
    CONSTRAINT toolchain_runs_profile_hash_format
        CHECK (profile_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT toolchain_runs_context_hash_format
        CHECK (context_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT toolchain_runs_stage_closed
        CHECK (stage IN ('ADMITTED', 'STARTED', 'RAW_COMMITTED', 'CLEANED', 'TERMINAL'))
);

CREATE TABLE IF NOT EXISTS mkso_i06.toolchain_audit_events (
    run_id bigint NOT NULL REFERENCES mkso_i06.toolchain_runs (run_id),
    ordinal smallint NOT NULL,
    event_kind text NOT NULL,
    actor name NOT NULL,
    commitment_hash text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (run_id, ordinal),
    CONSTRAINT toolchain_audit_events_kind_once UNIQUE (run_id, event_kind),
    CONSTRAINT toolchain_audit_events_ordinal_closed CHECK (ordinal BETWEEN 1 AND 6),
    CONSTRAINT toolchain_audit_events_kind_closed CHECK (
        event_kind IN (
            'admission',
            'start',
            'raw_output_commitment',
            'cleanup',
            'terminal_result',
            'signature_commitment'
        )
    ),
    CONSTRAINT toolchain_audit_events_commitment_hash_format
        CHECK (commitment_hash ~ '^sha256:[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS mkso_i06.toolchain_terminal_results (
    run_id bigint PRIMARY KEY REFERENCES mkso_i06.toolchain_runs (run_id),
    result_hash text NOT NULL UNIQUE,
    signed_document_hash text NOT NULL UNIQUE,
    result_document bytea NOT NULL,
    CONSTRAINT toolchain_terminal_results_result_hash_format
        CHECK (result_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT toolchain_terminal_results_document_hash_format
        CHECK (signed_document_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT toolchain_terminal_results_document_nonempty
        CHECK (octet_length(result_document) > 0)
);

CREATE TABLE IF NOT EXISTS mkso_i06.toolchain_private_runs (
    run_id bigint PRIMARY KEY REFERENCES mkso_i06.toolchain_runs (run_id),
    raw_output_manifest_hash text NOT NULL,
    cleanup_observation_hash text NOT NULL,
    postgres_event_prefix_hash text NOT NULL,
    raw_run_hash text NOT NULL UNIQUE,
    retained_manifest_hash text NOT NULL UNIQUE,
    manifest_document bytea NOT NULL,
    CONSTRAINT toolchain_private_runs_raw_output_hash_format
        CHECK (raw_output_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT toolchain_private_runs_cleanup_hash_format
        CHECK (cleanup_observation_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT toolchain_private_runs_event_prefix_hash_format
        CHECK (postgres_event_prefix_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT toolchain_private_runs_raw_run_hash_format
        CHECK (raw_run_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT toolchain_private_runs_manifest_hash_format
        CHECK (retained_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT toolchain_private_runs_manifest_nonempty
        CHECK (octet_length(manifest_document) > 0)
);

CREATE TABLE IF NOT EXISTS mkso_i06.toolchain_private_blobs (
    run_id bigint NOT NULL REFERENCES mkso_i06.toolchain_private_runs (run_id),
    ordinal integer NOT NULL,
    role text NOT NULL,
    logical_name text NOT NULL,
    content_hash text NOT NULL,
    content_size bigint NOT NULL,
    content bytea NOT NULL,
    PRIMARY KEY (run_id, ordinal),
    CONSTRAINT toolchain_private_blobs_identity_once
        UNIQUE (run_id, role, logical_name),
    CONSTRAINT toolchain_private_blobs_ordinal_positive CHECK (ordinal > 0),
    CONSTRAINT toolchain_private_blobs_role_closed CHECK (
        role IN (
            'profile',
            'context_file',
            'build_request',
            'stdout',
            'stderr',
            'network_observation',
            'runtime_observation',
            'required_output',
            'raw_output_manifest',
            'adapter_cleanup_observation',
            'cleanup_observation',
            'failure_observation',
            'postgres_event_prefix'
        )
    ),
    CONSTRAINT toolchain_private_blobs_logical_name_ascii CHECK (
        logical_name <> '' AND octet_length(logical_name) = char_length(logical_name)
    ),
    CONSTRAINT toolchain_private_blobs_content_hash_format
        CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT toolchain_private_blobs_content_size_exact CHECK (
        content_size >= 0 AND content_size = octet_length(content)
    ),
    CONSTRAINT toolchain_private_blobs_event_prefix_nonempty CHECK (
        role <> 'postgres_event_prefix' OR content_size > 0
    )
);

ALTER TABLE mkso_i06.toolchain_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE mkso_i06.toolchain_profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE mkso_i06.toolchain_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mkso_i06.toolchain_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE mkso_i06.toolchain_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE mkso_i06.toolchain_audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE mkso_i06.toolchain_terminal_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE mkso_i06.toolchain_terminal_results FORCE ROW LEVEL SECURITY;
ALTER TABLE mkso_i06.toolchain_private_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mkso_i06.toolchain_private_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE mkso_i06.toolchain_private_blobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mkso_i06.toolchain_private_blobs FORCE ROW LEVEL SECURITY;

DO $policies$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'toolchain_profiles',
        'toolchain_runs',
        'toolchain_audit_events',
        'toolchain_terminal_results',
        'toolchain_private_runs',
        'toolchain_private_blobs'
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_policy
            WHERE polname = 'mkso_i06_owner_all'
              AND polrelid = format('mkso_i06.%I', table_name)::regclass
        ) THEN
            EXECUTE format(
                'CREATE POLICY mkso_i06_owner_all ON mkso_i06.%I '
                'FOR ALL TO mkso_i06_owner USING (true) WITH CHECK (true)',
                table_name
            );
        END IF;
        IF NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_policy
            WHERE polname = 'mkso_i06_private_human_read'
              AND polrelid = format('mkso_i06.%I', table_name)::regclass
        ) THEN
            EXECUTE format(
                'CREATE POLICY mkso_i06_private_human_read ON mkso_i06.%I '
                'FOR SELECT TO mkso_i06_private_human USING (true)',
                table_name
            );
        END IF;
    END LOOP;
END
$policies$;

CREATE OR REPLACE FUNCTION mkso_i06.reject_append_only_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $function$
BEGIN
    RAISE EXCEPTION 'append-only relation % rejects %', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '55000';
END
$function$;

DO $triggers$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'toolchain_profiles',
        'toolchain_audit_events',
        'toolchain_terminal_results',
        'toolchain_private_runs',
        'toolchain_private_blobs'
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_trigger
            WHERE tgname = 'reject_append_only_mutation'
              AND tgrelid = format('mkso_i06.%I', table_name)::regclass
              AND NOT tgisinternal
        ) THEN
            EXECUTE format(
                'CREATE TRIGGER reject_append_only_mutation '
                'BEFORE UPDATE OR DELETE OR TRUNCATE ON mkso_i06.%I '
                'FOR EACH STATEMENT EXECUTE FUNCTION mkso_i06.reject_append_only_mutation()',
                table_name
            );
        END IF;
    END LOOP;
END
$triggers$;

CREATE OR REPLACE FUNCTION mkso_i06.admit_toolchain_run(
    profile_document bytea,
    profile_hash text,
    claim_id text,
    context_manifest_hash text
)
RETURNS TABLE (run_id bigint, disposition text, terminal_document bytea)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
DECLARE
    selected_run_id bigint;
    selected_stage text;
    retained_profile mkso_i06.toolchain_profiles%ROWTYPE;
    retained_terminal bytea;
BEGIN
    IF current_setting('transaction_isolation') <> 'serializable' THEN
        RAISE EXCEPTION 'toolchain admission requires a serializable transaction'
            USING ERRCODE = '25001';
    END IF;
    IF profile_document IS NULL OR octet_length(profile_document) = 0 THEN
        RAISE EXCEPTION 'profile document must be non-empty' USING ERRCODE = '22023';
    END IF;
    IF profile_hash IS NULL OR profile_hash !~ '^sha256:[0-9a-f]{64}$'
       OR context_manifest_hash IS NULL
       OR context_manifest_hash !~ '^sha256:[0-9a-f]{64}$'
       OR claim_id IS NULL
       OR claim_id !~ '^[A-Za-z][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION 'invalid admission key' USING ERRCODE = '22023';
    END IF;

    INSERT INTO mkso_i06.toolchain_profiles (
        profile_hash, qualification_claim_id, context_manifest_hash, profile_document
    ) VALUES (
        admit_toolchain_run.profile_hash,
        admit_toolchain_run.claim_id,
        admit_toolchain_run.context_manifest_hash,
        admit_toolchain_run.profile_document
    )
    ON CONFLICT DO NOTHING;

    SELECT profile.*
    INTO retained_profile
    FROM mkso_i06.toolchain_profiles AS profile
    WHERE profile.profile_hash = admit_toolchain_run.profile_hash
    FOR UPDATE;

    IF NOT FOUND
       OR retained_profile.qualification_claim_id <> admit_toolchain_run.claim_id
       OR retained_profile.context_manifest_hash <> admit_toolchain_run.context_manifest_hash
       OR retained_profile.profile_document <> admit_toolchain_run.profile_document THEN
        RAISE EXCEPTION 'profile hash is already bound to different retained bytes or key'
            USING ERRCODE = '23505';
    END IF;

    INSERT INTO mkso_i06.toolchain_runs (
        qualification_claim_id, profile_hash, context_manifest_hash, stage
    ) VALUES (
        admit_toolchain_run.claim_id,
        admit_toolchain_run.profile_hash,
        admit_toolchain_run.context_manifest_hash,
        'ADMITTED'
    )
    ON CONFLICT ON CONSTRAINT toolchain_runs_complete_key DO NOTHING
    RETURNING toolchain_runs.run_id INTO selected_run_id;

    IF selected_run_id IS NOT NULL THEN
        INSERT INTO mkso_i06.toolchain_audit_events (
            run_id, ordinal, event_kind, actor, commitment_hash
        ) VALUES (
            selected_run_id,
            1,
            'admission',
            'mkso_i06_broker',
            admit_toolchain_run.profile_hash
        );
        RETURN QUERY SELECT selected_run_id, 'ADMITTED'::text, NULL::bytea;
        RETURN;
    END IF;

    SELECT run.run_id, run.stage
    INTO selected_run_id, selected_stage
    FROM mkso_i06.toolchain_runs AS run
    WHERE run.qualification_claim_id = admit_toolchain_run.claim_id
      AND run.profile_hash = admit_toolchain_run.profile_hash
      AND run.context_manifest_hash = admit_toolchain_run.context_manifest_hash
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'admitted run disappeared' USING ERRCODE = '55000';
    END IF;
    IF selected_stage = 'TERMINAL' THEN
        SELECT terminal.result_document
        INTO retained_terminal
        FROM mkso_i06.toolchain_terminal_results AS terminal
        WHERE terminal.run_id = selected_run_id;
        IF retained_terminal IS NULL THEN
            RAISE EXCEPTION 'terminal stage has no retained result' USING ERRCODE = '55000';
        END IF;
        RETURN QUERY SELECT selected_run_id, 'TERMINAL'::text, retained_terminal;
    ELSE
        RETURN QUERY SELECT selected_run_id, 'ACTIVE'::text, NULL::bytea;
    END IF;
END
$function$;

CREATE OR REPLACE FUNCTION mkso_i06.start_toolchain_run(
    claim_id text,
    profile_hash text,
    context_manifest_hash text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
DECLARE
    selected_run_id bigint;
    selected_stage text;
BEGIN
    IF current_setting('transaction_isolation') <> 'serializable' THEN
        RAISE EXCEPTION 'toolchain start requires a serializable transaction'
            USING ERRCODE = '25001';
    END IF;
    SELECT run.run_id, run.stage
    INTO selected_run_id, selected_stage
    FROM mkso_i06.toolchain_runs AS run
    WHERE run.qualification_claim_id = claim_id
      AND run.profile_hash = start_toolchain_run.profile_hash
      AND run.context_manifest_hash = start_toolchain_run.context_manifest_hash
    FOR UPDATE;
    IF NOT FOUND OR selected_stage <> 'ADMITTED' THEN
        RAISE EXCEPTION 'start requires ADMITTED' USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id
          AND event.ordinal = 1
          AND event.event_kind = 'admission'
          AND event.commitment_hash = start_toolchain_run.profile_hash
    ) THEN
        RAISE EXCEPTION 'start lacks its exact admission predecessor' USING ERRCODE = '55000';
    END IF;
    UPDATE mkso_i06.toolchain_runs SET stage = 'STARTED' WHERE run_id = selected_run_id;
    INSERT INTO mkso_i06.toolchain_audit_events (
        run_id, ordinal, event_kind, actor, commitment_hash
    ) VALUES (
        selected_run_id, 2, 'start', 'mkso_i06_runner', start_toolchain_run.profile_hash
    );
END
$function$;

CREATE OR REPLACE FUNCTION mkso_i06.commit_raw_output(
    claim_id text,
    profile_hash text,
    context_manifest_hash text,
    raw_output_commitment text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
DECLARE
    selected_run_id bigint;
    selected_stage text;
BEGIN
    IF current_setting('transaction_isolation') <> 'serializable' THEN
        RAISE EXCEPTION 'raw-output commitment requires a serializable transaction'
            USING ERRCODE = '25001';
    END IF;
    IF raw_output_commitment IS NULL
       OR raw_output_commitment !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid raw-output commitment' USING ERRCODE = '22023';
    END IF;
    SELECT run.run_id, run.stage
    INTO selected_run_id, selected_stage
    FROM mkso_i06.toolchain_runs AS run
    WHERE run.qualification_claim_id = claim_id
      AND run.profile_hash = commit_raw_output.profile_hash
      AND run.context_manifest_hash = commit_raw_output.context_manifest_hash
    FOR UPDATE;
    IF NOT FOUND OR selected_stage <> 'STARTED' THEN
        RAISE EXCEPTION 'raw-output commitment requires STARTED' USING ERRCODE = '55000';
    END IF;
    IF (
        SELECT array_agg(event.event_kind ORDER BY event.ordinal)
        FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id
    ) IS DISTINCT FROM ARRAY['admission', 'start']::text[] THEN
        RAISE EXCEPTION 'raw-output commitment lacks its exact predecessor sequence'
            USING ERRCODE = '55000';
    END IF;
    UPDATE mkso_i06.toolchain_runs SET stage = 'RAW_COMMITTED' WHERE run_id = selected_run_id;
    INSERT INTO mkso_i06.toolchain_audit_events (
        run_id, ordinal, event_kind, actor, commitment_hash
    ) VALUES (
        selected_run_id, 3, 'raw_output_commitment', 'mkso_i06_runner', raw_output_commitment
    );
END
$function$;

CREATE OR REPLACE FUNCTION mkso_i06.commit_cleanup(
    claim_id text,
    profile_hash text,
    context_manifest_hash text,
    cleanup_commitment text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
DECLARE
    selected_run_id bigint;
    selected_stage text;
BEGIN
    IF current_setting('transaction_isolation') <> 'serializable' THEN
        RAISE EXCEPTION 'cleanup commitment requires a serializable transaction'
            USING ERRCODE = '25001';
    END IF;
    IF cleanup_commitment IS NULL OR cleanup_commitment !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid cleanup commitment' USING ERRCODE = '22023';
    END IF;
    SELECT run.run_id, run.stage
    INTO selected_run_id, selected_stage
    FROM mkso_i06.toolchain_runs AS run
    WHERE run.qualification_claim_id = claim_id
      AND run.profile_hash = commit_cleanup.profile_hash
      AND run.context_manifest_hash = commit_cleanup.context_manifest_hash
    FOR UPDATE;
    IF NOT FOUND OR selected_stage <> 'RAW_COMMITTED' THEN
        RAISE EXCEPTION 'cleanup commitment requires RAW_COMMITTED' USING ERRCODE = '55000';
    END IF;
    IF (
        SELECT array_agg(event.event_kind ORDER BY event.ordinal)
        FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id
    ) IS DISTINCT FROM ARRAY['admission', 'start', 'raw_output_commitment']::text[] THEN
        RAISE EXCEPTION 'cleanup commitment lacks its exact predecessor sequence'
            USING ERRCODE = '55000';
    END IF;
    UPDATE mkso_i06.toolchain_runs SET stage = 'CLEANED' WHERE run_id = selected_run_id;
    INSERT INTO mkso_i06.toolchain_audit_events (
        run_id, ordinal, event_kind, actor, commitment_hash
    ) VALUES (selected_run_id, 4, 'cleanup', 'mkso_i06_runner', cleanup_commitment);
END
$function$;

CREATE OR REPLACE FUNCTION mkso_i06.read_toolchain_event_prefix(
    claim_id text,
    profile_hash text,
    context_manifest_hash text
)
RETURNS TABLE (
    run_id bigint,
    ordinal smallint,
    event_kind text,
    actor name,
    commitment_hash text,
    recorded_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
DECLARE
    selected_run_id bigint;
    selected_stage text;
BEGIN
    IF current_setting('transaction_isolation') <> 'serializable' THEN
        RAISE EXCEPTION 'event-prefix read requires a serializable transaction'
            USING ERRCODE = '25001';
    END IF;
    IF claim_id IS NULL OR claim_id !~ '^[A-Za-z][A-Za-z0-9._:-]{0,127}$'
       OR profile_hash IS NULL OR profile_hash !~ '^sha256:[0-9a-f]{64}$'
       OR context_manifest_hash IS NULL
       OR context_manifest_hash !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid event-prefix run key' USING ERRCODE = '22023';
    END IF;

    SELECT run.run_id, run.stage
    INTO selected_run_id, selected_stage
    FROM mkso_i06.toolchain_runs AS run
    WHERE run.qualification_claim_id = claim_id
      AND run.profile_hash = read_toolchain_event_prefix.profile_hash
      AND run.context_manifest_hash = read_toolchain_event_prefix.context_manifest_hash;

    IF NOT FOUND OR selected_stage NOT IN ('CLEANED', 'TERMINAL') THEN
        RAISE EXCEPTION 'event-prefix read requires CLEANED or TERMINAL'
            USING ERRCODE = '55000';
    END IF;
    IF (
        SELECT array_agg(event.event_kind ORDER BY event.ordinal)
        FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id
          AND event.ordinal BETWEEN 1 AND 4
    ) IS DISTINCT FROM ARRAY[
        'admission', 'start', 'raw_output_commitment', 'cleanup'
    ]::text[] OR (
        SELECT array_agg(event.actor::text ORDER BY event.ordinal)
        FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id
          AND event.ordinal BETWEEN 1 AND 4
    ) IS DISTINCT FROM ARRAY[
        'mkso_i06_broker',
        'mkso_i06_runner',
        'mkso_i06_runner',
        'mkso_i06_runner'
    ]::text[] OR (
        SELECT array_agg(event.commitment_hash ORDER BY event.ordinal)
        FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id
          AND event.ordinal BETWEEN 1 AND 2
    ) IS DISTINCT FROM ARRAY[
        read_toolchain_event_prefix.profile_hash,
        read_toolchain_event_prefix.profile_hash
    ]::text[] THEN
        RAISE EXCEPTION 'event-prefix read lacks its exact predecessor sequence'
            USING ERRCODE = '55000';
    END IF;

    RETURN QUERY
    SELECT
        selected_run_id,
        event.ordinal,
        event.event_kind,
        event.actor,
        event.commitment_hash,
        event.recorded_at
    FROM mkso_i06.toolchain_audit_events AS event
    WHERE event.run_id = selected_run_id
      AND event.ordinal BETWEEN 1 AND 4
    ORDER BY event.ordinal;
END
$function$;

CREATE OR REPLACE FUNCTION mkso_i06.retain_toolchain_private_run(
    claim_id text,
    profile_hash text,
    context_manifest_hash text,
    raw_output_manifest_hash text,
    cleanup_observation_hash text,
    requested_postgres_event_prefix_hash text,
    requested_raw_run_hash text,
    requested_retained_manifest_hash text,
    manifest_document bytea,
    blob_roles text[],
    blob_logical_names text[],
    blob_hashes text[],
    blob_sizes bigint[],
    blob_contents bytea[]
)
RETURNS TABLE (
    raw_run_hash text,
    retained_manifest_hash text,
    postgres_event_prefix_hash text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
DECLARE
    selected_run_id bigint;
    selected_stage text;
    blob_count integer;
    blob_index integer;
    role_order integer;
    previous_role_order integer := 0;
    previous_logical_name bytea;
    event_prefix_count integer := 0;
    retained_private mkso_i06.toolchain_private_runs%ROWTYPE;
    retained_blob_roles text[];
    retained_blob_logical_names text[];
    retained_blob_hashes text[];
    retained_blob_sizes bigint[];
    retained_blob_contents bytea[];
BEGIN
    IF current_setting('transaction_isolation') <> 'serializable' THEN
        RAISE EXCEPTION 'private-run retention requires a serializable transaction'
            USING ERRCODE = '25001';
    END IF;
    IF claim_id IS NULL OR claim_id !~ '^[A-Za-z][A-Za-z0-9._:-]{0,127}$'
       OR profile_hash IS NULL OR profile_hash !~ '^sha256:[0-9a-f]{64}$'
       OR context_manifest_hash IS NULL
       OR context_manifest_hash !~ '^sha256:[0-9a-f]{64}$'
       OR raw_output_manifest_hash IS NULL
       OR raw_output_manifest_hash !~ '^sha256:[0-9a-f]{64}$'
       OR cleanup_observation_hash IS NULL
       OR cleanup_observation_hash !~ '^sha256:[0-9a-f]{64}$'
       OR requested_postgres_event_prefix_hash IS NULL
       OR requested_postgres_event_prefix_hash !~ '^sha256:[0-9a-f]{64}$'
       OR requested_raw_run_hash IS NULL
       OR requested_raw_run_hash !~ '^sha256:[0-9a-f]{64}$'
       OR requested_retained_manifest_hash IS NULL
       OR requested_retained_manifest_hash !~ '^sha256:[0-9a-f]{64}$'
       OR manifest_document IS NULL OR octet_length(manifest_document) = 0 THEN
        RAISE EXCEPTION 'invalid private-run scalar or manifest'
            USING ERRCODE = '22023';
    END IF;
    IF requested_retained_manifest_hash <> 'sha256:' || encode(
        sha256(manifest_document), 'hex'
    ) THEN
        RAISE EXCEPTION 'retained manifest hash does not match its exact bytes'
            USING ERRCODE = '22023';
    END IF;

    IF array_ndims(blob_roles) IS DISTINCT FROM 1
       OR array_ndims(blob_logical_names) IS DISTINCT FROM 1
       OR array_ndims(blob_hashes) IS DISTINCT FROM 1
       OR array_ndims(blob_sizes) IS DISTINCT FROM 1
       OR array_ndims(blob_contents) IS DISTINCT FROM 1
       OR array_lower(blob_roles, 1) IS DISTINCT FROM 1
       OR array_lower(blob_logical_names, 1) IS DISTINCT FROM 1
       OR array_lower(blob_hashes, 1) IS DISTINCT FROM 1
       OR array_lower(blob_sizes, 1) IS DISTINCT FROM 1
       OR array_lower(blob_contents, 1) IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'private-run blob arrays must be one-dimensional and one-based'
            USING ERRCODE = '22023';
    END IF;
    blob_count := cardinality(blob_roles);
    IF blob_count = 0
       OR cardinality(blob_logical_names) <> blob_count
       OR cardinality(blob_hashes) <> blob_count
       OR cardinality(blob_sizes) <> blob_count
       OR cardinality(blob_contents) <> blob_count
       OR array_position(blob_roles, NULL) IS NOT NULL
       OR array_position(blob_logical_names, NULL) IS NOT NULL
       OR array_position(blob_hashes, NULL) IS NOT NULL
       OR array_position(blob_sizes, NULL) IS NOT NULL
       OR array_position(blob_contents, NULL) IS NOT NULL THEN
        RAISE EXCEPTION 'private-run blob arrays must be equal, non-empty, and contain no null'
            USING ERRCODE = '22023';
    END IF;

    FOR blob_index IN 1..blob_count LOOP
        role_order := CASE blob_roles[blob_index]
            WHEN 'profile' THEN 1
            WHEN 'context_file' THEN 2
            WHEN 'build_request' THEN 3
            WHEN 'stdout' THEN 4
            WHEN 'stderr' THEN 5
            WHEN 'network_observation' THEN 6
            WHEN 'runtime_observation' THEN 7
            WHEN 'required_output' THEN 8
            WHEN 'raw_output_manifest' THEN 9
            WHEN 'adapter_cleanup_observation' THEN 10
            WHEN 'cleanup_observation' THEN 11
            WHEN 'failure_observation' THEN 12
            WHEN 'postgres_event_prefix' THEN 13
            ELSE 0
        END;
        IF role_order = 0
           OR blob_logical_names[blob_index] = ''
           OR octet_length(blob_logical_names[blob_index])
                <> char_length(blob_logical_names[blob_index])
           OR blob_hashes[blob_index] !~ '^sha256:[0-9a-f]{64}$'
           OR blob_sizes[blob_index] < 0
           OR blob_sizes[blob_index] <> octet_length(blob_contents[blob_index])
           OR blob_hashes[blob_index] <> 'sha256:' || encode(
                sha256(blob_contents[blob_index]), 'hex'
              ) THEN
            RAISE EXCEPTION 'invalid private-run blob at ordinal %', blob_index
                USING ERRCODE = '22023';
        END IF;
        IF role_order < previous_role_order
           OR (
                role_order = previous_role_order
                AND convert_to(blob_logical_names[blob_index], 'UTF8')
                    <= previous_logical_name
           ) THEN
            RAISE EXCEPTION 'private-run blobs are not in canonical role/name order'
                USING ERRCODE = '22023';
        END IF;
        IF blob_roles[blob_index] = 'postgres_event_prefix' THEN
            event_prefix_count := event_prefix_count + 1;
            IF blob_hashes[blob_index] <> requested_postgres_event_prefix_hash
               OR octet_length(blob_contents[blob_index]) = 0 THEN
                RAISE EXCEPTION 'event-prefix blob does not match its requested hash'
                    USING ERRCODE = '22023';
            END IF;
        END IF;
        previous_role_order := role_order;
        previous_logical_name := convert_to(blob_logical_names[blob_index], 'UTF8');
    END LOOP;
    IF event_prefix_count <> 1 THEN
        RAISE EXCEPTION 'private run requires exactly one event-prefix blob'
            USING ERRCODE = '22023';
    END IF;

    SELECT run.run_id, run.stage
    INTO selected_run_id, selected_stage
    FROM mkso_i06.toolchain_runs AS run
    WHERE run.qualification_claim_id = claim_id
      AND run.profile_hash = retain_toolchain_private_run.profile_hash
      AND run.context_manifest_hash = retain_toolchain_private_run.context_manifest_hash
    FOR UPDATE;
    IF NOT FOUND OR selected_stage NOT IN ('CLEANED', 'TERMINAL') THEN
        RAISE EXCEPTION 'private-run retention requires CLEANED or identical retained replay'
            USING ERRCODE = '55000';
    END IF;
    IF (
        SELECT array_agg(event.event_kind ORDER BY event.ordinal)
        FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id
          AND event.ordinal BETWEEN 1 AND 4
    ) IS DISTINCT FROM ARRAY[
        'admission', 'start', 'raw_output_commitment', 'cleanup'
    ]::text[] OR (
        SELECT array_agg(event.actor::text ORDER BY event.ordinal)
        FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id
          AND event.ordinal BETWEEN 1 AND 4
    ) IS DISTINCT FROM ARRAY[
        'mkso_i06_broker',
        'mkso_i06_runner',
        'mkso_i06_runner',
        'mkso_i06_runner'
    ]::text[] OR (
        SELECT array_agg(event.commitment_hash ORDER BY event.ordinal)
        FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id
          AND event.ordinal BETWEEN 1 AND 2
    ) IS DISTINCT FROM ARRAY[
        retain_toolchain_private_run.profile_hash,
        retain_toolchain_private_run.profile_hash
    ]::text[] OR (
        SELECT event.commitment_hash
        FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id AND event.ordinal = 3
    ) IS DISTINCT FROM raw_output_manifest_hash OR (
        SELECT event.commitment_hash
        FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id AND event.ordinal = 4
    ) IS DISTINCT FROM cleanup_observation_hash THEN
        RAISE EXCEPTION 'private-run retention lacks its exact event commitments'
            USING ERRCODE = '55000';
    END IF;

    SELECT private_run.*
    INTO retained_private
    FROM mkso_i06.toolchain_private_runs AS private_run
    WHERE private_run.run_id = selected_run_id;
    IF FOUND THEN
        SELECT
            array_agg(blob.role ORDER BY blob.ordinal),
            array_agg(blob.logical_name ORDER BY blob.ordinal),
            array_agg(blob.content_hash ORDER BY blob.ordinal),
            array_agg(blob.content_size ORDER BY blob.ordinal),
            array_agg(blob.content ORDER BY blob.ordinal)
        INTO
            retained_blob_roles,
            retained_blob_logical_names,
            retained_blob_hashes,
            retained_blob_sizes,
            retained_blob_contents
        FROM mkso_i06.toolchain_private_blobs AS blob
        WHERE blob.run_id = selected_run_id;
        IF retained_private.raw_output_manifest_hash <> raw_output_manifest_hash
           OR retained_private.cleanup_observation_hash <> cleanup_observation_hash
           OR retained_private.postgres_event_prefix_hash
                <> requested_postgres_event_prefix_hash
           OR retained_private.raw_run_hash <> requested_raw_run_hash
           OR retained_private.retained_manifest_hash
                <> requested_retained_manifest_hash
           OR retained_private.manifest_document <> manifest_document
           OR retained_blob_roles IS DISTINCT FROM blob_roles
           OR retained_blob_logical_names IS DISTINCT FROM blob_logical_names
           OR retained_blob_hashes IS DISTINCT FROM blob_hashes
           OR retained_blob_sizes IS DISTINCT FROM blob_sizes
           OR retained_blob_contents IS DISTINCT FROM blob_contents THEN
            RAISE EXCEPTION 'private-run replay differs from retained bytes or identity'
                USING ERRCODE = '23505';
        END IF;
        RETURN QUERY SELECT
            retained_private.raw_run_hash,
            retained_private.retained_manifest_hash,
            retained_private.postgres_event_prefix_hash;
        RETURN;
    END IF;

    IF selected_stage <> 'CLEANED' OR (
        SELECT array_agg(event.event_kind ORDER BY event.ordinal)
        FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id
    ) IS DISTINCT FROM ARRAY[
        'admission', 'start', 'raw_output_commitment', 'cleanup'
    ]::text[] THEN
        RAISE EXCEPTION 'a new private run requires the exact CLEANED prefix'
            USING ERRCODE = '55000';
    END IF;

    INSERT INTO mkso_i06.toolchain_private_runs (
        run_id,
        raw_output_manifest_hash,
        cleanup_observation_hash,
        postgres_event_prefix_hash,
        raw_run_hash,
        retained_manifest_hash,
        manifest_document
    ) VALUES (
        selected_run_id,
        retain_toolchain_private_run.raw_output_manifest_hash,
        retain_toolchain_private_run.cleanup_observation_hash,
        requested_postgres_event_prefix_hash,
        requested_raw_run_hash,
        requested_retained_manifest_hash,
        retain_toolchain_private_run.manifest_document
    );
    INSERT INTO mkso_i06.toolchain_private_blobs (
        run_id, ordinal, role, logical_name, content_hash, content_size, content
    )
    SELECT
        selected_run_id,
        input.ordinal,
        blob_roles[input.ordinal],
        blob_logical_names[input.ordinal],
        blob_hashes[input.ordinal],
        blob_sizes[input.ordinal],
        blob_contents[input.ordinal]
    FROM generate_subscripts(blob_roles, 1) AS input(ordinal)
    ORDER BY input.ordinal;

    RETURN QUERY SELECT
        requested_raw_run_hash,
        requested_retained_manifest_hash,
        requested_postgres_event_prefix_hash;
END
$function$;

CREATE OR REPLACE FUNCTION mkso_i06.commit_terminal_result(
    result_document bytea,
    result_hash text,
    signed_document_hash text,
    claim_id text,
    profile_hash text,
    context_manifest_hash text
)
RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
DECLARE
    selected_run_id bigint;
    selected_stage text;
    retained_result mkso_i06.toolchain_terminal_results%ROWTYPE;
BEGIN
    IF current_setting('transaction_isolation') <> 'serializable' THEN
        RAISE EXCEPTION 'terminal commitment requires a serializable transaction'
            USING ERRCODE = '25001';
    END IF;
    IF result_document IS NULL OR octet_length(result_document) = 0
       OR result_hash IS NULL OR result_hash !~ '^sha256:[0-9a-f]{64}$'
       OR signed_document_hash IS NULL
       OR signed_document_hash !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid terminal commitment' USING ERRCODE = '22023';
    END IF;
    SELECT run.run_id, run.stage
    INTO selected_run_id, selected_stage
    FROM mkso_i06.toolchain_runs AS run
    WHERE run.qualification_claim_id = claim_id
      AND run.profile_hash = commit_terminal_result.profile_hash
      AND run.context_manifest_hash = commit_terminal_result.context_manifest_hash
    FOR UPDATE;
    IF NOT FOUND OR selected_stage NOT IN ('CLEANED', 'TERMINAL') THEN
        RAISE EXCEPTION 'terminal commitment requires CLEANED or identical TERMINAL replay'
            USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM mkso_i06.toolchain_private_runs AS private_run
        WHERE private_run.run_id = selected_run_id
    ) THEN
        RAISE EXCEPTION 'terminal commitment lacks its retained private-run predecessor'
            USING ERRCODE = '55000';
    END IF;
    IF selected_stage = 'TERMINAL' THEN
        SELECT terminal.*
        INTO retained_result
        FROM mkso_i06.toolchain_terminal_results AS terminal
        WHERE terminal.run_id = selected_run_id;
        IF NOT FOUND
           OR retained_result.result_hash <> result_hash
           OR retained_result.signed_document_hash <> signed_document_hash
           OR retained_result.result_document <> result_document THEN
            RAISE EXCEPTION 'terminal replay differs from retained result'
                USING ERRCODE = '23505';
        END IF;
        IF (
            SELECT array_agg(event.event_kind ORDER BY event.ordinal)
            FROM mkso_i06.toolchain_audit_events AS event
            WHERE event.run_id = selected_run_id
        ) IS DISTINCT FROM ARRAY[
            'admission',
            'start',
            'raw_output_commitment',
            'cleanup',
            'terminal_result',
            'signature_commitment'
        ]::text[] THEN
            RAISE EXCEPTION 'terminal replay lacks its exact audit sequence'
                USING ERRCODE = '55000';
        END IF;
        RETURN retained_result.result_document;
    END IF;

    IF (
        SELECT array_agg(event.event_kind ORDER BY event.ordinal)
        FROM mkso_i06.toolchain_audit_events AS event
        WHERE event.run_id = selected_run_id
    ) IS DISTINCT FROM ARRAY[
        'admission', 'start', 'raw_output_commitment', 'cleanup'
    ]::text[] THEN
        RAISE EXCEPTION 'terminal commitment lacks its exact predecessor sequence'
            USING ERRCODE = '55000';
    END IF;

    INSERT INTO mkso_i06.toolchain_audit_events (
        run_id, ordinal, event_kind, actor, commitment_hash
    ) VALUES (selected_run_id, 5, 'terminal_result', 'mkso_i06_runner', result_hash);
    INSERT INTO mkso_i06.toolchain_audit_events (
        run_id, ordinal, event_kind, actor, commitment_hash
    ) VALUES (
        selected_run_id, 6, 'signature_commitment', 'mkso_i06_runner', signed_document_hash
    );
    INSERT INTO mkso_i06.toolchain_terminal_results (
        run_id, result_hash, signed_document_hash, result_document
    ) VALUES (
        selected_run_id,
        commit_terminal_result.result_hash,
        commit_terminal_result.signed_document_hash,
        commit_terminal_result.result_document
    );
    UPDATE mkso_i06.toolchain_runs SET stage = 'TERMINAL' WHERE run_id = selected_run_id;
    RETURN result_document;
END
$function$;

CREATE OR REPLACE FUNCTION mkso_i06.read_toolchain_terminal(
    claim_id text,
    profile_hash text,
    context_manifest_hash text
)
RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
DECLARE
    retained_document bytea;
BEGIN
    IF current_setting('transaction_isolation') <> 'serializable' THEN
        RAISE EXCEPTION 'terminal read requires a serializable transaction'
            USING ERRCODE = '25001';
    END IF;
    SELECT terminal.result_document
    INTO retained_document
    FROM mkso_i06.toolchain_runs AS run
    JOIN mkso_i06.toolchain_terminal_results AS terminal ON terminal.run_id = run.run_id
    WHERE run.qualification_claim_id = claim_id
      AND run.profile_hash = read_toolchain_terminal.profile_hash
      AND run.context_manifest_hash = read_toolchain_terminal.context_manifest_hash
      AND run.stage = 'TERMINAL';
    RETURN retained_document;
END
$function$;

REVOKE ALL ON ALL TABLES IN SCHEMA mkso_i06 FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mkso_i06 FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mkso_i06 FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mkso_i06
    FROM mkso_i06_broker, mkso_i06_runner, mkso_i06_private_human;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mkso_i06
    FROM mkso_i06_broker, mkso_i06_runner, mkso_i06_private_human;

GRANT SELECT ON
    mkso_i06.toolchain_profiles,
    mkso_i06.toolchain_runs,
    mkso_i06.toolchain_audit_events,
    mkso_i06.toolchain_terminal_results,
    mkso_i06.toolchain_private_runs,
    mkso_i06.toolchain_private_blobs
TO mkso_i06_private_human;

GRANT EXECUTE ON FUNCTION mkso_i06.admit_toolchain_run(bytea, text, text, text)
    TO mkso_i06_broker;
GRANT EXECUTE ON FUNCTION mkso_i06.read_toolchain_terminal(text, text, text)
    TO mkso_i06_broker, mkso_i06_private_human;
GRANT EXECUTE ON FUNCTION mkso_i06.start_toolchain_run(text, text, text)
    TO mkso_i06_runner;
GRANT EXECUTE ON FUNCTION mkso_i06.commit_raw_output(text, text, text, text)
    TO mkso_i06_runner;
GRANT EXECUTE ON FUNCTION mkso_i06.commit_cleanup(text, text, text, text)
    TO mkso_i06_runner;
GRANT EXECUTE ON FUNCTION mkso_i06.read_toolchain_event_prefix(text, text, text)
    TO mkso_i06_runner;
GRANT EXECUTE ON FUNCTION mkso_i06.retain_toolchain_private_run(
    text, text, text, text, text, text, text, text, bytea,
    text[], text[], text[], bigint[], bytea[]
) TO mkso_i06_runner;
GRANT EXECUTE ON FUNCTION mkso_i06.commit_terminal_result(bytea, text, text, text, text, text)
    TO mkso_i06_runner;

RESET ROLE;
