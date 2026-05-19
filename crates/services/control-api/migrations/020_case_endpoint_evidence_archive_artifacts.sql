DO $$
DECLARE
    artifact_kind_constraint TEXT;
BEGIN
    SELECT conname
    INTO artifact_kind_constraint
    FROM pg_constraint
    WHERE conrelid = 'fleet_case_artifacts'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%artifact_kind%'
    LIMIT 1;

    IF artifact_kind_constraint IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE fleet_case_artifacts DROP CONSTRAINT %I',
            artifact_kind_constraint
        );
    END IF;
END $$;

ALTER TABLE fleet_case_artifacts
    ADD CONSTRAINT fleet_case_artifacts_artifact_kind_check
    CHECK (
        artifact_kind IN (
            'fleet_event',
            'raw_envelope',
            'saved_hunt',
            'hunt_job',
            'detection',
            'response_action',
            'grant',
            'graph_snapshot',
            'endpoint_evidence_archive',
            'note',
            'bundle_export'
        )
    );
