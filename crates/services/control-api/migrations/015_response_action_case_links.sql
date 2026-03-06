CREATE UNIQUE INDEX IF NOT EXISTS idx_fleet_cases_tenant_id
ON fleet_cases(tenant_id, id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'response_actions_case_tenant_fk'
    ) THEN
        ALTER TABLE response_actions
            ADD CONSTRAINT response_actions_case_tenant_fk
            FOREIGN KEY (tenant_id, case_id)
            REFERENCES fleet_cases(tenant_id, id)
            ON DELETE SET NULL;
    END IF;
END $$;
