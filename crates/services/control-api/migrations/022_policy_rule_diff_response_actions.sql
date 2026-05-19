-- Allow policy proposal fleet rule-diff validation to use the durable
-- response-action delivery and acknowledgement ledger.

ALTER TABLE response_actions
    DROP CONSTRAINT IF EXISTS response_actions_action_type_check;

ALTER TABLE response_actions
    ADD CONSTRAINT response_actions_action_type_check CHECK (
        action_type IN (
            'transition_posture',
            'request_policy_reload',
            'terminate_session',
            'kill_switch',
            'quarantine_principal',
            'revoke_grant',
            'revoke_principal',
            'policy_rule_diff_validation'
        )
    );
