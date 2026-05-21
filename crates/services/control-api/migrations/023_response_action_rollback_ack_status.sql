-- Allow endpoint rollback acknowledgements to reach the same durable terminal
-- status in the action, delivery, and acknowledgement ledgers.

ALTER TABLE response_actions
    DROP CONSTRAINT IF EXISTS response_actions_status_check;

ALTER TABLE response_actions
    ADD CONSTRAINT response_actions_status_check CHECK (
        status IN (
            'queued',
            'approved',
            'published',
            'acknowledged',
            'rejected',
            'failed',
            'expired',
            'cancelled',
            'rolled_back'
        )
    );

ALTER TABLE response_action_deliveries
    DROP CONSTRAINT IF EXISTS response_action_deliveries_status_check;

ALTER TABLE response_action_deliveries
    ADD CONSTRAINT response_action_deliveries_status_check CHECK (
        status IN (
            'queued',
            'approved',
            'published',
            'acknowledged',
            'rejected',
            'failed',
            'expired',
            'cancelled',
            'rolled_back'
        )
    );

ALTER TABLE response_action_acks
    DROP CONSTRAINT IF EXISTS response_action_acks_status_check;

ALTER TABLE response_action_acks
    ADD CONSTRAINT response_action_acks_status_check CHECK (
        status IN (
            'acknowledged',
            'rejected',
            'failed',
            'expired',
            'rolled_back'
        )
    );
