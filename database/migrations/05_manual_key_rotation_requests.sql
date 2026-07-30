BEGIN;

CREATE TABLE IF NOT EXISTS api_key_rotation_requests (
    id BIGSERIAL PRIMARY KEY,

    device_id VARCHAR(80) NOT NULL
        REFERENCES devices(device_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    action VARCHAR(20) NOT NULL
        CHECK (
            action IN (
                'rotate',
                'activate'
            )
        ),

    source VARCHAR(20) NOT NULL
        DEFAULT 'admin'
        CHECK (
            source IN (
                'admin',
                'system'
            )
        ),

    status VARCHAR(20) NOT NULL
        DEFAULT 'pending'
        CHECK (
            status IN (
                'pending',
                'completed',
                'failed',
                'cancelled'
            )
        ),

    requested_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),

    backend_installed_at TIMESTAMPTZ,

    completed_at TIMESTAMPTZ,

    credential_version INTEGER,

    attempts INTEGER NOT NULL DEFAULT 0,

    last_error TEXT,

    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS
idx_key_rotation_requests_status
ON api_key_rotation_requests(
    status,
    requested_at
);

CREATE INDEX IF NOT EXISTS
idx_key_rotation_requests_device
ON api_key_rotation_requests(
    device_id,
    requested_at DESC
);

CREATE UNIQUE INDEX IF NOT EXISTS
uq_key_rotation_request_pending
ON api_key_rotation_requests(device_id)
WHERE status = 'pending';

COMMIT;
