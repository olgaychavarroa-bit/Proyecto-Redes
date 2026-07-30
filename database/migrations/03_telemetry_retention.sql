BEGIN;

CREATE INDEX IF NOT EXISTS
idx_telemetry_received_at
ON telemetry(received_at);

ANALYZE telemetry;

COMMIT;
