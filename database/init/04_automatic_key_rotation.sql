BEGIN;

CREATE INDEX IF NOT EXISTS
idx_devices_next_key_rotation
ON devices(next_key_rotation_at)
WHERE status = 'active';

CREATE INDEX IF NOT EXISTS
idx_device_credentials_grace
ON device_credentials(device_id, grace_until)
WHERE status = 'grace';

UPDATE devices
SET next_key_rotation_at =
    COALESCE(
        last_key_rotation_at,
        NOW()
    ) + INTERVAL '30 days'
WHERE status = 'active'
  AND next_key_rotation_at IS NULL;

UPDATE device_credentials AS credential
SET expires_at = device.next_key_rotation_at
FROM devices AS device
WHERE credential.device_id = device.device_id
  AND credential.status = 'current'
  AND credential.expires_at IS NULL;

COMMIT;
