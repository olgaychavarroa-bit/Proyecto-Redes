BEGIN;

-- ============================================================
-- 1. AMPLIACIÓN DE LA TABLA DEVICES
-- ============================================================

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS reactivated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_key_rotation_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS next_key_rotation_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS credential_version INTEGER NOT NULL DEFAULT 1;

-- Consideramos la creación inicial como la primera versión
-- de credencial de los dispositivos existentes.
UPDATE devices
SET last_key_rotation_at = COALESCE(last_key_rotation_at, created_at)
WHERE last_key_rotation_at IS NULL;


-- ============================================================
-- 2. TABLA DE HISTORIAL DE CREDENCIALES
-- ============================================================

CREATE TABLE IF NOT EXISTS device_credentials (
    id BIGSERIAL PRIMARY KEY,

    device_id VARCHAR(100) NOT NULL
        REFERENCES devices(device_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    api_key_hash TEXT NOT NULL,

    credential_version INTEGER NOT NULL,

    status VARCHAR(20) NOT NULL DEFAULT 'current'
        CHECK (
            status IN (
                'current',
                'grace',
                'revoked',
                'expired'
            )
        ),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    grace_until TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT uq_device_credential_version
        UNIQUE (device_id, credential_version),

    CONSTRAINT chk_api_key_hash_sha256
        CHECK (api_key_hash ~ '^[0-9a-f]{64}$'),

    CONSTRAINT chk_credential_version_positive
        CHECK (credential_version > 0)
);

-- Cada dispositivo solo puede tener una credencial marcada
-- como current.
CREATE UNIQUE INDEX IF NOT EXISTS
    uq_device_credentials_current
ON device_credentials(device_id)
WHERE status = 'current';

CREATE INDEX IF NOT EXISTS
    idx_device_credentials_device
ON device_credentials(device_id);

CREATE INDEX IF NOT EXISTS
    idx_device_credentials_status
ON device_credentials(status);

CREATE INDEX IF NOT EXISTS
    idx_device_credentials_expiration
ON device_credentials(expires_at);


-- ============================================================
-- 3. COPIAR LAS CREDENCIALES ACTUALES AL HISTORIAL
-- ============================================================

INSERT INTO device_credentials (
    device_id,
    api_key_hash,
    credential_version,
    status,
    created_at
)
SELECT
    d.device_id,
    d.api_key_hash,
    d.credential_version,
    'current',
    COALESCE(
        d.last_key_rotation_at,
        d.created_at,
        NOW()
    )
FROM devices d
WHERE d.api_key_hash IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM device_credentials dc
      WHERE dc.device_id = d.device_id
  );


-- ============================================================
-- 4. TABLA DE USUARIOS ADMINISTRADORES
-- ============================================================

CREATE TABLE IF NOT EXISTS admin_users (
    id BIGSERIAL PRIMARY KEY,

    username VARCHAR(100) NOT NULL UNIQUE,

    -- Nunca se guardará la contraseña en texto plano.
    password_hash TEXT NOT NULL,

    role VARCHAR(30) NOT NULL DEFAULT 'admin'
        CHECK (role IN ('admin', 'viewer')),

    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS
    idx_admin_users_status
ON admin_users(status);


-- ============================================================
-- 5. TABLA DE AUDITORÍA ADMINISTRATIVA
-- ============================================================

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id BIGSERIAL PRIMARY KEY,

    actor_type VARCHAR(20) NOT NULL DEFAULT 'admin'
        CHECK (actor_type IN ('admin', 'system')),

    actor_id VARCHAR(100),

    action VARCHAR(100) NOT NULL,

    target_device_id VARCHAR(100)
        REFERENCES devices(device_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL,

    result VARCHAR(20) NOT NULL DEFAULT 'success'
        CHECK (result IN ('success', 'failure')),

    details JSONB NOT NULL DEFAULT '{}'::JSONB,

    ip_address INET,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS
    idx_admin_audit_device
ON admin_audit_log(target_device_id);

CREATE INDEX IF NOT EXISTS
    idx_admin_audit_created
ON admin_audit_log(created_at DESC);

CREATE INDEX IF NOT EXISTS
    idx_admin_audit_action
ON admin_audit_log(action);


-- ============================================================
-- 6. ACTUALIZACIÓN AUTOMÁTICA DE updated_at
-- ============================================================

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_devices_updated_at ON devices;

CREATE TRIGGER trg_devices_updated_at
BEFORE UPDATE ON devices
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_admin_users_updated_at ON admin_users;

CREATE TRIGGER trg_admin_users_updated_at
BEFORE UPDATE ON admin_users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();


-- ============================================================
-- 7. ACTUALIZAR last_seen_at CUANDO LLEGA TELEMETRÍA
-- ============================================================

CREATE OR REPLACE FUNCTION update_device_last_seen()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE devices
    SET last_seen_at = COALESCE(NEW.received_at, NOW())
    WHERE device_id = NEW.device_id;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS
    trg_telemetry_update_last_seen
ON telemetry;

CREATE TRIGGER trg_telemetry_update_last_seen
AFTER INSERT ON telemetry
FOR EACH ROW
EXECUTE FUNCTION update_device_last_seen();


-- Cargar la última fecha de los registros que ya existían.
UPDATE devices d
SET last_seen_at = latest.last_seen_at
FROM (
    SELECT
        device_id,
        MAX(received_at) AS last_seen_at
    FROM telemetry
    GROUP BY device_id
) AS latest
WHERE d.device_id = latest.device_id
  AND (
      d.last_seen_at IS NULL
      OR d.last_seen_at < latest.last_seen_at
  );


-- ============================================================
-- 8. ÍNDICES ADICIONALES
-- ============================================================

CREATE INDEX IF NOT EXISTS
    idx_devices_last_seen
ON devices(last_seen_at);

CREATE INDEX IF NOT EXISTS
    idx_devices_status
ON devices(status);

CREATE INDEX IF NOT EXISTS
    idx_devices_area
ON devices(area);


-- ============================================================
-- 9. VISTA DE DISPOSITIVOS PARA EL DASHBOARD GENERAL
-- ============================================================

CREATE OR REPLACE VIEW public_device_overview AS
SELECT
    d.id,
    d.device_id,
    d.name,
    d.area,
    d.status,
    d.created_at,
    d.updated_at,
    d.last_seen_at
FROM devices d;


-- ============================================================
-- 10. VISTA PARA EL PANEL ADMINISTRATIVO
-- ============================================================

CREATE OR REPLACE VIEW admin_device_overview AS
SELECT
    d.id,
    d.device_id,
    d.name,
    d.area,
    d.status,
    d.created_at,
    d.updated_at,
    d.last_seen_at,
    d.revoked_at,
    d.reactivated_at,
    d.credential_version,
    d.last_key_rotation_at,
    d.next_key_rotation_at,

    dc.status AS credential_status,

    -- Solo muestra una huella parcial del hash.
    RIGHT(
        COALESCE(dc.api_key_hash, d.api_key_hash),
        12
    ) AS hash_fingerprint,

    dc.created_at AS credential_created_at,
    dc.expires_at AS credential_expires_at,
    dc.grace_until AS credential_grace_until

FROM devices d

LEFT JOIN device_credentials dc
    ON dc.device_id = d.device_id
   AND dc.status = 'current';


COMMIT;
