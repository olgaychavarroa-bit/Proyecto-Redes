CREATE TABLE IF NOT EXISTS devices (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(80) UNIQUE NOT NULL,
    name VARCHAR(120) NOT NULL,
    area VARCHAR(50) NOT NULL,
    api_key_hash VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_area
        CHECK (area IN ('uci', 'urgencias', 'laboratorio')),

    CONSTRAINT valid_device_status
        CHECK (status IN ('active', 'revoked'))
);


CREATE TABLE IF NOT EXISTS telemetry (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(80) NOT NULL,
    temperature DOUBLE PRECISION NOT NULL,
    humidity DOUBLE PRECISION NOT NULL,
    co2 DOUBLE PRECISION NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_telemetry_device
        FOREIGN KEY (device_id)
        REFERENCES devices(device_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,

    CONSTRAINT valid_humidity
        CHECK (humidity >= 0 AND humidity <= 100),

    CONSTRAINT valid_co2
        CHECK (co2 >= 0)
);


CREATE INDEX IF NOT EXISTS idx_telemetry_device_time
ON telemetry(device_id, received_at DESC);


CREATE INDEX IF NOT EXISTS idx_devices_area
ON devices(area);
