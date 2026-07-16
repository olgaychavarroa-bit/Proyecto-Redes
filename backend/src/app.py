import hashlib
import hmac
import json
import math
import os
import secrets
from typing import Any

import paho.mqtt.client as mqtt
import psycopg2
from flask import Flask, jsonify, request
from psycopg2.extras import RealDictCursor


# ============================================================
# CONFIGURACIÓN MEDIANTE VARIABLES DE ENTORNO
# ============================================================

MQTT_HOST = os.environ["MQTT_HOST"]
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USER = os.environ["MQTT_USER"]
MQTT_PASSWORD = os.environ["MQTT_PASSWORD"]
MQTT_TOPIC = os.environ.get("MQTT_TOPIC", "hospital/+/telemetry")

POSTGRES_HOST = os.environ["POSTGRES_HOST"]
POSTGRES_PORT = int(os.environ.get("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.environ["POSTGRES_DB"]
POSTGRES_USER = os.environ["POSTGRES_USER"]
POSTGRES_PASSWORD = os.environ["POSTGRES_PASSWORD"]

BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "5000"))

VALID_AREAS = {"uci", "urgencias", "laboratorio"}

app = Flask(__name__)
mqtt_client: mqtt.Client | None = None


# ============================================================
# FUNCIONES DE BASE DE DATOS
# ============================================================

def get_db_connection():
    """Abre una conexión nueva con PostgreSQL."""
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
        connect_timeout=5,
    )


# ============================================================
# FUNCIONES PARA API KEYS
# ============================================================

def generate_api_key() -> str:
    """Genera una API Key aleatoria y difícil de predecir."""
    return secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    """Convierte una API Key en un hash SHA-256."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def verify_api_key(api_key: str, stored_hash: str) -> bool:
    """Compara de forma segura la clave recibida con el hash guardado."""
    received_hash = hash_api_key(api_key)
    return hmac.compare_digest(received_hash, stored_hash)


# ============================================================
# VALIDACIÓN DE TELEMETRÍA
# ============================================================

def topic_area(topic: str) -> str | None:
    """
    Extrae el área desde un tópico como:
    hospital/uci/telemetry
    """
    parts = topic.strip("/").lower().split("/")

    if len(parts) != 3:
        return None

    if parts[0] != "hospital" or parts[2] != "telemetry":
        return None

    if parts[1] not in VALID_AREAS:
        return None

    return parts[1]


def parse_number(value: Any, field_name: str) -> float:
    """Convierte un valor a número y rechaza valores no válidos."""
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} debe ser numérico") from exc

    if not math.isfinite(number):
        raise ValueError(f"{field_name} no es un valor finito")

    return number


def validate_environmental_values(
    temperature: float,
    humidity: float,
    co2: float,
) -> None:
    """
    Valida límites técnicos generales.

    Estos no son los rangos clínicos de alerta del dashboard.
    Solo evitan valores imposibles o claramente inválidos.
    """
    if not -10 <= temperature <= 60:
        raise ValueError("temperature está fuera del rango técnico permitido")

    if not 0 <= humidity <= 100:
        raise ValueError("humidity debe estar entre 0 y 100")

    if not 0 <= co2 <= 10000:
        raise ValueError("co2 está fuera del rango técnico permitido")


# ============================================================
# API REST
# ============================================================

@app.get("/health")
def health():
    """Comprueba el estado del backend, PostgreSQL y MQTT."""
    database_ok = False

    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                database_ok = cur.fetchone()[0] == 1
        finally:
            conn.close()
    except Exception:
        database_ok = False

    mqtt_ok = bool(mqtt_client and mqtt_client.is_connected())

    status = "ok" if database_ok and mqtt_ok else "degraded"

    return jsonify(
        {
            "status": status,
            "database": database_ok,
            "mqtt": mqtt_ok,
        }
    ), 200 if database_ok else 503


@app.post("/api/v1/devices")
def register_device():
    """
    Registra un nodo y genera una API Key.

    La API Key completa se devuelve una sola vez.
    En PostgreSQL se almacena únicamente su hash.
    """
    payload = request.get_json(silent=True) or {}

    device_id = str(payload.get("device_id", "")).strip()
    name = str(payload.get("name", "")).strip()
    area = str(payload.get("area", "")).strip().lower()

    if not device_id or not name or not area:
        return jsonify(
            {
                "error": "device_id, name y area son obligatorios"
            }
        ), 400

    if area not in VALID_AREAS:
        return jsonify(
            {
                "error": "area debe ser uci, urgencias o laboratorio"
            }
        ), 400

    api_key = generate_api_key()
    api_key_hash = hash_api_key(api_key)

    conn = get_db_connection()

    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO devices
                        (device_id, name, area, api_key_hash, status)
                    VALUES
                        (%s, %s, %s, %s, 'active')
                    ON CONFLICT (device_id) DO NOTHING
                    RETURNING
                        device_id, name, area, status, created_at;
                    """,
                    (device_id, name, area, api_key_hash),
                )

                device = cur.fetchone()

                if device is None:
                    return jsonify(
                        {
                            "error": "El device_id ya está registrado"
                        }
                    ), 409

        response = dict(device)
        response["api_key"] = api_key
        response["warning"] = (
            "Guarde esta API Key. No volverá a mostrarse."
        )

        return jsonify(response), 201

    finally:
        conn.close()


@app.get("/api/v1/devices")
def list_devices():
    """Lista los dispositivos sin mostrar los hashes de sus claves."""
    conn = get_db_connection()

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    device_id,
                    name,
                    area,
                    status,
                    created_at
                FROM devices
                ORDER BY created_at ASC;
                """
            )

            devices = [dict(row) for row in cur.fetchall()]

        return jsonify(devices)

    finally:
        conn.close()


@app.patch("/api/v1/devices/<device_id>/revoke")
def revoke_device(device_id: str):
    """Inhabilita un dispositivo y su API Key."""
    conn = get_db_connection()

    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    UPDATE devices
                    SET status = 'revoked'
                    WHERE device_id = %s
                    RETURNING device_id, name, area, status;
                    """,
                    (device_id,),
                )

                device = cur.fetchone()

                if device is None:
                    return jsonify(
                        {
                            "error": "Dispositivo no encontrado"
                        }
                    ), 404

        return jsonify(dict(device))

    finally:
        conn.close()


@app.post("/api/v1/devices/<device_id>/rotate")
def rotate_device_key(device_id: str):
    """
    Genera una API Key nueva.

    La clave anterior deja de funcionar.
    En esta versión, la rotación también deja el dispositivo activo.
    """
    new_api_key = generate_api_key()
    new_hash = hash_api_key(new_api_key)

    conn = get_db_connection()

    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    UPDATE devices
                    SET
                        api_key_hash = %s,
                        status = 'active'
                    WHERE device_id = %s
                    RETURNING device_id, name, area, status;
                    """,
                    (new_hash, device_id),
                )

                device = cur.fetchone()

                if device is None:
                    return jsonify(
                        {
                            "error": "Dispositivo no encontrado"
                        }
                    ), 404

        response = dict(device)
        response["api_key"] = new_api_key
        response["warning"] = (
            "Guarde la nueva API Key. La anterior ya no funciona."
        )

        return jsonify(response)

    finally:
        conn.close()


@app.get("/api/v1/telemetry")
def list_telemetry():
    """Consulta el histórico de telemetría."""
    device_id = request.args.get("device_id")
    area = request.args.get("area")

    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        return jsonify({"error": "limit debe ser numérico"}), 400

    limit = max(1, min(limit, 500))

    conditions = []
    parameters: list[Any] = []

    if device_id:
        conditions.append("t.device_id = %s")
        parameters.append(device_id)

    if area:
        area = area.lower()

        if area not in VALID_AREAS:
            return jsonify(
                {
                    "error": "area debe ser uci, urgencias o laboratorio"
                }
            ), 400

        conditions.append("d.area = %s")
        parameters.append(area)

    where_clause = ""

    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    parameters.append(limit)

    conn = get_db_connection()

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT
                    t.id,
                    t.device_id,
                    d.name,
                    d.area,
                    t.temperature,
                    t.humidity,
                    t.co2,
                    t.received_at
                FROM telemetry AS t
                INNER JOIN devices AS d
                    ON d.device_id = t.device_id
                {where_clause}
                ORDER BY t.received_at DESC
                LIMIT %s;
                """,
                parameters,
            )

            rows = [dict(row) for row in cur.fetchall()]

        return jsonify(rows)

    finally:
        conn.close()


@app.get("/api/v1/telemetry/latest")
def latest_telemetry():
    """Devuelve la última lectura registrada de cada dispositivo."""
    conn = get_db_connection()

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT DISTINCT ON (d.device_id)
                    d.device_id,
                    d.name,
                    d.area,
                    d.status,
                    t.temperature,
                    t.humidity,
                    t.co2,
                    t.received_at
                FROM devices AS d
                LEFT JOIN telemetry AS t
                    ON t.device_id = d.device_id
                ORDER BY
                    d.device_id,
                    t.received_at DESC NULLS LAST;
                """
            )

            rows = [dict(row) for row in cur.fetchall()]

        return jsonify(rows)

    finally:
        conn.close()


# ============================================================
# CONSUMIDOR MQTT
# ============================================================

def on_connect(
    client,
    userdata,
    flags,
    reason_code,
    properties,
):
    """Se ejecuta cuando el backend se conecta con Mosquitto."""
    print(
        f"[mqtt] conectado a {MQTT_HOST}:{MQTT_PORT}; "
        f"suscripción: {MQTT_TOPIC}"
    )

    client.subscribe(MQTT_TOPIC, qos=1)


def on_disconnect(
    client,
    userdata,
    disconnect_flags,
    reason_code,
    properties,
):
    print(f"[mqtt] desconectado; motivo: {reason_code}")


def on_message(client, userdata, message):
    """
    Recibe un mensaje MQTT, valida el nodo y guarda la telemetría.
    """
    area_from_topic = topic_area(message.topic)

    if area_from_topic is None:
        print(f"[rechazado] tópico no permitido: {message.topic}")
        return

    try:
        payload = json.loads(message.payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        print(f"[rechazado] JSON inválido en {message.topic}")
        return

    if not isinstance(payload, dict):
        print("[rechazado] el JSON debe ser un objeto")
        return

    device_id = str(payload.get("device_id", "")).strip()
    api_key = str(payload.get("api_key", "")).strip()

    if not device_id or not api_key:
        print("[rechazado] faltan device_id o api_key")
        return

    try:
        temperature = parse_number(
            payload.get("temperature"),
            "temperature",
        )
        humidity = parse_number(
            payload.get("humidity"),
            "humidity",
        )
        co2 = parse_number(
            payload.get("co2"),
            "co2",
        )

        validate_environmental_values(
            temperature,
            humidity,
            co2,
        )

    except ValueError as error:
        print(f"[rechazado] {device_id}: {error}")
        return

    conn = None

    try:
        conn = get_db_connection()

        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT
                        device_id,
                        area,
                        api_key_hash,
                        status
                    FROM devices
                    WHERE device_id = %s;
                    """,
                    (device_id,),
                )

                device = cur.fetchone()

                if device is None:
                    print(
                        f"[rechazado] dispositivo inexistente: {device_id}"
                    )
                    return

                if device["status"] != "active":
                    print(
                        f"[rechazado] dispositivo revocado: {device_id}"
                    )
                    return

                if device["area"] != area_from_topic:
                    print(
                        f"[rechazado] {device_id} no corresponde "
                        f"al tópico {message.topic}"
                    )
                    return

                if not verify_api_key(
                    api_key,
                    device["api_key_hash"],
                ):
                    print(
                        f"[rechazado] API Key incorrecta: {device_id}"
                    )
                    return

                cur.execute(
                    """
                    INSERT INTO telemetry
                        (
                            device_id,
                            temperature,
                            humidity,
                            co2
                        )
                    VALUES
                        (%s, %s, %s, %s)
                    RETURNING id, received_at;
                    """,
                    (
                        device_id,
                        temperature,
                        humidity,
                        co2,
                    ),
                )

                inserted = cur.fetchone()

        print(
            f"[guardado] {device_id} | "
            f"T={temperature} °C | "
            f"H={humidity} % | "
            f"CO2={co2} ppm | "
            f"id={inserted['id']}"
        )

    except Exception as error:
        print(f"[error de base de datos] {error}")

    finally:
        if conn is not None:
            conn.close()


def start_mqtt():
    """Configura e inicia el cliente MQTT en segundo plano."""
    global mqtt_client

    mqtt_client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="iot-backend",
        protocol=mqtt.MQTTv5,
    )

    mqtt_client.username_pw_set(
        MQTT_USER,
        MQTT_PASSWORD,
    )

    mqtt_client.reconnect_delay_set(
        min_delay=1,
        max_delay=30,
    )

    mqtt_client.on_connect = on_connect
    mqtt_client.on_disconnect = on_disconnect
    mqtt_client.on_message = on_message

    mqtt_client.connect_async(
        MQTT_HOST,
        MQTT_PORT,
        keepalive=60,
    )

    mqtt_client.loop_start()


# ============================================================
# INICIO DEL PROGRAMA
# ============================================================

if __name__ == "__main__":
    start_mqtt()

    app.run(
        host="0.0.0.0",
        port=BACKEND_PORT,
        debug=False,
        use_reloader=False,
        threaded=True,
    )
