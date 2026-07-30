import json
import os
import random
import signal
import ssl
import threading
from pathlib import Path

import paho.mqtt.client as mqtt


# ============================================================
# FUNCIONES DE CONFIGURACIÓN
# ============================================================

def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()

    if not value:
        raise RuntimeError(
            f"Falta la variable obligatoria {name}"
        )

    return value


def env_float(
    name: str,
    default: float,
) -> float:
    return float(
        os.getenv(name, str(default))
    )


def env_int(
    name: str,
    default: int,
) -> int:
    return int(
        os.getenv(name, str(default))
    )


def env_bool(
    name: str,
    default: bool = False,
) -> bool:
    value = os.getenv(
        name,
        str(default),
    ).strip().lower()

    return value in {
        "1",
        "true",
        "yes",
        "on",
    }


def read_secret(
    path: str,
    description: str,
) -> str:
    try:
        value = Path(path).read_text(
            encoding="utf-8"
        ).strip()

    except OSError as error:
        raise RuntimeError(
            f"No se pudo leer {description}: {error}"
        ) from error

    if not value:
        raise RuntimeError(
            f"El archivo de {description} está vacío"
        )

    return value


def clamp(
    value: float,
    minimum: float,
    maximum: float,
) -> float:
    return max(
        minimum,
        min(maximum, value),
    )


# ============================================================
# CONFIGURACIÓN DEL NODO
# ============================================================

DEVICE_ID = required_env("DEVICE_ID")
AREA = required_env("AREA")

MQTT_HOST = required_env("MQTT_HOST")
MQTT_PORT = env_int("MQTT_PORT", 8883)
MQTT_TOPIC = required_env("MQTT_TOPIC")
MQTT_USERNAME = required_env(
    "MQTT_USERNAME"
)

MQTT_CA_CERT = os.getenv(
    "MQTT_CA_CERT",
    "/app/certs/ca.crt",
)

MQTT_PASSWORD_FILE = os.getenv(
    "MQTT_PASSWORD_FILE",
    "/run/secrets/simulator/mqtt_password",
)

API_KEY_FILE = os.getenv(
    "API_KEY_FILE",
    "/run/secrets/simulator/api_key",
)

PUBLISH_INTERVAL = env_float(
    "PUBLISH_INTERVAL",
    10,
)

ANOMALY_PROBABILITY = env_float(
    "ANOMALY_PROBABILITY",
    0.04,
)

ANOMALY_CRITICAL_PROBABILITY = env_float(
    "ANOMALY_CRITICAL_PROBABILITY",
    0.30,
)

ANOMALY_MIN_CYCLES = env_int(
    "ANOMALY_MIN_CYCLES",
    2,
)

ANOMALY_MAX_CYCLES = env_int(
    "ANOMALY_MAX_CYCLES",
    4,
)

FORCE_INITIAL_ANOMALY = env_bool(
    "FORCE_INITIAL_ANOMALY",
    False,
)


# ============================================================
# VALORES BASE POR ÁREA
# ============================================================

BASE_VALUES = {
    "temperature": env_float(
        "BASE_TEMPERATURE",
        24.0,
    ),

    "humidity": env_float(
        "BASE_HUMIDITY",
        55.0,
    ),

    "co2": env_float(
        "BASE_CO2",
        700.0,
    ),
}


# Límites usados para mantener las mediciones normales
# dentro de la zona normal del dashboard.

NORMAL_LIMITS = {
    "temperature": (19.0, 26.5),
    "humidity": (35.0, 68.0),
    "co2": (500.0, 950.0),
}


# Variación máxima por publicación normal.

NORMAL_STEP = {
    "temperature": 0.35,
    "humidity": 1.20,
    "co2": 30.0,
}


current_values = dict(BASE_VALUES)

anomaly_state = {
    "sensor": None,
    "severity": None,
    "remaining": 0,
}

initial_anomaly_pending = (
    FORCE_INITIAL_ANOMALY
)

connected_event = threading.Event()
stop_event = threading.Event()


# ============================================================
# GENERACIÓN DE MEDICIONES NORMALES
# ============================================================

def update_normal_values() -> None:
    for sensor in current_values:
        current = current_values[sensor]
        base = BASE_VALUES[sensor]

        # Fuerza suave para regresar al valor base.
        correction = (
            base - current
        ) * 0.20

        noise = random.uniform(
            -NORMAL_STEP[sensor],
            NORMAL_STEP[sensor],
        )

        minimum, maximum = (
            NORMAL_LIMITS[sensor]
        )

        current_values[sensor] = clamp(
            current + correction + noise,
            minimum,
            maximum,
        )


# ============================================================
# GENERACIÓN DE ANOMALÍAS
# ============================================================

def start_anomaly() -> None:
    sensor = random.choice(
        [
            "temperature",
            "humidity",
            "co2",
        ]
    )

    severity = (
        "critical"
        if random.random()
        < ANOMALY_CRITICAL_PROBABILITY
        else "warning"
    )

    cycles = random.randint(
        ANOMALY_MIN_CYCLES,
        ANOMALY_MAX_CYCLES,
    )

    anomaly_state.update(
        {
            "sensor": sensor,
            "severity": severity,
            "remaining": cycles,
        }
    )

    print(
        "[alarma simulada] "
        f"device={DEVICE_ID} | "
        f"sensor={sensor} | "
        f"nivel={severity} | "
        f"duración={cycles} ciclos"
    )


def maybe_start_anomaly() -> None:
    global initial_anomaly_pending

    if anomaly_state["remaining"] > 0:
        return

    forced = initial_anomaly_pending
    initial_anomaly_pending = False

    if (
        forced
        or random.random()
        < ANOMALY_PROBABILITY
    ):
        start_anomaly()


def alarm_value(
    sensor: str,
    severity: str,
) -> float:
    if sensor == "temperature":
        direction = random.choice(
            ["low", "high"]
        )

        if severity == "warning":
            if direction == "low":
                return random.uniform(
                    16.0,
                    17.5,
                )

            return random.uniform(
                28.0,
                29.5,
            )

        if direction == "low":
            return random.uniform(
                11.0,
                14.0,
            )

        return random.uniform(
            31.0,
            34.0,
        )

    if sensor == "humidity":
        direction = random.choice(
            ["low", "high"]
        )

        if severity == "warning":
            if direction == "low":
                return random.uniform(
                    22.0,
                    28.0,
                )

            return random.uniform(
                72.0,
                78.0,
            )

        if direction == "low":
            return random.uniform(
                8.0,
                18.0,
            )

        return random.uniform(
            82.0,
            92.0,
        )

    if severity == "warning":
        return random.uniform(
            1100.0,
            1450.0,
        )

    return random.uniform(
        1600.0,
        2200.0,
    )


def generate_measurement() -> tuple[
    dict[str, float],
    dict[str, str] | None,
]:
    update_normal_values()
    maybe_start_anomaly()

    alarm_information = None

    if anomaly_state["remaining"] > 0:
        sensor = anomaly_state["sensor"]
        severity = anomaly_state["severity"]

        current_values[sensor] = alarm_value(
            sensor,
            severity,
        )

        alarm_information = {
            "sensor": sensor,
            "severity": severity,
        }

        anomaly_state["remaining"] -= 1

        if anomaly_state["remaining"] == 0:
            print(
                "[alarma finalizada] "
                f"device={DEVICE_ID} | "
                f"sensor={sensor}"
            )

            # La próxima medición regresará
            # a la zona normal.
            current_values[sensor] = (
                BASE_VALUES[sensor]
            )

    measurement = {
        "temperature": round(
            current_values["temperature"],
            1,
        ),

        "humidity": round(
            current_values["humidity"],
            1,
        ),

        "co2": round(
            current_values["co2"],
            0,
        ),
    }

    return measurement, alarm_information


# ============================================================
# CALLBACKS MQTT
# ============================================================

def on_connect(
    client,
    userdata,
    flags,
    reason_code,
    properties,
) -> None:
    if reason_code == 0:
        connected_event.set()

        print(
            "[mqtt] conectado | "
            f"device={DEVICE_ID} | "
            f"broker={MQTT_HOST}:{MQTT_PORT} | "
            "TLS=activo"
        )
    else:
        connected_event.clear()

        print(
            "[mqtt] conexión rechazada | "
            f"device={DEVICE_ID} | "
            f"motivo={reason_code}"
        )


def on_disconnect(
    client,
    userdata,
    disconnect_flags,
    reason_code,
    properties,
) -> None:
    connected_event.clear()

    if not stop_event.is_set():
        print(
            "[mqtt] desconectado | "
            f"device={DEVICE_ID} | "
            f"motivo={reason_code}"
        )


def handle_signal(
    signum,
    frame,
) -> None:
    print(
        f"[sistema] señal {signum}; "
        "cerrando simulador"
    )

    stop_event.set()


# ============================================================
# PUBLICACIÓN
# ============================================================

def publish_loop(
    client: mqtt.Client,
) -> None:
    while not stop_event.is_set():
        if not connected_event.wait(
            timeout=1
        ):
            continue

        try:
            api_key = read_secret(
                API_KEY_FILE,
                "API Key",
            )

            measurement, alarm = (
                generate_measurement()
            )

            payload = {
                "device_id": DEVICE_ID,
                "api_key": api_key,
                "temperature":
                    measurement["temperature"],
                "humidity":
                    measurement["humidity"],
                "co2":
                    measurement["co2"],
            }

            message = json.dumps(
                payload,
                separators=(",", ":"),
            )

            publish_result = client.publish(
                MQTT_TOPIC,
                payload=message,
                qos=1,
                retain=False,
            )

            if (
                publish_result.rc
                != mqtt.MQTT_ERR_SUCCESS
            ):
                raise RuntimeError(
                    "Paho no pudo iniciar "
                    f"la publicación: "
                    f"{publish_result.rc}"
                )

            publish_result.wait_for_publish(
                timeout=10
            )

            if not publish_result.is_published():
                raise TimeoutError(
                    "La publicación no fue "
                    "confirmada en 10 segundos"
                )

            alarm_text = "normal"

            if alarm:
                alarm_text = (
                    f"{alarm['severity']}:"
                    f"{alarm['sensor']}"
                )

            print(
                "[publicado] "
                f"device={DEVICE_ID} | "
                f"área={AREA} | "
                f"T={measurement['temperature']} °C | "
                f"H={measurement['humidity']} % | "
                f"CO2={measurement['co2']} ppm | "
                f"estado={alarm_text}"
            )

        except Exception as error:
            print(
                "[error] "
                f"device={DEVICE_ID} | "
                f"{error}"
            )

        stop_event.wait(
            PUBLISH_INTERVAL
        )


# ============================================================
# INICIO DEL SIMULADOR
# ============================================================

def main() -> None:
    if not (
        0.0
        <= ANOMALY_PROBABILITY
        <= 1.0
    ):
        raise RuntimeError(
            "ANOMALY_PROBABILITY debe "
            "estar entre 0 y 1"
        )

    if (
        ANOMALY_MIN_CYCLES < 1
        or ANOMALY_MAX_CYCLES
        < ANOMALY_MIN_CYCLES
    ):
        raise RuntimeError(
            "Configuración inválida de "
            "duración de anomalías"
        )

    mqtt_password = read_secret(
        MQTT_PASSWORD_FILE,
        "contraseña MQTT",
    )

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"sim-{DEVICE_ID}",
        protocol=mqtt.MQTTv5,
    )

    client.username_pw_set(
        MQTT_USERNAME,
        mqtt_password,
    )

    client.tls_set(
        ca_certs=MQTT_CA_CERT,
        cert_reqs=ssl.CERT_REQUIRED,
    )

    client.tls_insecure_set(False)

    client.reconnect_delay_set(
        min_delay=1,
        max_delay=30,
    )

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect

    print(
        "[inicio] "
        f"device={DEVICE_ID} | "
        f"área={AREA} | "
        f"tópico={MQTT_TOPIC} | "
        f"intervalo={PUBLISH_INTERVAL}s | "
        f"probabilidad_alarma="
        f"{ANOMALY_PROBABILITY}"
    )

    client.connect_async(
        MQTT_HOST,
        MQTT_PORT,
        keepalive=60,
    )

    client.loop_start()

    try:
        publish_loop(client)

    finally:
        try:
            client.disconnect()
        finally:
            client.loop_stop()

        print(
            f"[fin] simulador {DEVICE_ID} detenido"
        )


if __name__ == "__main__":
    signal.signal(
        signal.SIGTERM,
        handle_signal,
    )

    signal.signal(
        signal.SIGINT,
        handle_signal,
    )

    main()
