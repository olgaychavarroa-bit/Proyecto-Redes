import os
import socket
import sys
import time


DEPENDENCIES = [
    (
        "PostgreSQL",
        os.environ.get("POSTGRES_HOST", "iot-postgres"),
        int(os.environ.get("POSTGRES_PORT", "5432")),
    ),
    (
        "Mosquitto",
        os.environ.get("MQTT_HOST", "iot-mosquitto"),
        int(os.environ.get("MQTT_PORT", "1883")),
    ),
]

TIMEOUT = int(os.environ.get("WAIT_TIMEOUT", "120"))
INTERVAL = int(os.environ.get("WAIT_INTERVAL", "2"))


def reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection(
            (host, port),
            timeout=2,
        ):
            return True

    except OSError:
        return False


def main():
    deadline = time.time() + TIMEOUT

    while time.time() < deadline:
        unavailable = []

        for name, host, port in DEPENDENCIES:
            if not reachable(host, port):
                unavailable.append(
                    f"{name} ({host}:{port})"
                )

        if not unavailable:
            print("[wait] Mosquitto y PostgreSQL están disponibles")
            os.execvp(
                "python",
                ["python", "-u", "app.py"],
            )

        print(
            "[wait] esperando: "
            + ", ".join(unavailable)
        )

        time.sleep(INTERVAL)

    print("[wait] tiempo de espera agotado")
    sys.exit(1)


if __name__ == "__main__":
    main()
