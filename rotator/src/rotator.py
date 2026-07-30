import argparse
import json
import os
import secrets
import signal
import time
import urllib.error
import urllib.request
from pathlib import Path


BACKEND_URL = os.environ.get(
    "BACKEND_URL",
    "http://iot-backend:5000",
).rstrip("/")

ROTATOR_TOKEN_FILE = os.environ.get(
    "ROTATOR_TOKEN_FILE",
    "/run/secrets/rotator/service_token",
)

ROTATOR_CHECK_INTERVAL = max(
    60,
    int(
        os.environ.get(
            "ROTATOR_CHECK_INTERVAL",
            "3600",
        )
    ),
)

ROTATOR_DEVICE_MAP = os.environ.get(
    "ROTATOR_DEVICE_MAP",
    (
        "iot_uci_01=uci,"
        "iot_urgencias_01=urgencias,"
        "iot_laboratorio_01=laboratorio"
    ),
)

KEY_ROOT = Path(
    os.environ.get(
        "KEY_ROOT",
        "/keys",
    )
)

stop_requested = False


def parse_device_map() -> dict[str, str]:
    mapping = {}

    for item in ROTATOR_DEVICE_MAP.split(","):
        item = item.strip()

        if not item:
            continue

        if "=" not in item:
            raise RuntimeError(
                "ROTATOR_DEVICE_MAP inválido"
            )

        device_id, area = item.split(
            "=",
            1,
        )

        mapping[
            device_id.strip()
        ] = area.strip()

    return mapping


DEVICE_MAP = parse_device_map()


def read_token() -> str:
    token = Path(
        ROTATOR_TOKEN_FILE
    ).read_text(
        encoding="utf-8"
    ).strip()

    if not token:
        raise RuntimeError(
            "El token interno está vacío"
        )

    return token


def request_json(
    path: str,
    method: str = "GET",
    payload=None,
):
    body = None

    headers = {
        "Accept": "application/json",
        "X-Rotator-Token": read_token(),
    }

    if payload is not None:
        body = json.dumps(
            payload
        ).encode("utf-8")

        headers["Content-Type"] = (
            "application/json"
        )

    request_object = urllib.request.Request(
        BACKEND_URL + path,
        data=body,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(
            request_object,
            timeout=15,
        ) as response:
            content = response.read()

    except urllib.error.HTTPError as error:
        content = error.read()

        try:
            data = json.loads(
                content.decode("utf-8")
            )

            message = (
                data.get("error")
                or data.get("message")
                or str(data)
            )

        except Exception:
            message = content.decode(
                "utf-8",
                errors="replace",
            )

        raise RuntimeError(
            f"HTTP {error.code}: {message}"
        ) from error

    return (
        json.loads(
            content.decode("utf-8")
        )
        if content
        else {}
    )


def active_key_path(
    device_id: str,
) -> Path:
    area = DEVICE_MAP.get(
        device_id
    )

    if not area:
        raise RuntimeError(
            "No existe un área configurada "
            f"para {device_id}"
        )

    return (
        KEY_ROOT
        / area
        / "api_key"
    )


def pending_key_path(
    device_id: str,
) -> Path:
    return active_key_path(
        device_id
    ).with_name(
        "api_key.pending"
    )


def write_private_file(
    path: Path,
    value: str,
):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = path.with_name(
        path.name + ".tmp"
    )

    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC,
        0o600,
    )

    with os.fdopen(
        descriptor,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(value)
        file.flush()
        os.fsync(
            file.fileno()
        )

    os.chmod(
        temporary,
        0o600,
    )

    os.replace(
        temporary,
        path,
    )


def prepare_pending_key(
    device_id: str,
) -> tuple[Path, str]:
    pending = pending_key_path(
        device_id
    )

    if pending.exists():
        key = pending.read_text(
            encoding="utf-8"
        ).strip()

        if not key:
            raise RuntimeError(
                f"Archivo pendiente vacío: "
                f"{pending}"
            )

        return pending, key

    key = secrets.token_urlsafe(32)

    write_private_file(
        pending,
        key,
    )

    return pending, key


def rotate_device(
    device_id: str,
    force: bool,
):
    pending, new_key = (
        prepare_pending_key(
            device_id
        )
    )

    result = request_json(
        "/api/v1/internal/"
        "key-rotation/activate",
        method="POST",
        payload={
            "device_id": device_id,
            "api_key": new_key,
            "force": force,
        },
    )

    destination = active_key_path(
        device_id
    )

    os.replace(
        pending,
        destination,
    )

    os.chmod(
        destination,
        0o600,
    )

    print(
        "[rotación completada] "
        f"device={device_id} | "
        f"versión="
        f"{result.get('credential_version')} | "
        f"idempotente="
        f"{result.get('idempotent', False)}"
    )


def recover_pending_files():
    for device_id in DEVICE_MAP:
        pending = pending_key_path(
            device_id
        )

        if not pending.exists():
            continue

        print(
            "[recuperación] clave pendiente | "
            f"device={device_id}"
        )

        try:
            rotate_device(
                device_id,
                force=False,
            )

        except Exception as error:
            print(
                "[recuperación pendiente] "
                f"device={device_id} | "
                f"{error}"
            )


def run_due_rotations():
    recover_pending_files()

    result = request_json(
        "/api/v1/internal/"
        "key-rotation/due"
    )

    devices = result.get(
        "devices",
        [],
    )

    if not devices:
        print(
            "[rotador] no hay rotaciones "
            "pendientes"
        )

        return

    for device in devices:
        device_id = device.get(
            "device_id"
        )

        if device_id not in DEVICE_MAP:
            print(
                "[omitido] dispositivo no "
                f"configurado: {device_id}"
            )

            continue

        try:
            rotate_device(
                device_id,
                force=False,
            )

        except Exception as error:
            print(
                "[error de rotación] "
                f"device={device_id} | "
                f"{error}"
            )


def handle_signal(
    signum,
    frame,
):
    global stop_requested

    stop_requested = True

    print(
        f"[rotador] señal {signum}; "
        "cerrando"
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--once",
        action="store_true",
    )

    parser.add_argument(
        "--force-device",
    )

    args = parser.parse_args()

    print(
        "[rotador iniciado] "
        f"backend={BACKEND_URL} | "
        f"intervalo="
        f"{ROTATOR_CHECK_INTERVAL}s"
    )

    if args.force_device:
        if (
            args.force_device
            not in DEVICE_MAP
        ):
            raise RuntimeError(
                "Dispositivo forzado "
                "no configurado"
            )

        rotate_device(
            args.force_device,
            force=True,
        )

        if args.once:
            return

    elif args.once:
        run_due_rotations()
        return

    while not stop_requested:
        try:
            run_due_rotations()

        except Exception as error:
            print(
                "[error del rotador] "
                f"{error}"
            )

        for _ in range(
            ROTATOR_CHECK_INTERVAL
        ):
            if stop_requested:
                break

            time.sleep(1)


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
