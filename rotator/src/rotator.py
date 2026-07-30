import argparse
import json
import os
import secrets
import signal
import shutil
import subprocess
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

ROTATOR_REQUEST_INTERVAL = max(
    2,
    int(
        os.environ.get(
            "ROTATOR_REQUEST_INTERVAL",
            "5",
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

BROKER_AUTH_FILE = os.environ.get(
    "BROKER_AUTH_FILE",
    "",
).strip()

BROKER_AUTH_PATH = (
    Path(BROKER_AUTH_FILE)
    if BROKER_AUTH_FILE
    else None
)

BROKER_AUTH_DEVICE_MAP = os.environ.get(
    "BROKER_AUTH_DEVICE_MAP",
    "",
).strip()

stop_requested = False


def parse_device_map():
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


def parse_broker_auth_map():
    mapping = {}

    if not BROKER_AUTH_DEVICE_MAP:
        return mapping

    for item in BROKER_AUTH_DEVICE_MAP.split(","):
        item = item.strip()

        if not item:
            continue

        if "=" not in item:
            raise RuntimeError(
                "BROKER_AUTH_DEVICE_MAP inválido"
            )

        device_id, username = item.split(
            "=",
            1,
        )

        device_id = device_id.strip()
        username = username.strip()

        if not device_id or not username:
            raise RuntimeError(
                "BROKER_AUTH_DEVICE_MAP inválido"
            )

        mapping[device_id] = username

    return mapping


BROKER_AUTH_MAP = parse_broker_auth_map()



def read_token():
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
    path,
    method="GET",
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


def active_key_path(device_id):
    area = DEVICE_MAP.get(device_id)

    if not area:
        raise RuntimeError(
            "No existe área configurada para "
            f"{device_id}"
        )

    return KEY_ROOT / area / "api_key"


def pending_key_path(device_id):
    return active_key_path(
        device_id
    ).with_name(
        "api_key.pending"
    )


def pending_metadata_path(device_id):
    return active_key_path(
        device_id
    ).with_name(
        "api_key.pending.json"
    )


def write_private_file(path, value):
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
        os.fsync(file.fileno())

    os.chmod(
        temporary,
        0o600,
    )

    os.replace(
        temporary,
        path,
    )


def write_pending_metadata(
    device_id,
    metadata,
):
    write_private_file(
        pending_metadata_path(device_id),
        json.dumps(
            metadata,
            separators=(",", ":"),
        ),
    )


def prepare_pending_key(
    device_id,
    action,
    request_id,
    force,
):
    pending = pending_key_path(
        device_id
    )

    metadata_path = (
        pending_metadata_path(
            device_id
        )
    )

    expected_metadata = {
        "device_id": device_id,
        "action": action,
        "request_id": request_id,
        "force": force,
    }

    if pending.exists():
        key = pending.read_text(
            encoding="utf-8"
        ).strip()

        if not key:
            raise RuntimeError(
                f"Archivo pendiente vacío: {pending}"
            )

        if metadata_path.exists():
            stored_metadata = json.loads(
                metadata_path.read_text(
                    encoding="utf-8"
                )
            )

            if (
                stored_metadata.get("device_id")
                != device_id
            ):
                raise RuntimeError(
                    "Metadatos pendientes inválidos"
                )

            expected_metadata = (
                stored_metadata
            )

        else:
            write_pending_metadata(
                device_id,
                expected_metadata,
            )

        return (
            pending,
            key,
            expected_metadata,
        )

    key = secrets.token_urlsafe(32)

    write_private_file(
        pending,
        key,
    )

    write_pending_metadata(
        device_id,
        expected_metadata,
    )

    return (
        pending,
        key,
        expected_metadata,
    )


def sync_broker_password(
    device_id,
    new_key,
):
    username = BROKER_AUTH_MAP.get(
        device_id
    )

    # Solo actúa sobre dispositivos incluidos
    # en el piloto del broker.
    if not username:
        return False

    if BROKER_AUTH_PATH is None:
        raise RuntimeError(
            "BROKER_AUTH_FILE no está configurado"
        )

    if not BROKER_AUTH_PATH.exists():
        raise RuntimeError(
            "No existe el archivo MQTT: "
            f"{BROKER_AUTH_PATH}"
        )

    temporary = BROKER_AUTH_PATH.with_name(
        BROKER_AUTH_PATH.name
        + f".tmp.{os.getpid()}"
    )

    shutil.copy2(
        BROKER_AUTH_PATH,
        temporary,
    )

    try:
        completed = subprocess.run(
            [
                "mosquitto_passwd",
                "-b",
                str(temporary),
                username,
                new_key,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
            check=False,
        )

        if completed.returncode != 0:
            message = (
                completed.stderr.strip()
                or completed.stdout.strip()
                or "mosquitto_passwd falló"
            )

            raise RuntimeError(
                "No se pudo actualizar "
                f"la credencial MQTT: {message}"
            )

        os.chmod(
            temporary,
            0o644,
        )

        os.replace(
            temporary,
            BROKER_AUTH_PATH,
        )

    finally:
        if temporary.exists():
            temporary.unlink()

    print(
        "[broker actualizado] "
        f"device={device_id} | "
        f"usuario={username}",
        flush=True,
    )

    return True


BROKER_PLACEHOLDER_USER = (
    "__credencial_interna_deshabilitada__"
)


def broker_usernames(path):
    usernames = set()

    for line in path.read_text(
        encoding="utf-8"
    ).splitlines():
        if ":" not in line:
            continue

        username = line.split(
            ":",
            1,
        )[0].strip()

        if username:
            usernames.add(username)

    return usernames


def run_mosquitto_passwd(arguments):
    completed = subprocess.run(
        [
            "mosquitto_passwd",
            *arguments,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=False,
    )

    if completed.returncode != 0:
        message = (
            completed.stderr.strip()
            or completed.stdout.strip()
            or "mosquitto_passwd falló"
        )

        raise RuntimeError(message)


def remove_broker_user(device_id):
    username = BROKER_AUTH_MAP.get(
        device_id
    )

    if not username:
        return False

    if BROKER_AUTH_PATH is None:
        raise RuntimeError(
            "BROKER_AUTH_FILE no está configurado"
        )

    if not BROKER_AUTH_PATH.exists():
        raise RuntimeError(
            "No existe el archivo MQTT: "
            f"{BROKER_AUTH_PATH}"
        )

    current_users = broker_usernames(
        BROKER_AUTH_PATH
    )

    if username not in current_users:
        return False

    temporary = BROKER_AUTH_PATH.with_name(
        BROKER_AUTH_PATH.name
        + f".revoke.{os.getpid()}"
    )

    shutil.copy2(
        BROKER_AUTH_PATH,
        temporary,
    )

    try:
        run_mosquitto_passwd(
            [
                "-D",
                str(temporary),
                username,
            ]
        )

        remaining_users = broker_usernames(
            temporary
        )

        # Evita un password_file completamente vacío.
        if not remaining_users:
            run_mosquitto_passwd(
                [
                    "-b",
                    "-c",
                    str(temporary),
                    BROKER_PLACEHOLDER_USER,
                    secrets.token_urlsafe(48),
                ]
            )

        os.chmod(
            temporary,
            0o644,
        )

        os.replace(
            temporary,
            BROKER_AUTH_PATH,
        )

    finally:
        if temporary.exists():
            temporary.unlink()

    print(
        "[broker revocado] "
        f"device={device_id} | "
        f"usuario={username}",
        flush=True,
    )

    return True


def invalidate_revoked_key(device_id):
    path = active_key_path(
        device_id
    )

    current_value = ""

    if path.exists():
        current_value = path.read_text(
            encoding="utf-8"
        ).strip()

    # Evita cambiar el archivo repetidamente.
    if current_value.startswith(
        "revoked_"
    ):
        return False

    revoked_value = (
        "revoked_"
        + secrets.token_urlsafe(32)
    )

    write_private_file(
        path,
        revoked_value,
    )

    print(
        "[clave local invalidada] "
        f"device={device_id}",
        flush=True,
    )

    return True


def sync_revoked_devices():
    result = request_json(
        "/api/v1/internal/"
        "key-rotation/device-status"
    )

    for device in result.get(
        "devices",
        [],
    ):
        device_id = device.get(
            "device_id"
        )

        status = device.get(
            "status"
        )

        if device_id not in BROKER_AUTH_MAP:
            continue

        if status != "revoked":
            continue

        remove_broker_user(
            device_id
        )

        invalidate_revoked_key(
            device_id
        )


def finalize_key_file(device_id):
    pending = pending_key_path(
        device_id
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

    metadata = pending_metadata_path(
        device_id
    )

    if metadata.exists():
        metadata.unlink()


def report_request_error(
    request_id,
    error,
):
    if request_id is None:
        return

    try:
        request_json(
            "/api/v1/internal/key-rotation/"
            f"requests/{request_id}/error",
            method="POST",
            payload={
                "error": str(error),
            },
        )

    except Exception as report_error:
        print(
            "[error al reportar solicitud] "
            f"request={request_id} | "
            f"{report_error}"
        )


def process_rotation(
    device_id,
    action="rotate",
    request_id=None,
    force=False,
):
    (
        pending,
        new_key,
        metadata,
    ) = prepare_pending_key(
        device_id,
        action,
        request_id,
        force,
    )

    actual_action = metadata.get(
        "action",
        action,
    )

    actual_request_id = metadata.get(
        "request_id",
        request_id,
    )

    actual_force = bool(
        metadata.get(
            "force",
            force,
        )
    )

    try:
        result = request_json(
            "/api/v1/internal/"
            "key-rotation/activate",
            method="POST",
            payload={
                "device_id": device_id,
                "api_key": new_key,
                "action": actual_action,
                "request_id":
                    actual_request_id,
                "force": actual_force,
            },
        )

        sync_broker_password(
            device_id,
            new_key,
        )

        finalize_key_file(
            device_id
        )

        if actual_request_id is not None:
            request_json(
                "/api/v1/internal/key-rotation/"
                f"requests/"
                f"{actual_request_id}/complete",
                method="POST",
                payload={
                    "credential_version":
                        result.get(
                            "credential_version"
                        ),
                },
            )

        print(
            "[rotación completada] "
            f"device={device_id} | "
            f"acción={actual_action} | "
            f"solicitud={actual_request_id} | "
            f"versión="
            f"{result.get('credential_version')} | "
            f"idempotente="
            f"{result.get('idempotent', False)}"
        )

    except Exception as error:
        report_request_error(
            actual_request_id,
            error,
        )

        raise


def recover_pending_files():
    for device_id in DEVICE_MAP:
        pending = pending_key_path(
            device_id
        )

        if not pending.exists():
            continue

        metadata_path = (
            pending_metadata_path(
                device_id
            )
        )

        metadata = {
            "device_id": device_id,
            "action": "rotate",
            "request_id": None,
            "force": True,
        }

        if metadata_path.exists():
            try:
                metadata = json.loads(
                    metadata_path.read_text(
                        encoding="utf-8"
                    )
                )

            except Exception as error:
                print(
                    "[metadatos pendientes inválidos] "
                    f"device={device_id} | "
                    f"{error}"
                )

        print(
            "[recuperación de clave pendiente] "
            f"device={device_id}"
        )

        try:
            process_rotation(
                device_id,
                action=metadata.get(
                    "action",
                    "rotate",
                ),
                request_id=metadata.get(
                    "request_id"
                ),
                force=bool(
                    metadata.get(
                        "force",
                        True,
                    )
                ),
            )

        except Exception as error:
            print(
                "[recuperación pendiente] "
                f"device={device_id} | "
                f"{error}"
            )


def run_manual_requests():
    result = request_json(
        "/api/v1/internal/"
        "key-rotation/requests"
    )

    requests_list = result.get(
        "requests",
        [],
    )

    for item in requests_list:
        device_id = item.get(
            "device_id"
        )

        request_id = item.get("id")
        action = item.get("action")

        if device_id not in DEVICE_MAP:
            error = RuntimeError(
                "Dispositivo no configurado "
                f"en el rotador: {device_id}"
            )

            report_request_error(
                request_id,
                error,
            )

            print(
                "[solicitud omitida] "
                f"{error}"
            )

            continue

        try:
            process_rotation(
                device_id,
                action=action,
                request_id=request_id,
                force=False,
            )

        except Exception as error:
            print(
                "[error de solicitud manual] "
                f"request={request_id} | "
                f"device={device_id} | "
                f"{error}"
            )


def run_due_rotations():
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
            "programadas pendientes"
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
            process_rotation(
                device_id,
                action="rotate",
                request_id=None,
                force=False,
            )

        except Exception as error:
            print(
                "[error de rotación programada] "
                f"device={device_id} | "
                f"{error}"
            )




def handle_signal(signum, frame):
    global stop_requested

    stop_requested = True

    print(
        f"[rotador] señal {signum}; cerrando"
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
        f"solicitudes={ROTATOR_REQUEST_INTERVAL}s | "
        f"programadas={ROTATOR_CHECK_INTERVAL}s"
    )

    # Esperar hasta que el backend esté disponible.
    while not stop_requested:
        try:
            request_json(
                "/api/v1/internal/"
                "key-rotation/requests"
            )

            print(
                "[rotador] backend disponible",
                flush=True,
            )

            break

        except Exception as error:
            print(
                "[rotador] esperando al backend | "
                f"{error}",
                flush=True,
            )

            time.sleep(3)

    if stop_requested:
        return

    recover_pending_files()

    sync_revoked_devices()

    if args.force_device:
        if (
            args.force_device
            not in DEVICE_MAP
        ):
            raise RuntimeError(
                "Dispositivo forzado no configurado"
            )

        process_rotation(
            args.force_device,
            action="rotate",
            request_id=None,
            force=True,
        )

        if args.once:
            return

    elif args.once:
        run_manual_requests()
        run_due_rotations()
        return

    last_due_check = 0.0

    while not stop_requested:
        try:
            sync_revoked_devices()

        except Exception as error:
            print(
                "[error sincronizando estados] "
                f"{error}",
                flush=True,
            )

        try:
            run_manual_requests()

        except Exception as error:
            print(
                "[error consultando solicitudes] "
                f"{error}"
            )

        current_time = time.monotonic()

        if (
            current_time - last_due_check
            >= ROTATOR_CHECK_INTERVAL
        ):
            try:
                run_due_rotations()

            except Exception as error:
                print(
                    "[error del rotador programado] "
                    f"{error}"
                )

            last_due_check = current_time

        for _ in range(
            ROTATOR_REQUEST_INTERVAL
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
