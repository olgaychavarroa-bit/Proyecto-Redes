import hmac
import os
import re
from functools import wraps
from pathlib import Path
from typing import Any

import psycopg2
from flask import Blueprint, jsonify, request
from psycopg2.extras import Json, RealDictCursor

from credential_service import (
    hash_api_key,
    install_device_credential,
)


key_rotation_bp = Blueprint(
    "key_rotation",
    __name__,
)


POSTGRES_HOST = os.environ["POSTGRES_HOST"]
POSTGRES_PORT = int(
    os.environ.get(
        "POSTGRES_PORT",
        "5432",
    )
)
POSTGRES_DB = os.environ["POSTGRES_DB"]
POSTGRES_USER = os.environ["POSTGRES_USER"]
POSTGRES_PASSWORD = os.environ[
    "POSTGRES_PASSWORD"
]

ROTATOR_SERVICE_TOKEN_FILE = os.environ.get(
    "ROTATOR_SERVICE_TOKEN_FILE",
    "/run/secrets/rotator/service_token",
)

API_KEY_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{40,128}$"
)


def db():
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
        connect_timeout=5,
    )


def read_service_token() -> str:
    try:
        token = Path(
            ROTATOR_SERVICE_TOKEN_FILE
        ).read_text(
            encoding="utf-8"
        ).strip()

    except OSError as error:
        raise RuntimeError(
            "No se pudo leer el token "
            f"del rotador: {error}"
        ) from error

    if not token:
        raise RuntimeError(
            "El token del rotador está vacío"
        )

    return token


def rotator_token_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get(
            "X-Rotator-Token",
            "",
        )

        try:
            expected = read_service_token()

        except RuntimeError as error:
            return jsonify(
                error=str(error)
            ), 503

        if not hmac.compare_digest(
            supplied,
            expected,
        ):
            return jsonify(
                error="Token interno inválido"
            ), 401

        return function(
            *args,
            **kwargs,
        )

    return wrapper


def write_system_audit(
    cursor,
    action: str,
    device_id: str,
    details: dict[str, Any],
):
    cursor.execute(
        """
        INSERT INTO admin_audit_log (
            actor_type,
            actor_id,
            action,
            target_device_id,
            result,
            details,
            ip_address
        )
        VALUES (
            'system',
            NULL,
            %s,
            %s,
            'success',
            %s,
            %s
        )
        """,
        (
            action,
            device_id,
            Json(details),
            request.remote_addr,
        ),
    )


def expire_old_grace_credentials(
    cursor,
):
    cursor.execute(
        """
        UPDATE device_credentials
        SET
            status = 'expired',
            expires_at = COALESCE(
                expires_at,
                NOW()
            )
        WHERE status = 'grace'
          AND grace_until <= NOW()
        """
    )


@key_rotation_bp.get(
    "/api/v1/internal/key-rotation/due"
)
@rotator_token_required
def due_rotations():
    connection = db()

    try:
        with connection:
            with connection.cursor(
                cursor_factory=RealDictCursor
            ) as cursor:
                expire_old_grace_credentials(
                    cursor
                )

                cursor.execute(
                    """
                    SELECT
                        device_id,
                        area,
                        credential_version,
                        next_key_rotation_at
                    FROM devices
                    WHERE status = 'active'
                      AND (
                          next_key_rotation_at
                              IS NULL
                          OR next_key_rotation_at
                              <= NOW()
                      )
                    ORDER BY
                        next_key_rotation_at
                            NULLS FIRST,
                        device_id
                    """
                )

                devices = []

                for row in cursor.fetchall():
                    devices.append(
                        {
                            "device_id":
                                row["device_id"],

                            "area":
                                row["area"],

                            "credential_version":
                                row[
                                    "credential_version"
                                ],

                            "next_key_rotation_at":
                                (
                                    row[
                                        "next_key_rotation_at"
                                    ].isoformat()
                                    if row[
                                        "next_key_rotation_at"
                                    ]
                                    else None
                                ),
                        }
                    )

        return jsonify(
            devices=devices,
            count=len(devices),
        )

    finally:
        connection.close()


@key_rotation_bp.post(
    "/api/v1/internal/key-rotation/activate"
)
@rotator_token_required
def activate_rotated_key():
    payload = request.get_json(
        silent=True
    ) or {}

    device_id = str(
        payload.get(
            "device_id",
            "",
        )
    ).strip()

    new_api_key = str(
        payload.get(
            "api_key",
            "",
        )
    ).strip()

    force = bool(
        payload.get(
            "force",
            False,
        )
    )

    if not device_id:
        return jsonify(
            error="Falta device_id"
        ), 400

    if not API_KEY_PATTERN.fullmatch(
        new_api_key
    ):
        return jsonify(
            error=(
                "La nueva API Key no tiene "
                "un formato válido"
            )
        ), 400

    connection = db()

    try:
        with connection:
            with connection.cursor(
                cursor_factory=RealDictCursor
            ) as cursor:
                expire_old_grace_credentials(
                    cursor
                )

                cursor.execute(
                    """
                    SELECT
                        device_id,
                        area,
                        status,
                        credential_version,
                        next_key_rotation_at,
                        (
                            next_key_rotation_at
                                IS NULL
                            OR next_key_rotation_at
                                <= NOW()
                        ) AS rotation_due
                    FROM devices
                    WHERE device_id = %s
                    FOR UPDATE
                    """,
                    (
                        device_id,
                    ),
                )

                device = cursor.fetchone()

                if not device:
                    return jsonify(
                        error=(
                            "Dispositivo no encontrado"
                        )
                    ), 404

                if device["status"] != "active":
                    return jsonify(
                        error=(
                            "El dispositivo no está activo"
                        )
                    ), 409

                new_hash = hash_api_key(
                    new_api_key
                )

                # Recuperación idempotente:
                # si el backend ya instaló esta misma
                # clave, puede confirmarla otra vez.
                cursor.execute(
                    """
                    SELECT
                        credential_version
                    FROM device_credentials
                    WHERE device_id = %s
                      AND status = 'current'
                      AND api_key_hash = %s
                    """,
                    (
                        device_id,
                        new_hash,
                    ),
                )

                existing = cursor.fetchone()

                if existing:
                    return jsonify(
                        device_id=device_id,
                        status="already_current",
                        credential_version=(
                            existing[
                                "credential_version"
                            ]
                        ),
                        idempotent=True,
                    )

                if (
                    not force
                    and not device["rotation_due"]
                ):
                    return jsonify(
                        error=(
                            "La rotación todavía "
                            "no está programada"
                        ),
                        next_key_rotation_at=(
                            device[
                                "next_key_rotation_at"
                            ].isoformat()
                            if device[
                                "next_key_rotation_at"
                            ]
                            else None
                        ),
                    ), 409

                result = (
                    install_device_credential(
                        cursor,
                        device,
                        device_id,
                        new_api_key,
                        "rotate",
                    )
                )

                write_system_audit(
                    cursor,
                    (
                        "api_key_auto_rotate_force"
                        if force
                        else "api_key_auto_rotate"
                    ),
                    device_id,
                    details={
                        "previous_version":
                            result[
                                "previous_version"
                            ],

                        "new_version":
                            result[
                                "new_version"
                            ],

                        "hash_fingerprint":
                            result[
                                "hash_fingerprint"
                            ],

                        "grace_seconds":
                            result[
                                "grace_seconds"
                            ],

                        "forced":
                            force,
                    },
                )

        return jsonify(
            device_id=device_id,
            status="rotated",
            credential_version=(
                result["new_version"]
            ),
            grace_seconds=(
                result["grace_seconds"]
            ),
            idempotent=False,
        )

    finally:
        connection.close()
