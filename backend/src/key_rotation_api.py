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
    token = Path(
        ROTATOR_SERVICE_TOKEN_FILE
    ).read_text(
        encoding="utf-8"
    ).strip()

    if not token:
        raise RuntimeError(
            "El token interno del rotador está vacío"
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

        except Exception as error:
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


def expire_old_grace_credentials(cursor):
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
                          next_key_rotation_at IS NULL
                          OR next_key_rotation_at <= NOW()
                      )
                    ORDER BY
                        next_key_rotation_at NULLS FIRST,
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
            count=len(devices),
            devices=devices,
        )

    finally:
        connection.close()


@key_rotation_bp.get(
    "/api/v1/internal/key-rotation/requests"
)
@rotator_token_required
def pending_manual_requests():
    connection = db()

    try:
        with connection.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    device_id,
                    action,
                    source,
                    status,
                    requested_at,
                    attempts
                FROM api_key_rotation_requests
                WHERE status = 'pending'
                ORDER BY requested_at, id
                LIMIT 20
                """
            )

            requests_list = []

            for row in cursor.fetchall():
                requests_list.append(
                    {
                        "id": row["id"],
                        "device_id":
                            row["device_id"],
                        "action":
                            row["action"],
                        "source":
                            row["source"],
                        "status":
                            row["status"],
                        "attempts":
                            row["attempts"],
                        "requested_at":
                            row[
                                "requested_at"
                            ].isoformat(),
                    }
                )

        return jsonify(
            count=len(requests_list),
            requests=requests_list,
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
        payload.get("device_id", "")
    ).strip()

    new_api_key = str(
        payload.get("api_key", "")
    ).strip()

    action = str(
        payload.get("action", "rotate")
    ).strip().lower()

    force = bool(
        payload.get("force", False)
    )

    request_id = payload.get("request_id")

    if action not in {
        "rotate",
        "activate",
    }:
        return jsonify(
            error="Acción de credencial inválida"
        ), 400

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

    if request_id is not None:
        try:
            request_id = int(request_id)

        except (
            TypeError,
            ValueError,
        ):
            return jsonify(
                error="request_id inválido"
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

                rotation_request = None

                if request_id is not None:
                    cursor.execute(
                        """
                        SELECT
                            id,
                            device_id,
                            action,
                            status
                        FROM api_key_rotation_requests
                        WHERE id = %s
                        FOR UPDATE
                        """,
                        (
                            request_id,
                        ),
                    )

                    rotation_request = (
                        cursor.fetchone()
                    )

                    if not rotation_request:
                        return jsonify(
                            error=(
                                "Solicitud de rotación "
                                "no encontrada"
                            )
                        ), 404

                    if (
                        rotation_request["device_id"]
                        != device_id
                        or rotation_request["action"]
                        != action
                    ):
                        return jsonify(
                            error=(
                                "La solicitud no corresponde "
                                "al dispositivo o acción"
                            )
                        ), 409

                    if (
                        rotation_request["status"]
                        == "cancelled"
                    ):
                        return jsonify(
                            error=(
                                "La solicitud fue cancelada"
                            )
                        ), 409

                cursor.execute(
                    """
                    SELECT
                        device_id,
                        area,
                        status,
                        credential_version,
                        next_key_rotation_at,
                        (
                            next_key_rotation_at IS NULL
                            OR next_key_rotation_at <= NOW()
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
                        error="Dispositivo no encontrado"
                    ), 404

                new_hash = hash_api_key(
                    new_api_key
                )

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
                    if request_id is not None:
                        cursor.execute(
                            """
                            UPDATE api_key_rotation_requests
                            SET
                                backend_installed_at =
                                    COALESCE(
                                        backend_installed_at,
                                        NOW()
                                    ),
                                credential_version = %s
                            WHERE id = %s
                            """,
                            (
                                existing[
                                    "credential_version"
                                ],
                                request_id,
                            ),
                        )

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

                if action == "rotate":
                    if device["status"] != "active":
                        return jsonify(
                            error=(
                                "El dispositivo debe estar "
                                "activo para rotar"
                            )
                        ), 409

                    if (
                        request_id is None
                        and not force
                        and not device["rotation_due"]
                    ):
                        return jsonify(
                            error=(
                                "La rotación todavía "
                                "no está programada"
                            )
                        ), 409

                if action == "activate":
                    if device["status"] == "active":
                        return jsonify(
                            error=(
                                "El dispositivo ya está activo"
                            )
                        ), 409

                result = install_device_credential(
                    cursor,
                    device,
                    device_id,
                    new_api_key,
                    action,
                )

                if request_id is not None:
                    cursor.execute(
                        """
                        UPDATE api_key_rotation_requests
                        SET
                            backend_installed_at = NOW(),
                            credential_version = %s,
                            last_error = NULL
                        WHERE id = %s
                        """,
                        (
                            result["new_version"],
                            request_id,
                        ),
                    )

                if request_id is not None:
                    audit_action = (
                        "device_manual_activate_completed"
                        if action == "activate"
                        else "api_key_manual_rotate_completed"
                    )
                else:
                    audit_action = (
                        "api_key_auto_rotate_force"
                        if force
                        else "api_key_auto_rotate"
                    )

                write_system_audit(
                    cursor,
                    audit_action,
                    device_id,
                    details={
                        "request_id":
                            request_id,

                        "action":
                            action,

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

                        "automatic_file_update":
                            True,
                    },
                )

        return jsonify(
            device_id=device_id,
            action=action,
            status="installed",
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


@key_rotation_bp.post(
    "/api/v1/internal/key-rotation/"
    "requests/<int:request_id>/complete"
)
@rotator_token_required
def complete_manual_request(request_id):
    payload = request.get_json(
        silent=True
    ) or {}

    credential_version = payload.get(
        "credential_version"
    )

    connection = db()

    try:
        with connection:
            with connection.cursor(
                cursor_factory=RealDictCursor
            ) as cursor:
                cursor.execute(
                    """
                    UPDATE api_key_rotation_requests
                    SET
                        status = 'completed',
                        completed_at = NOW(),
                        credential_version =
                            COALESCE(
                                %s,
                                credential_version
                            ),
                        last_error = NULL
                    WHERE id = %s
                      AND status = 'pending'
                    RETURNING
                        id,
                        device_id,
                        action,
                        status
                    """,
                    (
                        credential_version,
                        request_id,
                    ),
                )

                row = cursor.fetchone()

                if not row:
                    cursor.execute(
                        """
                        SELECT
                            id,
                            device_id,
                            action,
                            status
                        FROM api_key_rotation_requests
                        WHERE id = %s
                        """,
                        (
                            request_id,
                        ),
                    )

                    row = cursor.fetchone()

                if not row:
                    return jsonify(
                        error=(
                            "Solicitud no encontrada"
                        )
                    ), 404

        return jsonify(
            request_id=row["id"],
            device_id=row["device_id"],
            action=row["action"],
            status=row["status"],
        )

    finally:
        connection.close()


@key_rotation_bp.post(
    "/api/v1/internal/key-rotation/"
    "requests/<int:request_id>/error"
)
@rotator_token_required
def report_manual_request_error(request_id):
    payload = request.get_json(
        silent=True
    ) or {}

    error_message = str(
        payload.get(
            "error",
            "Error no especificado",
        )
    )[:2000]

    connection = db()

    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE api_key_rotation_requests
                    SET
                        attempts = attempts + 1,
                        last_error = %s
                    WHERE id = %s
                      AND status = 'pending'
                    """,
                    (
                        error_message,
                        request_id,
                    ),
                )

        return jsonify(
            request_id=request_id,
            status="pending",
            error_recorded=True,
        )

    finally:
        connection.close()
