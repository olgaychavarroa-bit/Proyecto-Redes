import hashlib
import os
import re
import secrets
from datetime import datetime

import psycopg2
from admin_auth import jwt_required
from credential_service import install_device_credential
from flask import Blueprint, g, jsonify, request
from psycopg2.extras import Json, RealDictCursor


public_bp = Blueprint(
    "public_devices",
    __name__,
    url_prefix="/api/v1",
)

admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/api/v1/admin",
)

OLD_ADMIN_PATH = re.compile(
    r"^/api/v1/devices/[^/]+/(revoke|rotate)$"
)


def db():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "iot-postgres"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        dbname=os.getenv("POSTGRES_DB", "iot_hospital"),
        user=os.getenv("POSTGRES_USER", "iot_admin"),
        password=os.getenv("POSTGRES_PASSWORD", ""),
    )


def hash_api_key(value):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def serialize_rows(rows):
    output = []

    for row in rows:
        item = dict(row)

        for key, value in item.items():
            if isinstance(value, datetime):
                item[key] = value.isoformat()

            elif key == "ip_address" and value is not None:
                item[key] = str(value)

        output.append(item)

    return output


def write_audit(
    conn,
    action,
    device_id=None,
    result="success",
    details=None,
):
    forwarded = request.headers.get(
        "X-Forwarded-For",
        "",
    )

    ip_address = (
        forwarded.split(",", 1)[0].strip()
        or request.remote_addr
    )

    actor = (
        g.admin_user["username"]
        if getattr(g, "admin_user", None)
        else "unknown-admin"
    )

    with conn.cursor() as cursor:
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
                'admin',
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            """,
            (
                actor,
                action,
                device_id,
                result,
                Json(details or {}),
                ip_address,
            ),
        )


@admin_bp.before_app_request
def disable_old_admin_routes():
    if (
        request.method
        in {"POST", "PATCH", "PUT", "DELETE"}
        and OLD_ADMIN_PATH.fullmatch(request.path)
    ):
        return jsonify(
            error=(
                "Use los nuevos endpoints protegidos "
                "/api/v1/admin/devices/<device_id>/..."
            )
        ), 410

    return None


# ============================================================
# VISTA PÚBLICA DE DISPOSITIVOS
# ============================================================

@public_bp.get("/devices/overview")
def public_devices():
    conn = db()

    try:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    device_id,
                    name,
                    area,
                    status,
                    created_at,
                    updated_at,
                    last_seen_at
                FROM public_device_overview
                ORDER BY area, device_id
                """
            )

            rows = cursor.fetchall()

        return jsonify(
            serialize_rows(rows)
        )

    finally:
        conn.close()


# ============================================================
# LISTADO ADMINISTRATIVO
# ============================================================

@admin_bp.get("/devices")
@jwt_required(roles={"admin", "viewer"})
def admin_devices():
    conn = db()

    try:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:
            cursor.execute(
                """
                SELECT *
                FROM admin_device_overview
                ORDER BY area, device_id
                """
            )

            rows = cursor.fetchall()

        return jsonify(
            serialize_rows(rows)
        )

    finally:
        conn.close()


# ============================================================
# AUDITORÍA
# ============================================================

@admin_bp.get("/audit")
@jwt_required(roles={"admin", "viewer"})
def admin_audit():
    try:
        limit = int(
            request.args.get("limit", "100")
        )

    except ValueError:
        return jsonify(
            error="limit debe ser numérico"
        ), 400

    limit = max(1, min(limit, 500))

    conn = db()

    try:
        with conn.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    actor_type,
                    actor_id,
                    action,
                    target_device_id,
                    result,
                    details,
                    ip_address,
                    created_at
                FROM admin_audit_log
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,),
            )

            rows = cursor.fetchall()

        return jsonify(
            serialize_rows(rows)
        )

    finally:
        conn.close()


# ============================================================
# REVOCAR DISPOSITIVO
# ============================================================

@admin_bp.patch(
    "/devices/<device_id>/revoke"
)
@jwt_required(roles={"admin"})
def revoke_device(device_id):
    conn = db()

    try:
        with conn:
            with conn.cursor(
                cursor_factory=RealDictCursor
            ) as cursor:
                cursor.execute(
                    """
                    SELECT
                        device_id,
                        status,
                        credential_version
                    FROM devices
                    WHERE device_id = %s
                    FOR UPDATE
                    """,
                    (device_id,),
                )

                device = cursor.fetchone()

                if not device:
                    return jsonify(
                        error=(
                            "Dispositivo no encontrado"
                        )
                    ), 404

                if device["status"] == "revoked":
                    return jsonify(
                        device_id=device_id,
                        status="revoked",
                        message=(
                            "El dispositivo ya estaba "
                            "revocado"
                        ),
                    )

                cursor.execute(
                    """
                    UPDATE devices
                    SET
                        status = 'revoked',
                        revoked_at = NOW()
                    WHERE device_id = %s
                    """,
                    (device_id,),
                )

                cursor.execute(
                    """
                    UPDATE device_credentials
                    SET
                        status = 'revoked',
                        revoked_at = NOW()
                    WHERE device_id = %s
                      AND status IN (
                          'current',
                          'grace'
                      )
                    """,
                    (device_id,),
                )

                write_audit(
                    conn,
                    "device_revoke",
                    device_id,
                    details={
                        "credential_version":
                            device[
                                "credential_version"
                            ]
                    },
                )

        return jsonify(
            device_id=device_id,
            status="revoked",
            message="Dispositivo revocado",
        )

    finally:
        conn.close()


# ============================================================
# CREAR NUEVA CREDENCIAL
# ============================================================

def create_credential(
    conn,
    cursor,
    device,
    device_id,
    action,
):
    new_api_key = secrets.token_urlsafe(32)

    result = install_device_credential(
        cursor,
        device,
        device_id,
        new_api_key,
        action,
    )

    write_audit(
        conn,
        (
            "device_activate"
            if action == "activate"
            else "api_key_rotate"
        ),
        device_id,
        details={
            "previous_version":
                result["previous_version"],

            "new_version":
                result["new_version"],

            "hash_fingerprint":
                result["hash_fingerprint"],

            "grace_seconds":
                result["grace_seconds"],

            "next_rotation_days":
                result["rotation_days"],
        },
    )

    return (
        new_api_key,
        result["new_version"],
    )



def enqueue_key_rotation_request(
    conn,
    cursor,
    device_id,
    action,
):
    """
    Registra una solicitud para que iot-key-rotator
    genere, instale y guarde la nueva API Key.
    """

    cursor.execute(
        """
        SELECT
            id,
            action,
            status,
            requested_at
        FROM api_key_rotation_requests
        WHERE device_id = %s
          AND status = 'pending'
        ORDER BY id DESC
        LIMIT 1
        FOR UPDATE
        """,
        (device_id,),
    )

    existing = cursor.fetchone()

    if existing:
        return {
            "request_id": existing["id"],
            "created": False,
            "existing_action": existing["action"],
        }

    cursor.execute(
        """
        INSERT INTO api_key_rotation_requests (
            device_id,
            action,
            source,
            status
        )
        VALUES (
            %s,
            %s,
            'admin',
            'pending'
        )
        RETURNING id
        """,
        (
            device_id,
            action,
        ),
    )

    request_id = cursor.fetchone()["id"]

    write_audit(
        conn,
        (
            "device_activate_requested"
            if action == "activate"
            else "api_key_rotate_requested"
        ),
        device_id,
        details={
            "request_id": request_id,
            "action": action,
            "automatic_file_update": True,
        },
    )

    return {
        "request_id": request_id,
        "created": True,
        "existing_action": None,
    }


# ============================================================
# REACTIVAR DISPOSITIVO
# ============================================================

@admin_bp.patch(
    "/devices/<device_id>/activate"
)
@jwt_required(roles={"admin"})
def activate_device(device_id):
    conn = db()

    try:
        with conn:
            with conn.cursor(
                cursor_factory=RealDictCursor
            ) as cursor:
                cursor.execute(
                    """
                    SELECT
                        device_id,
                        status,
                        credential_version
                    FROM devices
                    WHERE device_id = %s
                    FOR UPDATE
                    """,
                    (device_id,),
                )

                device = cursor.fetchone()

                if not device:
                    return jsonify(
                        error="Dispositivo no encontrado"
                    ), 404

                if device["status"] == "active":
                    return jsonify(
                        error=(
                            "El dispositivo ya está activo"
                        )
                    ), 409

                request_result = (
                    enqueue_key_rotation_request(
                        conn,
                        cursor,
                        device_id,
                        "activate",
                    )
                )

        return jsonify(
            message=(
                "Reactivación solicitada. "
                "El rotador generará la API Key "
                "y actualizará automáticamente "
                "el archivo privado del simulador."
            ),
            request_id=request_result["request_id"],
            device_id=device_id,
            action=(
                request_result["existing_action"]
                if not request_result["created"]
                else "activate"
            ),
            status="pending",
            created=request_result["created"],
        ), 202

    finally:
        conn.close()



# ============================================================
# ROTAR API KEY
# ============================================================

@admin_bp.post(
    "/devices/<device_id>/rotate"
)
@jwt_required(roles={"admin"})
def rotate_device(device_id):
    conn = db()

    try:
        with conn:
            with conn.cursor(
                cursor_factory=RealDictCursor
            ) as cursor:
                cursor.execute(
                    """
                    SELECT
                        device_id,
                        status,
                        credential_version
                    FROM devices
                    WHERE device_id = %s
                    FOR UPDATE
                    """,
                    (device_id,),
                )

                device = cursor.fetchone()

                if not device:
                    return jsonify(
                        error="Dispositivo no encontrado"
                    ), 404

                if device["status"] != "active":
                    return jsonify(
                        error=(
                            "El dispositivo debe estar activo "
                            "para rotar su API Key"
                        )
                    ), 409

                request_result = (
                    enqueue_key_rotation_request(
                        conn,
                        cursor,
                        device_id,
                        "rotate",
                    )
                )

        return jsonify(
            message=(
                "Rotación solicitada. "
                "La API Key será instalada y "
                "guardada automáticamente en el "
                "archivo privado del simulador."
            ),
            request_id=request_result["request_id"],
            device_id=device_id,
            action=(
                request_result["existing_action"]
                if not request_result["created"]
                else "rotate"
            ),
            status="pending",
            created=request_result["created"],
        ), 202

    finally:
        conn.close()
