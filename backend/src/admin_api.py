import hashlib
import os
import re
import secrets
from datetime import datetime
from functools import wraps

import psycopg2
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

    actor = os.getenv(
        "ADMIN_ACTOR",
        "bootstrap-admin",
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


def admin_required(view):
    @wraps(view)
    def protected(*args, **kwargs):
        expected = os.getenv(
            "ADMIN_API_TOKEN",
            "",
        )

        scheme, _, received = request.headers.get(
            "Authorization",
            "",
        ).partition(" ")

        if len(expected) < 32:
            return jsonify(
                error=(
                    "ADMIN_API_TOKEN no está "
                    "configurado correctamente"
                )
            ), 500

        valid = (
            scheme.lower() == "bearer"
            and secrets.compare_digest(
                received,
                expected,
            )
        )

        if not valid:
            return jsonify(
                error="Token administrativo inválido"
            ), 401

        g.admin_actor = os.getenv(
            "ADMIN_ACTOR",
            "bootstrap-admin",
        )

        return view(*args, **kwargs)

    return protected


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
@admin_required
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
@admin_required
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
@admin_required
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

    new_hash = hash_api_key(
        new_api_key
    )

    new_version = (
        int(device["credential_version"])
        + 1
    )

    cursor.execute(
        """
        UPDATE device_credentials
        SET
            status = 'revoked',
            revoked_at = COALESCE(
                revoked_at,
                NOW()
            )
        WHERE device_id = %s
          AND status IN (
              'current',
              'grace'
          )
        """,
        (device_id,),
    )

    cursor.execute(
        """
        INSERT INTO device_credentials (
            device_id,
            api_key_hash,
            credential_version,
            status
        )
        VALUES (
            %s,
            %s,
            %s,
            'current'
        )
        """,
        (
            device_id,
            new_hash,
            new_version,
        ),
    )

    if action == "activate":
        cursor.execute(
            """
            UPDATE devices
            SET
                status = 'active',
                api_key_hash = %s,
                credential_version = %s,
                reactivated_at = NOW(),
                revoked_at = NULL,
                last_key_rotation_at = NOW()
            WHERE device_id = %s
            """,
            (
                new_hash,
                new_version,
                device_id,
            ),
        )

    else:
        cursor.execute(
            """
            UPDATE devices
            SET
                api_key_hash = %s,
                credential_version = %s,
                last_key_rotation_at = NOW()
            WHERE device_id = %s
            """,
            (
                new_hash,
                new_version,
                device_id,
            ),
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
                device[
                    "credential_version"
                ],
            "new_version":
                new_version,
            "hash_fingerprint":
                new_hash[-12:],
        },
    )

    return new_api_key, new_version


# ============================================================
# REACTIVAR DISPOSITIVO
# ============================================================

@admin_bp.patch(
    "/devices/<device_id>/activate"
)
@admin_required
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
                        error=(
                            "Dispositivo no encontrado"
                        )
                    ), 404

                if device["status"] == "active":
                    return jsonify(
                        error=(
                            "El dispositivo ya está "
                            "activo"
                        )
                    ), 409

                new_key, new_version = (
                    create_credential(
                        conn,
                        cursor,
                        device,
                        device_id,
                        "activate",
                    )
                )

        return jsonify(
            device_id=device_id,
            status="active",
            credential_version=new_version,
            api_key=new_key,
            warning=(
                "Guarde la nueva API Key. "
                "Se muestra una sola vez."
            ),
        )

    finally:
        conn.close()


# ============================================================
# ROTAR API KEY
# ============================================================

@admin_bp.post(
    "/devices/<device_id>/rotate"
)
@admin_required
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
                        error=(
                            "Dispositivo no encontrado"
                        )
                    ), 404

                if device["status"] != "active":
                    return jsonify(
                        error=(
                            "El dispositivo debe estar "
                            "activo para rotar su API Key"
                        )
                    ), 409

                new_key, new_version = (
                    create_credential(
                        conn,
                        cursor,
                        device,
                        device_id,
                        "rotate",
                    )
                )

        return jsonify(
            device_id=device_id,
            status="active",
            credential_version=new_version,
            api_key=new_key,
            warning=(
                "Guarde la nueva API Key. "
                "La anterior dejó de funcionar."
            ),
        )

    finally:
        conn.close()
