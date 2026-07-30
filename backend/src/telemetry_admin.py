import os
import threading
import time
from datetime import datetime
from typing import Any

import psycopg2
from flask import Blueprint, g, jsonify, request
from psycopg2.extras import Json, RealDictCursor

from admin_auth import jwt_required


telemetry_admin_bp = Blueprint(
    "telemetry_admin",
    __name__,
)


# ============================================================
# CONFIGURACIÓN
# ============================================================

POSTGRES_HOST = os.environ["POSTGRES_HOST"]
POSTGRES_PORT = int(
    os.environ.get("POSTGRES_PORT", "5432")
)
POSTGRES_DB = os.environ["POSTGRES_DB"]
POSTGRES_USER = os.environ["POSTGRES_USER"]
POSTGRES_PASSWORD = os.environ["POSTGRES_PASSWORD"]


def environment_boolean(
    name: str,
    default: bool,
) -> bool:
    value = os.environ.get(
        name,
        str(default),
    ).strip().lower()

    return value in {
        "1",
        "true",
        "yes",
        "on",
    }


TELEMETRY_RETENTION_ENABLED = environment_boolean(
    "TELEMETRY_RETENTION_ENABLED",
    True,
)

TELEMETRY_RETENTION_DAYS = int(
    os.environ.get(
        "TELEMETRY_RETENTION_DAYS",
        "30",
    )
)

TELEMETRY_RETENTION_INTERVAL_SECONDS = max(
    60,
    int(
        os.environ.get(
            "TELEMETRY_RETENTION_INTERVAL_SECONDS",
            "86400",
        )
    ),
)

ALLOWED_RETENTION_DAYS = {
    7,
    30,
    90,
    365,
}

# Bloqueo interno de PostgreSQL.
# Evita que dos procesos limpien simultáneamente.
RETENTION_LOCK_ID = 888330

_retention_thread_started = False
_retention_thread_lock = threading.Lock()


# ============================================================
# BASE DE DATOS
# ============================================================

def get_db_connection():
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
        connect_timeout=5,
    )


def iso_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None

    return value.isoformat()


def admin_field(
    field_name: str,
    default: Any = None,
) -> Any:
    admin_user = getattr(
        g,
        "admin_user",
        None,
    )

    if isinstance(admin_user, dict):
        return admin_user.get(
            field_name,
            default,
        )

    return getattr(
        admin_user,
        field_name,
        default,
    )


def requester_ip() -> str | None:
    forwarded = request.headers.get(
        "X-Forwarded-For",
        "",
    )

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.remote_addr


def insert_audit(
    cursor,
    *,
    actor_type: str,
    actor_id: int | None,
    action: str,
    result: str,
    details: dict[str, Any],
    ip_address: str | None,
) -> None:
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
            %s,
            %s,
            %s,
            NULL,
            %s,
            %s,
            %s
        )
        """,
        (
            actor_type,
            actor_id,
            action,
            result,
            Json(details),
            ip_address,
        ),
    )


def record_failure_audit(
    *,
    actor_type: str,
    actor_id: int | None,
    action: str,
    error: Exception,
    ip_address: str | None,
) -> None:
    connection = None

    try:
        connection = get_db_connection()

        with connection:
            with connection.cursor() as cursor:
                insert_audit(
                    cursor,
                    actor_type=actor_type,
                    actor_id=actor_id,
                    action=action,
                    result="failure",
                    details={
                        "error": str(error),
                    },
                    ip_address=ip_address,
                )

    except Exception as audit_error:
        print(
            "[retention] no se pudo registrar "
            f"auditoría de error: {audit_error}"
        )

    finally:
        if connection is not None:
            connection.close()


# ============================================================
# CONSULTA DE ESTADO
# ============================================================

def telemetry_statistics() -> dict[str, Any]:
    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor(
            cursor_factory=RealDictCursor
        ) as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(*)::bigint
                        AS total_rows,

                    MIN(received_at)
                        AS oldest_received_at,

                    MAX(received_at)
                        AS newest_received_at,

                    COUNT(*) FILTER (
                        WHERE received_at
                            < NOW()
                            - (
                                %s
                                * INTERVAL '1 day'
                            )
                    )::bigint
                        AS expired_rows,

                    pg_total_relation_size(
                        'telemetry'::regclass
                    )::bigint
                        AS table_size_bytes

                FROM telemetry
                """,
                (
                    TELEMETRY_RETENTION_DAYS,
                ),
            )

            row = cursor.fetchone()

        return {
            "total_rows":
                int(row["total_rows"] or 0),

            "expired_rows":
                int(row["expired_rows"] or 0),

            "oldest_received_at":
                iso_datetime(
                    row["oldest_received_at"]
                ),

            "newest_received_at":
                iso_datetime(
                    row["newest_received_at"]
                ),

            "table_size_bytes":
                int(
                    row["table_size_bytes"]
                    or 0
                ),

            "retention": {
                "enabled":
                    TELEMETRY_RETENTION_ENABLED,

                "days":
                    TELEMETRY_RETENTION_DAYS,

                "interval_seconds":
                    TELEMETRY_RETENTION_INTERVAL_SECONDS,
            },
        }

    finally:
        if connection is not None:
            connection.close()


# ============================================================
# ELIMINACIÓN POR ANTIGÜEDAD
# ============================================================

def delete_expired_telemetry(
    *,
    retention_days: int,
    actor_type: str,
    actor_id: int | None,
    ip_address: str | None,
    audit_when_empty: bool,
) -> dict[str, Any]:
    connection = None

    try:
        connection = get_db_connection()

        with connection:
            with connection.cursor(
                cursor_factory=RealDictCursor
            ) as cursor:
                cursor.execute(
                    """
                    SELECT
                        pg_try_advisory_xact_lock(
                            %s
                        ) AS acquired
                    """,
                    (
                        RETENTION_LOCK_ID,
                    ),
                )

                acquired = bool(
                    cursor.fetchone()["acquired"]
                )

                if not acquired:
                    return {
                        "skipped": True,
                        "deleted_rows": 0,
                        "reason":
                            "Existe otra limpieza "
                            "en ejecución.",
                    }

                cursor.execute(
                    """
                    SELECT
                        NOW()
                        - (
                            %s
                            * INTERVAL '1 day'
                        ) AS cutoff
                    """,
                    (
                        retention_days,
                    ),
                )

                cutoff = cursor.fetchone()["cutoff"]

                cursor.execute(
                    """
                    WITH deleted AS (
                        DELETE FROM telemetry
                        WHERE received_at < %s
                        RETURNING id
                    )
                    SELECT
                        COUNT(*)::bigint
                            AS deleted_rows
                    FROM deleted
                    """,
                    (
                        cutoff,
                    ),
                )

                deleted_rows = int(
                    cursor.fetchone()[
                        "deleted_rows"
                    ]
                )

                if (
                    deleted_rows > 0
                    or audit_when_empty
                ):
                    insert_audit(
                        cursor,
                        actor_type=actor_type,
                        actor_id=actor_id,
                        action=(
                            "telemetry_retention_cleanup"
                        ),
                        result="success",
                        details={
                            "retention_days":
                                retention_days,

                            "cutoff":
                                iso_datetime(cutoff),

                            "deleted_rows":
                                deleted_rows,
                        },
                        ip_address=ip_address,
                    )

        return {
            "skipped": False,
            "deleted_rows": deleted_rows,
            "retention_days": retention_days,
            "cutoff": iso_datetime(cutoff),
        }

    except Exception as error:
        record_failure_audit(
            actor_type=actor_type,
            actor_id=actor_id,
            action=(
                "telemetry_retention_cleanup"
            ),
            error=error,
            ip_address=ip_address,
        )

        raise

    finally:
        if connection is not None:
            connection.close()


# ============================================================
# VACIADO TOTAL
# ============================================================

def purge_all_telemetry(
    *,
    actor_id: int | None,
    ip_address: str | None,
) -> int:
    connection = None

    try:
        connection = get_db_connection()

        with connection:
            with connection.cursor(
                cursor_factory=RealDictCursor
            ) as cursor:
                cursor.execute(
                    """
                    SELECT
                        pg_try_advisory_xact_lock(
                            %s
                        ) AS acquired
                    """,
                    (
                        RETENTION_LOCK_ID,
                    ),
                )

                acquired = bool(
                    cursor.fetchone()["acquired"]
                )

                if not acquired:
                    raise RuntimeError(
                        "Existe otra limpieza "
                        "en ejecución."
                    )

                cursor.execute(
                    """
                    WITH deleted AS (
                        DELETE FROM telemetry
                        RETURNING id
                    )
                    SELECT
                        COUNT(*)::bigint
                            AS deleted_rows
                    FROM deleted
                    """
                )

                deleted_rows = int(
                    cursor.fetchone()[
                        "deleted_rows"
                    ]
                )

                insert_audit(
                    cursor,
                    actor_type="admin",
                    actor_id=actor_id,
                    action="telemetry_purge",
                    result="success",
                    details={
                        "deleted_rows":
                            deleted_rows,

                        "confirmation":
                            "ELIMINAR TELEMETRIA",
                    },
                    ip_address=ip_address,
                )

        return deleted_rows

    except Exception as error:
        record_failure_audit(
            actor_type="admin",
            actor_id=actor_id,
            action="telemetry_purge",
            error=error,
            ip_address=ip_address,
        )

        raise

    finally:
        if connection is not None:
            connection.close()


# ============================================================
# ENDPOINTS ADMINISTRATIVOS
# ============================================================

@telemetry_admin_bp.get(
    "/api/v1/admin/telemetry/maintenance"
)
@jwt_required(
    roles=(
        "admin",
        "viewer",
    )
)
def get_telemetry_maintenance():
    try:
        return jsonify(
            telemetry_statistics()
        )

    except Exception as error:
        return jsonify(
            {
                "error":
                    "No fue posible consultar "
                    "el mantenimiento.",

                "details":
                    str(error),
            }
        ), 500


@telemetry_admin_bp.post(
    "/api/v1/admin/telemetry/cleanup"
)
@jwt_required(
    roles=(
        "admin",
    )
)
def cleanup_telemetry():
    payload = request.get_json(
        silent=True
    ) or {}

    try:
        retention_days = int(
            payload.get(
                "retention_days",
                TELEMETRY_RETENTION_DAYS,
            )
        )

    except (
        TypeError,
        ValueError,
    ):
        return jsonify(
            {
                "error":
                    "retention_days debe "
                    "ser un número entero."
            }
        ), 400

    if (
        retention_days
        not in ALLOWED_RETENTION_DAYS
    ):
        return jsonify(
            {
                "error":
                    "El periodo permitido es "
                    "7, 30, 90 o 365 días."
            }
        ), 400

    try:
        result = delete_expired_telemetry(
            retention_days=retention_days,
            actor_type="admin",
            actor_id=admin_field("id"),
            ip_address=requester_ip(),
            audit_when_empty=True,
        )

        if result["skipped"]:
            return jsonify(
                {
                    "error":
                        result["reason"]
                }
            ), 409

        return jsonify(
            {
                "message":
                    "Limpieza de telemetría "
                    "completada.",

                **result,
            }
        )

    except Exception as error:
        return jsonify(
            {
                "error":
                    "No fue posible limpiar "
                    "la telemetría.",

                "details":
                    str(error),
            }
        ), 500


@telemetry_admin_bp.post(
    "/api/v1/admin/telemetry/purge"
)
@jwt_required(
    roles=(
        "admin",
    )
)
def purge_telemetry():
    payload = request.get_json(
        silent=True
    ) or {}

    confirmation = str(
        payload.get(
            "confirmation",
            "",
        )
    ).strip()

    if (
        confirmation
        != "ELIMINAR TELEMETRIA"
    ):
        return jsonify(
            {
                "error":
                    "La frase de confirmación "
                    "no es correcta."
            }
        ), 400

    try:
        deleted_rows = purge_all_telemetry(
            actor_id=admin_field("id"),
            ip_address=requester_ip(),
        )

        return jsonify(
            {
                "message":
                    "La tabla de telemetría "
                    "fue vaciada.",

                "deleted_rows":
                    deleted_rows,
            }
        )

    except Exception as error:
        return jsonify(
            {
                "error":
                    "No fue posible vaciar "
                    "la telemetría.",

                "details":
                    str(error),
            }
        ), 500


# ============================================================
# RETENCIÓN AUTOMÁTICA
# ============================================================

def retention_worker() -> None:
    print(
        "[retention] trabajador iniciado | "
        f"activo={TELEMETRY_RETENTION_ENABLED} | "
        f"días={TELEMETRY_RETENTION_DAYS} | "
        f"intervalo="
        f"{TELEMETRY_RETENTION_INTERVAL_SECONDS}s"
    )

    while True:
        try:
            result = delete_expired_telemetry(
                retention_days=(
                    TELEMETRY_RETENTION_DAYS
                ),
                actor_type="system",
                actor_id=None,
                ip_address=None,
                audit_when_empty=False,
            )

            if result["skipped"]:
                print(
                    "[retention] limpieza omitida: "
                    f"{result['reason']}"
                )
            else:
                print(
                    "[retention] limpieza completada | "
                    f"eliminados="
                    f"{result['deleted_rows']} | "
                    f"días="
                    f"{TELEMETRY_RETENTION_DAYS}"
                )

        except Exception as error:
            print(
                "[retention] error durante "
                f"la limpieza: {error}"
            )

        time.sleep(
            TELEMETRY_RETENTION_INTERVAL_SECONDS
        )


def start_retention_worker() -> None:
    global _retention_thread_started

    if not TELEMETRY_RETENTION_ENABLED:
        print(
            "[retention] limpieza automática "
            "desactivada"
        )

        return

    with _retention_thread_lock:
        if _retention_thread_started:
            return

        thread = threading.Thread(
            target=retention_worker,
            name="telemetry-retention",
            daemon=True,
        )

        thread.start()
        _retention_thread_started = True
