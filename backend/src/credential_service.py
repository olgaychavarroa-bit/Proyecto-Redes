import hashlib
import hmac
import os
from typing import Any


API_KEY_GRACE_SECONDS = max(
    0,
    int(
        os.environ.get(
            "API_KEY_GRACE_SECONDS",
            "120",
        )
    ),
)

API_KEY_ROTATION_DAYS = max(
    1,
    int(
        os.environ.get(
            "API_KEY_ROTATION_DAYS",
            "30",
        )
    ),
)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(
        api_key.encode("utf-8")
    ).hexdigest()


def install_device_credential(
    cursor,
    device: dict[str, Any],
    device_id: str,
    new_api_key: str,
    action: str,
) -> dict[str, Any]:
    """
    Instala una credencial nueva.

    action='activate':
        revoca todas las credenciales anteriores.

    action='rotate':
        pasa la credencial current a grace y crea
        una nueva credencial current.
    """
    if action not in {
        "activate",
        "rotate",
    }:
        raise ValueError(
            "Acción de credencial inválida"
        )

    new_hash = hash_api_key(
        new_api_key
    )

    previous_version = int(
        device["credential_version"]
    )

    new_version = (
        previous_version + 1
    )

    if action == "activate":
        cursor.execute(
            """
            UPDATE device_credentials
            SET
                status = 'revoked',
                revoked_at = COALESCE(
                    revoked_at,
                    NOW()
                ),
                grace_until = NULL
            WHERE device_id = %s
              AND status IN (
                  'current',
                  'grace'
              )
            """,
            (
                device_id,
            ),
        )

    else:
        # Una gracia anterior ya no debe seguir activa.
        cursor.execute(
            """
            UPDATE device_credentials
            SET
                status = 'expired',
                expires_at = COALESCE(
                    expires_at,
                    NOW()
                )
            WHERE device_id = %s
              AND status = 'grace'
            """,
            (
                device_id,
            ),
        )

        # La clave current anterior pasa temporalmente
        # al estado grace.
        cursor.execute(
            """
            UPDATE device_credentials
            SET
                status = 'grace',
                grace_until =
                    NOW()
                    + (
                        %s
                        * INTERVAL '1 second'
                    ),
                expires_at =
                    NOW()
                    + (
                        %s
                        * INTERVAL '1 second'
                    )
            WHERE device_id = %s
              AND status = 'current'
            """,
            (
                API_KEY_GRACE_SECONDS,
                API_KEY_GRACE_SECONDS,
                device_id,
            ),
        )

    cursor.execute(
        """
        INSERT INTO device_credentials (
            device_id,
            api_key_hash,
            credential_version,
            status,
            expires_at
        )
        VALUES (
            %s,
            %s,
            %s,
            'current',
            NOW()
            + (
                %s
                * INTERVAL '1 day'
            )
        )
        """,
        (
            device_id,
            new_hash,
            new_version,
            API_KEY_ROTATION_DAYS,
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
                last_key_rotation_at = NOW(),
                next_key_rotation_at =
                    NOW()
                    + (
                        %s
                        * INTERVAL '1 day'
                    )
            WHERE device_id = %s
            """,
            (
                new_hash,
                new_version,
                API_KEY_ROTATION_DAYS,
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
                last_key_rotation_at = NOW(),
                next_key_rotation_at =
                    NOW()
                    + (
                        %s
                        * INTERVAL '1 day'
                    )
            WHERE device_id = %s
            """,
            (
                new_hash,
                new_version,
                API_KEY_ROTATION_DAYS,
                device_id,
            ),
        )

    return {
        "previous_version":
            previous_version,

        "new_version":
            new_version,

        "new_hash":
            new_hash,

        "hash_fingerprint":
            new_hash[-12:],

        "grace_seconds":
            (
                0
                if action == "activate"
                else API_KEY_GRACE_SECONDS
            ),

        "rotation_days":
            API_KEY_ROTATION_DAYS,
    }


def validate_device_api_key(
    cursor,
    device_id: str,
    api_key: str,
):
    """
    Acepta una credencial current o una credencial
    grace que todavía no haya vencido.
    """
    cursor.execute(
        """
        UPDATE device_credentials
        SET
            status = 'expired',
            expires_at = COALESCE(
                expires_at,
                NOW()
            )
        WHERE device_id = %s
          AND status = 'grace'
          AND grace_until <= NOW()
        """,
        (
            device_id,
        ),
    )

    cursor.execute(
        """
        SELECT
            credential_version,
            api_key_hash,
            status,
            grace_until
        FROM device_credentials
        WHERE device_id = %s
          AND (
              status = 'current'
              OR (
                  status = 'grace'
                  AND grace_until > NOW()
              )
          )
        ORDER BY
            CASE
                WHEN status = 'current'
                    THEN 0
                ELSE 1
            END,
            credential_version DESC
        """,
        (
            device_id,
        ),
    )

    received_hash = hash_api_key(
        api_key
    )

    for credential in cursor.fetchall():
        if hmac.compare_digest(
            received_hash,
            credential["api_key_hash"],
        ):
            return credential

    return None
