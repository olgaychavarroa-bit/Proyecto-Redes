import argparse
import getpass
import os
import re
import sys

import psycopg2
from psycopg2.extras import Json
from werkzeug.security import (
    generate_password_hash,
)


USERNAME_PATTERN = re.compile(
    r"^[a-z0-9_.-]{3,50}$"
)


def db():
    return psycopg2.connect(
        host=os.getenv(
            "POSTGRES_HOST",
            "iot-postgres",
        ),
        port=int(
            os.getenv(
                "POSTGRES_PORT",
                "5432",
            )
        ),
        dbname=os.getenv(
            "POSTGRES_DB",
            "iot_hospital",
        ),
        user=os.getenv(
            "POSTGRES_USER",
            "iot_admin",
        ),
        password=os.getenv(
            "POSTGRES_PASSWORD",
            "",
        ),
    )


def valid_password(password):
    return (
        len(password) >= 12
        and any(
            char.islower()
            for char in password
        )
        and any(
            char.isupper()
            for char in password
        )
        and any(
            char.isdigit()
            for char in password
        )
        and any(
            not char.isalnum()
            for char in password
        )
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--username",
        required=True,
    )

    parser.add_argument(
        "--role",
        choices=["admin", "viewer"],
        default="admin",
    )

    args = parser.parse_args()

    username = (
        args.username
        .strip()
        .lower()
    )

    if not USERNAME_PATTERN.fullmatch(
        username
    ):
        sys.exit(
            "El usuario debe tener entre 3 y "
            "50 caracteres y usar solamente "
            "letras minúsculas, números, punto, "
            "guion o guion bajo."
        )

    password = getpass.getpass(
        "Contraseña administrativa: "
    )

    confirmation = getpass.getpass(
        "Repita la contraseña: "
    )

    if password != confirmation:
        sys.exit(
            "Las contraseñas no coinciden."
        )

    if not valid_password(password):
        sys.exit(
            "La contraseña debe tener al menos "
            "12 caracteres, mayúscula, minúscula, "
            "número y carácter especial."
        )

    password_hash = (
        generate_password_hash(password)
    )

    conn = db()

    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT 1
                    FROM admin_users
                    WHERE username = %s
                    """,
                    (username,),
                )

                if cursor.fetchone():
                    sys.exit(
                        "El usuario ya existe."
                    )

                cursor.execute(
                    """
                    INSERT INTO admin_users (
                        username,
                        password_hash,
                        role,
                        status
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        'active'
                    )
                    RETURNING id
                    """,
                    (
                        username,
                        password_hash,
                        args.role,
                    ),
                )

                user_id = cursor.fetchone()[0]

                cursor.execute(
                    """
                    INSERT INTO admin_audit_log (
                        actor_type,
                        actor_id,
                        action,
                        result,
                        details
                    )
                    VALUES (
                        'system',
                        'bootstrap',
                        'admin_user_create',
                        'success',
                        %s
                    )
                    """,
                    (
                        Json(
                            {
                                "user_id":
                                    user_id,
                                "username":
                                    username,
                                "role":
                                    args.role,
                            }
                        ),
                    ),
                )

        print(
            "Usuario administrativo creado "
            "correctamente."
        )

        print(
            f"Usuario: {username}"
        )

        print(
            f"Rol: {args.role}"
        )

    finally:
        conn.close()


if __name__ == "__main__":
    main()
