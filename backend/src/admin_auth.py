import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
import psycopg2
from flask import Blueprint, g, jsonify, request
from jwt import ExpiredSignatureError, InvalidTokenError
from psycopg2.extras import Json, RealDictCursor
from werkzeug.security import check_password_hash


auth_bp = Blueprint(
    "admin_auth",
    __name__,
    url_prefix="/api/v1/auth",
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


def client_ip():
    forwarded = request.headers.get(
        "X-Forwarded-For",
        "",
    )

    value = (
        forwarded.split(",", 1)[0].strip()
        or request.remote_addr
    )

    return value or None


def jwt_secret():
    secret = os.getenv(
        "JWT_SECRET_KEY",
        "",
    )

    if len(secret) < 64:
        raise RuntimeError(
            "JWT_SECRET_KEY debe tener "
            "al menos 64 caracteres"
        )

    return secret


def jwt_issuer():
    return os.getenv(
        "JWT_ISSUER",
        "iot-hospital-backend",
    )


def jwt_audience():
    return os.getenv(
        "JWT_AUDIENCE",
        "iot-hospital-admin",
    )


def access_minutes():
    try:
        value = int(
            os.getenv(
                "JWT_ACCESS_MINUTES",
                "30",
            )
        )

    except ValueError:
        value = 30

    return max(5, min(value, 1440))


def write_login_audit(
    conn,
    username,
    result,
    details=None,
):
    with conn.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO admin_audit_log (
                actor_type,
                actor_id,
                action,
                result,
                details,
                ip_address
            )
            VALUES (
                'admin',
                %s,
                'admin_login',
                %s,
                %s,
                %s
            )
            """,
            (
                username,
                result,
                Json(details or {}),
                client_ip(),
            ),
        )


def create_access_token(user):
    now = datetime.now(timezone.utc)

    expiration = now + timedelta(
        minutes=access_minutes()
    )

    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "iat": now,
        "nbf": now,
        "exp": expiration,
        "iss": jwt_issuer(),
        "aud": jwt_audience(),
        "jti": str(uuid.uuid4()),
    }

    token = jwt.encode(
        payload,
        jwt_secret(),
        algorithm="HS256",
    )

    return token, expiration


def jwt_required(roles=None):
    allowed_roles = set(roles or [])

    def decorator(view):
        @wraps(view)
        def protected(*args, **kwargs):
            scheme, _, token = (
                request.headers.get(
                    "Authorization",
                    "",
                ).partition(" ")
            )

            if (
                scheme.lower() != "bearer"
                or not token
            ):
                return jsonify(
                    error=(
                        "Se requiere un token "
                        "Bearer"
                    )
                ), 401

            try:
                payload = jwt.decode(
                    token,
                    jwt_secret(),
                    algorithms=["HS256"],
                    issuer=jwt_issuer(),
                    audience=jwt_audience(),
                    options={
                        "require": [
                            "sub",
                            "username",
                            "role",
                            "iat",
                            "nbf",
                            "exp",
                            "iss",
                            "aud",
                            "jti",
                        ]
                    },
                )

            except ExpiredSignatureError:
                return jsonify(
                    error=(
                        "El token administrativo "
                        "expiró"
                    )
                ), 401

            except InvalidTokenError:
                return jsonify(
                    error=(
                        "Token administrativo "
                        "inválido"
                    )
                ), 401

            conn = db()

            try:
                with conn.cursor(
                    cursor_factory=RealDictCursor
                ) as cursor:
                    cursor.execute(
                        """
                        SELECT
                            id,
                            username,
                            role,
                            status,
                            last_login_at
                        FROM admin_users
                        WHERE id = %s
                          AND username = %s
                        """,
                        (
                            payload["sub"],
                            payload["username"],
                        ),
                    )

                    user = cursor.fetchone()

            finally:
                conn.close()

            if (
                not user
                or user["status"] != "active"
            ):
                return jsonify(
                    error=(
                        "La cuenta administrativa "
                        "no está activa"
                    )
                ), 401

            if (
                allowed_roles
                and user["role"]
                not in allowed_roles
            ):
                return jsonify(
                    error=(
                        "La cuenta no tiene permisos "
                        "para esta operación"
                    )
                ), 403

            g.admin_user = dict(user)
            g.jwt_payload = payload

            return view(*args, **kwargs)

        return protected

    return decorator


@auth_bp.post("/login")
def login():
    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get(
            "username",
            "",
        )
    ).strip().lower()

    password = str(
        data.get(
            "password",
            "",
        )
    )

    if (
        not USERNAME_PATTERN.fullmatch(
            username
        )
        or not password
    ):
        return jsonify(
            error=(
                "Usuario o contraseña "
                "incorrectos"
            )
        ), 401

    conn = db()

    try:
        with conn:
            with conn.cursor(
                cursor_factory=RealDictCursor
            ) as cursor:
                cursor.execute(
                    """
                    SELECT
                        id,
                        username,
                        password_hash,
                        role,
                        status
                    FROM admin_users
                    WHERE username = %s
                    """,
                    (username,),
                )

                user = cursor.fetchone()

                password_ok = False

                if user:
                    try:
                        password_ok = (
                            check_password_hash(
                                user[
                                    "password_hash"
                                ],
                                password,
                            )
                        )

                    except ValueError:
                        password_ok = False

                if (
                    not user
                    or not password_ok
                    or user["status"]
                    != "active"
                ):
                    write_login_audit(
                        conn,
                        username,
                        "failure",
                        {
                            "reason":
                                "invalid_credentials"
                        },
                    )

                    return jsonify(
                        error=(
                            "Usuario o contraseña "
                            "incorrectos"
                        )
                    ), 401

                cursor.execute(
                    """
                    UPDATE admin_users
                    SET last_login_at = NOW()
                    WHERE id = %s
                    """,
                    (user["id"],),
                )

                token, expiration = (
                    create_access_token(user)
                )

                write_login_audit(
                    conn,
                    username,
                    "success",
                    {
                        "role": user["role"]
                    },
                )

        return jsonify(
            access_token=token,
            token_type="Bearer",
            expires_in=(
                access_minutes() * 60
            ),
            expires_at=(
                expiration.isoformat()
            ),
            user={
                "id": user["id"],
                "username":
                    user["username"],
                "role": user["role"],
            },
        )

    finally:
        conn.close()


@auth_bp.get("/me")
@jwt_required(
    roles={"admin", "viewer"}
)
def current_user():
    user = g.admin_user

    return jsonify(
        id=user["id"],
        username=user["username"],
        role=user["role"],
        status=user["status"],
        last_login_at=(
            user["last_login_at"]
            .isoformat()
            if user["last_login_at"]
            else None
        ),
    )
