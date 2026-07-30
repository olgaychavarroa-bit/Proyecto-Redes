FROM python:3.12-slim

ARG ROTATOR_UID=1000
ARG ROTATOR_GID=1000

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN groupadd \
        --gid "${ROTATOR_GID}" rotator \
    && useradd \
        --create-home \
        --uid "${ROTATOR_UID}" \
        --gid "${ROTATOR_GID}" \
        rotator

WORKDIR /app

COPY src/rotator.py /app/rotator.py

USER rotator

CMD ["python", "/app/rotator.py"]
