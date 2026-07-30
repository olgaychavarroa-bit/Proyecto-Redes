FROM python:3.12-slim

ARG SIM_UID=1000
ARG SIM_GID=1000

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN groupadd \
        --gid "${SIM_GID}" simulator \
    && useradd \
        --create-home \
        --uid "${SIM_UID}" \
        --gid "${SIM_GID}" \
        simulator

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN pip install \
    --no-cache-dir \
    -r /app/requirements.txt

COPY src/simulator.py /app/simulator.py

USER simulator

CMD ["python", "/app/simulator.py"]
