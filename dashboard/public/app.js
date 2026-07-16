"use strict";

const AREAS = {
    uci: {
        label: "UCI",
        description: "Unidad de Cuidados Intensivos"
    },
    urgencias: {
        label: "Urgencias",
        description: "Servicio de urgencias"
    },
    laboratorio: {
        label: "Laboratorio",
        description: "Laboratorio clínico"
    }
};

/*
 * Límites configurados únicamente para demostrar
 * los cambios visuales del dashboard.
 */
const THRESHOLDS = {
    temperature: {
        normalMin: 18,
        normalMax: 27,
        warningMin: 15,
        warningMax: 30
    },
    humidity: {
        normalMin: 30,
        normalMax: 70,
        warningMin: 20,
        warningMax: 80
    },
    co2: {
        normalMax: 1000,
        warningMax: 1500
    }
};

const API_ENDPOINTS = [
    "/api/v1/telemetry/latest",
    "/api/v1/telemetry?limit=100"
];

const areaCards = document.getElementById("area-cards");
const telemetryTable = document.getElementById("telemetry-table");
const connectionMessage = document.getElementById("connection-message");
const refreshButton = document.getElementById("refresh-button");

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function numberFrom(row, names) {
    for (const name of names) {
        const rawValue = row?.[name];

        if (
            rawValue !== undefined &&
            rawValue !== null &&
            rawValue !== ""
        ) {
            const number = Number(rawValue);
            return Number.isFinite(number) ? number : null;
        }
    }

    return null;
}

function detectArea(row) {
    const directArea = String(row?.area ?? "")
        .trim()
        .toLowerCase();

    if (AREAS[directArea]) {
        return directArea;
    }

    const deviceId = String(row?.device_id ?? "")
        .trim()
        .toLowerCase();

    for (const area of Object.keys(AREAS)) {
        if (deviceId.includes(area)) {
            return area;
        }
    }

    return null;
}

function normalizeDate(row) {
    return (
        row?.received_at ??
        row?.timestamp ??
        row?.created_at ??
        row?.date ??
        null
    );
}

function normalizeRow(row) {
    return {
        area: detectArea(row),
        deviceId: String(row?.device_id ?? "Sin identificar"),
        name: String(row?.name ?? row?.device_name ?? ""),
        temperature: numberFrom(row, [
            "temperature",
            "temp",
            "temperatura"
        ]),
        humidity: numberFrom(row, [
            "humidity",
            "hum",
            "humedad"
        ]),
        co2: numberFrom(row, [
            "co2",
            "co2_ppm",
            "carbon_dioxide"
        ]),
        receivedAt: normalizeDate(row)
    };
}

function unwrapPayload(payload) {
    if (Array.isArray(payload)) {
        return payload;
    }

    if (!payload || typeof payload !== "object") {
        return [];
    }

    const possibleKeys = [
        "telemetry",
        "data",
        "items",
        "results",
        "readings",
        "latest"
    ];

    for (const key of possibleKeys) {
        if (Array.isArray(payload[key])) {
            return payload[key];
        }
    }

    const values = Object.values(payload);

    if (
        values.length > 0 &&
        values.every(
            value =>
                value &&
                typeof value === "object" &&
                !Array.isArray(value)
        )
    ) {
        return values;
    }

    return [];
}

function metricStatus(metric, value) {
    if (value === null) {
        return "unknown";
    }

    if (metric === "co2") {
        if (value < 0 || value > THRESHOLDS.co2.warningMax) {
            return "critical";
        }

        if (value > THRESHOLDS.co2.normalMax) {
            return "warning";
        }

        return "normal";
    }

    const limits = THRESHOLDS[metric];

    if (
        value < limits.warningMin ||
        value > limits.warningMax
    ) {
        return "critical";
    }

    if (
        value < limits.normalMin ||
        value > limits.normalMax
    ) {
        return "warning";
    }

    return "normal";
}

function overallStatus(row) {
    if (!row) {
        return "unknown";
    }

    const statuses = [
        metricStatus("temperature", row.temperature),
        metricStatus("humidity", row.humidity),
        metricStatus("co2", row.co2)
    ];

    if (statuses.includes("critical")) {
        return "critical";
    }

    if (statuses.includes("warning")) {
        return "warning";
    }

    if (statuses.includes("unknown")) {
        return "unknown";
    }

    return "normal";
}

function statusLabel(status) {
    const labels = {
        normal: "Normal",
        warning: "Advertencia",
        critical: "Crítico",
        unknown: "Sin datos"
    };

    return labels[status] ?? "Sin datos";
}

function formatMetric(value, unit) {
    if (value === null) {
        return "—";
    }

    return `${value.toFixed(1)} ${unit}`;
}

function formatDate(value) {
    if (!value) {
        return "Sin fecha";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return new Intl.DateTimeFormat("es-CO", {
        dateStyle: "short",
        timeStyle: "medium"
    }).format(date);
}

function timestampValue(row) {
    if (!row?.receivedAt) {
        return 0;
    }

    const timestamp = new Date(row.receivedAt).getTime();
    return Number.isNaN(timestamp) ? 0 : timestamp;
}

function latestByArea(rows) {
    const latest = {};

    for (const row of rows) {
        if (!row.area || !AREAS[row.area]) {
            continue;
        }

        const current = latest[row.area];

        if (
            !current ||
            timestampValue(row) >= timestampValue(current)
        ) {
            latest[row.area] = row;
        }
    }

    return latest;
}

function renderCards(latest) {
    areaCards.innerHTML = Object.entries(AREAS)
        .map(([area, config]) => {
            const row = latest[area];
            const status = overallStatus(row);

            return `
                <article class="area-card">
                    <div class="area-card-header">
                        <div>
                            <h3>${escapeHtml(config.label)}</h3>
                            <small>${escapeHtml(config.description)}</small>
                        </div>

                        <span class="status-badge status-${status}">
                            ${statusLabel(status)}
                        </span>
                    </div>

                    <div class="metrics">
                        <div class="metric">
                            <span>Temperatura</span>
                            <strong>
                                ${formatMetric(
                                    row?.temperature ?? null,
                                    "°C"
                                )}
                            </strong>
                        </div>

                        <div class="metric">
                            <span>Humedad</span>
                            <strong>
                                ${formatMetric(
                                    row?.humidity ?? null,
                                    "%"
                                )}
                            </strong>
                        </div>

                        <div class="metric">
                            <span>CO₂</span>
                            <strong>
                                ${formatMetric(
                                    row?.co2 ?? null,
                                    "ppm"
                                )}
                            </strong>
                        </div>
                    </div>

                    <div class="card-footer">
                        Dispositivo:
                        ${escapeHtml(row?.deviceId ?? "Sin datos")}
                        <br>
                        Última lectura:
                        ${escapeHtml(
                            formatDate(row?.receivedAt)
                        )}
                    </div>
                </article>
            `;
        })
        .join("");
}

function renderTable(latest) {
    telemetryTable.innerHTML = Object.entries(AREAS)
        .map(([area, config]) => {
            const row = latest[area];
            const status = overallStatus(row);

            return `
                <tr>
                    <td>${escapeHtml(config.label)}</td>
                    <td>${escapeHtml(row?.deviceId ?? "—")}</td>
                    <td>
                        ${formatMetric(
                            row?.temperature ?? null,
                            "°C"
                        )}
                    </td>
                    <td>
                        ${formatMetric(
                            row?.humidity ?? null,
                            "%"
                        )}
                    </td>
                    <td>
                        ${formatMetric(
                            row?.co2 ?? null,
                            "ppm"
                        )}
                    </td>
                    <td>
                        <span class="status-badge status-${status}">
                            ${statusLabel(status)}
                        </span>
                    </td>
                    <td>
                        ${escapeHtml(
                            formatDate(row?.receivedAt)
                        )}
                    </td>
                </tr>
            `;
        })
        .join("");
}

function updateSummary(latest) {
    const rows = Object.values(latest);
    const areasWithData = rows.length;

    const alertCount = rows.filter(row => {
        const status = overallStatus(row);
        return status === "warning" || status === "critical";
    }).length;

    document.getElementById("areas-with-data").textContent =
        String(areasWithData);

    document.getElementById("alert-count").textContent =
        String(alertCount);

    document.getElementById("last-update").textContent =
        new Intl.DateTimeFormat("es-CO", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        }).format(new Date());
}

async function requestJson(url) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    try {
        const response = await fetch(url, {
            method: "GET",
            cache: "no-store",
            headers: {
                Accept: "application/json"
            },
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status} al consultar ${url}`
            );
        }

        return await response.json();
    } finally {
        clearTimeout(timeout);
    }
}

async function obtainTelemetry() {
    let lastError = null;

    for (const endpoint of API_ENDPOINTS) {
        try {
            const payload = await requestJson(endpoint);
            return unwrapPayload(payload);
        } catch (error) {
            lastError = error;
        }
    }

    throw lastError ?? new Error("No fue posible consultar la API");
}

async function loadDashboard() {
    refreshButton.disabled = true;

    connectionMessage.className = "message";
    connectionMessage.textContent =
        "Consultando información del backend...";

    try {
        const rawRows = await obtainTelemetry();

        const normalizedRows = rawRows
            .map(normalizeRow)
            .filter(row => row.area !== null);

        const latest = latestByArea(normalizedRows);

        renderCards(latest);
        renderTable(latest);
        updateSummary(latest);

        connectionMessage.className = "message success";

        if (normalizedRows.length === 0) {
            connectionMessage.textContent =
                "El backend respondió correctamente, pero todavía no hay " +
                "mediciones reconocidas para las áreas configuradas.";
        } else {
            connectionMessage.textContent =
                "Conexión correcta con el backend. Datos actualizados.";
        }
    } catch (error) {
        renderCards({});
        renderTable({});
        updateSummary({});

        connectionMessage.className = "message error";
        connectionMessage.textContent =
            `No fue posible consultar el backend: ${error.message}`;
    } finally {
        refreshButton.disabled = false;
    }
}

refreshButton.addEventListener("click", loadDashboard);

loadDashboard();

setInterval(loadDashboard, 10000);
EOF 







