"use strict";

(() => {
    const HISTORY_ENDPOINT =
        "/api/v1/telemetry?limit=300";

    const MAX_POINTS = 20;

    const AREAS = {
        uci: {
            label: "UCI",
            description:
                "Unidad de Cuidados Intensivos"
        },

        urgencias: {
            label: "Urgencias",
            description:
                "Servicio de urgencias"
        },

        laboratorio: {
            label: "Laboratorio",
            description:
                "Laboratorio clínico"
        }
    };

    const METRICS = {
        temperature: {
            label: "Temperatura",
            unit: "°C",
            decimals: 1
        },

        humidity: {
            label: "Humedad",
            unit: "%",
            decimals: 1
        },

        co2: {
            label: "CO₂",
            unit: "ppm",
            decimals: 0
        }
    };

    const chartsContainer = document.getElementById(
        "history-charts"
    );

    const historyMessage = document.getElementById(
        "history-message"
    );

    const metricSelector = document.getElementById(
        "history-metric"
    );

    const refreshButton = document.getElementById(
        "refresh-button"
    );

    let telemetryCache = [];
    let resizeTimer = null;


    function escapeHistoryHtml(value) {
        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }


    function unwrapPayload(payload) {
        if (Array.isArray(payload)) {
            return payload;
        }

        if (
            !payload
            || typeof payload !== "object"
        ) {
            return [];
        }

        const keys = [
            "telemetry",
            "data",
            "items",
            "results",
            "readings"
        ];

        for (const key of keys) {
            if (Array.isArray(payload[key])) {
                return payload[key];
            }
        }

        return [];
    }


    function numericValue(row, names) {
        for (const name of names) {
            const value = row?.[name];

            if (
                value !== undefined
                && value !== null
                && value !== ""
            ) {
                const number = Number(value);

                if (Number.isFinite(number)) {
                    return number;
                }
            }
        }

        return null;
    }


    function detectHistoryArea(row) {
        const directArea = String(
            row?.area ?? ""
        ).trim().toLowerCase();

        if (AREAS[directArea]) {
            return directArea;
        }

        const deviceId = String(
            row?.device_id ?? ""
        ).trim().toLowerCase();

        for (const area of Object.keys(AREAS)) {
            if (deviceId.includes(area)) {
                return area;
            }
        }

        return null;
    }


    function normalizeHistoryRow(row) {
        const receivedAt = (
            row?.received_at
            ?? row?.timestamp
            ?? row?.created_at
            ?? null
        );

        const date = receivedAt
            ? new Date(receivedAt)
            : null;

        return {
            area: detectHistoryArea(row),

            deviceId: String(
                row?.device_id
                ?? "Sin identificar"
            ),

            temperature: numericValue(
                row,
                [
                    "temperature",
                    "temp",
                    "temperatura"
                ]
            ),

            humidity: numericValue(
                row,
                [
                    "humidity",
                    "hum",
                    "humedad"
                ]
            ),

            co2: numericValue(
                row,
                [
                    "co2",
                    "co2_ppm",
                    "carbon_dioxide"
                ]
            ),

            receivedAt,

            timestamp: (
                date
                && !Number.isNaN(date.getTime())
            )
                ? date.getTime()
                : 0
        };
    }


    function createChartCards() {
        chartsContainer.innerHTML =
            Object.entries(AREAS)
                .map(([area, config]) => `
                    <article
                        class="history-card"
                        data-history-area="${area}"
                    >
                        <div class="history-card-header">
                            <div>
                                <h3>
                                    ${escapeHistoryHtml(
                                        config.label
                                    )}
                                </h3>

                                <p>
                                    ${escapeHistoryHtml(
                                        config.description
                                    )}
                                </p>
                            </div>

                            <span
                                id="history-count-${area}"
                                class="history-count"
                            >
                                0 datos
                            </span>
                        </div>

                        <p class="history-device">
                            Dispositivo:
                            <strong
                                id="history-device-${area}"
                            >
                                Sin datos
                            </strong>
                        </p>

                        <div class="history-canvas-wrapper">
                            <canvas
                                id="history-chart-${area}"
                                aria-label="Gráfico de ${escapeHistoryHtml(
                                    config.label
                                )}"
                                role="img"
                            ></canvas>
                        </div>

                        <div class="history-stats">
                            <div>
                                <span>Mínimo</span>
                                <strong
                                    id="history-min-${area}"
                                >
                                    —
                                </strong>
                            </div>

                            <div>
                                <span>Promedio</span>
                                <strong
                                    id="history-avg-${area}"
                                >
                                    —
                                </strong>
                            </div>

                            <div>
                                <span>Máximo</span>
                                <strong
                                    id="history-max-${area}"
                                >
                                    —
                                </strong>
                            </div>
                        </div>

                        <p
                            id="history-range-${area}"
                            class="history-range"
                        >
                            Sin mediciones disponibles.
                        </p>
                    </article>
                `)
                .join("");
    }


    function formatMetricValue(
        value,
        metric
    ) {
        if (!Number.isFinite(value)) {
            return "—";
        }

        const config = METRICS[metric];

        return (
            value.toFixed(config.decimals)
            + " "
            + config.unit
        );
    }


    function formatHistoryTime(value) {
        if (!value) {
            return "Sin fecha";
        }

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {
            return String(value);
        }

        return new Intl.DateTimeFormat(
            "es-CO",
            {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            }
        ).format(date);
    }


    function formatHistoryDate(value) {
        if (!value) {
            return "Sin fecha";
        }

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {
            return String(value);
        }

        return new Intl.DateTimeFormat(
            "es-CO",
            {
                dateStyle: "short",
                timeStyle: "short"
            }
        ).format(date);
    }


    function canvasColors() {
        const styles = getComputedStyle(
            document.documentElement
        );

        return {
            line: (
                styles.getPropertyValue(
                    "--history-line"
                ).trim()
                || "#17677d"
            ),

            grid: (
                styles.getPropertyValue(
                    "--history-grid"
                ).trim()
                || "#dfe6ee"
            ),

            text: (
                styles.getPropertyValue(
                    "--history-text"
                ).trim()
                || "#667085"
            ),

            point: (
                styles.getPropertyValue(
                    "--history-point"
                ).trim()
                || "#153d66"
            )
        };
    }


    function drawEmptyChart(
        context,
        width,
        height
    ) {
        const colors = canvasColors();

        context.clearRect(
            0,
            0,
            width,
            height
        );

        context.fillStyle = colors.text;
        context.font = "14px Arial";
        context.textAlign = "center";
        context.textBaseline = "middle";

        context.fillText(
            "No hay mediciones disponibles",
            width / 2,
            height / 2
        );
    }


    function drawLineChart(
        canvas,
        rows,
        metric
    ) {
        const ratio = (
            window.devicePixelRatio || 1
        );

        const width = Math.max(
            canvas.clientWidth,
            280
        );

        const height = 240;

        canvas.width = Math.floor(
            width * ratio
        );

        canvas.height = Math.floor(
            height * ratio
        );

        const context = canvas.getContext(
            "2d"
        );

        context.setTransform(
            ratio,
            0,
            0,
            ratio,
            0,
            0
        );

        const values = rows
            .map(row => row[metric])
            .filter(Number.isFinite);

        if (values.length === 0) {
            drawEmptyChart(
                context,
                width,
                height
            );

            return;
        }

        const colors = canvasColors();

        const margins = {
            top: 20,
            right: 16,
            bottom: 38,
            left: 55
        };

        const plotWidth = (
            width
            - margins.left
            - margins.right
        );

        const plotHeight = (
            height
            - margins.top
            - margins.bottom
        );

        let minimum = Math.min(...values);
        let maximum = Math.max(...values);

        if (minimum === maximum) {
            const adjustment = (
                Math.abs(minimum) * 0.05
                || 1
            );

            minimum -= adjustment;
            maximum += adjustment;
        } else {
            const padding = (
                maximum - minimum
            ) * 0.12;

            minimum -= padding;
            maximum += padding;
        }

        const xForIndex = index => {
            if (values.length === 1) {
                return (
                    margins.left
                    + plotWidth / 2
                );
            }

            return (
                margins.left
                + plotWidth
                * index
                / (values.length - 1)
            );
        };

        const yForValue = value => (
            margins.top
            + (
                maximum - value
            )
            / (
                maximum - minimum
            )
            * plotHeight
        );

        context.clearRect(
            0,
            0,
            width,
            height
        );

        context.font = "11px Arial";
        context.textAlign = "right";
        context.textBaseline = "middle";

        const gridLines = 4;

        for (
            let index = 0;
            index <= gridLines;
            index += 1
        ) {
            const proportion = (
                index / gridLines
            );

            const value = (
                maximum
                - proportion
                * (maximum - minimum)
            );

            const y = (
                margins.top
                + proportion
                * plotHeight
            );

            context.beginPath();
            context.strokeStyle = colors.grid;
            context.lineWidth = 1;

            context.moveTo(
                margins.left,
                y
            );

            context.lineTo(
                width - margins.right,
                y
            );

            context.stroke();

            context.fillStyle = colors.text;

            context.fillText(
                value.toFixed(
                    METRICS[metric].decimals
                ),
                margins.left - 8,
                y
            );
        }

        context.beginPath();
        context.strokeStyle = colors.line;
        context.lineWidth = 2.5;
        context.lineJoin = "round";
        context.lineCap = "round";

        values.forEach((value, index) => {
            const x = xForIndex(index);
            const y = yForValue(value);

            if (index === 0) {
                context.moveTo(x, y);
            } else {
                context.lineTo(x, y);
            }
        });

        context.stroke();

        values.forEach((value, index) => {
            const x = xForIndex(index);
            const y = yForValue(value);

            context.beginPath();
            context.fillStyle = colors.point;

            context.arc(
                x,
                y,
                3.5,
                0,
                Math.PI * 2
            );

            context.fill();
        });

        const labelIndexes = Array.from(
            new Set(
                [
                    0,
                    Math.floor(
                        (rows.length - 1) / 2
                    ),
                    rows.length - 1
                ]
            )
        );

        context.font = "10px Arial";
        context.fillStyle = colors.text;
        context.textAlign = "center";
        context.textBaseline = "top";

        labelIndexes.forEach(index => {
            context.fillText(
                formatHistoryTime(
                    rows[index]?.receivedAt
                ),
                xForIndex(index),
                height - margins.bottom + 12
            );
        });
    }


    function rowsForArea(
        area,
        metric
    ) {
        return telemetryCache
            .filter(
                row => (
                    row.area === area
                    && Number.isFinite(
                        row[metric]
                    )
                )
            )
            .sort(
                (
                    first,
                    second
                ) => (
                    first.timestamp
                    - second.timestamp
                )
            )
            .slice(-MAX_POINTS);
    }


    function renderAreaChart(
        area,
        metric
    ) {
        const rows = rowsForArea(
            area,
            metric
        );

        const canvas = document.getElementById(
            `history-chart-${area}`
        );

        const deviceElement =
            document.getElementById(
                `history-device-${area}`
            );

        const countElement =
            document.getElementById(
                `history-count-${area}`
            );

        const minElement =
            document.getElementById(
                `history-min-${area}`
            );

        const avgElement =
            document.getElementById(
                `history-avg-${area}`
            );

        const maxElement =
            document.getElementById(
                `history-max-${area}`
            );

        const rangeElement =
            document.getElementById(
                `history-range-${area}`
            );

        drawLineChart(
            canvas,
            rows,
            metric
        );

        countElement.textContent =
            `${rows.length} dato${
                rows.length === 1 ? "" : "s"
            }`;

        if (rows.length === 0) {
            deviceElement.textContent =
                "Sin datos";

            minElement.textContent = "—";
            avgElement.textContent = "—";
            maxElement.textContent = "—";

            rangeElement.textContent =
                "Sin mediciones disponibles.";

            return;
        }

        const values = rows.map(
            row => row[metric]
        );

        const average = (
            values.reduce(
                (total, value) => (
                    total + value
                ),
                0
            )
            / values.length
        );

        const latestRow = rows[
            rows.length - 1
        ];

        deviceElement.textContent =
            latestRow.deviceId;

        minElement.textContent =
            formatMetricValue(
                Math.min(...values),
                metric
            );

        avgElement.textContent =
            formatMetricValue(
                average,
                metric
            );

        maxElement.textContent =
            formatMetricValue(
                Math.max(...values),
                metric
            );

        rangeElement.textContent =
            `Desde ${
                formatHistoryDate(
                    rows[0].receivedAt
                )
            } hasta ${
                formatHistoryDate(
                    latestRow.receivedAt
                )
            }.`;
    }


    function renderHistoryCharts() {
        const metric = metricSelector.value;

        Object.keys(AREAS).forEach(
            area => renderAreaChart(
                area,
                metric
            )
        );
    }


    async function requestHistory() {
        const controller =
            new AbortController();

        const timeout = setTimeout(
            () => controller.abort(),
            8000
        );

        try {
            const response = await fetch(
                HISTORY_ENDPOINT,
                {
                    method: "GET",
                    cache: "no-store",
                    headers: {
                        Accept:
                            "application/json"
                    },
                    signal:
                        controller.signal
                }
            );

            if (!response.ok) {
                throw new Error(
                    `HTTP ${response.status}`
                );
            }

            const payload =
                await response.json();

            return unwrapPayload(payload)
                .map(normalizeHistoryRow)
                .filter(
                    row => (
                        row.area !== null
                        && row.timestamp > 0
                    )
                );
        } finally {
            clearTimeout(timeout);
        }
    }


    async function loadHistoryCharts() {
        historyMessage.className =
            "message";

        historyMessage.textContent =
            "Consultando historial de mediciones...";

        try {
            telemetryCache =
                await requestHistory();

            renderHistoryCharts();

            historyMessage.className =
                "message success";

            if (
                telemetryCache.length === 0
            ) {
                historyMessage.textContent =
                    "El backend respondió correctamente, "
                    + "pero todavía no hay historial.";
            } else {
                historyMessage.textContent =
                    "Historial actualizado correctamente. "
                    + "Los gráficos muestran hasta 20 "
                    + "mediciones por área.";
            }
        } catch (error) {
            telemetryCache = [];
            renderHistoryCharts();

            historyMessage.className =
                "message error";

            historyMessage.textContent =
                "No fue posible consultar el historial: "
                + error.message;
        }
    }


    createChartCards();

    metricSelector.addEventListener(
        "change",
        renderHistoryCharts
    );

    if (refreshButton) {
        refreshButton.addEventListener(
            "click",
            loadHistoryCharts
        );
    }

    window.addEventListener(
        "resize",
        () => {
            clearTimeout(resizeTimer);

            resizeTimer = setTimeout(
                renderHistoryCharts,
                150
            );
        }
    );

    loadHistoryCharts();

    setInterval(
        loadHistoryCharts,
        10000
    );
})();
