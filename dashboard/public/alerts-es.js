"use strict";

(() => {
    /*
     * Este archivo complementa la interfaz de monitoreo:
     *
     * 1. Traduce los estados al español.
     * 2. Identifica qué sensor está en alarma.
     * 3. Resalta visualmente el sensor.
     * 4. Agrega una explicación debajo de la tarjeta.
     *
     * No modifica datos ni llamadas al backend.
     */

    const areaCardsContainer =
        document.getElementById("area-cards");

    const telemetryTable =
        document.getElementById("telemetry-table");

    if (!areaCardsContainer) {
        console.warn(
            "[alertas-es] No se encontró #area-cards"
        );

        return;
    }

    const STATE_TRANSLATIONS = {
        normal: "NORMAL",
        warning: "ADVERTENCIA",
        critical: "CRÍTICA",
        advertencia: "ADVERTENCIA",
        critica: "CRÍTICA",
        crítica: "CRÍTICA"
    };

    const SENSOR_CONFIG = {
        temperature: {
            labels: [
                "temperatura",
                "temperature"
            ],

            displayName: "Temperatura",
            unit: "°C"
        },

        humidity: {
            labels: [
                "humedad",
                "humidity"
            ],

            displayName: "Humedad",
            unit: "%"
        },

        co2: {
            labels: [
                "co₂",
                "co2",
                "co 2"
            ],

            displayName: "CO₂",
            unit: "ppm"
        }
    };

    let processing = false;
    let updateTimer = null;


    function normalizeText(value) {
        return String(value ?? "")
            .trim()
            .toLowerCase()
            .normalize("NFD")
            .replace(
                /[\u0300-\u036f]/g,
                ""
            )
            .replace(/\s+/g, " ");
    }


    function parseDisplayedNumber(value) {
        const text = String(value ?? "");

        const match = text.match(
            /-?\d+(?:[.,]\d+)?/
        );

        if (!match) {
            return null;
        }

        const normalized = match[0]
            .replace(",", ".");

        const number = Number(normalized);

        return Number.isFinite(number)
            ? number
            : null;
    }


    function formatSensorValue(
        value,
        sensor
    ) {
        if (!Number.isFinite(value)) {
            return "sin valor";
        }

        if (sensor === "co2") {
            return (
                Math.round(value)
                    .toLocaleString("es-CO")
                + " ppm"
            );
        }

        return (
            value.toLocaleString(
                "es-CO",
                {
                    minimumFractionDigits: 1,
                    maximumFractionDigits: 1
                }
            )
            + " "
            + SENSOR_CONFIG[sensor].unit
        );
    }


    /*
     * Límites visuales que ya utiliza el prototipo:
     *
     * Temperatura:
     * normal      18–27 °C
     * advertencia 15–18 o 27–30 °C
     * crítica     menor de 15 o mayor de 30 °C
     *
     * Humedad:
     * normal      30–70 %
     * advertencia 20–30 o 70–80 %
     * crítica     menor de 20 o mayor de 80 %
     *
     * CO₂:
     * normal      hasta 1000 ppm
     * advertencia mayor de 1000 hasta 1500 ppm
     * crítica     mayor de 1500 ppm
     */

    function classifySensor(
        sensor,
        value
    ) {
        if (!Number.isFinite(value)) {
            return {
                severity: "unknown",
                direction: null
            };
        }

        if (sensor === "temperature") {
            if (value < 15) {
                return {
                    severity: "critical",
                    direction: "baja"
                };
            }

            if (value > 30) {
                return {
                    severity: "critical",
                    direction: "alta"
                };
            }

            if (value < 18) {
                return {
                    severity: "warning",
                    direction: "baja"
                };
            }

            if (value > 27) {
                return {
                    severity: "warning",
                    direction: "alta"
                };
            }

            return {
                severity: "normal",
                direction: null
            };
        }

        if (sensor === "humidity") {
            if (value < 20) {
                return {
                    severity: "critical",
                    direction: "baja"
                };
            }

            if (value > 80) {
                return {
                    severity: "critical",
                    direction: "alta"
                };
            }

            if (value < 30) {
                return {
                    severity: "warning",
                    direction: "baja"
                };
            }

            if (value > 70) {
                return {
                    severity: "warning",
                    direction: "alta"
                };
            }

            return {
                severity: "normal",
                direction: null
            };
        }

        if (sensor === "co2") {
            if (value > 1500) {
                return {
                    severity: "critical",
                    direction: "alto"
                };
            }

            if (value > 1000) {
                return {
                    severity: "warning",
                    direction: "alto"
                };
            }

            return {
                severity: "normal",
                direction: null
            };
        }

        return {
            severity: "unknown",
            direction: null
        };
    }


    function isSensorLabel(
        element,
        sensor
    ) {
        if (
            !element
            || element.children.length !== 0
        ) {
            return false;
        }

        const text = normalizeText(
            element.textContent
        );

        return SENSOR_CONFIG[sensor].labels
            .some(
                label => (
                    text
                    === normalizeText(label)
                )
            );
    }


    function findSensorLabelElement(
        card,
        sensor
    ) {
        return Array.from(
            card.querySelectorAll("*")
        ).find(
            element => isSensorLabel(
                element,
                sensor
            )
        ) ?? null;
    }


    /*
     * Busca el recuadro que contiene:
     *
     * Temperatura
     * 24.3 °C
     *
     * Se limita el ascenso para no seleccionar
     * accidentalmente toda la tarjeta.
     */

    function findSensorBlock(
        card,
        sensor
    ) {
        const labelElement =
            findSensorLabelElement(
                card,
                sensor
            );

        if (!labelElement) {
            return null;
        }

        let current =
            labelElement.parentElement;

        for (
            let level = 0;
            level < 4 && current;
            level += 1
        ) {
            if (current === card) {
                break;
            }

            const text = current.textContent;

            const hasUnit = (
                sensor === "temperature"
                    ? text.includes("°C")
                    : sensor === "humidity"
                        ? text.includes("%")
                        : normalizeText(text)
                            .includes("ppm")
            );

            if (
                hasUnit
                && text.length < 120
            ) {
                return current;
            }

            current = current.parentElement;
        }

        return labelElement.parentElement;
    }


    function sensorValueFromBlock(
        block,
        sensor
    ) {
        if (!block) {
            return null;
        }

        const text = block.textContent;

        let pattern;

        if (sensor === "temperature") {
            pattern =
                /(-?\d+(?:[.,]\d+)?)\s*°C/i;
        } else if (sensor === "humidity") {
            pattern =
                /(-?\d+(?:[.,]\d+)?)\s*%/i;
        } else {
            pattern =
                /(-?\d+(?:[.,]\d+)?)\s*ppm/i;
        }

        const match = text.match(pattern);

        return match
            ? parseDisplayedNumber(match[1])
            : null;
    }


    function removePreviousSensorState(
        block
    ) {
        if (!block) {
            return;
        }

        block.classList.remove(
            "sensor-state-normal",
            "sensor-state-warning",
            "sensor-state-critical"
        );

        block.querySelectorAll(
            ".sensor-state-label"
        ).forEach(
            element => element.remove()
        );
    }


    function addSensorState(
        block,
        classification
    ) {
        if (!block) {
            return;
        }

        removePreviousSensorState(block);

        if (
            classification.severity
            === "unknown"
        ) {
            return;
        }

        block.classList.add(
            `sensor-state-${
                classification.severity
            }`
        );

        const label =
            document.createElement("span");

        label.className =
            "sensor-state-label";

        label.textContent =
            STATE_TRANSLATIONS[
                classification.severity
            ];

        block.appendChild(label);
    }


    function updateStatusBadge(
        card,
        severity
    ) {
        const acceptedTexts = new Set([
            "normal",
            "warning",
            "critical",
            "advertencia",
            "critica"
        ]);

        const candidates = Array.from(
            card.querySelectorAll("*")
        ).filter(
            element => (
                element.children.length === 0
                && acceptedTexts.has(
                    normalizeText(
                        element.textContent
                    )
                )
            )
        );

        if (candidates.length === 0) {
            return;
        }

        /*
         * Preferimos un elemento cuyo nombre de clase
         * contenga status, state o badge.
         */

        const badge = candidates.find(
            element => (
                /status|state|badge/i.test(
                    element.className
                )
            )
        ) ?? candidates[0];

        badge.textContent =
            STATE_TRANSLATIONS[severity]
            ?? "NORMAL";

        badge.classList.remove(
            "translated-status-normal",
            "translated-status-warning",
            "translated-status-critical"
        );

        badge.classList.add(
            `translated-status-${severity}`
        );
    }


    function severityRank(severity) {
        const ranks = {
            normal: 0,
            warning: 1,
            critical: 2
        };

        return ranks[severity] ?? -1;
    }


    function overallSeverity(alerts) {
        if (
            alerts.some(
                alert => (
                    alert.classification
                        .severity
                    === "critical"
                )
            )
        ) {
            return "critical";
        }

        if (
            alerts.some(
                alert => (
                    alert.classification
                        .severity
                    === "warning"
                )
            )
        ) {
            return "warning";
        }

        return "normal";
    }


    function createAlertDescription(
        alert
    ) {
        const {
            sensor,
            value,
            classification
        } = alert;

        const sensorName =
            SENSOR_CONFIG[sensor].displayName;

        const direction =
            classification.direction;

        return (
            `${sensorName} ${direction}: `
            + formatSensorValue(
                value,
                sensor
            )
        );
    }


    function renderCardAlertDetails(
        card,
        alerts,
        severity
    ) {
        card.querySelectorAll(
            ".area-alert-detail"
        ).forEach(
            element => element.remove()
        );

        if (
            severity === "normal"
            || alerts.length === 0
        ) {
            return;
        }

        const detail =
            document.createElement("div");

        detail.className =
            `area-alert-detail `
            + `area-alert-${severity}`;

        const heading =
            document.createElement("strong");

        heading.className =
            "area-alert-heading";

        heading.textContent = (
            severity === "critical"
                ? "Alerta crítica detectada"
                : "Advertencia detectada"
        );

        detail.appendChild(heading);

        const list =
            document.createElement("ul");

        alerts
            .sort(
                (
                    first,
                    second
                ) => (
                    severityRank(
                        second.classification
                            .severity
                    )
                    - severityRank(
                        first.classification
                            .severity
                    )
                )
            )
            .forEach(alert => {
                const item =
                    document.createElement("li");

                item.textContent =
                    createAlertDescription(
                        alert
                    );

                list.appendChild(item);
            });

        detail.appendChild(list);
        card.appendChild(detail);
    }


    function processAreaCard(card) {
        const alerts = [];

        for (
            const sensor
            of Object.keys(SENSOR_CONFIG)
        ) {
            const block = findSensorBlock(
                card,
                sensor
            );

            if (!block) {
                continue;
            }

            const value =
                sensorValueFromBlock(
                    block,
                    sensor
                );

            const classification =
                classifySensor(
                    sensor,
                    value
                );

            addSensorState(
                block,
                classification
            );

            if (
                classification.severity
                === "warning"
                || classification.severity
                === "critical"
            ) {
                alerts.push({
                    sensor,
                    value,
                    classification
                });
            }
        }

        const severity =
            overallSeverity(alerts);

        updateStatusBadge(
            card,
            severity
        );

        renderCardAlertDetails(
            card,
            alerts,
            severity
        );
    }


    function translateTableStates() {
        if (!telemetryTable) {
            return;
        }

        Array.from(
            telemetryTable.querySelectorAll("*")
        ).forEach(element => {
            if (
                element.children.length !== 0
            ) {
                return;
            }

            const normalized =
                normalizeText(
                    element.textContent
                );

            const translated =
                STATE_TRANSLATIONS[normalized];

            if (
                translated
                && element.textContent
                !== translated
            ) {
                element.textContent =
                    translated;
            }
        });
    }


    function processMonitoringAlerts() {
        if (processing) {
            return;
        }

        processing = true;

        try {
            const cards = Array.from(
                areaCardsContainer.children
            ).filter(
                element => (
                    element.nodeType
                    === Node.ELEMENT_NODE
                )
            );

            cards.forEach(
                processAreaCard
            );

            translateTableStates();

        } finally {
            processing = false;
        }
    }


    function scheduleUpdate() {
        clearTimeout(updateTimer);

        updateTimer = setTimeout(
            processMonitoringAlerts,
            50
        );
    }


    /*
     * app.js vuelve a renderizar las tarjetas
     * periódicamente. El observador ejecuta de nuevo
     * esta mejora después de cada actualización.
     */

    const observer =
        new MutationObserver(scheduleUpdate);

    observer.observe(
        areaCardsContainer,
        {
            childList: true,
            subtree: true,
            characterData: true
        }
    );

    if (telemetryTable) {
        observer.observe(
            telemetryTable,
            {
                childList: true,
                subtree: true,
                characterData: true
            }
        );
    }

    processMonitoringAlerts();
})();
