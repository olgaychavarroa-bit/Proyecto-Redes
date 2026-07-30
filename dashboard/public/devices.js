"use strict";

const DEVICES_ENDPOINT = "/api/v1/devices/overview";

const tabButtons = document.querySelectorAll(
    ".dashboard-tab"
);

const dashboardViews = document.querySelectorAll(
    ".dashboard-view"
);

const devicesTable = document.getElementById(
    "devices-table"
);

const devicesMessage = document.getElementById(
    "devices-message"
);

const devicesEmpty = document.getElementById(
    "devices-empty"
);

const refreshDevicesButton = document.getElementById(
    "refresh-devices-button"
);

const areaFilter = document.getElementById(
    "device-area-filter"
);

const statusFilter = document.getElementById(
    "device-status-filter"
);

let devicesCache = [];
let devicesLoaded = false;


function escapeDeviceHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function areaLabel(area) {
    const labels = {
        uci: "UCI",
        urgencias: "Urgencias",
        laboratorio: "Laboratorio"
    };

    return labels[
        String(area ?? "").toLowerCase()
    ] ?? String(area ?? "Sin área");
}


function statusLabel(status) {
    const labels = {
        active: "Activo",
        revoked: "Revocado"
    };

    return labels[
        String(status ?? "").toLowerCase()
    ] ?? String(status ?? "Desconocido");
}


function statusClass(status) {
    if (status === "active") {
        return "device-status-active";
    }

    if (status === "revoked") {
        return "device-status-revoked";
    }

    return "device-status-unknown";
}


function formatDeviceDate(value) {
    if (!value) {
        return "Sin registro";
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


function relativeDate(value) {
    if (!value) {
        return "Nunca ha enviado datos";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    const differenceSeconds = Math.floor(
        (Date.now() - date.getTime()) / 1000
    );

    if (differenceSeconds < 0) {
        return formatDeviceDate(value);
    }

    if (differenceSeconds < 60) {
        return `Hace ${differenceSeconds} s`;
    }

    const minutes = Math.floor(
        differenceSeconds / 60
    );

    if (minutes < 60) {
        return `Hace ${minutes} min`;
    }

    const hours = Math.floor(
        minutes / 60
    );

    if (hours < 24) {
        return `Hace ${hours} h`;
    }

    const days = Math.floor(
        hours / 24
    );

    return `Hace ${days} día${days === 1 ? "" : "s"}`;
}


function updateDeviceSummary(devices) {
    const active = devices.filter(
        device => device.status === "active"
    ).length;

    const revoked = devices.filter(
        device => device.status === "revoked"
    ).length;

    const neverSeen = devices.filter(
        device => !device.last_seen_at
    ).length;

    document.getElementById(
        "device-total"
    ).textContent = String(devices.length);

    document.getElementById(
        "device-active"
    ).textContent = String(active);

    document.getElementById(
        "device-revoked"
    ).textContent = String(revoked);

    document.getElementById(
        "device-never-seen"
    ).textContent = String(neverSeen);
}


function filteredDevices() {
    const selectedArea = areaFilter.value;
    const selectedStatus = statusFilter.value;

    return devicesCache.filter(device => {
        const areaMatches = (
            selectedArea === "all"
            || device.area === selectedArea
        );

        const statusMatches = (
            selectedStatus === "all"
            || device.status === selectedStatus
        );

        return areaMatches && statusMatches;
    });
}


function renderDevices() {
    const devices = filteredDevices();

    devicesEmpty.hidden = devices.length !== 0;

    devicesTable.innerHTML = devices
        .map(device => `
            <tr>
                <td>
                    <code class="device-id">
                        ${escapeDeviceHtml(device.device_id)}
                    </code>
                </td>

                <td>
                    ${escapeDeviceHtml(device.name)}
                </td>

                <td>
                    ${escapeDeviceHtml(
                        areaLabel(device.area)
                    )}
                </td>

                <td>
                    <span
                        class="device-status-badge
                        ${statusClass(device.status)}"
                    >
                        ${escapeDeviceHtml(
                            statusLabel(device.status)
                        )}
                    </span>
                </td>

                <td>
                    <span
                        title="${escapeDeviceHtml(
                            formatDeviceDate(
                                device.last_seen_at
                            )
                        )}"
                    >
                        ${escapeDeviceHtml(
                            relativeDate(
                                device.last_seen_at
                            )
                        )}
                    </span>
                </td>

                <td>
                    ${escapeDeviceHtml(
                        formatDeviceDate(
                            device.created_at
                        )
                    )}
                </td>
            </tr>
        `)
        .join("");
}


async function requestDevices() {
    const controller = new AbortController();

    const timeout = setTimeout(
        () => controller.abort(),
        8000
    );

    try {
        const response = await fetch(
            DEVICES_ENDPOINT,
            {
                method: "GET",
                cache: "no-store",
                headers: {
                    Accept: "application/json"
                },
                signal: controller.signal
            }
        );

        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status}`
            );
        }

        const payload = await response.json();

        if (!Array.isArray(payload)) {
            throw new Error(
                "La API no devolvió una lista"
            );
        }

        return payload.map(device => ({
            id: device.id,
            device_id: String(
                device.device_id ?? ""
            ),
            name: String(
                device.name ?? "Sin nombre"
            ),
            area: String(
                device.area ?? ""
            ).toLowerCase(),
            status: String(
                device.status ?? ""
            ).toLowerCase(),
            created_at: device.created_at ?? null,
            updated_at: device.updated_at ?? null,
            last_seen_at: device.last_seen_at ?? null
        }));
    } finally {
        clearTimeout(timeout);
    }
}


async function loadDevices() {
    refreshDevicesButton.disabled = true;

    devicesMessage.className = "message";
    devicesMessage.textContent =
        "Consultando dispositivos registrados...";

    try {
        devicesCache = await requestDevices();
        devicesLoaded = true;

        updateDeviceSummary(devicesCache);
        renderDevices();

        devicesMessage.className =
            "message success";

        devicesMessage.textContent =
            `Consulta correcta: ${devicesCache.length} `
            + "dispositivo(s) registrado(s).";
    } catch (error) {
        devicesMessage.className =
            "message error";

        devicesMessage.textContent =
            "No fue posible consultar los dispositivos: "
            + error.message;
    } finally {
        refreshDevicesButton.disabled = false;
    }
}


function showView(viewName) {
    dashboardViews.forEach(view => {
        const isSelected = (
            view.id === `view-${viewName}`
        );

        view.hidden = !isSelected;
    });

    tabButtons.forEach(button => {
        const isSelected = (
            button.dataset.view === viewName
        );

        button.classList.toggle(
            "active",
            isSelected
        );

        button.setAttribute(
            "aria-selected",
            String(isSelected)
        );
    });

    const monitoringRefresh = document.getElementById(
        "refresh-button"
    );

    if (monitoringRefresh) {
        monitoringRefresh.hidden = (
            viewName !== "monitoring"
        );
    }

    if (
        viewName === "devices"
        && !devicesLoaded
    ) {
        loadDevices();
    }
}


tabButtons.forEach(button => {
    button.addEventListener(
        "click",
        () => showView(
            button.dataset.view
        )
    );
});


refreshDevicesButton.addEventListener(
    "click",
    loadDevices
);


areaFilter.addEventListener(
    "change",
    renderDevices
);


statusFilter.addEventListener(
    "change",
    renderDevices
);


/*
 * Actualiza el tiempo relativo mostrado sin consultar
 * nuevamente el backend.
 */
setInterval(
    () => {
        const devicesView = document.getElementById(
            "view-devices"
        );

        if (
            devicesLoaded
            && !devicesView.hidden
        ) {
            renderDevices();
        }
    },
    30000
);
