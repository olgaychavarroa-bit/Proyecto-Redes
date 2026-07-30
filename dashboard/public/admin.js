"use strict";

(() => {
    const LOGIN_ENDPOINT =
        "/api/v1/auth/login";

    const PROFILE_ENDPOINT =
        "/api/v1/auth/me";

    const DEVICES_ENDPOINT =
        "/api/v1/admin/devices";

    const AUDIT_ENDPOINT =
        "/api/v1/admin/audit?limit=20";


    const TELEMETRY_MAINTENANCE_ENDPOINT =
        "/api/v1/admin/telemetry/maintenance";

    const TELEMETRY_CLEANUP_ENDPOINT =
        "/api/v1/admin/telemetry/cleanup";

    const TELEMETRY_PURGE_ENDPOINT =
        "/api/v1/admin/telemetry/purge";

    let adminAccessToken = null;
    let adminUser = null;
    let adminExpiresAt = null;
    let adminRefreshRunning = false;

    const adminView =
        document.getElementById("view-admin");

    const loginPanel =
        document.getElementById("admin-login-panel");

    const authenticatedPanel =
        document.getElementById(
            "admin-authenticated-panel"
        );

    const loginForm =
        document.getElementById("admin-login-form");

    const usernameInput =
        document.getElementById("admin-username");

    const passwordInput =
        document.getElementById("admin-password");

    const loginButton =
        document.getElementById("admin-login-button");

    const loginMessage =
        document.getElementById(
            "admin-login-message"
        );

    const panelMessage =
        document.getElementById(
            "admin-panel-message"
        );

    const logoutButton =
        document.getElementById(
            "admin-logout-button"
        );

    const refreshButton =
        document.getElementById(
            "refresh-admin-button"
        );

    const devicesTable =
        document.getElementById(
            "admin-devices-table"
        );

    const devicesEmpty =
        document.getElementById(
            "admin-devices-empty"
        );

    const auditTable =
        document.getElementById(
            "admin-audit-table"
        );

    const credentialResult =
        document.getElementById(
            "credential-result"
        );

    const credentialDescription =
        document.getElementById(
            "credential-result-description"
        );

    const credentialApiKey =
        document.getElementById(
            "credential-api-key"
        );

    const selectApiKeyButton =
        document.getElementById(
            "select-api-key-button"
        );

    const hideApiKeyButton =
        document.getElementById(
            "hide-api-key-button"
        );


    const cleanupTelemetryButton =
        document.getElementById(
            "cleanup-telemetry-button"
        );

    const telemetryRetentionDays =
        document.getElementById(
            "telemetry-retention-days"
        );

    const telemetryMaintenanceMessage =
        document.getElementById(
            "telemetry-maintenance-message"
        );

    const purgeTelemetryConfirmation =
        document.getElementById(
            "purge-telemetry-confirmation"
        );

    const purgeTelemetryButton =
        document.getElementById(
            "purge-telemetry-button"
        );


    function escapeAdminHtml(value) {
        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }


    function formatAdminDate(value) {
        if (!value) {
            return "Sin registro";
        }

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {
            return String(value);
        }

        return new Intl.DateTimeFormat(
            "es-CO",
            {
                dateStyle: "short",
                timeStyle: "medium"
            }
        ).format(date);
    }


    function adminAreaLabel(area) {
        const labels = {
            uci: "UCI",
            urgencias: "Urgencias",
            laboratorio: "Laboratorio"
        };

        return labels[
            String(area ?? "").toLowerCase()
        ] ?? String(area ?? "Sin área");
    }


    function adminStatusLabel(status) {
        const labels = {
            active: "Activo",
            revoked: "Revocado"
        };

        return labels[
            String(status ?? "").toLowerCase()
        ] ?? String(status ?? "Desconocido");
    }


    function auditActionLabel(action) {
        const labels = {
            admin_login: "Inicio de sesión",
            admin_user_create:
                "Creación de administrador",
            device_revoke:
                "Revocación de dispositivo",
            device_activate:
                "Reactivación de dispositivo",
            api_key_rotate:
                "Rotación de API Key"
        };

        return labels[action] ?? action;
    }


    function showLoginMessage(
        message,
        type = "error"
    ) {
        loginMessage.hidden = false;
        loginMessage.className =
            `message admin-message ${type}`;

        loginMessage.textContent = message;
    }


    function showPanelMessage(
        message,
        type = ""
    ) {
        panelMessage.className =
            type
                ? `message ${type}`
                : "message";

        panelMessage.textContent = message;
    }


    async function parseResponse(response) {
        const text = await response.text();

        let payload = {};

        if (text) {
            try {
                payload = JSON.parse(text);
            } catch {
                payload = {
                    error:
                        "El servidor devolvió una "
                        + "respuesta no válida."
                };
            }
        }

        if (!response.ok) {
            const error = new Error(
                payload.error
                ?? payload.message
                ?? `Error HTTP ${response.status}`
            );

            error.status = response.status;
            throw error;
        }

        return payload;
    }


    async function protectedRequest(
        endpoint,
        options = {}
    ) {
        if (!adminAccessToken) {
            throw new Error(
                "No existe una sesión administrativa."
            );
        }

        const headers = {
            Accept: "application/json",
            Authorization:
                `Bearer ${adminAccessToken}`,
            ...(options.headers ?? {})
        };

        const response = await fetch(
            endpoint,
            {
                ...options,
                cache: "no-store",
                headers
            }
        );

        try {
            return await parseResponse(response);
        } catch (error) {
            if (error.status === 401) {
                logoutAdmin(
                    "La sesión expiró o dejó de ser válida."
                );
            }

            throw error;
        }
    }


    function setAuthenticatedState(
        authenticated
    ) {
        loginPanel.hidden = authenticated;
        authenticatedPanel.hidden =
            !authenticated;
    }


    function updateSessionInformation() {
        document.getElementById(
            "admin-session-user"
        ).textContent =
            adminUser?.username ?? "—";

        document.getElementById(
            "admin-session-role"
        ).textContent =
            adminUser?.role ?? "—";

        document.getElementById(
            "admin-session-expiration"
        ).textContent =
            adminExpiresAt
                ? (
                    "JWT válido hasta "
                    + formatAdminDate(
                        adminExpiresAt
                    )
                )
                : "Sin fecha de expiración";
    }


    function logoutAdmin(message = null) {
        adminAccessToken = null;
        adminUser = null;
        adminExpiresAt = null;

        devicesTable.innerHTML = "";
        auditTable.innerHTML = "";

        hideCredentialResult();
        setAuthenticatedState(false);

        passwordInput.value = "";

        if (message) {
            showLoginMessage(
                message,
                "error"
            );
        } else {
            loginMessage.hidden = true;
        }
    }


    async function loginAdmin(event) {
        event.preventDefault();

        loginButton.disabled = true;
        loginMessage.hidden = true;

        const username =
            usernameInput.value
                .trim()
                .toLowerCase();

        const password =
            passwordInput.value;

        try {
            const response = await fetch(
                LOGIN_ENDPOINT,
                {
                    method: "POST",
                    cache: "no-store",
                    headers: {
                        Accept: "application/json",
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify({
                        username,
                        password
                    })
                }
            );

            const data =
                await parseResponse(response);

            adminAccessToken =
                data.access_token;

            adminUser =
                data.user;

            adminExpiresAt =
                data.expires_at;

            passwordInput.value = "";

            setAuthenticatedState(true);
            updateSessionInformation();

            await loadAdminPanel();

        } catch (error) {
            passwordInput.value = "";

            showLoginMessage(
                error.message,
                "error"
            );
        } finally {
            loginButton.disabled = false;
        }
    }


    async function loadProfile() {
        const profile = await protectedRequest(
            PROFILE_ENDPOINT
        );

        adminUser = {
            id: profile.id,
            username: profile.username,
            role: profile.role,
            status: profile.status
        };

        updateSessionInformation();
    }


    function renderAdminSummary(
        devices,
        audits
    ) {
        const active = devices.filter(
            device => (
                device.status === "active"
            )
        ).length;

        const revoked = devices.filter(
            device => (
                device.status === "revoked"
            )
        ).length;

        document.getElementById(
            "admin-device-total"
        ).textContent =
            String(devices.length);

        document.getElementById(
            "admin-device-active"
        ).textContent =
            String(active);

        document.getElementById(
            "admin-device-revoked"
        ).textContent =
            String(revoked);

        document.getElementById(
            "admin-audit-count"
        ).textContent =
            String(audits.length);
    }


    function actionButtons(device) {
        if (adminUser?.role !== "admin") {
            return `
                <span class="admin-readonly">
                    Solo lectura
                </span>
            `;
        }

        if (device.status === "revoked") {
            return `
                <button
                    type="button"
                    class="admin-action-button
                    admin-action-activate"
                    data-admin-action="activate"
                    data-device-id="${escapeAdminHtml(
                        device.device_id
                    )}"
                >
                    Reactivar
                </button>
            `;
        }

        return `
            <div class="admin-action-group">
                <button
                    type="button"
                    class="admin-action-button
                    admin-action-rotate"
                    data-admin-action="rotate"
                    data-device-id="${escapeAdminHtml(
                        device.device_id
                    )}"
                >
                    Rotar
                </button>

                <button
                    type="button"
                    class="admin-action-button
                    admin-action-revoke"
                    data-admin-action="revoke"
                    data-device-id="${escapeAdminHtml(
                        device.device_id
                    )}"
                >
                    Revocar
                </button>
            </div>
        `;
    }


    function renderAdminDevices(devices) {
        devicesEmpty.hidden =
            devices.length !== 0;

        devicesTable.innerHTML = devices
            .map(device => `
                <tr>
                    <td>
                        <code class="device-id">
                            ${escapeAdminHtml(
                                device.device_id
                            )}
                        </code>

                        <br>

                        <small>
                            ${escapeAdminHtml(
                                device.name
                            )}
                        </small>
                    </td>

                    <td>
                        ${escapeAdminHtml(
                            adminAreaLabel(
                                device.area
                            )
                        )}
                    </td>

                    <td>
                        <span
                            class="device-status-badge
                            ${
                                device.status
                                === "active"
                                    ? "device-status-active"
                                    : "device-status-revoked"
                            }"
                        >
                            ${escapeAdminHtml(
                                adminStatusLabel(
                                    device.status
                                )
                            )}
                        </span>
                    </td>

                    <td>
                        ${escapeAdminHtml(
                            device.credential_version
                            ?? "—"
                        )}
                    </td>

                    <td>
                        <code class="hash-fingerprint">
                            …${escapeAdminHtml(
                                device.hash_fingerprint
                                ?? "sin-huella"
                            )}
                        </code>
                    </td>

                    <td>
                        ${escapeAdminHtml(
                            formatAdminDate(
                                device
                                    .last_key_rotation_at
                            )
                        )}
                    </td>

                    <td>
                        ${escapeAdminHtml(
                            formatAdminDate(
                                device.last_seen_at
                            )
                        )}
                    </td>

                    <td>
                        ${actionButtons(device)}
                    </td>
                </tr>
            `)
            .join("");
    }


    function renderAudit(audits) {
        auditTable.innerHTML = audits
            .map(record => {
                const details = (
                    record.details
                    && typeof record.details
                        === "object"
                )
                    ? JSON.stringify(
                        record.details
                    )
                    : String(
                        record.details ?? "{}"
                    );

                return `
                    <tr>
                        <td>
                            ${escapeAdminHtml(
                                formatAdminDate(
                                    record.created_at
                                )
                            )}
                        </td>

                        <td>
                            ${escapeAdminHtml(
                                record.actor_id
                                ?? record.actor_type
                                ?? "sistema"
                            )}
                        </td>

                        <td>
                            ${escapeAdminHtml(
                                auditActionLabel(
                                    record.action
                                )
                            )}
                        </td>

                        <td>
                            ${escapeAdminHtml(
                                record.target_device_id
                                ?? "—"
                            )}
                        </td>

                        <td>
                            <span
                                class="audit-result
                                ${
                                    record.result
                                    === "success"
                                        ? "audit-success"
                                        : "audit-failure"
                                }"
                            >
                                ${escapeAdminHtml(
                                    record.result
                                )}
                            </span>
                        </td>

                        <td>
                            <code class="audit-details">
                                ${escapeAdminHtml(
                                    details
                                )}
                            </code>
                        </td>
                    </tr>
                `;
            })
            .join("");
    }



    function formatStorageSize(bytes) {
        const value = Number(bytes);

        if (
            !Number.isFinite(value)
            || value <= 0
        ) {
            return "0 B";
        }

        const units = [
            "B",
            "KB",
            "MB",
            "GB"
        ];

        const index = Math.min(
            Math.floor(
                Math.log(value)
                / Math.log(1024)
            ),
            units.length - 1
        );

        const converted = (
            value
            / Math.pow(1024, index)
        );

        return (
            converted.toLocaleString(
                "es-CO",
                {
                    maximumFractionDigits: 2
                }
            )
            + " "
            + units[index]
        );
    }


    function showTelemetryMaintenanceMessage(
        message,
        type = ""
    ) {
        telemetryMaintenanceMessage.hidden =
            false;

        telemetryMaintenanceMessage.className =
            type
                ? `message ${type}`
                : "message";

        telemetryMaintenanceMessage.textContent =
            message;
    }


    function updatePurgeButton() {
        const isAdmin = (
            adminUser?.role === "admin"
        );

        const confirmationMatches = (
            purgeTelemetryConfirmation.value
                .trim()
            === "ELIMINAR TELEMETRIA"
        );

        purgeTelemetryButton.disabled = !(
            isAdmin
            && confirmationMatches
        );
    }


    function renderTelemetryMaintenance(data) {
        document.getElementById(
            "telemetry-total-rows"
        ).textContent =
            Number(
                data.total_rows ?? 0
            ).toLocaleString("es-CO");

        document.getElementById(
            "telemetry-expired-rows"
        ).textContent =
            Number(
                data.expired_rows ?? 0
            ).toLocaleString("es-CO");

        document.getElementById(
            "telemetry-oldest-date"
        ).textContent =
            formatAdminDate(
                data.oldest_received_at
            );

        document.getElementById(
            "telemetry-table-size"
        ).textContent =
            formatStorageSize(
                data.table_size_bytes
            );

        const retention =
            data.retention ?? {};

        document.getElementById(
            "telemetry-retention-status"
        ).textContent =
            retention.enabled
                ? (
                    "Activa: conserva los "
                    + `${retention.days} días `
                    + "más recientes y se "
                    + "revisa automáticamente."
                )
                : "Desactivada";

        const isAdmin = (
            adminUser?.role === "admin"
        );

        cleanupTelemetryButton.disabled =
            !isAdmin;

        purgeTelemetryConfirmation.disabled =
            !isAdmin;

        updatePurgeButton();
    }


    async function cleanupOldTelemetry() {
        const retentionDays = Number(
            telemetryRetentionDays.value
        );

        const confirmed = window.confirm(
            "Se eliminarán las mediciones "
            + `con más de ${retentionDays} días. `
            + "Los dispositivos, credenciales "
            + "y administradores se conservarán."
        );

        if (!confirmed) {
            return;
        }

        cleanupTelemetryButton.disabled = true;

        showTelemetryMaintenanceMessage(
            "Ejecutando limpieza de telemetría..."
        );

        try {
            const result =
                await protectedRequest(
                    TELEMETRY_CLEANUP_ENDPOINT,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            retention_days:
                                retentionDays
                        })
                    }
                );

            await loadAdminPanel(true);

            showTelemetryMaintenanceMessage(
                "Limpieza completada. "
                + "Registros eliminados: "
                + `${result.deleted_rows}.`,
                "success"
            );

        } catch (error) {
            showTelemetryMaintenanceMessage(
                "La limpieza no pudo "
                + "completarse: "
                + error.message,
                "error"
            );

        } finally {
            cleanupTelemetryButton.disabled =
                adminUser?.role !== "admin";
        }
    }


    async function purgeAllTelemetry() {
        const confirmation = (
            purgeTelemetryConfirmation.value
                .trim()
        );

        if (
            confirmation
            !== "ELIMINAR TELEMETRIA"
        ) {
            return;
        }

        const confirmed = window.confirm(
            "Esta operación eliminará TODAS "
            + "las mediciones de telemetría. "
            + "Esta acción no se puede deshacer."
        );

        if (!confirmed) {
            return;
        }

        purgeTelemetryButton.disabled = true;

        showTelemetryMaintenanceMessage(
            "Vaciando la tabla de telemetría..."
        );

        try {
            const result =
                await protectedRequest(
                    TELEMETRY_PURGE_ENDPOINT,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            confirmation:
                                "ELIMINAR TELEMETRIA"
                        })
                    }
                );

            purgeTelemetryConfirmation.value =
                "";

            await loadAdminPanel(true);

            showTelemetryMaintenanceMessage(
                "Telemetría eliminada. "
                + "Registros borrados: "
                + `${result.deleted_rows}.`,
                "success"
            );

        } catch (error) {
            showTelemetryMaintenanceMessage(
                "No fue posible vaciar "
                + "la telemetría: "
                + error.message,
                "error"
            );
        }

        updatePurgeButton();
    }


    async function loadAdminPanel(
        silent = false
    ) {
        if (
            !adminAccessToken
            || adminRefreshRunning
        ) {
            return;
        }

        adminRefreshRunning = true;
        refreshButton.disabled = true;

        if (!silent) {
            showPanelMessage(
                "Consultando información administrativa..."
            );
        }

        try {
            const [
                profile,
                devices,
                audits,
                telemetryMaintenance
            ] = await Promise.all([
                protectedRequest(
                    PROFILE_ENDPOINT
                ),

                protectedRequest(
                    DEVICES_ENDPOINT
                ),

                protectedRequest(
                    AUDIT_ENDPOINT
                ),

                protectedRequest(
                    TELEMETRY_MAINTENANCE_ENDPOINT
                )
            ]);

            adminUser = {
                id: profile.id,
                username: profile.username,
                role: profile.role,
                status: profile.status
            };

            updateSessionInformation();
            renderAdminSummary(devices, audits);
            renderAdminDevices(devices);
            renderAudit(audits);
            renderTelemetryMaintenance(
                telemetryMaintenance
            );

            if (!silent) {
                showPanelMessage(
                    "Información administrativa "
                    + "actualizada correctamente.",
                    "success"
                );
            }

        } catch (error) {
            if (adminAccessToken) {
                showPanelMessage(
                    "No fue posible actualizar el "
                    + "panel: "
                    + error.message,
                    "error"
                );
            }
        } finally {
            adminRefreshRunning = false;
            refreshButton.disabled = false;
        }
    }


    function showCredentialResult(
        deviceId,
        action,
        apiKey
    ) {
        const actionLabels = {
            activate:
                "Reactivación del dispositivo",
            rotate:
                "Rotación de API Key"
        };

        credentialDescription.textContent =
            `${actionLabels[action]} `
            + `para ${deviceId}. Guarda esta `
            + "clave antes de ocultarla.";

        credentialApiKey.value = apiKey;
        credentialResult.hidden = false;

        credentialResult.scrollIntoView({
            behavior: "smooth",
            block: "center"
        });
    }


    function hideCredentialResult() {
        credentialApiKey.value = "";
        credentialResult.hidden = true;
    }


    async function executeAdminAction(
        action,
        deviceId
    ) {
        const confirmationMessages = {
            revoke:
                `¿Confirmas la revocación de `
                + `${deviceId}? El nodo dejará `
                + "de enviar telemetría válida.",

            activate:
                `¿Confirmas la reactivación de `
                + `${deviceId}? Se generará una `
                + "API Key nueva y el archivo del "
                + "simulador se actualizará "
                + "automáticamente.",

            rotate:
                `¿Confirmas la rotación de la `
                + `API Key de ${deviceId}? La nueva `
                + "clave se guardará automáticamente "
                + "y la anterior tendrá un periodo "
                + "temporal de gracia."
        };

        if (
            !window.confirm(
                confirmationMessages[action]
            )
        ) {
            return;
        }

        const methods = {
            revoke: "PATCH",
            activate: "PATCH",
            rotate: "POST"
        };

        showPanelMessage(
            `Ejecutando ${action} sobre `
            + `${deviceId}...`
        );

        try {
            const result = await protectedRequest(
                `/api/v1/admin/devices/`
                + `${encodeURIComponent(deviceId)}`
                + `/${action}`,
                {
                    method: methods[action]
                }
            );

            if (result.api_key) {
                showCredentialResult(
                    deviceId,
                    action,
                    result.api_key
                );
            }

            await loadAdminPanel(true);

            showPanelMessage(
                result.message
                ?? result.warning
                ?? "Operación completada.",
                "success"
            );

        } catch (error) {
            showPanelMessage(
                "La operación no pudo completarse: "
                + error.message,
                "error"
            );
        }
    }



    cleanupTelemetryButton.addEventListener(
        "click",
        cleanupOldTelemetry
    );


    purgeTelemetryConfirmation.addEventListener(
        "input",
        updatePurgeButton
    );


    purgeTelemetryButton.addEventListener(
        "click",
        purgeAllTelemetry
    );


    loginForm.addEventListener(
        "submit",
        loginAdmin
    );


    logoutButton.addEventListener(
        "click",
        () => logoutAdmin()
    );


    refreshButton.addEventListener(
        "click",
        () => loadAdminPanel()
    );


    devicesTable.addEventListener(
        "click",
        event => {
            const button = event.target.closest(
                "[data-admin-action]"
            );

            if (!button) {
                return;
            }

            executeAdminAction(
                button.dataset.adminAction,
                button.dataset.deviceId
            );
        }
    );


    selectApiKeyButton.addEventListener(
        "click",
        () => {
            credentialApiKey.focus();
            credentialApiKey.select();
        }
    );


    hideApiKeyButton.addEventListener(
        "click",
        hideCredentialResult
    );


    document.getElementById(
        "tab-admin"
    ).addEventListener(
        "click",
        () => {
            if (adminAccessToken) {
                loadAdminPanel();
            }
        }
    );


    /*
     * Actualización automática cada 10 segundos.
     * Solo funciona mientras exista una sesión y la
     * pestaña Administración esté visible.
     */
    setInterval(
        () => {
            if (
                adminAccessToken
                && !adminView.hidden
            ) {
                loadAdminPanel(true);
            }
        },
        10000
    );


    setAuthenticatedState(false);
})();
