/**
 * GODRECON Dashboard — client-side JavaScript
 * Self-contained, no external dependencies.
 */

(function () {
    "use strict";

    // -----------------------------------------------------------------------
    // Auto-refresh for active scans
    // -----------------------------------------------------------------------
    const AUTO_REFRESH_MS = 5000;

    function setupAutoRefresh() {
        const activeEl = document.querySelector(".status-running, .status-pending");
        if (activeEl) {
            setTimeout(() => location.reload(), AUTO_REFRESH_MS);
        }
    }

    // -----------------------------------------------------------------------
    // Generic table client-side filter
    // -----------------------------------------------------------------------

    /**
     * Attach a live filter to an input element that filters rows of a table.
     * @param {string} inputId  - ID of the text input.
     * @param {string} tableId  - ID of the <table> element.
     */
    function filterTable(inputId, tableId) {
        const input = document.getElementById(inputId);
        const table = document.getElementById(tableId);
        if (!input || !table) return;
        input.addEventListener("input", function () {
            const q = this.value.toLowerCase();
            table.querySelectorAll("tbody tr").forEach(function (row) {
                row.style.display = row.textContent.toLowerCase().includes(q) ? "" : "none";
            });
        });
    }

    // -----------------------------------------------------------------------
    // Quick scan form (index page)
    // -----------------------------------------------------------------------

    function setupQuickScan() {
        const form = document.getElementById("quick-scan-form");
        if (!form) return;
        form.addEventListener("submit", async function (e) {
            e.preventDefault();
            const targetInput = document.getElementById("qs-target");
            const statusEl = document.getElementById("qs-status");
            const target = (targetInput && targetInput.value.trim()) || "";
            if (!target) {
                if (statusEl) { statusEl.textContent = "Please enter a target."; }
                return;
            }
            if (statusEl) {
                statusEl.textContent = "Starting scan…";
                statusEl.style.color = "";
            }
            try {
                const resp = await fetch("/api/v1/scan", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ target: target }),
                });
                if (resp.ok) {
                    const data = await resp.json();
                    if (statusEl) {
                        statusEl.textContent = "Scan started! ID: " + data.scan_id;
                        statusEl.style.color = "var(--green)";
                    }
                    setTimeout(function () {
                        location.href = "/dashboard/scans/" + data.scan_id;
                    }, 1500);
                } else {
                    const err = await resp.json().catch(() => ({}));
                    if (statusEl) {
                        statusEl.textContent = "Error: " + (err.detail || resp.statusText);
                        statusEl.style.color = "var(--red)";
                    }
                }
            } catch (err) {
                if (statusEl) {
                    statusEl.textContent = "Error: " + err.message;
                    statusEl.style.color = "var(--red)";
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Scan detail: live poll while scan is running
    // -----------------------------------------------------------------------

    function setupScanPoll() {
        const scanIdEl = document.getElementById("scan-id-data");
        if (!scanIdEl) return;
        const scanId = scanIdEl.dataset.scanId;
        const statusEl = document.querySelector(".scan-status-badge");
        if (!scanId || !statusEl) return;
        const active = ["running", "pending"];
        if (!active.includes(statusEl.dataset.status || "")) return;

        function poll() {
            fetch("/api/v1/scan/" + scanId)
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (!active.includes(data.status)) {
                        // Refresh page to show full results
                        location.reload();
                    } else {
                        setTimeout(poll, AUTO_REFRESH_MS);
                    }
                })
                .catch(function () {
                    setTimeout(poll, AUTO_REFRESH_MS * 2);
                });
        }
        setTimeout(poll, AUTO_REFRESH_MS);
    }

    // -----------------------------------------------------------------------
    // Init
    // -----------------------------------------------------------------------

    document.addEventListener("DOMContentLoaded", function () {
        setupAutoRefresh();
        setupQuickScan();
        setupScanPoll();

        // Wire up any filter inputs declared with data-filter-table attribute
        document.querySelectorAll("[data-filter-table]").forEach(function (input) {
            filterTable(input.id, input.dataset.filterTable);
        });
    });

    // Expose filterTable globally for inline calls in templates
    window.filterTable = filterTable;
})();
