/**
 * NyxOS Dashboard — Scan Viewer Component
 *
 * Visualises nmap port scan results as a table and
 * gobuster/directory-brute results as a list.
 */

'use strict';

class ScanViewer {
    /**
     * @param {HTMLElement} containerEl  The #scan-content element.
     */
    constructor(containerEl) {
        this.container = containerEl;
        this._portClickCb = null;
    }

    /**
     * Render nmap port scan results.
     *
     * @param {object} scanData
     *   {
     *     hosts: [{
     *       ip: "192.168.1.1",
     *       hostname: "router.local",
     *       status: "up",
     *       ports: [
     *         { port: 22, protocol: "tcp", state: "open", service: "ssh", version: "OpenSSH 8.9" }
     *       ]
     *     }]
     *   }
     */
    renderPortTable(scanData) {
        this.container.innerHTML = '';

        if (!scanData || !scanData.hosts || scanData.hosts.length === 0) {
            this._showEmpty('No hosts found in scan data.');
            return;
        }

        var hosts = scanData.hosts;
        for (var h = 0; h < hosts.length; h++) {
            var host = hosts[h];
            var card = document.createElement('div');
            card.className = 'scan-host';

            // Host title
            var title = document.createElement('div');
            title.className = 'scan-host-title';
            var hostLabel = host.ip || 'Unknown';
            if (host.hostname) {
                hostLabel += ' (' + this._esc(host.hostname) + ')';
            }
            var statusClass = host.status === 'up' ? 'pill-online' : 'pill-error';
            title.innerHTML = '&#x1F5A5; ' + this._esc(hostLabel) +
                ' <span class="pill ' + statusClass + '">' +
                this._esc(host.status || 'unknown') + '</span>';
            card.appendChild(title);

            // Port table
            if (host.ports && host.ports.length > 0) {
                var table = document.createElement('table');
                table.className = 'port-table';

                var thead = document.createElement('thead');
                thead.innerHTML =
                    '<tr>' +
                    '<th>Port</th>' +
                    '<th>State</th>' +
                    '<th>Service</th>' +
                    '<th>Version</th>' +
                    '</tr>';
                table.appendChild(thead);

                var tbody = document.createElement('tbody');
                for (var p = 0; p < host.ports.length; p++) {
                    var port = host.ports[p];
                    var tr = document.createElement('tr');
                    tr.dataset.port = port.port;
                    tr.dataset.host = host.ip;

                    var stateClass = 'ps-' + (port.state || 'closed');

                    tr.innerHTML =
                        '<td>' + this._esc(String(port.port)) + '/' +
                        this._esc(port.protocol || 'tcp') + '</td>' +
                        '<td class="' + stateClass + '">' +
                        this._esc(port.state || 'unknown') + '</td>' +
                        '<td>' + this._esc(port.service || '\u2014') + '</td>' +
                        '<td>' + this._esc(port.version || '\u2014') + '</td>';

                    // Closure for click handler
                    var self = this;
                    (function (portData, hostIp) {
                        tr.addEventListener('click', function () {
                            if (self._portClickCb) {
                                self._portClickCb(portData, hostIp);
                            }
                        });
                    })(port, host.ip);

                    tbody.appendChild(tr);
                }
                table.appendChild(tbody);
                card.appendChild(table);
            } else {
                var noports = document.createElement('p');
                noports.style.cssText = 'color:var(--text-dim);font-size:12px;padding:8px 0';
                noports.textContent = 'No open ports detected.';
                card.appendChild(noports);
            }

            this.container.appendChild(card);
        }
    }

    /**
     * Render directory brute-force results (gobuster/ffuf).
     *
     * @param {object} dirData
     *   {
     *     target: "http://example.com",
     *     entries: [
     *       { path: "/admin", status: 200, size: 1234 },
     *       { path: "/login", status: 301, size: 0 }
     *     ]
     *   }
     */
    renderDirectoryTree(dirData) {
        this.container.innerHTML = '';

        if (!dirData || !dirData.entries || dirData.entries.length === 0) {
            this._showEmpty('No directories found.');
            return;
        }

        var heading = document.createElement('div');
        heading.className = 'scan-host-title';
        heading.innerHTML = '&#x1F4C2; ' + this._esc(dirData.target || 'Unknown target');
        this.container.appendChild(heading);

        var tree = document.createElement('div');
        tree.className = 'dir-tree';

        // Sort: 200s first, then alphabetical
        var sorted = dirData.entries.slice().sort(function (a, b) {
            if (a.status === 200 && b.status !== 200) return -1;
            if (a.status !== 200 && b.status === 200) return 1;
            return (a.path || '').localeCompare(b.path || '');
        });

        for (var i = 0; i < sorted.length; i++) {
            var entry = sorted[i];
            var item = document.createElement('div');
            item.className = 'dir-item';

            var statusCls = 'ds-' + (entry.status || 0);
            var sizeStr = this._humanSize(entry.size || 0);

            item.innerHTML =
                '<span class="dir-status ' + statusCls + '">' +
                (entry.status || '?') + '</span>' +
                '<span class="dir-path">' + this._esc(entry.path || '/') + '</span>' +
                '<span class="dir-size">' + sizeStr + '</span>';

            tree.appendChild(item);
        }

        this.container.appendChild(tree);
    }

    /**
     * Register callback for port row clicks.
     * @param {Function} callback  Receives (portObject, hostIp).
     */
    onPortClick(callback) {
        this._portClickCb = callback;
    }

    /** Clear the viewer. */
    clear() {
        this.container.innerHTML = '';
    }

    // ── Private ──

    _showEmpty(msg) {
        this.container.innerHTML =
            '<div class="empty-state">' +
            '<span class="empty-icon">&#x1F50D;</span>' +
            '<p>' + this._esc(msg) + '</p>' +
            '</div>';
    }

    _esc(s) {
        var d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    _humanSize(bytes) {
        if (bytes === 0) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB'];
        var i = 0;
        var val = bytes;
        while (val >= 1024 && i < units.length - 1) {
            val /= 1024;
            i++;
        }
        return val.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
    }
}
