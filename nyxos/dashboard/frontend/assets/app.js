/**
 * NyxOS Dashboard — Main Application Logic
 *
 * Initialises all components, manages WebSocket connection with
 * exponential-backoff reconnect, handles API calls, and wires
 * up all user interactions.
 */

'use strict';

class NyxDashboard {
    constructor() {
        /** @type {TerminalComponent|null} */
        this.terminal = null;
        /** @type {ScanViewer|null} */
        this.scanViewer = null;
        /** @type {FindingsPanel|null} */
        this.findingsPanel = null;
        /** @type {WebSocket|null} */
        this.ws = null;

        /** WebSocket reconnect state */
        this._wsRetries = 0;
        this._wsMaxRetries = 20;
        this._wsBaseDelay = 1000;
        this._wsReconnectTimer = null;

        /** @type {string} Base API URL */
        this.apiBase = window.location.origin + '/api';

        /** @type {string} WebSocket URL */
        this.wsUrl = 'ws://' + window.location.host + '/ws/live';

        /** @type {boolean} Is a command currently executing? */
        this.busy = false;

        /** @type {Array<string>} Command history for up/down arrow */
        this.cmdHistory = [];
        this.cmdHistoryIdx = -1;
    }

    /**
     * Initialise all components and event listeners.
     * Call this once on page load.
     */
    init() {
        // Initialise components
        this.terminal = new TerminalComponent(document.getElementById('terminal-output'));
        this.scanViewer = new ScanViewer(document.getElementById('scan-content'));
        this.findingsPanel = new FindingsPanel(document.getElementById('findings-list'));

        // Terminal link click → execute scan on that target
        var self = this;
        this.terminal.setLinkClickHandler(function (value) {
            var input = document.getElementById('cmd-input');
            input.value = 'scan ' + value;
            input.focus();
        });

        // Scan viewer port click → show info in terminal
        this.scanViewer.onPortClick(function (portData, hostIp) {
            self.terminal.appendLine(
                'Port ' + portData.port + '/' + (portData.protocol || 'tcp') +
                ' on ' + hostIp + ' — ' + (portData.service || 'unknown') +
                ' ' + (portData.version || ''),
                'system'
            );
        });

        // Wire up UI events
        this._bindEvents();

        // Connect WebSocket
        this.connectWebSocket();

        // Initial data fetch
        this.refreshStatus();
        this.refreshFindings();
        this.refreshStats();
        this.refreshSkills();

        this.terminal.appendLine('Dashboard initialised. WebSocket connecting...', 'system');
    }

    // ═══════════════ WebSocket ═══════════════

    /** Connect to the WebSocket endpoint with auto-reconnect. */
    connectWebSocket() {
        if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
            return;
        }

        var self = this;

        try {
            this.ws = new WebSocket(this.wsUrl);
        } catch (e) {
            this._scheduleReconnect();
            return;
        }

        this.ws.onopen = function () {
            self._wsRetries = 0;
            self._setWsStatus(true);
            self.terminal.appendLine('WebSocket connected.', 'success');
        };

        this.ws.onclose = function () {
            self._setWsStatus(false);
            self._scheduleReconnect();
        };

        this.ws.onerror = function () {
            self._setWsStatus(false);
        };

        this.ws.onmessage = function (event) {
            self.onMessage(event);
        };
    }

    /**
     * Handle incoming WebSocket messages.
     * Expected message format: { event: "string", data: { ... } }
     */
    onMessage(event) {
        var msg;
        try {
            msg = JSON.parse(event.data);
        } catch (e) {
            return;
        }

        var evType = msg.event || msg.type || '';
        var data = msg.data || {};

        switch (evType) {
            case 'command_started':
                this.terminal.appendLine(data.command || '', 'command');
                this._setAiStatus('busy');
                this._showThinking(true);
                break;

            case 'command_output':
                this.terminal.appendBlock(data.output || '', data.stream || 'stdout');
                break;

            case 'command_completed':
                this._showThinking(false);
                this._setAiStatus('idle');
                if (data.output) {
                    this.terminal.appendBlock(data.output, 'stdout');
                }
                this._incrementCommandCount();
                break;

            case 'command_error':
                this._showThinking(false);
                this._setAiStatus('idle');
                this.terminal.appendLine(data.error || 'Command failed', 'error');
                break;

            case 'ai_thinking':
                this._showThinking(true);
                this._setAiStatus('busy');
                break;

            case 'ai_response':
                this._showThinking(false);
                this._setAiStatus('idle');
                if (data.text) {
                    this.terminal.appendBlock(data.text, 'ai');
                }
                break;

            case 'new_finding':
                this.findingsPanel.addFinding(data);
                this._toast('New finding: ' + (data.title || 'Unknown'), 'info');
                break;

            case 'scan_result':
                if (data.hosts) {
                    this.scanViewer.renderPortTable(data);
                } else if (data.entries) {
                    this.scanViewer.renderDirectoryTree(data);
                }
                break;

            case 'token_update':
                this.updateTokenCounter(data.today || 0);
                break;

            case 'scan_progress':
                if (data.message) {
                    this.terminal.appendLine(data.message, 'system');
                }
                break;

            default:
                // Unknown event — log to terminal for debugging
                if (data.message) {
                    this.terminal.appendLine(data.message, 'system');
                }
        }
    }

    // ═══════════════ API Calls ═══════════════

    /**
     * Execute a command via the REST API.
     * @param {string} text  The command or natural language query.
     */
    executeCommand(text) {
        if (!text || !text.trim() || this.busy) return;

        text = text.trim();
        this.busy = true;

        // Add to history
        this.cmdHistory.push(text);
        if (this.cmdHistory.length > 100) this.cmdHistory.shift();
        this.cmdHistoryIdx = this.cmdHistory.length;

        // Show in terminal immediately
        this.terminal.appendLine(text, 'command');
        this._showThinking(true);
        this._setAiStatus('busy');
        this._setExecEnabled(false);

        var self = this;
        this._post('/api/command', { text: text })
            .then(function (resp) {
                self._showThinking(false);
                self._setAiStatus('idle');
                self.busy = false;
                self._setExecEnabled(true);

                if (!resp) return;

                // Display output
                if (resp.output) {
                    self.terminal.appendBlock(resp.output, 'stdout');
                }
                if (resp.ai_response) {
                    self.terminal.appendBlock(resp.ai_response, 'ai');
                }
                if (resp.error) {
                    self.terminal.appendLine(resp.error, 'error');
                }

                // If findings came back, add them
                if (resp.findings && resp.findings.length) {
                    for (var i = 0; i < resp.findings.length; i++) {
                        self.findingsPanel.addFinding(resp.findings[i]);
                    }
                }

                // If scan data came back, render it
                if (resp.scan_data) {
                    if (resp.scan_data.hosts) {
                        self.scanViewer.renderPortTable(resp.scan_data);
                    } else if (resp.scan_data.entries) {
                        self.scanViewer.renderDirectoryTree(resp.scan_data);
                    }
                }

                self._incrementCommandCount();
                self.refreshStats();
            })
            .catch(function (err) {
                self._showThinking(false);
                self._setAiStatus('idle');
                self.busy = false;
                self._setExecEnabled(true);
                self.terminal.appendLine('Error: ' + (err.message || 'Request failed'), 'error');
                self._toast('Command failed: ' + (err.message || 'Unknown error'), 'error');
            });
    }

    /** Fetch and display system status. */
    refreshStatus() {
        var self = this;
        this._get('/api/status')
            .then(function (data) {
                if (!data) return;
                self._setText('topbar-project', data.current_project || 'default');
                self._setText('topbar-provider', data.active_provider || '\u2014');
                self._setText('st-cmds', data.session_commands || 0);
                self._setText('st-finds', data.session_findings || 0);
                if (data.token_budget_remaining !== undefined) {
                    self.updateTokenCounter(data.tokens_today || 0);
                }
            })
            .catch(function () { /* silent */ });
    }

    /** Fetch and display all findings. */
    refreshFindings() {
        var self = this;
        this._get('/api/findings')
            .then(function (data) {
                if (data && Array.isArray(data)) {
                    self.findingsPanel.render(data);
                }
            })
            .catch(function () { /* silent */ });
    }

    /** Fetch and display token stats. */
    refreshStats() {
        var self = this;
        this._get('/api/stats')
            .then(function (data) {
                if (!data) return;
                var todayTokens = data.today_tokens || data.tokens_today || 0;
                var monthTokens = data.month_tokens || data.tokens_month || 0;
                var dailyLimit = data.daily_limit || 100000;
                var monthlyLimit = data.monthly_limit || 1000000;

                self._setText('topbar-tokens', todayTokens);
                self._setText('bar-today-val', todayTokens);
                self._setText('bar-month-val', monthTokens);

                var todayPct = Math.min((todayTokens / dailyLimit) * 100, 100);
                var monthPct = Math.min((monthTokens / monthlyLimit) * 100, 100);
                self._setWidth('bar-today', todayPct + '%');
                self._setWidth('bar-month', monthPct + '%');
            })
            .catch(function () { /* silent */ });
    }

    /** Fetch skills list and populate sidebar. */
    refreshSkills() {
        var self = this;
        this._get('/api/skills')
            .then(function (data) {
                if (!data || !Array.isArray(data)) return;
                var list = document.getElementById('skills-list');
                if (!list) return;
                list.innerHTML = '';
                for (var i = 0; i < data.length; i++) {
                    var skill = data[i];
                    var li = document.createElement('li');
                    li.className = 'sb-list-item';
                    li.dataset.skill = skill.name || skill;
                    li.innerHTML = '<span class="sb-dot"></span>' +
                        self._esc(skill.name || skill);
                    li.addEventListener('click', (function (name) {
                        return function () {
                            var input = document.getElementById('cmd-input');
                            input.value = 'skills info ' + name;
                            input.focus();
                        };
                    })(skill.name || skill));
                    list.appendChild(li);
                }
            })
            .catch(function () { /* silent — keep default skills in HTML */ });
    }

    /**
     * Generate a report.
     * @param {string} reportType  "pentest" | "bug_bounty" | "executive" | "ctf_writeup"
     */
    generateReport(reportType) {
        var self = this;
        this.terminal.appendLine('Generating ' + reportType + ' report...', 'system');
        this._showThinking(true);

        this._post('/api/report', { report_type: reportType, output_format: 'html' })
            .then(function (data) {
                self._showThinking(false);
                if (data && data.html) {
                    var reportEl = document.getElementById('report-content');
                    reportEl.innerHTML = '';
                    var iframe = document.createElement('iframe');
                    iframe.srcdoc = data.html;
                    iframe.style.cssText = 'width:100%;height:100%;border:none;background:#fff;border-radius:6px';
                    reportEl.appendChild(iframe);

                    // Switch to report tab
                    self._switchView('report');
                    self.terminal.appendLine('Report generated. View in Report tab.', 'success');
                    self._toast('Report generated successfully', 'success');
                } else if (data && data.path) {
                    self.terminal.appendLine('Report saved to: ' + data.path, 'success');
                    self._toast('Report saved: ' + data.path, 'success');
                } else {
                    self.terminal.appendLine('Report generation returned no data.', 'error');
                }
            })
            .catch(function (err) {
                self._showThinking(false);
                self.terminal.appendLine('Report generation failed: ' + (err.message || ''), 'error');
                self._toast('Report failed', 'error');
            });
    }

    /** Toggle dark/light theme. */
    toggleTheme() {
        var html = document.documentElement;
        var current = html.getAttribute('data-theme') || 'dark';
        var next = current === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        try {
            localStorage.setItem('nyxos-theme', next);
        } catch (e) { /* ignore */ }
    }

    /**
     * Update the token counter in the top bar.
     * @param {number} count
     */
    updateTokenCounter(count) {
        this._setText('topbar-tokens', count);
    }

    // ═══════════════ Private: Events ═══════════════

    /** Bind all UI event listeners. */
    _bindEvents() {
        var self = this;

        // Execute button
        var btnExec = document.getElementById('btn-exec');
        btnExec.addEventListener('click', function () {
            var input = document.getElementById('cmd-input');
            self.executeCommand(input.value);
            input.value = '';
            input.focus();
        });

        // Input: Enter to execute, Ctrl+L to clear, Up/Down for history
        var cmdInput = document.getElementById('cmd-input');
        cmdInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                self.executeCommand(cmdInput.value);
                cmdInput.value = '';
            } else if (e.key === 'l' && e.ctrlKey) {
                e.preventDefault();
                self.terminal.clear();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (self.cmdHistory.length > 0) {
                    self.cmdHistoryIdx = Math.max(0, self.cmdHistoryIdx - 1);
                    cmdInput.value = self.cmdHistory[self.cmdHistoryIdx] || '';
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (self.cmdHistoryIdx < self.cmdHistory.length - 1) {
                    self.cmdHistoryIdx++;
                    cmdInput.value = self.cmdHistory[self.cmdHistoryIdx] || '';
                } else {
                    self.cmdHistoryIdx = self.cmdHistory.length;
                    cmdInput.value = '';
                }
            }
        });

        // View tabs
        var tabs = document.querySelectorAll('.tab');
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].addEventListener('click', function () {
                self._switchView(this.dataset.view);
            });
        }

        // Theme toggle
        document.getElementById('btn-theme').addEventListener('click', function () {
            self.toggleTheme();
        });

        // Report button → open modal
        document.getElementById('btn-report').addEventListener('click', function () {
            self._showModal(true);
        });

        // Report modal cancel
        document.getElementById('btn-rpt-cancel').addEventListener('click', function () {
            self._showModal(false);
        });

        // Report modal background click to close
        var modalBg = document.querySelector('#report-modal .modal-bg');
        if (modalBg) {
            modalBg.addEventListener('click', function () {
                self._showModal(false);
            });
        }

        // Report modal generate
        document.getElementById('btn-rpt-go').addEventListener('click', function () {
            var select = document.getElementById('rpt-type');
            self.generateReport(select.value);
            self._showModal(false);
        });

        // Severity filter clicks
        var sevRows = document.querySelectorAll('.sev-row');
        for (var j = 0; j < sevRows.length; j++) {
            sevRows[j].addEventListener('click', function () {
                var sev = this.dataset.severity;
                self._filterFindings(sev);
            });
        }

        // Restore saved theme
        try {
            var saved = localStorage.getItem('nyxos-theme');
            if (saved) {
                document.documentElement.setAttribute('data-theme', saved);
            }
        } catch (e) { /* ignore */ }

        // Focus input on load
        cmdInput.focus();
    }

    // ═══════════════ Private: Helpers ═══════════════

    /** Schedule a WebSocket reconnect with exponential backoff. */
    _scheduleReconnect() {
        if (this._wsRetries >= this._wsMaxRetries) {
            this.terminal.appendLine('WebSocket: max reconnect attempts reached.', 'error');
            return;
        }
        var delay = Math.min(this._wsBaseDelay * Math.pow(2, this._wsRetries), 30000);
        this._wsRetries++;
        var self = this;
        clearTimeout(this._wsReconnectTimer);
        this._wsReconnectTimer = setTimeout(function () {
            self.connectWebSocket();
        }, delay);
    }

    /** Update WebSocket indicator. */
    _setWsStatus(connected) {
        var el = document.getElementById('ws-indicator');
        if (!el) return;
        if (connected) {
            el.className = 'ws-badge ws-on';
            el.querySelector('.ws-text').textContent = 'Connected';
        } else {
            el.className = 'ws-badge ws-off';
            el.querySelector('.ws-text').textContent = 'Disconnected';
        }
    }

    /** Show/hide AI thinking indicator. */
    _showThinking(show) {
        var el = document.getElementById('ai-thinking');
        if (el) {
            if (show) {
                el.classList.remove('hidden');
            } else {
                el.classList.add('hidden');
            }
        }
    }

    /** Set AI status pill. */
    _setAiStatus(status) {
        var el = document.getElementById('st-ai');
        if (!el) return;
        el.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        el.className = 'pill pill-' + status;
    }

    /** Enable/disable execute button. */
    _setExecEnabled(enabled) {
        var btn = document.getElementById('btn-exec');
        if (btn) btn.disabled = !enabled;
    }

    /** Switch visible view tab. */
    _switchView(viewName) {
        var tabs = document.querySelectorAll('.tab');
        var views = document.querySelectorAll('.view');
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].classList.toggle('active', tabs[i].dataset.view === viewName);
        }
        for (var j = 0; j < views.length; j++) {
            views[j].classList.toggle('active', views[j].id === 'view-' + viewName);
        }
    }

    /** Show or hide the report modal. */
    _showModal(show) {
        var modal = document.getElementById('report-modal');
        if (modal) {
            if (show) {
                modal.classList.remove('hidden');
            } else {
                modal.classList.add('hidden');
            }
        }
    }

    /** Increment the commands counter in sidebar. */
    _incrementCommandCount() {
        var el = document.getElementById('st-cmds');
        if (el) {
            el.textContent = parseInt(el.textContent || '0', 10) + 1;
        }
    }

    /** Filter findings list by severity (toggle). */
    _filterFindings(severity) {
        var cards = this.findingsPanel.container.querySelectorAll('.f-card');
        var allHidden = true;

        for (var i = 0; i < cards.length; i++) {
            var badge = cards[i].querySelector('.sev-badge');
            if (!badge) continue;
            var cardSev = badge.textContent.trim().toLowerCase();
            if (cardSev === severity) {
                cards[i].style.display = '';
                allHidden = false;
            }
        }

        // If all were already shown filtered, show everything (toggle off)
        if (allHidden) {
            for (var j = 0; j < cards.length; j++) {
                cards[j].style.display = '';
            }
        } else {
            // Hide non-matching
            for (var k = 0; k < cards.length; k++) {
                var b = cards[k].querySelector('.sev-badge');
                if (b && b.textContent.trim().toLowerCase() !== severity) {
                    cards[k].style.display = 'none';
                }
            }
        }
    }

    /** Set text content of an element by ID. */
    _setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    /** Set width style of an element by ID. */
    _setWidth(id, val) {
        var el = document.getElementById(id);
        if (el) el.style.width = val;
    }

    /** Escape HTML. */
    _esc(s) {
        var d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    /**
     * Show a toast notification.
     * @param {string} message
     * @param {'error'|'success'|'info'|'warning'} type
     */
    _toast(message, type) {
        type = type || 'info';
        var container = document.getElementById('toast-container');
        if (!container) return;

        var toast = document.createElement('div');
        toast.className = 'toast toast-' + type;
        toast.textContent = message;
        container.appendChild(toast);

        // Auto-remove after 4 seconds
        setTimeout(function () {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 4000);
    }

    // ═══════════════ Private: HTTP Helpers ═══════════════

    /**
     * GET request.
     * @param {string} path
     * @returns {Promise<object|null>}
     */
    _get(path) {
        var self = this;
        return fetch(this.apiBase.replace('/api', '') + path, {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
        }).then(function (resp) {
            if (!resp.ok) {
                throw new Error('HTTP ' + resp.status);
            }
            return resp.json();
        }).catch(function (err) {
            // Don't toast on every failed polling request
            return null;
        });
    }

    /**
     * POST request.
     * @param {string} path
     * @param {object} body
     * @returns {Promise<object>}
     */
    _post(path, body) {
        return fetch(this.apiBase.replace('/api', '') + path, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(body)
        }).then(function (resp) {
            if (!resp.ok) {
                return resp.text().then(function (t) {
                    throw new Error('HTTP ' + resp.status + ': ' + t);
                });
            }
            return resp.json();
        });
    }
}

// ═══════════════ Bootstrap ═══════════════
document.addEventListener('DOMContentLoaded', function () {
    window.nyxDashboard = new NyxDashboard();
    window.nyxDashboard.init();
});
