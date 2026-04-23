/**
 * NyxOS Dashboard — Findings Panel Component
 *
 * Renders security findings grouped by severity with expandable
 * detail cards, false-positive marking, and single-finding export.
 */

'use strict';

class FindingsPanel {
    /**
     * @param {HTMLElement} containerEl  The #findings-list element.
     */
    constructor(containerEl) {
        this.container = containerEl;

        /** @type {Array<object>} All findings currently rendered. */
        this.findings = [];

        /** @type {Set<string>} IDs of findings marked as false positive. */
        this.falsePositives = new Set();

        /** @type {Function|null} Called when false positive is toggled. */
        this.onFalsePositiveToggle = null;

        /** @type {Function|null} Called when export is clicked. */
        this.onExportFinding = null;
    }

    /**
     * Replace all findings and re-render.
     * @param {Array<object>} findings  Array of finding objects.
     *   Each: { id, type, title, severity, description, evidence, timestamp, recommendation }
     */
    render(findings) {
        this.findings = findings || [];
        this.container.innerHTML = '';

        if (this.findings.length === 0) {
            this.container.innerHTML =
                '<div class="empty-state" style="padding:40px 0">' +
                '<span class="empty-icon">&#x1F6E1;</span>' +
                '<p>No findings yet. Run a scan to discover vulnerabilities.</p>' +
                '</div>';
            this._updateCounts();
            return;
        }

        // Group by severity
        var groups = this._groupBySeverity(this.findings);
        var order = ['critical', 'high', 'medium', 'low', 'info'];

        for (var g = 0; g < order.length; g++) {
            var sev = order[g];
            var items = groups[sev];
            if (!items || items.length === 0) continue;

            for (var i = 0; i < items.length; i++) {
                var card = this._buildCard(items[i]);
                this.container.appendChild(card);
            }
        }

        this._updateCounts();
    }

    /**
     * Add a single finding (e.g. from WebSocket event) without full re-render.
     * @param {object} finding
     */
    addFinding(finding) {
        if (!finding || !finding.id) {
            finding = finding || {};
            finding.id = 'f-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7);
        }

        this.findings.push(finding);

        // Remove empty state if present
        var empty = this.container.querySelector('.empty-state');
        if (empty) empty.remove();

        // Insert card at the top
        var card = this._buildCard(finding);
        if (this.container.firstChild) {
            this.container.insertBefore(card, this.container.firstChild);
        } else {
            this.container.appendChild(card);
        }

        this._updateCounts();

        // Flash animation
        card.style.animation = 'tin .3s ease';
    }

    /**
     * Toggle expand/collapse of a finding detail.
     * @param {string} findingId
     */
    toggleDetail(findingId) {
        var card = this.container.querySelector('[data-finding-id="' + findingId + '"]');
        if (card) {
            card.classList.toggle('expanded');
        }
    }

    /**
     * Mark or unmark a finding as false positive.
     * @param {string} findingId
     */
    markFalsePositive(findingId) {
        var card = this.container.querySelector('[data-finding-id="' + findingId + '"]');
        if (!card) return;

        if (this.falsePositives.has(findingId)) {
            this.falsePositives.delete(findingId);
            card.classList.remove('false-positive');
        } else {
            this.falsePositives.add(findingId);
            card.classList.add('false-positive');
        }

        this._updateCounts();

        if (this.onFalsePositiveToggle) {
            this.onFalsePositiveToggle(findingId, this.falsePositives.has(findingId));
        }
    }

    /**
     * Export a single finding as JSON (triggers download).
     * @param {string} findingId
     */
    exportFinding(findingId) {
        var finding = null;
        for (var i = 0; i < this.findings.length; i++) {
            if (this.findings[i].id === findingId) {
                finding = this.findings[i];
                break;
            }
        }
        if (!finding) return;

        if (this.onExportFinding) {
            this.onExportFinding(finding);
            return;
        }

        // Default: download as JSON
        var json = JSON.stringify(finding, null, 2);
        var blob = new Blob([json], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'finding-' + findingId + '.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    /**
     * Get counts by severity (excluding false positives).
     * @returns {object} { critical: N, high: N, medium: N, low: N, info: N, total: N }
     */
    getCounts() {
        var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
        for (var i = 0; i < this.findings.length; i++) {
            var f = this.findings[i];
            if (this.falsePositives.has(f.id)) continue;
            var sev = (f.severity || 'info').toLowerCase();
            if (counts.hasOwnProperty(sev)) {
                counts[sev]++;
            } else {
                counts.info++;
            }
            counts.total++;
        }
        return counts;
    }

    // ─────────────────── Private ───────────────────

    /**
     * Build a finding card DOM element.
     * @param {object} finding
     * @returns {HTMLElement}
     */
    _buildCard(finding) {
        var card = document.createElement('div');
        card.className = 'f-card';
        card.dataset.findingId = finding.id;
        if (this.falsePositives.has(finding.id)) {
            card.classList.add('false-positive');
        }

        // Header (clickable to expand)
        var header = document.createElement('div');
        header.className = 'f-header';

        var badge = document.createElement('span');
        badge.className = 'sev-badge sb-' + (finding.severity || 'info').toLowerCase();
        badge.textContent = (finding.severity || 'INFO').toUpperCase();

        var title = document.createElement('span');
        title.className = 'f-title';
        title.textContent = finding.title || 'Untitled Finding';

        var arrow = document.createElement('span');
        arrow.className = 'f-arrow';
        arrow.textContent = '\u25B6';

        header.appendChild(badge);
        header.appendChild(title);
        header.appendChild(arrow);

        var self = this;
        header.addEventListener('click', function () {
            self.toggleDetail(finding.id);
        });

        card.appendChild(header);

        // Detail section (hidden by default)
        var detail = document.createElement('div');
        detail.className = 'f-detail';

        // Description
        if (finding.description) {
            detail.innerHTML +=
                '<div class="f-detail-sec">' +
                '<div class="f-detail-label">Description</div>' +
                '<div class="f-detail-text">' + this._esc(finding.description) + '</div>' +
                '</div>';
        }

        // Evidence
        if (finding.evidence) {
            detail.innerHTML +=
                '<div class="f-detail-sec">' +
                '<div class="f-detail-label">Evidence</div>' +
                '<div class="f-evidence">' + this._esc(finding.evidence) + '</div>' +
                '</div>';
        }

        // Recommendation
        if (finding.recommendation) {
            detail.innerHTML +=
                '<div class="f-detail-sec">' +
                '<div class="f-detail-label">Recommendation</div>' +
                '<div class="f-detail-text">' + this._esc(finding.recommendation) + '</div>' +
                '</div>';
        }

        // Timestamp
        if (finding.timestamp) {
            detail.innerHTML +=
                '<div class="f-detail-sec">' +
                '<div class="f-detail-label">Timestamp</div>' +
                '<div class="f-detail-text">' + this._esc(finding.timestamp) + '</div>' +
                '</div>';
        }

        // Action buttons
        var actions = document.createElement('div');
        actions.className = 'f-actions';

        var fpBtn = document.createElement('button');
        fpBtn.className = 'f-act-btn';
        fpBtn.textContent = this.falsePositives.has(finding.id) ? 'Unmark FP' : 'False Positive';
        fpBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            self.markFalsePositive(finding.id);
            fpBtn.textContent = self.falsePositives.has(finding.id) ? 'Unmark FP' : 'False Positive';
        });

        var expBtn = document.createElement('button');
        expBtn.className = 'f-act-btn';
        expBtn.textContent = 'Export';
        expBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            self.exportFinding(finding.id);
        });

        actions.appendChild(fpBtn);
        actions.appendChild(expBtn);
        detail.appendChild(actions);

        card.appendChild(detail);

        return card;
    }

    /**
     * Group findings array by severity.
     * @param {Array<object>} findings
     * @returns {object} { critical: [...], high: [...], ... }
     */
    _groupBySeverity(findings) {
        var groups = { critical: [], high: [], medium: [], low: [], info: [] };
        for (var i = 0; i < findings.length; i++) {
            var sev = (findings[i].severity || 'info').toLowerCase();
            if (!groups[sev]) sev = 'info';
            groups[sev].push(findings[i]);
        }
        return groups;
    }

    /**
     * Update the severity count badges in the sidebar summary.
     */
    _updateCounts() {
        var counts = this.getCounts();

        var ids = {
            'cnt-critical': counts.critical,
            'cnt-high': counts.high,
            'cnt-medium': counts.medium,
            'cnt-low': counts.low,
            'cnt-info': counts.info,
            'fp-total': counts.total,
            'st-finds': counts.total
        };

        for (var id in ids) {
            var el = document.getElementById(id);
            if (el) el.textContent = ids[id];
        }
    }

    /**
     * Escape HTML entities.
     * @param {string} s
     * @returns {string}
     */
    _esc(s) {
        var d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    /**
     * Generate a severity badge HTML string.
     * @param {string} severity
     * @returns {string}
     */
    _severityBadge(severity) {
        var sev = (severity || 'info').toLowerCase();
        return '<span class="sev-badge sb-' + sev + '">' + sev.toUpperCase() + '</span>';
    }
}
