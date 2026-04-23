/**
 * NyxOS Dashboard — Terminal Component
 * Renders streaming command output with ANSI color support
 * and clickable IP/URL detection.
 */

class TerminalComponent {
    /**
     * @param {HTMLElement} containerEl - The #terminal-output element
     */
    constructor(containerEl) {
        /** @type {HTMLElement} */
        this.container = containerEl;

        /** @type {number} Maximum lines kept in buffer */
        this.maxLines = 5000;

        /** @type {number} Current line count */
        this.lineCount = 0;

        /** @type {Function|null} Callback when a clickable link is clicked */
        this.onLinkClick = null;

        // Print welcome banner on init
        this._printBanner();
    }

    /**
     * Append a line of output to the terminal.
     * @param {string} text - The text content
     * @param {'stdout'|'stderr'|'system'|'command'|'ai'|'error'|'success'} type - Line type
     */
    appendLine(text, type = 'stdout') {
        const line = document.createElement('span');
        line.classList.add('term-line', `term-line-${type}`);

        if (type === 'stdout' || type === 'stderr') {
            line.innerHTML = this._linkifyOutput(this._ansiToHtml(this._escapeHtml(text)));
        } else if (type === 'command') {
            line.textContent = text;
        } else if (type === 'ai') {
            line.innerHTML = this._escapeHtml(text);
        } else if (type === 'error') {
            line.textContent = text;
        } else {
            line.innerHTML = this._escapeHtml(text);
        }

        this.container.appendChild(line);
        this.lineCount++;

        // Prune old lines
        this._pruneIfNeeded();

        this.scrollToBottom();
    }

    /**
     * Append multiple lines at once (for batch output).
     * @param {string} text - Multi-line text
     * @param {'stdout'|'stderr'|'system'|'command'|'ai'|'error'|'success'} type
     */
    appendBlock(text, type = 'stdout') {
        if (!text) return;
        const lines = text.split('\n');
        // Use document fragment for performance
        const fragment = document.createDocumentFragment();

        for (const lineText of lines) {
            const line = document.createElement('span');
            line.classList.add('term-line', `term-line-${type}`);

            if (type === 'stdout' || type === 'stderr') {
                line.innerHTML = this._linkifyOutput(this._ansiToHtml(this._escapeHtml(lineText)));
            } else if (type === 'command') {
                line.textContent = lineText;
            } else {
                line.innerHTML = this._escapeHtml(lineText);
            }

            fragment.appendChild(line);
            this.lineCount++;
        }

        this.container.appendChild(fragment);
        this._pruneIfNeeded();
        this.scrollToBottom();
    }

    /**
     * Clear all terminal output.
     */
    clear() {
        this.container.innerHTML = '';
        this.lineCount = 0;
    }

    /**
     * Scroll terminal to the bottom.
     */
    scrollToBottom() {
        requestAnimationFrame(() => {
            this.container.scrollTop = this.container.scrollHeight;
        });
    }

    /**
     * Register a callback for when clickable IPs/URLs are clicked.
     * @param {Function} callback - Receives the clicked value (IP or URL)
     */
    setLinkClickHandler(callback) {
        this.onLinkClick = callback;
    }

    // ─── PRIVATE METHODS ───

    /**
     * Print the NyxOS ASCII banner.
     */
    _printBanner() {
        const banner = [
            '',
            '  ███╗   ██╗██╗   ██╗██╗  ██╗ ██████╗ ███████╗',
            '  ████╗  ██║╚██╗ ██╔╝╚██╗██╔╝██╔═══██╗██╔════╝',
            '  ██╔██╗ ██║ ╚████╔╝  ╚███╔╝ ██║   ██║███████╗',
            '  ██║╚██╗██║  ╚██╔╝   ██╔██╗ ██║   ██║╚════██║',
            '  ██║ ╚████║   ██║   ██╔╝ ██╗╚██████╔╝███████║',
            '  ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝',
            '',
	     'Created by - NITIN BENIWAL'	
            '  AI-Native Cybersecurity Operating System',
            '  Dashboard v0.1.0 — Type a command below to get started.',
            ''
        ];

        for (const line of banner) {
            this.appendLine(line, 'system');
        }
    }

    /**
     * Prune oldest lines if buffer exceeds maxLines.
     */
    _pruneIfNeeded() {
        while (this.lineCount > this.maxLines && this.container.firstChild) {
            this.container.removeChild(this.container.firstChild);
            this.lineCount--;
        }
    }

    /**
     * Escape HTML special characters.
     * @param {string} text
     * @returns {string}
     */
    _escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Convert ANSI escape codes to HTML spans.
     * Supports: 30-37 (colors), 1 (bold), 2 (dim), 4 (underline),
     * 90-97 (bright colors), 0 (reset).
     * @param {string} text - Already HTML-escaped text
     * @returns {string} HTML with span classes
     */
    _ansiToHtml(text) {
        // Match ANSI escape sequences: ESC[ ... m
        // After HTML escaping, the ESC char is still raw \x1b
        // But since we escaped HTML first, we need to handle raw text before escaping
        // Actually, let's re-approach: we should process ANSI *before* HTML-escaping the non-ANSI parts.
        // For simplicity, we'll work on the original text.

        // Since _escapeHtml was already called, we need to unescape, process, then safely build HTML.
        // Let's redo: we'll revert and process raw text.

        // Actually, the approach: parse segments separated by ANSI codes, escape each segment, wrap in spans.
        // Let's work with the assumption text is already escaped but ANSI codes survive because
        // they don't contain < > & characters.

        const ANSI_REGEX = /\x1b\[([0-9;]*)m/g;

        // If no ANSI codes, return as is
        if (!ANSI_REGEX.test(text)) {
            return text;
        }
        ANSI_REGEX.lastIndex = 0;

        const COLOR_MAP = {
            '30': 'ansi-black',
            '31': 'ansi-red',
            '32': 'ansi-green',
            '33': 'ansi-yellow',
            '34': 'ansi-blue',
            '35': 'ansi-magenta',
            '36': 'ansi-cyan',
            '37': 'ansi-white',
            '90': 'ansi-bright-black',
            '91': 'ansi-bright-red',
            '92': 'ansi-bright-green',
            '93': 'ansi-bright-yellow',
            '94': 'ansi-bright-blue',
            '95': 'ansi-bright-magenta',
            '96': 'ansi-bright-cyan',
            '97': 'ansi-bright-white',
        };

        const STYLE_MAP = {
            '1': 'ansi-bold',
            '2': 'ansi-dim',
            '4': 'ansi-underline',
        };

        let result = '';
        let lastIndex = 0;
        let activeClasses = [];
        let match;

        while ((match = ANSI_REGEX.exec(text)) !== null) {
            // Add text before this match
            const beforeText = text.substring(lastIndex, match.index);
            if (beforeText) {
                if (activeClasses.length > 0) {
                    result += `<span class="${activeClasses.join(' ')}">${beforeText}</span>`;
                } else {
                    result += beforeText;
                }
            }

            // Parse ANSI codes
            const codes = match[1].split(';').filter(Boolean);
            for (const code of codes) {
                if (code === '0' || code === '') {
                    activeClasses = [];
                } else if (COLOR_MAP[code]) {
                    // Remove existing color class, add new one
                    activeClasses = activeClasses.filter(c => !c.startsWith('ansi-') || c.startsWith('ansi-bold') || c.startsWith('ansi-dim') || c.startsWith('ansi-underline'));
                    activeClasses.push(COLOR_MAP[code]);
                } else if (STYLE_MAP[code]) {
                    if (!activeClasses.includes(STYLE_MAP[code])) {
                        activeClasses.push(STYLE_MAP[code]);
                    }
                }
            }

            lastIndex = ANSI_REGEX.lastIndex;
        }

        // Add remaining text
        const remainingText = text.substring(lastIndex);
        if (remainingText) {
            if (activeClasses.length > 0
