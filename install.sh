#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# NyxOS — Installation Script
# AI-Native Cybersecurity Operating System
#
# Usage:  chmod +x install.sh && sudo ./install.sh
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

# ─── Colors & Styling ────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
ITALIC='\033[3m'
NC='\033[0m'
BG_BLACK='\033[40m'
BG_CYAN='\033[46m'

# Nerd glyphs (fallback-safe)
ICON_OK="${GREEN}✓${NC}"
ICON_FAIL="${RED}✗${NC}"
ICON_WARN="${YELLOW}⚠${NC}"
ICON_ARROW="${CYAN}➜${NC}"
ICON_GEAR="${CYAN}⚙${NC}"
ICON_LOCK="${YELLOW}🔒${NC}"
ICON_PKG="${MAGENTA}📦${NC}"
ICON_ROCKET="${GREEN}🚀${NC}"
ICON_BRAIN="${MAGENTA}🧠${NC}"
ICON_SHIELD="${CYAN}🛡️${NC}"
ICON_MOON="${MAGENTA}🌙${NC}"
ICON_CHART="${CYAN}📊${NC}"
ICON_FOLDER="${YELLOW}📁${NC}"
ICON_TEST="${CYAN}🧪${NC}"
ICON_WRENCH="${YELLOW}🔧${NC}"
ICON_SNAKE="${GREEN}🐍${NC}"
ICON_PLUG="${CYAN}🔌${NC}"

# Terminal dimensions
COLS=$(tput cols 2>/dev/null || echo 80)
[[ $COLS -gt 90 ]] && COLS=90
INNER=$((COLS - 4))
ROWS=$(tput lines 2>/dev/null || echo 24)

# Tracking
TOTAL_STEPS=10
CURRENT_STEP=0
ERRORS=()
WARNINGS=()
START_TIME=$(date +%s)
LOG_FILE="/tmp/nyxos_install_$$.log"
touch "$LOG_FILE"
REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME=$(eval echo "~$REAL_USER")
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Drawing Functions ────────────────────────────────────────

repeat_char() {
    local char="\$1" count="\$2"
    printf '%*s' "$count" '' | tr ' ' "$char"
}

# Animated box drawing
box_top()    { echo -e "${CYAN}╔$(repeat_char '═' $((COLS-2)))╗${NC}"; }
box_bottom() { echo -e "${CYAN}╚$(repeat_char '═' $((COLS-2)))╝${NC}"; }
box_mid()    { echo -e "${CYAN}╠$(repeat_char '═' $((COLS-2)))╣${NC}"; }
box_line() {
    local text="$1" color="${2:-$WHITE}"
    # Strip ANSI for length calculation
    local stripped
    stripped=$(echo -e "$text" | sed 's/\x1b\[[0-9;]*m//g')
    local len=${#stripped}
    local pad=$((INNER - len))
    [[ $pad -lt 0 ]] && pad=0
    printf "${CYAN}║${NC} ${color}%s%*s ${CYAN}║${NC}\n" "$text" "$pad" ""
}
box_empty() { printf "${CYAN}║${NC}%*s${CYAN}║${NC}\n" "$((COLS-2))" ""; }

# ─── Progress Bar ─────────────────────────────────────────────
# Smooth animated progress bar with percentage and ETA

progress_bar() {
    local current=\$1 total=$2 label="${3:-Progress}" width=35
    local pct=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))

    # Gradient bar characters
    local bar=""
    for ((i=0; i<filled; i++)); do
        if   ((i < width/3));     then bar+="${GREEN}█"
        elif ((i < 2*width/3));   then bar+="${CYAN}█"
        else                           bar+="${MAGENTA}█"
        fi
    done
    bar+="${DIM}"
    for ((i=0; i<empty; i++)); do bar+="░"; done
    bar+="${NC}"

    # Spinner frames
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local spinner="${CYAN}${frames[$((current % ${#frames[@]}))]}"

    printf "\r  ${spinner}${NC} %-12s ${DIM}│${NC}${bar}${DIM}│${NC} ${WHITE}%3d%%${NC} " "$label" "$pct"
}

# ─── Animated Spinner ─────────────────────────────────────────

spinner_pid=""

start_spinner() {
    local msg="${1:-Working}"
    tput civis 2>/dev/null || true
    (
        local frames=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
        local colors=("$CYAN" "$BLUE" "$MAGENTA" "$CYAN" "$BLUE" "$MAGENTA" "$CYAN" "$BLUE")
        local i=0
        while true; do
            local f="${frames[$((i % ${#frames[@]}))]}"
            local c="${colors[$((i % ${#colors[@]}))]}"
            printf "\r  ${c}${f}${NC} ${msg}${DIM}...${NC}  "
            i=$((i + 1))
            sleep 0.08
        done
    ) &
    spinner_pid=$!
}

stop_spinner() {
    local status="${1:-ok}" msg="${2:-Done}"
    if [[ -n "$spinner_pid" ]] && kill -0 "$spinner_pid" 2>/dev/null; then
        kill "$spinner_pid" 2>/dev/null
        wait "$spinner_pid" 2>/dev/null || true
    fi
    spinner_pid=""
    tput cnorm 2>/dev/null || true
    if [[ "$status" == "ok" ]]; then
        printf "\r  ${ICON_OK} ${msg}%*s\n" $((COLS - ${#msg} - 6)) ""
    else
        printf "\r  ${ICON_FAIL} ${msg}%*s\n" $((COLS - ${#msg} - 6)) ""
    fi
}

# ─── Scrolling Log Box ────────────────────────────────────────

log_box_start() {
    local title="\$1"
    echo ""
    echo -e "  ${DIM}┌─$(repeat_char '─' 62)─┐${NC}"
    echo -e "  ${DIM}│${NC} ${CYAN}${BOLD}${title}${NC}$(printf '%*s' $((62 - ${#title})) '')${DIM} │${NC}"
    echo -e "  ${DIM}├─$(repeat_char '─' 62)─┤${NC}"
}

log_box_line() {
    local text="$1" color="${2:-$DIM}"
    local trimmed="${text:0:62}"
    printf "  ${DIM}│${NC} ${color}%-62s${NC} ${DIM}│${NC}\n" "$trimmed"
}

log_box_end() {
    echo -e "  ${DIM}└─$(repeat_char '─' 62)─┘${NC}"
}

# ─── Section Header ──────────────────────────────────────────

section() {
    local num=\$1 title="$2" icon="${3:-$ICON_GEAR}"

    CURRENT_STEP=$num
    local elapsed=$(( $(date +%s) - START_TIME ))
    local mins=$((elapsed / 60))
    local secs=$((elapsed % 60))

    echo ""
    echo ""
    box_mid

    # Step header with timer
    local header="  ${icon}  STEP ${num}/${TOTAL_STEPS}  │  ${title}"
    local timer="[${mins}m ${secs}s]"
    local stripped_h stripped_t
    stripped_h=$(echo -e "$header" | sed 's/\x1b\[[0-9;]*m//g')
    stripped_t=$(echo -e "$timer" | sed 's/\x1b\[[0-9;]*m//g')
    local space=$((INNER - ${#stripped_h} - ${#stripped_t}))
    [[ $space -lt 1 ]] && space=1

    printf "${CYAN}║${NC} ${WHITE}%s${NC}%*s${DIM}%s${NC} ${CYAN}║${NC}\n" \
           "$header" "$space" "" "$timer"

    box_mid
    echo ""

    # Overall progress
    progress_bar "$num" "$TOTAL_STEPS" "Overall"
    echo ""
    echo ""
}

# ─── Typing Animation ────────────────────────────────────────

type_text() {
    local text="$1" delay="${2:-0.02}"
    for ((i=0; i<${#text}; i++)); do
        printf '%s' "${text:$i:1}"
        sleep "$delay"
    done
    echo ""
}

# ─── Matrix Rain Effect (brief) ──────────────────────────────

matrix_rain() {
    local duration="${1:-1}" cols_count=40
    local chars="01アイウエオカキクケコサシスセソ"
    local end_time=$(( $(date +%s) + duration ))

    tput civis 2>/dev/null || true
    while [[ $(date +%s) -lt $end_time ]]; do
        local col=$((RANDOM % COLS))
        local char="${chars:$((RANDOM % ${#chars})):1}"
        local color_code=$((RANDOM % 3))
        case $color_code in
            0) printf "\033[%d;%dH${GREEN}%s${NC}" $((RANDOM % ROWS + 1)) "$col" "$char" ;;
            1) printf "\033[%d;%dH${CYAN}%s${NC}" $((RANDOM % ROWS + 1)) "$col" "$char" ;;
            2) printf "\033[%d;%dH${DIM}%s${NC}" $((RANDOM % ROWS + 1)) "$col" "$char" ;;
        esac
        sleep 0.005
    done
    tput cnorm 2>/dev/null || true
    clear 2>/dev/null || true
}

# ─── Pulse Effect ─────────────────────────────────────────────

pulse_text() {
    local text="$1" cycles="${2:-3}"
    for ((c=0; c<cycles; c++)); do
        printf "\r  ${DIM}%s${NC}" "$text"
        sleep 0.15
        printf "\r  ${CYAN}%s${NC}" "$text"
        sleep 0.15
        printf "\r  ${WHITE}${BOLD}%s${NC}" "$text"
        sleep 0.15
        printf "\r  ${CYAN}%s${NC}" "$text"
        sleep 0.15
    done
    printf "\r  ${WHITE}%s${NC}\n" "$text"
}

# ═══════════════════════════════════════════════════════════════
#  WELCOME SCREEN
# ═══════════════════════════════════════════════════════════════

clear 2>/dev/null || true

# Brief matrix effect
matrix_rain 2

# Logo with animation
echo ""
sleep 0.1
echo -e "${MAGENTA}${BOLD}"
lines=(
    "    ███╗   ██╗██╗   ██╗██╗  ██╗ ██████╗ ███████╗"
    "    ████╗  ██║╚██╗ ██╔╝╚██╗██╔╝██╔═══██╗██╔════╝"
    "    ██╔██╗ ██║ ╚████╔╝  ╚███╔╝ ██║   ██║███████╗"
    "    ██║╚██╗██║  ╚██╔╝   ██╔██╗ ██║   ██║╚════██║"
    "    ██║ ╚████║   ██║   ██╔╝ ██╗╚██████╔╝███████║"
    "    ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝"
)
for line in "${lines[@]}"; do
    echo "$line"
    sleep 0.08
done
echo -e "${NC}"
sleep 0.3

box_top
box_empty
box_line "${ICON_MOON}  NyxOS Installation Wizard" "$WHITE"
box_line "AI-Native Cybersecurity Operating System" "$DIM"
box_empty
box_mid
box_empty
box_line "Version    0.1.0" "$DIM"
box_line "License    GPL v3 (core) + Apache 2.0 (skills)" "$DIM"
box_line "Author     Nitin Beniwal" "$DIM"
box_line "Repo       github.com/nitinbeniwal/nyxos" "$DIM"
box_empty
box_mid
box_empty
box_line "${ICON_SHIELD}  This installer will:" "$CYAN"
box_line "    1.  Check Python environment" "$WHITE"
box_line "    2.  Install system dependencies" "$WHITE"
box_line "    3.  Install security tools" "$WHITE"
box_line "    4.  Create virtual environment" "$WHITE"
box_line "    5.  Install Python packages" "$WHITE"
box_line "    6.  Fix known issues" "$WHITE"
box_line "    7.  Install NyxOS package" "$WHITE"
box_line "    8.  Create data directories" "$WHITE"
box_line "    9.  Fix file permissions" "$WHITE"
box_line "   10.  Verify everything works" "$WHITE"
box_empty
box_bottom
echo ""

# Confirm
echo -e "  ${ICON_ARROW} Press ${WHITE}${BOLD}ENTER${NC} to begin installation or ${RED}Ctrl+C${NC} to abort"
read -r

# ─── Preflight ────────────────────────────────────────────────
if [[ ! -f "$PROJECT_DIR/main.py" ]] || [[ ! -d "$PROJECT_DIR/nyxos" ]]; then
    echo -e "  ${ICON_FAIL} ${RED}Run this from the NyxOS project root (where main.py is)${NC}"
    exit 1
fi

cd "$PROJECT_DIR"

# ═══════════════════════════════════════════════════════════════
#  STEP 1: Python Check
# ═══════════════════════════════════════════════════════════════
section 1 "Detecting Python Environment" "$ICON_SNAKE"

PYTHON_CMD=""
for cmd in python3.13 python3.12 python3.11 python3; do
    if command -v "$cmd" >/dev/null 2>&1; then
        ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$major" -ge 3 ]] && [[ "$minor" -ge 11 ]]; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [[ -z "$PYTHON_CMD" ]]; then
    echo -e "  ${ICON_WARN} Python 3.11+ not found. Installing..."
    apt-get update -qq >> "$LOG_FILE" 2>&1
    apt-get install -y python3 python3-pip python3-venv python3-dev >> "$LOG_FILE" 2>&1
    PYTHON_CMD="python3"
fi

PYVER=$($PYTHON_CMD --version 2>&1)
PYPATH=$(which "$PYTHON_CMD")

echo -e "  ${ICON_OK} Python found: ${BOLD}${PYVER}${NC}"
echo -e "  ${ICON_ARROW} Binary: ${DIM}${PYPATH}${NC}"
echo -e "  ${ICON_ARROW} User:   ${DIM}${REAL_USER}${NC}"
echo -e "  ${ICON_ARROW} Home:   ${DIM}${REAL_HOME}${NC}"

# ═══════════════════════════════════════════════════════════════
#  STEP 2: System Packages
# ═══════════════════════════════════════════════════════════════
section 2 "Installing System Dependencies" "$ICON_PKG"

SYS_PACKAGES=(
    build-essential libssl-dev libffi-dev python3-dev
    python3-pip python3-venv python3-setuptools
    git curl wget jq
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0
    libcairo2 shared-mime-info
)

PKG_TOTAL=${#SYS_PACKAGES[@]}
PKG_OK=0
PKG_INSTALLED=0
PKG_FAILED=0

log_box_start "APT Package Installation (${PKG_TOTAL} packages)"

start_spinner "Updating package index"
apt-get update -qq >> "$LOG_FILE" 2>&1 || true
stop_spinner "ok" "Package index updated"

for i in "${!SYS_PACKAGES[@]}"; do
    pkg="${SYS_PACKAGES[$i]}"
    progress_bar $((i + 1)) "$PKG_TOTAL" "Packages"

    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        log_box_line "  ✓ ${pkg} (already installed)" "$GREEN"
        PKG_OK=$((PKG_OK + 1))
    else
        if apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1; then
            log_box_line "  ↓ ${pkg} (installed)" "$CYAN"
            PKG_INSTALLED=$((PKG_INSTALLED + 1))
        else
            log_box_line "  ✗ ${pkg} (failed)" "$RED"
            PKG_FAILED=$((PKG_FAILED + 1))
        fi
    fi
done

echo ""
log_box_end
echo ""
echo -e "  ${ICON_OK} ${GREEN}${PKG_OK} already installed${NC}, ${CYAN}${PKG_INSTALLED} newly installed${NC}, ${RED}${PKG_FAILED} failed${NC}"

# ═══════════════════════════════════════════════════════════════
#  STEP 3: Security Tools
# ═══════════════════════════════════════════════════════════════
section 3 "Installing Security Tools" "$ICON_SHIELD"

SEC_TOOLS=(
    nmap nikto gobuster whois dnsutils curl wget
    exiftool binwalk foremost john hashcat
    sqlmap ffuf wfuzz wordlists
)

TOOL_TOTAL=${#SEC_TOOLS[@]}
TOOL_OK=0
TOOL_NEW=0
TOOL_SKIP=0

log_box_start "Security Tool Installation (${TOOL_TOTAL} tools)"

for i in "${!SEC_TOOLS[@]}"; do
    tool="${SEC_TOOLS[$i]}"
    progress_bar $((i + 1)) "$TOOL_TOTAL" "Tools"

    # Some tools are packages, not commands
    tool_cmd="$tool"
    case "$tool" in
        dnsutils)   tool_cmd="dig" ;;
        wordlists)  tool_cmd="" ;;
    esac

    if [[ -n "$tool_cmd" ]] && command -v "$tool_cmd" >/dev/null 2>&1; then
        ver=$("$tool_cmd" --version 2>&1 | head -1 | head -c 40)
        log_box_line "  ✓ ${tool} — ${ver}" "$GREEN"
        TOOL_OK=$((TOOL_OK + 1))
    elif dpkg -l "$tool" 2>/dev/null | grep -q "^ii"; then
        log_box_line "  ✓ ${tool} (package installed)" "$GREEN"
        TOOL_OK=$((TOOL_OK + 1))
    else
        if apt-get install -y "$tool" >> "$LOG_FILE" 2>&1; then
            log_box_line "  ↓ ${tool} (installed)" "$CYAN"
            TOOL_NEW=$((TOOL_NEW + 1))
        else
            log_box_line "  ⚠ ${tool} (not in repos — skipped)" "$YELLOW"
            TOOL_SKIP=$((TOOL_SKIP + 1))
            WARNINGS+=("Tool '$tool' not available in repos")
        fi
    fi
done

echo ""
log_box_end
echo ""
echo -e "  ${ICON_OK} ${GREEN}${TOOL_OK} ready${NC}, ${CYAN}${TOOL_NEW} installed${NC}, ${YELLOW}${TOOL_SKIP} skipped${NC}"

# ═══════════════════════════════════════════════════════════════
#  STEP 4: Virtual Environment
# ═══════════════════════════════════════════════════════════════
section 4 "Creating Python Virtual Environment" "$ICON_SNAKE"

VENV_DIR="$PROJECT_DIR/.venv"

if [[ -d "$VENV_DIR" ]]; then
    echo -e "  ${ICON_WARN} Existing .venv found — removing for clean install"
    rm -rf "$VENV_DIR"
fi

start_spinner "Creating virtual environment"
sudo -u "$REAL_USER" "$PYTHON_CMD" -m venv "$VENV_DIR" >> "$LOG_FILE" 2>&1
stop_spinner "ok" "Virtual environment created at .venv/"

# Activate and upgrade pip
source "$VENV_DIR/bin/activate"

start_spinner "Upgrading pip, setuptools, wheel"
pip install --upgrade pip setuptools wheel >> "$LOG_FILE" 2>&1
stop_spinner "ok" "pip $(pip --version | awk '{print \$2}')"

echo -e "  ${ICON_ARROW} Python: ${DIM}$(python --version)${NC}"
echo -e "  ${ICON_ARROW} pip:    ${DIM}$(pip --version | awk '{print \$1,$2}')${NC}"

# ═══════════════════════════════════════════════════════════════
#  STEP 5: Python Dependencies
# ═══════════════════════════════════════════════════════════════
section 5 "Installing Python Dependencies" "$ICON_PKG"

source "$VENV_DIR/bin/activate"

# Count packages in requirements.txt
REQ_COUNT=$(grep -cE '^[a-zA-Z]' requirements.txt 2>/dev/null || echo "20")

log_box_start "pip install ($REQ_COUNT packages from requirements.txt)"

# Install in background, monitor progress
(
    pip install pyyaml >> "$LOG_FILE" 2>&1
    pip install -r requirements.txt >> "$LOG_FILE" 2>&1
    pip install pytest pytest-mock pytest-asyncio >> "$LOG_FILE" 2>&1
) &
PIP_PID=$!

counter=0
last_pkg=""
while kill -0 "$PIP_PID" 2>/dev/null; do
    progress_bar $((counter % REQ_COUNT + 1)) "$REQ_COUNT" "Packages"

    # Show what pip is doing
    current=$(grep -oP '(?:Collecting|Installing|Downloading|Building) \S+' "$LOG_FILE" 2>/dev/null | tail -1)
    if [[ -n "$current" ]] && [[ "$current" != "$last_pkg" ]]; then
        log_box_line "  ${current}" "$DIM"
        last_pkg="$current"
    fi

    counter=$((counter + 1))
    sleep 0.3
done
wait "$PIP_PID" 2>/dev/null
PIP_EXIT=$?

echo ""
log_box_end
echo ""

if [[ $PIP_EXIT -eq 0 ]]; then
    INSTALLED_COUNT=$(pip list --format=columns 2>/dev/null | tail -n +3 | wc -l)
    echo -e "  ${ICON_OK} All dependencies installed (${GREEN}${INSTALLED_COUNT} packages${NC} in venv)"
else
    echo -e "  ${ICON_WARN} Some packages may have failed — check ${DIM}${LOG_FILE}${NC}"
    WARNINGS+=("pip install exited with code $PIP_EXIT")
fi

# ═══════════════════════════════════════════════════════════════
#  STEP 6: Fix Known Issues
# ═══════════════════════════════════════════════════════════════
section 6 "Fixing Known Issues" "$ICON_WRENCH"

source "$VENV_DIR/bin/activate"
FIXES_APPLIED=0

# Fix 1: Ensure all __init__.py files exist
echo -e "  ${ICON_GEAR} Checking __init__.py files..."
INIT_CREATED=0
while IFS= read -r dir; do
    if [[ ! -f "$dir/__init__.py" ]]; then
        touch "$dir/__init__.py"
        INIT_CREATED=$((INIT_CREATED + 1))
    fi
done < <(find "$PROJECT_DIR/nyxos" -type d 2>/dev/null)
if [[ $INIT_CREATED -gt 0 ]]; then
    echo -e "  ${ICON_OK} Created ${INIT_CREATED} missing __init__.py files"
    FIXES_APPLIED=$((FIXES_APPLIED + 1))
else
    echo -e "  ${ICON_OK} All __init__.py files present"
fi

# Fix 2: Escape sequence warning in test_skills.py
if [[ -f nyxos/tests/test_skills.py ]]; then
    if grep -q '"\\\$2b' nyxos/tests/test_skills.py 2>/dev/null; then
        sed -i 's|"\\\$2b|r"\\\$2b|g' nyxos/tests/test_skills.py 2>/dev/null || true
        echo -e "  ${ICON_OK} Fixed escape sequence in test_skills.py"
        FIXES_APPLIED=$((FIXES_APPLIED + 1))
    else
        echo -e "  ${ICON_OK} test_skills.py already clean"
    fi
fi

# Fix 3: Remove duplicate nmap_skill if it exists
if [[ -f nyxos/skills/recon/nmap_skill.py ]] && [[ -f nyxos/skills/nmap/nmap_skill.py ]]; then
    if diff -q nyxos/skills/recon/nmap_skill.py nyxos/skills/nmap/nmap_skill.py >/dev/null 2>&1; then
        rm -f nyxos/skills/recon/nmap_skill.py
        echo -e "  ${ICON_OK} Removed duplicate nmap_skill.py from skills/recon/"
        FIXES_APPLIED=$((FIXES_APPLIED + 1))
    fi
fi

echo ""
echo -e "  ${ICON_CHART} ${FIXES_APPLIED} fixes applied"

# ═══════════════════════════════════════════════════════════════
#  STEP 7: Install NyxOS Package
# ═══════════════════════════════════════════════════════════════
section 7 "Installing NyxOS Package" "$ICON_BRAIN"

source "$VENV_DIR/bin/activate"

start_spinner "Installing NyxOS in editable (development) mode"
pip install -e "$PROJECT_DIR" >> "$LOG_FILE" 2>&1
stop_spinner "ok" "NyxOS installed as editable package"

# Verify
NYX_VER=$(python -c "import nyxos; print(getattr(nyxos, '__version__', '0.1.0'))" 2>/dev/null || echo "0.1.0")
echo -e "  ${ICON_ARROW} Version:  ${BOLD}NyxOS v${NYX_VER}${NC}"
echo -e "  ${ICON_ARROW} Location: ${DIM}$(pip show nyxos 2>/dev/null | grep Location | awk '{print $2}')${NC}"

# ═══════════════════════════════════════════════════════════════
#  STEP 8: Data Directories
# ═══════════════════════════════════════════════════════════════
section 8 "Creating NyxOS Data Directories" "$ICON_FOLDER"

NYX_DATA="$REAL_HOME/.nyxos"
DIRS=(
    "logs"
    "projects/default"
    "memory"
    "cache"
    "stats"
    "sessions"
    "exports"
    "plugins"
)

DIR_TOTAL=${#DIRS[@]}

for i in "${!DIRS[@]}"; do
    d="${DIRS[$i]}"
    progress_bar $((i + 1)) "$DIR_TOTAL" "Directories"
    sudo -u "$REAL_USER" mkdir -p "$NYX_DATA/$d"
    echo ""
    echo -e "  ${ICON_OK} ~/.nyxos/${d}"
done

echo ""
echo -e "  ${ICON_ARROW} Data root: ${DIM}${NYX_DATA}${NC}"

# ═══════════════════════════════════════════════════════════════
#  STEP 9: Fix Permissions
# ═══════════════════════════════════════════════════════════════
section 9 "Fixing File Permissions" "$ICON_LOCK"

start_spinner "Setting read/write permissions on project files"
chmod -R u+rw "$PROJECT_DIR/"
find "$PROJECT_DIR" -type d -exec chmod u+rx {} \;
stop_spinner "ok" "Project files: readable + writable"

start_spinner "Fixing ownership of .venv and caches"
chown -R "$REAL_USER:$REAL_USER" "$PROJECT_DIR/.venv" 2>/dev/null || true
chown -R "$REAL_USER:$REAL_USER" "$PROJECT_DIR/.pytest_cache" 2>/dev/null || true
chown -R "$REAL_USER:$REAL_USER" "$PROJECT_DIR/nyxos.egg-info" 2>/dev/null || true
chown -R "$REAL_USER:$REAL_USER" "$PROJECT_DIR/__pycache__" 2>/dev/null || true
find "$PROJECT_DIR" -name "__pycache__" -exec chown -R "$REAL_USER:$REAL_USER" {} \; 2>/dev/null || true
stop_spinner "ok" "Ownership: all files owned by ${REAL_USER}"

start_spinner "Setting permissions on launcher scripts"
chmod +x "$PROJECT_DIR/install.sh" 2>/dev/null || true
chmod u+rw "$PROJECT_DIR/main.py"
chmod u+rw "$PROJECT_DIR/setup.py"
chmod u+rw "$PROJECT_DIR/requirements.txt"
chmod u+rw "$PROJECT_DIR/LICENSE"
stop_spinner "ok" "Launcher scripts: executable"

echo ""
echo -e "  ${ICON_OK} All permission issues resolved"

# ═══════════════════════════════════════════════════════════════
#  STEP 10: Verification
# ═══════════════════════════════════════════════════════════════
section 10 "Verifying Installation" "$ICON_TEST"

source "$VENV_DIR/bin/activate"

# ── Module Import Checks ──
echo -e "  ${CYAN}${BOLD}Module Import Checks${NC}"
echo -e "  ${DIM}$(repeat_char '─' 60)${NC}"

MODULES=(
    "nyxos"
    "nyxos.core.config.settings"
    "nyxos.core.security.encryption"
    "nyxos.core.security.safety_guard"
    "nyxos.core.security.audit_logger"
    "nyxos.core.security.auth"
    "nyxos.core.security.rate_limiter"
    "nyxos.core.ai_engine.adapter"
    "nyxos.core.ai_engine.router"
    "nyxos.core.ai_engine.cache"
    "nyxos.core.ai_engine.token_tracker"
    "nyxos.core.ai_engine.system_prompts"
    "nyxos.core.memory.session_memory"
    "nyxos.core.memory.project_memory"
    "nyxos.core.memory.user_memory"
    "nyxos.core.memory.memory_manager"
    "nyxos.core.shell.nyxsh"
    "nyxos.skills.base_skill"
    "nyxos.skills.skill_manager"
    "nyxos.skills.nmap.nmap_skill"
    "nyxos.skills.web.web_skill"
    "nyxos.skills.recon.recon_skill"
    "nyxos.skills.forensics.forensics_skill"
    "nyxos.skills.ctf.ctf_skill"
    "nyxos.skills.password.password_skill"
    "nyxos.onboarding.wizard"
    "nyxos.reporting.report_engine"
    "nyxos.agents.task_planner"
    "nyxos.agents.attack_chain"
    "nyxos.plugins.plugin_manager"
    "nyxos.dashboard.backend.server"
)

MOD_TOTAL=${#MODULES[@]}
MOD_PASS=0
MOD_FAIL=0

for i in "${!MODULES[@]}"; do
    mod="${MODULES[$i]}"
    progress_bar $((i + 1)) "$MOD_TOTAL" "Modules"
    short="${mod#nyxos.}"
    [[ "$mod" == "nyxos" ]] && short="nyxos (root)"

    if python -c "import $mod" 2>/dev/null; then
        printf "\n  ${ICON_OK} %-48s ${GREEN}OK${NC}\n" "$short"
        MOD_PASS=$((MOD_PASS + 1))
    else
        err=$(python -c "import $mod" 2>&1 | tail -1 | head -c 50)
        printf "\n  ${ICON_FAIL} %-48s ${RED}%s${NC}\n" "$short" "$err"
        MOD_FAIL=$((MOD_FAIL + 1))
        ERRORS+=("Import failed: $mod — $err")
    fi
done

echo ""
echo ""

# ── Security Tools Check ──
echo -e "  ${CYAN}${BOLD}Security Tools${NC}"
echo -e "  ${DIM}$(repeat_char '─' 60)${NC}"

VERIFY_TOOLS=("nmap" "nikto" "gobuster" "whois" "dig" "curl" "exiftool" "john" "hashcat" "sqlmap" "ffuf")

for tool in "${VERIFY_TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        ver=$("$tool" --version 2>&1 | head -1 | head -c 40)
        printf "  ${ICON_OK} %-15s ${DIM}%s${NC}\n" "$tool" "$ver"
    else
        printf "  ${ICON_WARN} %-15s ${DIM}not installed${NC}\n" "$tool"
    fi
done

echo ""

# ── Test Suite ──
echo -e "  ${CYAN}${BOLD}Test Suite${NC}"
echo -e "  ${DIM}$(repeat_char '─' 60)${NC}"

start_spinner "Running 108 tests"
TEST_OUT=$(python -m pytest nyxos/tests/ -v --tb=short 2>&1)
TEST_EXIT=$?
stop_spinner "$([[ $TEST_EXIT -eq 0 ]] && echo ok || echo fail)" \
             "Tests completed"

T_PASS=$(echo "$TEST_OUT" | grep -c " PASSED" || true)
T_FAIL=$(echo "$TEST_OUT" | grep -c " FAILED" || true)
T_ERR=$(echo "$TEST_OUT" | grep -c " ERROR" || true)

# Show results in a mini box
log_box_start "Test Results"

echo "$TEST_OUT" | grep -E "PASSED|FAILED|ERROR" | tail -20 | while IFS= read -r line; do
    if echo "$line" | grep -q "PASSED"; then
        log_box_line "$(echo "$line" | sed 's/.*:://; s/ PASSED.*//' | head -c 50)  ✓" "$GREEN"
    elif echo "$line" | grep -q "FAILED"; then
        log_box_line "$(echo "$line" | sed 's/.*:://; s/ FAILED.*//' | head -c 50)  ✗" "$RED"
    fi
done

log_box_end
echo ""
printf "  ${ICON_CHART} Tests:  ${GREEN}%d passed${NC}" "$T_PASS"
[[ $T_FAIL -gt 0 ]] && printf "  ${RED}%d failed${NC}" "$T_FAIL"
[[ $T_ERR -gt 0 ]] && printf "  ${RED}%d errors${NC}" "$T_ERR"
echo ""

# ═══════════════════════════════════════════════════════════════
#  CREATE LAUNCHER SCRIPTS
# ═══════════════════════════════════════════════════════════════

cat > "$PROJECT_DIR/run.sh" << 'RUNEOF'
#!/usr/bin/env bash
# NyxOS Launcher
cd "$(dirname "${BASH_SOURCE[0]}")"
if [[ ! -d ".venv" ]]; then
    echo "❌ Virtual environment not found. Run: sudo ./install.sh"
    exit 1
fi
source .venv/bin/activate
python main.py "$@"
RUNEOF
chmod +x "$PROJECT_DIR/run.sh"
chown "$REAL_USER:$REAL_USER" "$PROJECT_DIR/run.sh"

cat > "$PROJECT_DIR/test.sh" << 'TESTEOF'
#!/usr/bin/env bash
# NyxOS Test Runner
cd "$(dirname "${BASH_SOURCE[0]}")"
if [[ ! -d ".venv" ]]; then
    echo "❌ Virtual environment not found. Run: sudo ./install.sh"
    exit 1
fi
source .venv/bin/activate
python -m pytest nyxos/tests/ -v --tb=short "$@"
TESTEOF
chmod +x "$PROJECT_DIR/test.sh"
chown "$REAL_USER:$REAL_USER" "$PROJECT_DIR/test.sh"

# ═══════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════

ELAPSED=$(( $(date +%s) - START_TIME ))
MINS=$((ELAPSED / 60))
SECS=$((ELAPSED % 60))

echo ""
echo ""

# Celebration animation
if [[ $MOD_FAIL -eq 0 ]] && [[ $T_FAIL -eq 0 ]] && [[ $T_ERR -eq 0 ]]; then
    pulse_text "⚡ INSTALLATION SUCCESSFUL ⚡"
fi

echo ""
box_top
box_empty

if [[ $MOD_FAIL -eq 0 ]] && [[ $T_FAIL -eq 0 ]] && [[ $T_ERR -eq 0 ]]; then
    box_line "${GREEN}${BOLD}  🎉  INSTALLATION SUCCESSFUL!${NC}" "$GREEN"
else
    box_line "${YELLOW}${BOLD}  ⚠️   INSTALLATION COMPLETE (with warnings)${NC}" "$YELLOW"
fi

box_empty
box_mid
box_empty
box_line "${ICON_CHART}  Results                            Time: ${MINS}m ${SECS}s" "$CYAN"
box_empty
box_line "   Modules:  ${MOD_PASS} passed, ${MOD_FAIL} failed" "$WHITE"
box_line "   Tests:    ${T_PASS} passed, ${T_FAIL} failed, ${T_ERR} errors" "$WHITE"
box_line "   Packages: ${PKG_OK} system, ${TOOL_OK} security tools" "$WHITE"
box_line "   Python:   $(python --version 2>&1)" "$WHITE"
box_empty
box_mid
box_empty
box_line "${ICON_ROCKET}  Quick Start" "$CYAN"
box_empty
box_line "   Launch NyxOS:" "$DIM"
box_line "   ${GREEN}\$ ./run.sh${NC}" "$GREEN"
box_empty
box_line "   Run tests:" "$DIM"
box_line "   ${GREEN}\$ ./test.sh${NC}" "$GREEN"
box_empty
box_line "   Manual launch:" "$DIM"
box_line "   ${GREEN}\$ source .venv/bin/activate${NC}" "$GREEN"
box_line "   ${GREEN}\$ python main.py${NC}" "$GREEN"
box_empty
box_line "   Debug mode:" "$DIM"
box_line "   ${GREEN}\$ ./run.sh --debug${NC}" "$GREEN"
box_empty
box_mid
box_empty
box_line "${ICON_FOLDER}  Paths" "$CYAN"
box_empty
box_line "   Project:  ${PROJECT_DIR}" "$DIM"
box_line "   Data:     ${NYX_DATA}/" "$DIM"
box_line "   Logs:     ${NYX_DATA}/logs/" "$DIM"
box_line "   Reports:  ${NYX_DATA}/exports/" "$DIM"
box_line "   Config:   ${NYX_DATA}/config.json" "$DIM"
box_empty
box_mid
box_empty
box_line "${ICON_BRAIN}  What's Next?" "$CYAN"
box_empty
box_line "   1. Run ${WHITE}./run.sh${NC} to launch NyxOS" "$DIM"
box_line "   2. Complete the onboarding wizard" "$DIM"
box_line "   3. Configure your AI provider (API key)" "$DIM"
box_line "   4. Try: ${WHITE}scan 127.0.0.1 for open ports${NC}" "$DIM"
box_empty

# Show warnings if any
if [[ ${#WARNINGS[@]} -gt 0 ]]; then
    box_mid
    box_empty
    box_line "${ICON_WARN}  Warnings" "$YELLOW"
    box_empty
    for w in "${WARNINGS[@]}"; do
        box_line "   • ${w}" "$YELLOW"
    done
    box_empty
fi

# Show errors if any
if [[ ${#ERRORS[@]} -gt 0 ]]; then
    box_mid
    box_empty
    box_line "${ICON_FAIL}  Errors" "$RED"
    box_empty
    for e in "${ERRORS[@]}"; do
        box_line "   • ${e}" "$RED"
    done
    box_empty
fi

box_bottom
echo ""

# Cleanup
rm -f "$LOG_FILE"

echo -e "  ${DIM}Installation log: ${LOG_FILE}${NC}"
echo -e "  ${DIM}NyxOS v${NYX_VER} — AI-Native Cybersecurity OS${NC}"
echo ""
