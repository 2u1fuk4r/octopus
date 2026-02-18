#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#  8PUS - Advanced Bug Bounty & Web Reconnaissance Framework
#  Version: 1.0
#  Author: Zulfukar Karabulut
#  GitHub: https://github.com/2u1fuk4r/octopus/
#  Linkedin: https://www.linkedin.com/in/2u1fuk4r/
#═══════════════════════════════════════════════════════════════════════════════

set -o pipefail

# -------------------- Colors --------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
GRAY='\033[0;90m'
NC='\033[0m'
BOLD='\033[1m'

# -------------------- Defaults --------------------
THREADS=100
TIMEOUT=10
MAX_DEPTH=3
RATE_LIMIT=150

SCREENSHOT=false
SKIP_XSS=false
CUSTOM_PAYLOADS=""
SILENT=false
VERBOSE=false

ONLY_SUBDOMAINS=false
ONLY_ALIVE=false
ONLY_URLS=false
ONLY_XSS=false
CHECK_ONLY=false

# performance profile (fast by default)
FAST_MODE=true
ALIVE_CAP=200
GAU_TIMEOUT=90
WAYBACK_TIMEOUT=90
KATANA_TIMEOUT=180

REQUIRE_ROOT=true

# -------------------- UI helpers --------------------
log()     { [ "$SILENT" = false ] && printf "%b\n" "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }
success() { [ "$SILENT" = false ] && printf "%b\n" "${GREEN}[✓]${NC} $*"; }
warning() { [ "$SILENT" = false ] && printf "%b\n" "${YELLOW}[!]${NC} $*"; }
error()   { printf "%b\n" "${RED}[✗]${NC} $*" >&2; }
info()    { [ "$VERBOSE" = true ] && printf "%b\n" "${CYAN}[i]${NC} $*"; }

phase_header() {
  local title="$1"
  echo ""
  printf "%b\n" "${CYAN}[${title}]${NC}"
}


# Spinner (for long-running commands that do NOT stream output)
SPINNER_PID=""
spinner_start() {
  local msg="$1"
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  # print initial line
  printf "%b" "[${frames[0]}] ${msg}..."
  (
    while true; do
      i=$(( (i + 1) % ${#frames[@]} ))
      printf "\r%b" "[${frames[$i]}] ${msg}..."
      sleep 0.12
    done
  ) &
  SPINNER_PID=$!
}
spinner_stop() {
  local status_msg="$1"
  if [ -n "${SPINNER_PID}" ] && kill -0 "${SPINNER_PID}" 2>/dev/null; then
    kill "${SPINNER_PID}" 2>/dev/null || true
    wait "${SPINNER_PID}" 2>/dev/null || true
  fi
  SPINNER_PID=""
  # clear line + print done
  printf "\r%b\n" "[${GREEN}✓${NC}] ${status_msg}"
}

# -------------------- Final summary (reusable) --------------------
show_final_summary() {
  # re-read counts from whatever has been saved so far
  _fc() { [ -f "$1" ] && wc -l < "$1" 2>/dev/null || echo 0; }
  SUBDOMAIN_COUNT="$(_fc "$SUBDIR_SUBDOMAINS/all_subdomains.txt")"
  ALIVE_COUNT="$(_fc "$SUBDIR_ALIVE/all_alive.txt")"
  URL_COUNT="$(_fc "$SUBDIR_URLS/all_urls.txt")"
  GET_COUNT="$(_fc "$SUBDIR_CATEG/get_params.txt")"
  CAND_COUNT="$(_fc "$SUBDIR_CATEG/reflected_params.txt")"
  JS_COUNT="$(_fc "$SUBDIR_CATEG/js_files.txt")"
  API_COUNT="$(_fc "$SUBDIR_CATEG/api_endpoints.txt")"
  REDIRECT_COUNT="$(_fc "$SUBDIR_CATEG/open_redirect.txt")"
  SENSITIVE_COUNT="$(_fc "$SUBDIR_CATEG/sensitive_data.txt")"
  ADMIN_COUNT="$(_fc "$SUBDIR_CATEG/admin_panels.txt")"
  UPLOAD_COUNT="$(_fc "$SUBDIR_CATEG/file_upload.txt")"
  SQLI_COUNT="$(_fc "$SUBDIR_CATEG/sqli_candidates.txt")"
  LFI_COUNT="$(_fc "$SUBDIR_CATEG/lfi_candidates.txt")"
  TOTAL_XSS="$(_fc "$SUBDIR_XSS/xss.txt")"

  # write report file if workspace exists
  if [ -n "${SUBDIR_REPORT:-}" ]; then
    REPORT_FILE="$SUBDIR_REPORT/REPORT.txt"
    mkdir -p "$SUBDIR_REPORT" 2>/dev/null || true
    cat > "$REPORT_FILE" << EOF
8PUS SCAN REPORT
========================
Target:      ${DOMAIN:-n/a}
Date:        $(date)
Threads:     ${THREADS:-n/a}
Timeout:     ${TIMEOUT:-n/a}s
Depth:       ${MAX_DEPTH:-n/a}
Rate limit:  ${RATE_LIMIT:-n/a}/s

── DISCOVERY ──────────────────────────────
Subdomains:        ${SUBDOMAIN_COUNT}
Alive hosts:       ${ALIVE_COUNT}
Total URLs:        ${URL_COUNT}
GET param URLs:    ${GET_COUNT}

── VULNERABILITY CANDIDATES ───────────────
XSS findings:      ${TOTAL_XSS}
XSS candidates:    ${CAND_COUNT}
SQLi candidates:   ${SQLI_COUNT}
LFI candidates:    ${LFI_COUNT}
Open redirect:     ${REDIRECT_COUNT}

── INTERESTING ENDPOINTS ──────────────────
JS files:          ${JS_COUNT}
API endpoints:     ${API_COUNT}
Admin panels:      ${ADMIN_COUNT}
File uploads:      ${UPLOAD_COUNT}
Sensitive files:   ${SENSITIVE_COUNT}

── ARTIFACTS ──────────────────────────────
Subdomains:        ${SUBDIR_SUBDOMAINS}/all_subdomains.txt
Alive hosts:       ${SUBDIR_ALIVE}/all_alive.txt
All URLs:          ${SUBDIR_URLS}/all_urls.txt
GET params:        ${SUBDIR_CATEG}/get_params.txt
XSS candidates:    ${SUBDIR_CATEG}/reflected_params.txt
SQLi candidates:   ${SUBDIR_CATEG}/sqli_candidates.txt
LFI candidates:    ${SUBDIR_CATEG}/lfi_candidates.txt
Open redirect:     ${SUBDIR_CATEG}/open_redirect.txt
JS files:          ${SUBDIR_CATEG}/js_files.txt
API endpoints:     ${SUBDIR_CATEG}/api_endpoints.txt
Admin panels:      ${SUBDIR_CATEG}/admin_panels.txt
File uploads:      ${SUBDIR_CATEG}/file_upload.txt
Sensitive files:   ${SUBDIR_CATEG}/sensitive_data.txt
XSS findings:      ${SUBDIR_XSS}/xss.txt
EOF
  fi

  echo ""
  printf "%b\n" "${GREEN}═══════════════════════════════════════════════════════════════════════════${NC}"
  printf "%b\n" "                        ${BOLD}FINAL SUMMARY${NC}"
  printf "%b\n" "${GREEN}═══════════════════════════════════════════════════════════════════════════${NC}"
  echo ""
  printf "%b\n" "${CYAN}  ── DISCOVERY ──────────────────────────────────────────────${NC}"
  printf "  %-22s %s\n" "Subdomains:"      "$SUBDOMAIN_COUNT"
  printf "  %-22s %s\n" "Alive hosts:"     "$ALIVE_COUNT"
  printf "  %-22s %s\n" "Total URLs:"      "$URL_COUNT"
  printf "  %-22s %s\n" "GET param URLs:"  "$GET_COUNT"
  echo ""
  printf "%b\n" "${RED}  ── VULNERABILITY CANDIDATES ────────────────────────────────${NC}"
  printf "  %-22s %b\n" "XSS findings:"    "${TOTAL_XSS:+${RED}}${TOTAL_XSS}${NC}"
  printf "  %-22s %s\n" "XSS candidates:"  "$CAND_COUNT"
  printf "  %-22s %s\n" "SQLi candidates:" "$SQLI_COUNT"
  printf "  %-22s %s\n" "LFI candidates:"  "$LFI_COUNT"
  printf "  %-22s %s\n" "Open redirect:"   "$REDIRECT_COUNT"
  echo ""
  printf "%b\n" "${YELLOW}  ── INTERESTING ENDPOINTS ───────────────────────────────────${NC}"
  printf "  %-22s %s\n" "JS files:"        "$JS_COUNT"
  printf "  %-22s %s\n" "API endpoints:"   "$API_COUNT"
  printf "  %-22s %s\n" "Admin panels:"    "$ADMIN_COUNT"
  printf "  %-22s %s\n" "File uploads:"    "$UPLOAD_COUNT"
  printf "  %-22s %s\n" "Sensitive files:" "$SENSITIVE_COUNT"
  echo ""
  # ---- generate xlsx ----
  if [ -n "${SUBDIR_REPORT:-}" ] && command -v python3 >/dev/null 2>&1; then
    local xlsx_out="$SUBDIR_REPORT/report.xlsx"
    # write python script to temp file so we can run it in background
    local py_script
    py_script="$(mktemp /tmp/recon_xlsx_XXXXXX.py)"
    cat > "$py_script" << 'PYEOF'
import sys, os
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

args = sys.argv[1:]
out_file = args[0]
files = {
  'subdomains':   args[1],
  'alive':        args[2],
  'all_urls':     args[3],
  'xss_cands':    args[4],
  'sqli':         args[5],
  'lfi':          args[6],
  'redirect':     args[7],
  'js':           args[8],
  'api':          args[9],
  'admin':        args[10],
  'uploads':      args[11],
  'sensitive':    args[12],
  'xss_found':    args[13],
}
domain = args[14]
counts = {k: int(v) for k, v in zip(
  ['subdomains','alive','urls','get','xss_cands','sqli','lfi','redirect',
   'js','api','admin','uploads','sensitive','xss_found'],
  args[15:]
)}

def read_file(path):
  try:
    with open(path) as f:
      return [l.strip() for l in f if l.strip()]
  except:
    return []

def hdr_fill(hex_color):
  return PatternFill('solid', start_color=hex_color, end_color=hex_color)

def thin_border():
  s = Side(style='thin', color='CCCCCC')
  return Border(left=s, right=s, top=s, bottom=s)

def style_header(cell, bg='1F3864', fg='FFFFFF'):
  cell.font = Font(bold=True, color=fg, name='Arial', size=10)
  cell.fill = hdr_fill(bg)
  cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
  cell.border = thin_border()

def style_cell(cell, color=None):
  cell.font = Font(name='Arial', size=9, color=color or '000000')
  cell.alignment = Alignment(vertical='center', wrap_text=False)
  cell.border = thin_border()

def add_url_sheet(wb, title, data, col_header, tab_color):
  ws = wb.create_sheet(title)
  ws.sheet_properties.tabColor = tab_color
  ws.row_dimensions[1].height = 22
  h = ws.cell(1, 1, col_header)
  style_header(h)
  ws.column_dimensions['A'].width = 90
  for i, row in enumerate(data, 2):
    c = ws.cell(i, 1, row)
    style_cell(c)
    ws.row_dimensions[i].height = 15
  return ws

wb = Workbook()
ws = wb.active
ws.title = 'Summary'
ws.sheet_properties.tabColor = '1F3864'
ws.column_dimensions['A'].width = 28
ws.column_dimensions['B'].width = 16

ws.merge_cells('A1:B1')
title_cell = ws['A1']
title_cell.value = f'8PUS — {domain}'
title_cell.font = Font(bold=True, name='Arial', size=13, color='FFFFFF')
title_cell.fill = hdr_fill('1F3864')
title_cell.alignment = Alignment(horizontal='center', vertical='center')
ws.row_dimensions[1].height = 28

sections = [
  ('DISCOVERY', '2E75B6', [
    ('Subdomains',      counts['subdomains']),
    ('Alive Hosts',     counts['alive']),
    ('Total URLs',      counts['urls']),
    ('GET Param URLs',  counts['get']),
  ]),
  ('VULNERABILITY CANDIDATES', 'C00000', [
    ('XSS Findings',    counts['xss_found']),
    ('XSS Candidates',  counts['xss_cands']),
    ('SQLi Candidates', counts['sqli']),
    ('LFI Candidates',  counts['lfi']),
    ('Open Redirect',   counts['redirect']),
  ]),
  ('INTERESTING ENDPOINTS', 'E2852A', [
    ('JS Files',        counts['js']),
    ('API Endpoints',   counts['api']),
    ('Admin Panels',    counts['admin']),
    ('File Uploads',    counts['uploads']),
    ('Sensitive Files', counts['sensitive']),
  ]),
]

row = 2
for sec_title, color, items in sections:
  ws.merge_cells(f'A{row}:B{row}')
  c = ws.cell(row, 1, sec_title)
  style_header(c, bg=color)
  ws.row_dimensions[row].height = 18
  row += 1
  for label, val in items:
    lc = ws.cell(row, 1, label)
    vc = ws.cell(row, 2, val)
    style_cell(lc, '2E2E2E')
    lc.font = Font(bold=False, name='Arial', size=9)
    vc.font = Font(bold=True, name='Arial', size=9,
                   color='C00000' if val > 0 and color == 'C00000' else '166534' if val > 0 else '6B7280')
    vc.alignment = Alignment(horizontal='center', vertical='center')
    vc.border = thin_border()
    lc.border = thin_border()
    ws.row_dimensions[row].height = 16
    row += 1

sheets_cfg = [
  ('All Subdomains',  'subdomains', '2E75B6', 'Subdomain'),
  ('Alive Hosts',     'alive',      '375623', 'URL'),
  ('All URLs',        'all_urls',   '1F3864', 'URL'),
  ('XSS Findings',    'xss_found',  'C00000', 'URL'),
  ('XSS Candidates',  'xss_cands',  'FF0000', 'URL'),
  ('SQLi Candidates', 'sqli',       'C55A11', 'URL'),
  ('LFI Candidates',  'lfi',        'C55A11', 'URL'),
  ('Open Redirect',   'redirect',   'E2852A', 'URL'),
  ('JS Files',        'js',         '7030A0', 'URL'),
  ('API Endpoints',   'api',        '0070C0', 'URL'),
  ('Admin Panels',    'admin',      'C00000', 'URL'),
  ('File Uploads',    'uploads',    'E2852A', 'URL'),
  ('Sensitive Files', 'sensitive',  'C00000', 'URL'),
]

for sheet_title, key, tab_color, col_hdr in sheets_cfg:
  data = read_file(files[key])
  add_url_sheet(wb, sheet_title, data, col_hdr, tab_color)

os.makedirs(os.path.dirname(out_file) if os.path.dirname(out_file) else '.', exist_ok=True)
wb.save(out_file)
PYEOF
    # ensure output dirs exist before python tries to read them
    mkdir -p "${SUBDIR_URLS:-/tmp}" "${SUBDIR_CATEG:-/tmp}" "${SUBDIR_XSS:-/tmp}" 2>/dev/null || true
    spinner_start "generating Excel report"
    python3 "$py_script" "$xlsx_out" \
      "${SUBDIR_SUBDOMAINS:-}/all_subdomains.txt" \
      "${SUBDIR_ALIVE:-}/all_alive.txt" \
      "${SUBDIR_URLS:-}/all_urls.txt" \
      "${SUBDIR_CATEG:-}/reflected_params.txt" \
      "${SUBDIR_CATEG:-}/sqli_candidates.txt" \
      "${SUBDIR_CATEG:-}/lfi_candidates.txt" \
      "${SUBDIR_CATEG:-}/open_redirect.txt" \
      "${SUBDIR_CATEG:-}/js_files.txt" \
      "${SUBDIR_CATEG:-}/api_endpoints.txt" \
      "${SUBDIR_CATEG:-}/admin_panels.txt" \
      "${SUBDIR_CATEG:-}/file_upload.txt" \
      "${SUBDIR_CATEG:-}/sensitive_data.txt" \
      "${SUBDIR_XSS:-}/xss.txt" \
      "$DOMAIN" "$SUBDOMAIN_COUNT" "$ALIVE_COUNT" "$URL_COUNT" \
      "$GET_COUNT" "$CAND_COUNT" "$SQLI_COUNT" "$LFI_COUNT" "$REDIRECT_COUNT" \
      "$JS_COUNT" "$API_COUNT" "$ADMIN_COUNT" "$UPLOAD_COUNT" "$SENSITIVE_COUNT" "$TOTAL_XSS" \
      2>/dev/null &
    _CHILD_PID=$!
    _XLSX_PID=$_CHILD_PID
    wait $_CHILD_PID 2>/dev/null || true
    local py_rc=$?
    _CHILD_PID=""
    _XLSX_PID=""
    rm -f "$py_script"
    if [ $py_rc -eq 0 ] && [ -f "$xlsx_out" ]; then
      spinner_stop "Excel report ready"
      printf "  %-22s %s\n" "Excel report:" "$xlsx_out"
    else
      spinner_stop "Excel report skipped (openpyxl not installed?)"
    fi
  fi

  echo ""
  printf "%b\n" "${GREEN}═══════════════════════════════════════════════════════════════════════════${NC}"
  [ -n "${WORKSPACE:-}" ]   && printf "  %-22s %s\n" "Output:"  "$WORKSPACE"
  [ -n "${REPORT_FILE:-}" ] && printf "  %-22s %s\n" "Report:"  "$REPORT_FILE"
  echo ""
}

# -------------------- CTRL+C trap --------------------
_CHILD_PID=""
_XLSX_PID=""
trap '_on_interrupt' INT TERM
_on_interrupt() {
  trap '' INT TERM  # ignore further signals
  echo ""
  warning "Interrupted! Saving collected data and generating report..."
  # stop spinner
  if [ -n "${SPINNER_PID:-}" ] && kill -0 "${SPINNER_PID}" 2>/dev/null; then
    kill "${SPINNER_PID}" 2>/dev/null || true
    wait "${SPINNER_PID}" 2>/dev/null || true
    SPINNER_PID=""
  fi
  # kill current foreground child tool
  for _pid in "${_CHILD_PID:-}" "${_XLSX_PID:-}"; do
    [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null && kill "$_pid" 2>/dev/null || true
  done
  _CHILD_PID=""; _XLSX_PID=""
  show_final_summary
  exit 0
}

sanitize_int() {
  local v="$1" def="$2"
  [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo "$def"
}

require_any_net_tool() {
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    error "Neither curl nor wget is installed. Please install one of them."
    exit 1
  fi
}

check_internet() {
  local urls=("https://1.1.1.1" "https://www.google.com" "https://github.com")
  for u in "${urls[@]}"; do
    if command -v curl >/dev/null 2>&1; then
      curl -kfsS --max-time 5 -I "$u" >/dev/null 2>&1 && return 0
    elif command -v wget >/dev/null 2>&1; then
      wget -q --spider --timeout=5 "$u" >/dev/null 2>&1 && return 0
    fi
  done
  return 1
}




check_tools() {
  log "Pre-flight checks..."
  require_any_net_tool

  log "Checking internet connectivity..."
  if check_internet; then
    success "Internet connectivity: OK"
  else
    error "No internet connectivity detected."
    exit 1
  fi

  log "Checking required tools..."
  local tools=("subfinder" "assetfinder" "httpx" "gau" "waybackurls" "katana" "dalfox")
  local missing=()

  echo ""
  echo "[TOOLS STATUS]"
  echo "────────────────────────────────────────"
  for t in "${tools[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then
      local p; p="$(command -v "$t")"
      printf "%b\n" "${GREEN}✓${NC} ${t}  (${p})"
    else
      printf "%b\n" "${RED}✗${NC} ${t}  (missing)"
      missing+=("$t")
    fi
  done
  echo ""

  if [ ${#missing[@]} -gt 0 ]; then
    warning "Missing tools: ${missing[*]}"
    warning "Scan continues, but phases may be skipped/limited."
  else
    success "All required tools are available."
  fi
  echo ""
}

print_banner() {
  [ "$SILENT" = true ] && return 0
  clear 2>/dev/null || true
  printf "%b\n" "${CYAN}"
  cat << "BANNER"
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║        █████╗ ██████╗ ██╗   ██╗███████╗                                 ║
║       ██╔══██╗██╔══██╗██║   ██║██╔════╝                                 ║
║       ╚█████╔╝██████╔╝██║   ██║███████╗                                 ║
║       ██╔══██╗██╔═══╝ ██║   ██║╚════██║                                 ║
║       ╚█████╔╝██║     ╚██████╔╝███████║                                 ║
║        ╚════╝ ╚═╝      ╚═════╝ ╚══════╝                                 ║
║                                                                          ║
║          🐙 Advanced Bug Bounty & Recon Framework 🐙                    ║
║                     Eight arms. One target.                              ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
BANNER
  printf "%b\n" "${NC}"
  printf "%b\n" "${GRAY}        Created by Zulfukar Karabulut | github.com/zkarabulut/8pus${NC}"
  echo ""
}

show_help() {
  print_banner
  cat << EOF
Usage:
  $0 -d <domain> [options]

Options:
  -d, --domain <domain>        Target domain
  -o, --output <dir>           Output directory (default: recon_<domain>_<ts>)
  -t, --threads <n>            Threads (default: 100)
  -T, --timeout <sec>          Request timeout (default: 10)
  -D, --depth <n>              Katana depth (default: 3)
  -r, --rate-limit <n>         Requests/s (default: 150)
  -p, --payloads <file>        Dalfox custom payload file
  -s, --silent                 Silent mode
  -v, --verbose                Verbose mode

Modes:
  --only-subdomains
  --only-alive
  --only-urls
  --only-xss
  --skip-xss
  --check-only                 Run pre-flight and exit

Performance:
  --fast                       Fast mode (default)
  --thorough                   More thorough (higher timeouts, no caps)
  --alive-cap=<n>              Limit alive hosts fed into URL collectors (default: 200)
  --gau-timeout=<sec>          (default: 90)
  --wayback-timeout=<sec>      (default: 90)
  --katana-timeout=<sec>       (default: 180)

Privilege:
  --no-sudo                    Do not auto-escalate to root

EOF
}


# Preserve original CLI args (needed for sudo re-exec)
ORIGINAL_ARGS=("$@")

# Auto sudo BEFORE parsing (so we don't lose args due to shift)
if [ "$REQUIRE_ROOT" = true ] && [ "${EUID:-$(id -u)}" -ne 0 ]; then
  # If user explicitly disabled, continue without sudo
  # Note: --no-sudo is parsed later; allow env override too.
  if printf "%s\0" "${ORIGINAL_ARGS[@]}" | grep -zq -- '--no-sudo'; then
    :
  else
    warning "Root privileges recommended. Re-running with sudo..."
    exec sudo -E bash "$0" "${ORIGINAL_ARGS[@]}"
  fi
fi

# -------------------- Args --------------------
DOMAIN=""
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
    -t|--threads) THREADS="$2"; shift 2 ;;
    -T|--timeout) TIMEOUT="$2"; shift 2 ;;
    -D|--depth) MAX_DEPTH="$2"; shift 2 ;;
    -r|--rate-limit) RATE_LIMIT="$2"; shift 2 ;;
    -p|--payloads) CUSTOM_PAYLOADS="$2"; shift 2 ;;
    -s|--silent) SILENT=true; shift ;;
    -v|--verbose) VERBOSE=true; shift ;;
    --skip-xss) SKIP_XSS=true; shift ;;
    --only-subdomains) ONLY_SUBDOMAINS=true; shift ;;
    --only-alive) ONLY_ALIVE=true; shift ;;
    --only-urls) ONLY_URLS=true; shift ;;
    --only-xss) ONLY_XSS=true; shift ;;
    --check-only) CHECK_ONLY=true; shift ;;
    --fast) FAST_MODE=true; shift ;;
    --thorough) FAST_MODE=false; shift ;;
    --alive-cap=*) ALIVE_CAP="${1#*=}"; shift ;;
    --gau-timeout=*) GAU_TIMEOUT="${1#*=}"; shift ;;
    --wayback-timeout=*) WAYBACK_TIMEOUT="${1#*=}"; shift ;;
    --katana-timeout=*) KATANA_TIMEOUT="${1#*=}"; shift ;;
    --no-sudo) REQUIRE_ROOT=false; shift ;;
    -h|--help) show_help; exit 0 ;;
    *) error "Unknown option: $1"; echo ""; echo "Use -h for help."; exit 1 ;;
  esac
done

if [ -z "$DOMAIN" ]; then
  show_help
  error "Domain is required. Example: bash $0 -d example.com"
  exit 1
fi

# sanitize
THREADS=$(sanitize_int "$THREADS" 100)
TIMEOUT=$(sanitize_int "$TIMEOUT" 10)
MAX_DEPTH=$(sanitize_int "$MAX_DEPTH" 3)
RATE_LIMIT=$(sanitize_int "$RATE_LIMIT" 150)
ALIVE_CAP=$(sanitize_int "$ALIVE_CAP" 200)
GAU_TIMEOUT=$(sanitize_int "$GAU_TIMEOUT" 90)
WAYBACK_TIMEOUT=$(sanitize_int "$WAYBACK_TIMEOUT" 90)
KATANA_TIMEOUT=$(sanitize_int "$KATANA_TIMEOUT" 180)

if [ "$FAST_MODE" = false ]; then
  GAU_TIMEOUT=600
  WAYBACK_TIMEOUT=600
  KATANA_TIMEOUT=900
  ALIVE_CAP=1000000
fi


print_banner
check_tools

if [ "$CHECK_ONLY" = true ]; then
  success "Pre-flight checks completed (--check-only)."
  exit 0
fi

# workspace
TS="$(date +%Y%m%d_%H%M%S)"
[ -z "$OUTPUT_DIR" ] && OUTPUT_DIR="recon_${DOMAIN}_${TS}"
WORKSPACE="$(pwd)/${OUTPUT_DIR}"
mkdir -p "$WORKSPACE" || { error "Cannot create output dir: $WORKSPACE"; exit 1; }

SUBDIR_SUBDOMAINS="$WORKSPACE/01_subdomains"
SUBDIR_ALIVE="$WORKSPACE/02_alive"
SUBDIR_URLS="$WORKSPACE/03_urls"
SUBDIR_CATEG="$WORKSPACE/04_categorized"
SUBDIR_XSS="$WORKSPACE/05_xss"
SUBDIR_REPORT="$WORKSPACE/06_report"

mkdir -p "$SUBDIR_SUBDOMAINS" "$SUBDIR_ALIVE" "$SUBDIR_URLS" "$SUBDIR_CATEG" "$SUBDIR_XSS" "$SUBDIR_REPORT"

log "Output directory: $WORKSPACE"

# -------------------- Phase 1: Subdomains --------------------
phase_header "PHASE 1 - SUBDOMAIN ENUMERATION"
: > "$SUBDIR_SUBDOMAINS/subfinder.txt"
: > "$SUBDIR_SUBDOMAINS/assetfinder.txt"
: > "$SUBDIR_SUBDOMAINS/all_subdomains.txt"

if [ "$ONLY_URLS" = false ] && [ "$ONLY_ALIVE" = false ] && [ "$ONLY_XSS" = false ]; then
  spinner_start "subfinder enumerating"
  if command -v subfinder >/dev/null 2>&1; then
    subfinder -d "$DOMAIN" -all -silent -o "$SUBDIR_SUBDOMAINS/subfinder.txt" >/dev/null 2>&1 || true
  fi
  spinner_stop "subfinder done ($(wc -l < "$SUBDIR_SUBDOMAINS/subfinder.txt" 2>/dev/null || echo 0))"
  while IFS= read -r line; do
    printf "%b\n" "    ${GRAY}${line}${NC}"
  done < "$SUBDIR_SUBDOMAINS/subfinder.txt" 2>/dev/null || true
  echo ""

  spinner_start "assetfinder enumerating"
  if command -v assetfinder >/dev/null 2>&1; then
    assetfinder --subs-only "$DOMAIN" 2>/dev/null | sort -u > "$SUBDIR_SUBDOMAINS/assetfinder.txt" || true
  fi
  spinner_stop "assetfinder done ($(wc -l < "$SUBDIR_SUBDOMAINS/assetfinder.txt" 2>/dev/null || echo 0))"
  while IFS= read -r line; do
    printf "%b\n" "    ${GRAY}${line}${NC}"
  done < "$SUBDIR_SUBDOMAINS/assetfinder.txt" 2>/dev/null || true
  echo ""

  cat "$SUBDIR_SUBDOMAINS/subfinder.txt" "$SUBDIR_SUBDOMAINS/assetfinder.txt" 2>/dev/null \
    | sed '/^\s*$/d' | grep -F "$DOMAIN" | sort -u > "$SUBDIR_SUBDOMAINS/all_subdomains.txt" || true

  SUBDOMAIN_COUNT="$(wc -l < "$SUBDIR_SUBDOMAINS/all_subdomains.txt" 2>/dev/null || echo 0)"
  if [ "$SUBDOMAIN_COUNT" -eq 0 ]; then
    warning "No subdomains found; adding base host(s)."
    printf "%s\n%s\n" "$DOMAIN" "www.$DOMAIN" > "$SUBDIR_SUBDOMAINS/all_subdomains.txt"
    SUBDOMAIN_COUNT=2
  fi
  success "Total subdomains: $SUBDOMAIN_COUNT"
  [ "$ONLY_SUBDOMAINS" = true ] && exit 0
else
  # bootstrap
  printf "%s\n%s\n" "$DOMAIN" "www.$DOMAIN" > "$SUBDIR_SUBDOMAINS/all_subdomains.txt"
  SUBDOMAIN_COUNT=2
  success "Total subdomains (bootstrap): $SUBDOMAIN_COUNT"
fi

# -------------------- Phase 2: Alive (httpx) --------------------
phase_header "PHASE 2 - ALIVE HOST DETECTION"
: > "$SUBDIR_ALIVE/httpx.txt"
: > "$SUBDIR_ALIVE/all_alive.txt"

spinner_start "httpx probing"
if command -v httpx >/dev/null 2>&1; then
  httpx -l "$SUBDIR_SUBDOMAINS/all_subdomains.txt" \
    -silent -threads "$THREADS" -timeout "$TIMEOUT" \
    -status-code -tech-detect \
    2>/dev/null | tee "$SUBDIR_ALIVE/httpx_verbose.txt" | cat > /dev/null || true
  # save only raw URLs for downstream tools
  awk '{print $1}' "$SUBDIR_ALIVE/httpx_verbose.txt" 2>/dev/null \
    | sed '/^\s*$/d' | sort -u > "$SUBDIR_ALIVE/httpx.txt" || true
else
  warning "httpx missing; cannot detect alive hosts."
fi
spinner_stop "httpx completed ($(wc -l < "$SUBDIR_ALIVE/httpx.txt" 2>/dev/null || echo 0) alive)"
# show verbose results with color by status code
while IFS= read -r line; do
  # status code is always the 2nd field: "https://url [CODE] [tech]"
  code="$(printf '%s' "$line" | awk '{print $2}' | tr -d '[]')"
  case "${code}" in
    2??) printf "%b\n" "    ${GREEN}${line}${NC}" ;;
    3??) printf "%b\n" "    ${YELLOW}${line}${NC}" ;;
    4??) printf "%b\n" "    ${RED}${line}${NC}" ;;
    5??) printf "%b\n" "    ${MAGENTA}${line}${NC}" ;;
    *)   printf "%b\n" "    ${GRAY}${line}${NC}" ;;
  esac
done < "$SUBDIR_ALIVE/httpx_verbose.txt" 2>/dev/null || true
echo ""

ALIVE_COUNT="$(wc -l < "$SUBDIR_ALIVE/httpx.txt" 2>/dev/null || echo 0)"
cp "$SUBDIR_ALIVE/httpx.txt" "$SUBDIR_ALIVE/all_alive.txt" 2>/dev/null || : > "$SUBDIR_ALIVE/all_alive.txt"
success "Total alive hosts: $ALIVE_COUNT"
[ "$ALIVE_COUNT" -eq 0 ] && { error "No alive hosts found."; exit 1; }
[ "$ONLY_ALIVE" = true ] && exit 0

# cap alive list for URL collectors
ALIVE_CAPPED="$SUBDIR_ALIVE/all_alive_capped.txt"
if [ "$ALIVE_CAP" -gt 0 ]; then
  head -n "$ALIVE_CAP" "$SUBDIR_ALIVE/all_alive.txt" > "$ALIVE_CAPPED" 2>/dev/null || : > "$ALIVE_CAPPED"
else
  cp "$SUBDIR_ALIVE/all_alive.txt" "$ALIVE_CAPPED" 2>/dev/null || : > "$ALIVE_CAPPED"
fi
ALIVE_CAP_COUNT="$(wc -l < "$ALIVE_CAPPED" 2>/dev/null || echo 0)"
log "Alive hosts used for URL collection: $ALIVE_CAP_COUNT"

# Extract hostnames (gau/waybackurls work best with hostnames, not full URLs)
ALIVE_HOSTS="$SUBDIR_ALIVE/all_alive_hosts.txt"
sed -E 's#^https?://##; s#/.*$##' "$ALIVE_CAPPED" 2>/dev/null | sed '/^\s*$/d' | sort -u > "$ALIVE_HOSTS" || : > "$ALIVE_HOSTS"
ALIVE_HOSTS_COUNT="$(wc -l < "$ALIVE_HOSTS" 2>/dev/null || echo 0)"
log "Alive hostnames for archive tools: $ALIVE_HOSTS_COUNT"

# -------------------- Phase 3: URL collection --------------------
phase_header "PHASE 3 - URL COLLECTION"
: > "$SUBDIR_URLS/gau.txt"
: > "$SUBDIR_URLS/wayback.txt"
: > "$SUBDIR_URLS/katana.txt"

spinner_start "gau collecting"
if command -v gau >/dev/null 2>&1; then
  if [ "$GAU_TIMEOUT" -gt 0 ]; then
    timeout "$GAU_TIMEOUT" gau --threads "$THREADS" --blacklist css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,webp,bmp,tiff \
      < "$ALIVE_HOSTS" 2>/dev/null \
      | grep -E "^https?://([a-zA-Z0-9-]+\.)*${DOMAIN}" \
      | sort -u >> "$SUBDIR_URLS/gau.txt" &
    _CHILD_PID=$!; wait $_CHILD_PID 2>/dev/null || true
  else
    gau --threads "$THREADS" --blacklist css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,webp,bmp,tiff \
      < "$ALIVE_HOSTS" 2>/dev/null \
      | grep -E "^https?://([a-zA-Z0-9-]+\.)*${DOMAIN}" | sort -u >> "$SUBDIR_URLS/gau.txt" &
    _CHILD_PID=$!; wait $_CHILD_PID 2>/dev/null || true
  fi
else
  warning "gau missing; skipping."
fi
_CHILD_PID=""
spinner_stop "gau done ($(wc -l < "$SUBDIR_URLS/gau.txt" 2>/dev/null || echo 0))"

spinner_start "waybackurls collecting"
if command -v waybackurls >/dev/null 2>&1; then
  if [ "$WAYBACK_TIMEOUT" -gt 0 ]; then
    timeout "$WAYBACK_TIMEOUT" waybackurls < "$ALIVE_HOSTS" 2>/dev/null \
      | grep -E "^https?://([a-zA-Z0-9-]+\.)*${DOMAIN}" \
      | sort -u >> "$SUBDIR_URLS/wayback.txt" &
    _CHILD_PID=$!; wait $_CHILD_PID 2>/dev/null || true
  else
    waybackurls < "$ALIVE_HOSTS" 2>/dev/null \
      | grep -E "^https?://([a-zA-Z0-9-]+\.)*${DOMAIN}" | sort -u >> "$SUBDIR_URLS/wayback.txt" &
    _CHILD_PID=$!; wait $_CHILD_PID 2>/dev/null || true
  fi
else
  warning "waybackurls missing; skipping."
fi
_CHILD_PID=""
spinner_stop "waybackurls done ($(wc -l < "$SUBDIR_URLS/wayback.txt" 2>/dev/null || echo 0))"

spinner_start "katana crawling"
if command -v katana >/dev/null 2>&1; then
  if [ "$KATANA_TIMEOUT" -gt 0 ]; then
    timeout "$KATANA_TIMEOUT" katana -list "$ALIVE_CAPPED" -d "$MAX_DEPTH" -silent -rl "$RATE_LIMIT" -concurrency "$THREADS" 2>/dev/null \
      | grep -E "^https?://([a-zA-Z0-9-]+\.)*${DOMAIN}" \
      | sort -u >> "$SUBDIR_URLS/katana.txt" &
    _CHILD_PID=$!; wait $_CHILD_PID 2>/dev/null || true
  else
    katana -list "$ALIVE_CAPPED" -d "$MAX_DEPTH" -silent -rl "$RATE_LIMIT" -concurrency "$THREADS" 2>/dev/null \
      | grep -E "^https?://([a-zA-Z0-9-]+\.)*${DOMAIN}" | sort -u >> "$SUBDIR_URLS/katana.txt" &
    _CHILD_PID=$!; wait $_CHILD_PID 2>/dev/null || true
  fi
else
  warning "katana missing; skipping."
fi
_CHILD_PID=""
spinner_stop "katana done ($(wc -l < "$SUBDIR_URLS/katana.txt" 2>/dev/null || echo 0))"

spinner_start "merging URL sources"
cat "$SUBDIR_URLS/gau.txt" "$SUBDIR_URLS/wayback.txt" "$SUBDIR_URLS/katana.txt" 2>/dev/null \
  | sed '/^\s*$/d' \
  | grep -E "^https?://" \
  | sort -u > "$SUBDIR_URLS/all_urls_raw.txt" || : > "$SUBDIR_URLS/all_urls_raw.txt"
RAW_URLS="$(wc -l < "$SUBDIR_URLS/all_urls_raw.txt" 2>/dev/null || echo 0)"
spinner_stop "merge completed (raw: $RAW_URLS)"

# final URL list (no 404 filtering)
cp "$SUBDIR_URLS/all_urls_raw.txt" "$SUBDIR_URLS/all_urls.txt" 2>/dev/null || : > "$SUBDIR_URLS/all_urls.txt"
URL_COUNT="$(wc -l < "$SUBDIR_URLS/all_urls.txt" 2>/dev/null || echo 0)"
success "Total unique URLs: $URL_COUNT"
[ "$URL_COUNT" -eq 0 ] && { error "No URLs collected."; exit 1; }
[ "$ONLY_URLS" = true ] && exit 0

# -------------------- Phase 4: Categorization --------------------
phase_header "PHASE 4 - URL CATEGORIZATION"
: > "$SUBDIR_CATEG/get_params.txt"
: > "$SUBDIR_CATEG/reflected_params.txt"
: > "$SUBDIR_CATEG/js_files.txt"
: > "$SUBDIR_CATEG/api_endpoints.txt"
: > "$SUBDIR_CATEG/open_redirect.txt"
: > "$SUBDIR_CATEG/sensitive_data.txt"
: > "$SUBDIR_CATEG/admin_panels.txt"
: > "$SUBDIR_CATEG/file_upload.txt"
: > "$SUBDIR_CATEG/sqli_candidates.txt"
: > "$SUBDIR_CATEG/lfi_candidates.txt"

spinner_start "categorizing URLs"

# GET params
grep "?" "$SUBDIR_URLS/all_urls.txt" 2>/dev/null \
  | sort -u > "$SUBDIR_CATEG/get_params.txt" || true

# XSS candidates
grep -iE '(\?|&)(q|query|search|s|term|keyword|id|url|redirect|next|return|page|name|text|input|value|data|content|msg|message|comment|title|desc|description)=' \
  "$SUBDIR_CATEG/get_params.txt" 2>/dev/null \
  | sort -u > "$SUBDIR_CATEG/reflected_params.txt" || true

# JavaScript files
grep -iE '\.js(\?|$)' "$SUBDIR_URLS/all_urls.txt" 2>/dev/null \
  | sort -u > "$SUBDIR_CATEG/js_files.txt" || true

# API endpoints
grep -iE '/(api|v1|v2|v3|v4|graphql|rest|service|services|endpoint|endpoints|rpc|ws|wss)(/|$|\?)' \
  "$SUBDIR_URLS/all_urls.txt" 2>/dev/null \
  | sort -u > "$SUBDIR_CATEG/api_endpoints.txt" || true

# Open redirect candidates
grep -iE '(\?|&)(url|redirect|next|return|returnurl|return_url|goto|dest|destination|target|redir|forward|continue|location|from)=' \
  "$SUBDIR_CATEG/get_params.txt" 2>/dev/null \
  | sort -u > "$SUBDIR_CATEG/open_redirect.txt" || true

# Sensitive data exposure
grep -iE '\.(env|config|conf|cfg|bak|backup|old|log|logs|sql|db|sqlite|sqlite3|dump|tar|zip|gz|7z|rar|pem|key|crt|cert|p12|pfx|json|xml|yaml|yml|toml|ini|htpasswd|htaccess|git|svn|DS_Store)(\?|$)' \
  "$SUBDIR_URLS/all_urls.txt" 2>/dev/null \
  | sort -u > "$SUBDIR_CATEG/sensitive_data.txt" || true

# Admin / login panels
grep -iE '/(admin|administrator|wp-admin|wp-login|login|signin|sign-in|panel|dashboard|cpanel|manager|manage|backend|backoffice|console|control|portal|phpmyadmin|adminer|setup|install|config)(/|$|\?)' \
  "$SUBDIR_URLS/all_urls.txt" 2>/dev/null \
  | sort -u > "$SUBDIR_CATEG/admin_panels.txt" || true

# File upload endpoints
grep -iE '/(upload|uploads|file|files|attach|attachment|attachments|media|import|fileupload|uploader)(/|$|\?)' \
  "$SUBDIR_URLS/all_urls.txt" 2>/dev/null \
  | sort -u > "$SUBDIR_CATEG/file_upload.txt" || true

# SQLi candidates
grep -iE '(\?|&)(id|uid|user_id|item|product|cat|category|order|sort|page|num|limit|offset|pid|aid|bid|cid|did|eid|fid|gid|hid|kid|mid|nid|oid|rid|sid|tid|vid|wid)=[0-9]' \
  "$SUBDIR_CATEG/get_params.txt" 2>/dev/null \
  | sort -u > "$SUBDIR_CATEG/sqli_candidates.txt" || true

# LFI candidates
grep -iE '(\?|&)(file|filename|path|page|include|inc|require|doc|document|template|layout|dir|folder|load|read|fetch|show|display|view|content|lang|language|locale|module|conf|config|theme|skin|style)=' \
  "$SUBDIR_CATEG/get_params.txt" 2>/dev/null \
  | sort -u > "$SUBDIR_CATEG/lfi_candidates.txt" || true

GET_COUNT="$(wc -l < "$SUBDIR_CATEG/get_params.txt" 2>/dev/null || echo 0)"
CAND_COUNT="$(wc -l < "$SUBDIR_CATEG/reflected_params.txt" 2>/dev/null || echo 0)"
JS_COUNT="$(wc -l < "$SUBDIR_CATEG/js_files.txt" 2>/dev/null || echo 0)"
API_COUNT="$(wc -l < "$SUBDIR_CATEG/api_endpoints.txt" 2>/dev/null || echo 0)"
REDIRECT_COUNT="$(wc -l < "$SUBDIR_CATEG/open_redirect.txt" 2>/dev/null || echo 0)"
SENSITIVE_COUNT="$(wc -l < "$SUBDIR_CATEG/sensitive_data.txt" 2>/dev/null || echo 0)"
ADMIN_COUNT="$(wc -l < "$SUBDIR_CATEG/admin_panels.txt" 2>/dev/null || echo 0)"
UPLOAD_COUNT="$(wc -l < "$SUBDIR_CATEG/file_upload.txt" 2>/dev/null || echo 0)"
SQLI_COUNT="$(wc -l < "$SUBDIR_CATEG/sqli_candidates.txt" 2>/dev/null || echo 0)"
LFI_COUNT="$(wc -l < "$SUBDIR_CATEG/lfi_candidates.txt" 2>/dev/null || echo 0)"

spinner_stop "categorization done"
echo ""
printf "%b\n" "${CYAN}  ── CATEGORIZATION RESULTS ──────────────────────────────────${NC}"
printf "  %-24s %s\n" "GET param URLs:"    "$GET_COUNT"
printf "  %-24s %s\n" "XSS candidates:"    "$CAND_COUNT"
printf "  %-24s %s\n" "SQLi candidates:"   "$SQLI_COUNT"
printf "  %-24s %s\n" "LFI candidates:"    "$LFI_COUNT"
printf "  %-24s %s\n" "Open redirect:"     "$REDIRECT_COUNT"
printf "  %-24s %s\n" "JS files:"          "$JS_COUNT"
printf "  %-24s %s\n" "API endpoints:"     "$API_COUNT"
printf "  %-24s %s\n" "Admin panels:"      "$ADMIN_COUNT"
printf "  %-24s %s\n" "File uploads:"      "$UPLOAD_COUNT"
printf "  %-24s %s\n" "Sensitive files:"   "$SENSITIVE_COUNT"
echo ""

# -------------------- Phase 5: XSS testing --------------------
phase_header "PHASE 5 - XSS TESTING"
: > "$SUBDIR_XSS/xss.txt"
TOTAL_XSS=0

if [ "$SKIP_XSS" = true ]; then
  warning "XSS testing skipped (--skip-xss)."
else
  if [ "$CAND_COUNT" -gt 0 ]; then
    spinner_start "dalfox testing (${CAND_COUNT} candidates)"
    if command -v dalfox >/dev/null 2>&1; then
      if [ -n "$CUSTOM_PAYLOADS" ] && [ -f "$CUSTOM_PAYLOADS" ]; then
        dalfox pipe --silence --skip-bav --custom-payload "$CUSTOM_PAYLOADS" \
          < "$SUBDIR_CATEG/reflected_params.txt" -o "$SUBDIR_XSS/xss.txt" 2>/dev/null &
      else
        dalfox pipe --silence --skip-bav \
          < "$SUBDIR_CATEG/reflected_params.txt" -o "$SUBDIR_XSS/xss.txt" 2>/dev/null &
      fi
      _CHILD_PID=$!; wait $_CHILD_PID 2>/dev/null || true; _CHILD_PID=""
      TOTAL_XSS="$(wc -l < "$SUBDIR_XSS/xss.txt" 2>/dev/null || echo 0)"
    else
      warning "dalfox missing; cannot test XSS."
    fi
    spinner_stop "dalfox completed (findings: $TOTAL_XSS)"
  else
    warning "No candidate URLs for XSS."
  fi
fi
[ "$ONLY_XSS" = true ] && exit 0

# -------------------- Phase 6: Report --------------------
phase_header "PHASE 6 - REPORT"
show_final_summary
success "Scan completed successfully!"
