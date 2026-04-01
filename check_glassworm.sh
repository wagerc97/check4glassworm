#!/bin/bash
# GlassWorm Infection Checker
# Based on indicators from Aikido, StepSecurity, Socket, and Truesec (March 2026)
# Run from your home directory: bash check_glassworm.sh

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
BLD='\033[1m'
RST='\033[0m'

HITS=0
SELF=$(basename "$0")

flag() {
    echo -e "${RED}[FOUND]${RST} $1"
    HITS=$((HITS + 1))
}

info() {
    echo -e "${YEL}[CHECK]${RST} $1"
}

ok() {
    echo -e "${GRN}[OK]${RST}    $1"
}

skip() {
    echo -e "${YEL}[SKIP]${RST}  $1"
}

echo -e "${BLD}========================================${RST}"
echo -e "${BLD}   GlassWorm Infection Checker          ${RST}"
echo -e "${BLD}========================================${RST}"
echo ""

# ── 1. Known malware marker variable ─────────────────────────────────────────
info "Searching for GlassWorm marker variable in current directory..."
if grep -r --include="*.py" --include="*.js" --include="*.ts" \
    "lzcdrtfxyqiplpd" . 2>/dev/null | grep -q .; then
    flag "GlassWorm marker 'lzcdrtfxyqiplpd' found in source files"
    grep -r --include="*.py" --include="*.js" --include="*.ts" \
        -l "lzcdrtfxyqiplpd" . 2>/dev/null
else
    ok "Marker variable not found"
fi
echo ""

# ── 2. Persistence file ───────────────────────────────────────────────────────
info "Checking for ~/init.json persistence file..."
if [ -f "$HOME/init.json" ]; then
    flag "Suspicious persistence file found: ~/init.json"
    echo "    Contents preview:"
    head -5 "$HOME/init.json" 2>/dev/null | sed 's/^/    /'
else
    ok "~/init.json not found"
fi
echo ""

# ── 3. Rogue Node.js installation ─────────────────────────────────────────────
info "Checking for unexpected Node.js installations in home directory..."
NODE_HITS=$(find "$HOME" -maxdepth 2 -name "node-v22*" -type d 2>/dev/null)
if [ -n "$NODE_HITS" ]; then
    flag "Unexpected Node.js found in home directory:"
    echo "$NODE_HITS" | sed 's/^/    /'
else
    ok "No rogue Node.js found in ~/"
fi
echo ""

# ── 4. Suspicious i.js files ──────────────────────────────────────────────────
info "Scanning for suspicious i.js files in recently cloned projects..."
IJS_HITS=$(find . -name "i.js" -not -path "*/node_modules/*" 2>/dev/null)
if [ -n "$IJS_HITS" ]; then
    flag "Suspicious i.js file(s) found:"
    echo "$IJS_HITS" | sed 's/^/    /'
else
    ok "No suspicious i.js files found"
fi
echo ""

# ── 5. Invisible Unicode characters in Python files ───────────────────────────
info "Checking Python files for invisible Unicode characters (GlassWorm obfuscation)..."
UNICODE_HITS=$(grep -rlP "[\x{E0000}-\x{E007F}\x{FFF0}-\x{FFFF}\x{200B}-\x{200F}]" \
    --include="*.py" --include="*.js" . 2>/dev/null)
if [ -n "$UNICODE_HITS" ]; then
    flag "Invisible Unicode characters found in:"
    echo "$UNICODE_HITS" | sed 's/^/    /'
else
    ok "No invisible Unicode characters found"
fi
echo ""

# ── 6. Solana C2 addresses in source files ────────────────────────────────────
info "Checking for known GlassWorm Solana C2 wallet addresses in source files..."
SOLANA_ADDRS=(
    "BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC"
    "28PKnu7RzizxBzFPoLp69HLXp9bJL3JFtT2s5QzHsEA2"
)
SOLANA_HIT=0
for SOLANA_ADDR in "${SOLANA_ADDRS[@]}"; do
    if grep -r --include="*.py" --include="*.js" --include="*.ts" --include="*.json" \
        "$SOLANA_ADDR" . 2>/dev/null | grep -q .; then
        flag "Known GlassWorm Solana C2 address found in source files: $SOLANA_ADDR"
        SOLANA_HIT=1
    fi
done
[ "$SOLANA_HIT" -eq 0 ] && ok "Solana C2 addresses not found"
echo ""

# ── 7. Base64 blobs appended to Python entry points ──────────────────────────
info "Checking common Python entry points for appended Base64 payloads..."
B64_CHECKED=0
for f in setup.py main.py app.py manage.py __init__.py; do
    if [ -f "$f" ]; then
        B64_CHECKED=$((B64_CHECKED + 1))
        if grep -qP "[A-Za-z0-9+/]{100,}={0,2}" "$f" 2>/dev/null; then
            flag "Possible Base64 payload appended to $f"
        else
            ok "$f looks clean"
        fi
    fi
done
[ "$B64_CHECKED" -eq 0 ] && skip "No Python entry point files found in current directory"
echo ""

# ── 8. Git history anomalies (committer date newer than author date) ───────────
info "Checking git log for suspicious force-push anomalies (last 20 commits)..."
if git rev-parse --is-inside-work-tree &>/dev/null; then
    ANOMALIES=$(git log --format="%H %ai %ci %s" -n 20 2>/dev/null | awk '
    {
        author_date=$2
        commit_date=$4
        if (commit_date > author_date) {
            print "  Suspicious commit: " $1 " | authored: " author_date " | committed: " commit_date
        }
    }')
    if [ -n "$ANOMALIES" ]; then
        flag "Git history anomalies detected (committer date newer than author date):"
        echo "$ANOMALIES"
    else
        ok "No git history anomalies found"
    fi
else
    skip "Not inside a git repository"
fi
echo ""

# ── 9. Suspicious outbound connections to known ports ─────────────────────────
info "Checking for suspicious active network connections..."
if command -v ss &>/dev/null; then
    SUSPICIOUS=$(ss -tnp 2>/dev/null | grep -E ":(4444|5555|8888|9999|1337)" || true)
    if [ -n "$SUSPICIOUS" ]; then
        flag "Suspicious outbound connections found:"
        echo "$SUSPICIOUS" | sed 's/^/    /'
    else
        ok "No suspicious connections on common RAT ports"
    fi
else
    skip "'ss' not available"
fi
echo ""

# ── 10. Active connections to known GlassWorm C2 IPs ─────────────────────────
info "Checking for active connections to known GlassWorm C2 servers..."
C2_IPS=("217.69.3.218" "140.82.52.31")
C2_HIT=0
if command -v ss &>/dev/null; then
    for IP in "${C2_IPS[@]}"; do
        CONN=$(ss -tnp 2>/dev/null | grep "$IP" || true)
        if [ -n "$CONN" ]; then
            flag "Active connection to GlassWorm C2 server $IP:"
            echo "$CONN" | sed 's/^/    /'
            C2_HIT=1
        fi
    done
    [ "$C2_HIT" -eq 0 ] && ok "No active connections to known C2 IPs"
else
    skip "'ss' not available"
fi
echo ""

# ── 11. GlassWorm C2 IPs / URLs in source files ───────────────────────────────
info "Checking source files for known GlassWorm C2 IPs and payload URLs..."
C2_PATTERNS=(
    "217\.69\.3\.218"
    "140\.82\.52\.31"
    "get_arhive_npm"
    "get_zombi_payload"
    "uhjdclolkdn@gmail\.com"
)
C2_SRC_HIT=0
for PAT in "${C2_PATTERNS[@]}"; do
    MATCHES=$(grep -r --include="*.py" --include="*.js" --include="*.ts" \
        --include="*.json" --include="*.sh" --exclude="$SELF" -l "$PAT" . 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        flag "C2 pattern '$PAT' found in:"
        echo "$MATCHES" | sed 's/^/    /'
        C2_SRC_HIT=1
    fi
done
[ "$C2_SRC_HIT" -eq 0 ] && ok "No C2 IPs or payload URLs found in source files"
echo ""

# ── 12. Google Calendar C2 references in source files ────────────────────────
info "Checking source files for Google Calendar C2 pattern..."
GCAL_PAT="calendar\.app\.google"
GCAL_HITS=$(grep -r --include="*.py" --include="*.js" --include="*.ts" \
    --include="*.json" --include="*.sh" --exclude="$SELF" -l "$GCAL_PAT" . 2>/dev/null || true)
if [ -n "$GCAL_HITS" ]; then
    flag "Google Calendar C2 reference found in:"
    echo "$GCAL_HITS" | sed 's/^/    /'
else
    ok "No Google Calendar C2 references found"
fi
echo ""

# ── 13. Windows Run-key persistence strings in source files ──────────────────
#info "Checking source files for Windows Run-key persistence strings..."
#RUNKEY_PAT="CurrentVersion\\\\Run"
#RUNKEY_HITS=$(grep -r --include="*.py" --include="*.js" --include="*.ts" \
#    --include="*.json" --include="*.sh" --exclude="$SELF" -l "$RUNKEY_PAT" . 2>/dev/null || true)
#if [ -n "$RUNKEY_HITS" ]; then
#    flag "Windows Run-key persistence string found in:"
#    echo "$RUNKEY_HITS" | sed 's/^/    /'
#else
#    ok "No Windows Run-key persistence strings found"
#fi
#echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "${BLD}========================================================${RST}"
if [ "$HITS" -gt 0 ]; then
    echo -e "${RED}${BLD}  $HITS indicator(s) found — investigate immediately${RST}"
    echo ""
    echo "  Recommended next steps:"
    echo "  1. Revoke GitHub, npm, and OpenVSX tokens immediately"
    echo "  2. Rotate any API keys stored in your environment"
    echo "  3. Check ~/.gitconfig and ~/.npmrc for unexpected changes"
    echo "  4. Block outbound traffic to 217.69.3.218 and 140.82.52.31"
    echo "  5. Report to your security team"
    echo ""
    echo "  Known C2 infrastructure:"
    echo "    Primary C2:        217.69.3.218"
    echo "    Exfil endpoint:    140.82.52.31:80/wall"
    echo "    Solana wallets:    BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC"
    echo "                       28PKnu7RzizxBzFPoLp69HLXp9bJL3JFtT2s5QzHsEA2"
    echo "    Calendar C2 org:   uhjdclolkdn@gmail.com"
else
    echo -e "${GRN}${BLD}  No GlassWorm indicators found${RST}"
    echo ""
    echo "  Stay cautious: audit your VS Code extensions and"
    echo "  review any recently cloned Python repos manually."
fi
echo -e "${BLD}========================================================${RST}"
