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

# ── 6. Solana C2 address in source files ──────────────────────────────────────
info "Checking for known GlassWorm Solana C2 wallet address in source files..."
SOLANA_ADDR="BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC"
if grep -r --include="*.py" --include="*.js" --include="*.ts" --include="*.json" \
    "$SOLANA_ADDR" . 2>/dev/null | grep -q .; then
    flag "Known GlassWorm Solana C2 address found in source files"
else
    ok "Solana C2 address not found"
fi
echo ""

# ── 7. Base64 blobs appended to Python entry points ──────────────────────────
info "Checking common Python entry points for appended Base64 payloads..."
for f in setup.py main.py app.py manage.py __init__.py; do
    if [ -f "$f" ]; then
        if grep -qP "[A-Za-z0-9+/]{100,}={0,2}" "$f" 2>/dev/null; then
            flag "Possible Base64 payload appended to $f"
        else
            ok "$f looks clean"
        fi
    fi
done
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
    echo -e "${YEL}[SKIP]${RST}  Not inside a git repository"
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
    echo -e "${YEL}[SKIP]${RST}  'ss' not available"
fi
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "${BLD}========================================${RST}"
if [ "$HITS" -gt 0 ]; then
    echo -e "${RED}${BLD}  $HITS indicator(s) found — investigate immediately${RST}"
    echo ""
    echo "  Recommended next steps:"
    echo "  1. Revoke GitHub, npm, and OpenVSX tokens immediately"
    echo "  2. Rotate any API keys stored in your environment"
    echo "  3. Check ~/.gitconfig and ~/.npmrc for unexpected changes"
    echo "  4. Report to your security team"
    echo "  5. See: https://www.truesec.com/hub/blog/glassworm-self-propagating-vscode-extension"
else
    echo -e "${GRN}${BLD}  No GlassWorm indicators found${RST}"
    echo ""
    echo "  Stay cautious: audit your VS Code extensions and"
    echo "  review any recently cloned Python repos manually."
fi
echo -e "${BLD}========================================${RST}"
