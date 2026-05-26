#!/bin/sh
# Render subfinder/amass provider configs from env vars at container start,
# then exec "$@" (typically /app/server). Idempotent: safe to re-run.
#
# Seeds baked-in config files into the runtime config dirs when those dirs
# are empty (first start after switching to a named volume). Existing files
# are never overwritten, so user edits inside the volume survive restarts.
#
# Only rewrites provider-config.yaml when the template exists; otherwise leaves
# any user-baked config alone. Sources without their env var stay empty and
# are silently skipped by subfinder, so the absence of a key is never fatal.
set -eu

SRC_SUBFINDER=/app/recon-config/subfinder
SRC_AMASS=/app/recon-config/amass
DST_SUBFINDER=/home/appuser/.config/subfinder
DST_AMASS=/home/appuser/.config/amass

seed_dir() {
    src="$1"
    dst="$2"
    [ -d "$src" ] || return 0
    mkdir -p "$dst"
    # cp -n = never overwrite. Copies only files missing in the destination,
    # so user edits and runtime outputs (logs, *.bolt) inside the volume stay.
    # Skip the template itself — it's rendered separately below.
    for f in "$src"/*; do
        [ -e "$f" ] || continue
        base=$(basename "$f")
        case "$base" in
            provider-config.yaml.tmpl) continue ;;
        esac
        cp -n "$f" "$dst/$base" 2>/dev/null || true
    done
}

seed_dir "$SRC_SUBFINDER" "$DST_SUBFINDER"
seed_dir "$SRC_AMASS"     "$DST_AMASS"

TMPL="$SRC_SUBFINDER/provider-config.yaml.tmpl"
DEST="$DST_SUBFINDER/provider-config.yaml"

if [ -f "$TMPL" ]; then
    mkdir -p "$(dirname "$DEST")"
    # envsubst is the only safe way to expand ${VAR} without running the
    # template as shell. Empty vars expand to empty strings, which subfinder
    # accepts (the YAML list is empty and the source is skipped).
    envsubst < "$TMPL" > "$DEST"
    echo "[render-config] wrote $DEST"
fi

exec "$@"
