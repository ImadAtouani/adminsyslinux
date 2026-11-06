#!/usr/bin/env bash
# helios-suivi-publish.sh - publie www/etat.json a partir de la derniere ligne de telemetry.csv
# Codes retour : 0 succes | 1 erreur interne | 2 autre instance en cours | 3 prerequis manquant
set -euo pipefail
IFS=$'\n\t'

readonly TAG="helios-suivi-publish"
readonly TELEMETRY="${HELIOS_TELEMETRY:-/var/lib/helios/telemetry.csv}"
readonly WWW="${HELIOS_WWW:-/srv/helios/suivi/www}"
readonly OUT="$WWW/etat.json"
TMP=""

log() {   # log <niveau> <message>
    logger -t "$TAG" -p "user.$1" -- "$2" || true
    if [[ -t 2 ]]; then echo "[$1] $2" >&2; fi
}
die() { log err "$2"; exit "$1"; }
cleanup() { [[ -n "$TMP" && -e "$TMP" ]] && rm -f -- "$TMP"; return 0; }
trap cleanup EXIT
trap 'log warning "interrompu par un signal"; exit 1' INT TERM

# --- prerequis (rc 3) : verifies AVANT de prendre le verrou
for c in logger flock date hostname tail wc python3 mktemp; do
    command -v "$c" >/dev/null 2>&1 || { echo "commande absente: $c" >&2; exit 3; }
done
[[ -r "$TELEMETRY" ]] || die 3 "telemetrie illisible: $TELEMETRY"
[[ -d "$WWW" && -w "$WWW" ]] || die 3 "repertoire non inscriptible: $WWW"

# --- verrou exclusif sur le repertoire lui-meme (aucune ecriture necessaire) -> rc 2
exec 9<"$WWW" || die 3 "impossible d'ouvrir $WWW"
flock -n 9 || { log warning "une autre instance tourne deja"; exit 2; }

# --- lecture et validation de la derniere ligne -> rc 1
last="$(tail -n 1 -- "$TELEMETRY")"
IFS=',' read -r ts load mem extra <<<"$last"
[[ -z "${extra:-}" ]] || die 1 "ligne de telemetrie invalide (trop de champs): $last"
[[ "${ts:-}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[T\ ][0-9:.]+([+-][0-9:]+|Z)?$ ]] || die 1 "horodatage invalide: $last"
[[ "${load:-}" =~ ^[0-9]+(\.[0-9]+)?$ ]] || die 1 "charge invalide: $last"
[[ "${mem:-}" =~ ^[0-9]+$ ]] || die 1 "memoire invalide: $last"
n="$(wc -l < "$TELEMETRY")"

# --- ecriture atomique : temporaire dans le MEME repertoire, puis rename
TMP="$(mktemp "$WWW/.etat.json.XXXXXX")" || die 3 "mktemp impossible dans $WWW"
python3 -c '
import json, sys
g, h, d, l, m, n = sys.argv[1:7]
print(json.dumps({"genere": g, "hote": h, "derniere_mesure": d,
                  "charge_1min": float(l), "mem_dispo_ko": int(m), "mesures": int(n)}, indent=2))
' "$(date --iso-8601=seconds)" "$(hostname -s)" "$ts" "$load" "$mem" "$n" > "$TMP"
python3 -m json.tool "$TMP" >/dev/null || die 1 "JSON genere invalide"
chmod 0660 -- "$TMP"
mv -f -- "$TMP" "$OUT"
TMP=""
log info "etat.json publie (mesures=$n, derniere=$ts)"
exit 0
