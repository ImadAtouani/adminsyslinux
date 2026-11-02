#!/usr/bin/bash
# helios-archive.sh — archive la telemetrie du jour, purge au-dela de 14 jours.
# Sortie : 0 OK · 1 erreur interne · 2 verrou deja pris · 3 prerequis manquant
set -euo pipefail
IFS=$'\n\t'
readonly SRC=/var/lib/helios/telemetry.csv
readonly DEST=/var/lib/helios/archives
readonly RETENTION_DAYS=14
readonly LOCK=/run/lock/helios-archive.lock
readonly TAG=helios-archive

log() { logger -t "$TAG" -p "daemon.${1}" -- "$2" ; }
die() { log err "$1" ; exit "${2:-1}" ; }
cleanup() { local rc=$? ; [[ -n "${TMPD:-}" ]] && rm -rf -- "$TMPD"
            log info "fin d execution rc=${rc}" ; return 0 ; }
trap cleanup EXIT
trap 'die "interrompu par signal" 1' INT TERM

exec 9>"$LOCK"                       # verrou exclusif non bloquant
flock -n 9 || { log warning "une autre instance tourne deja" ; exit 2 ; }

command -v gzip >/dev/null || die "gzip absent" 3
[[ -r "$SRC" ]] || die "source illisible : $SRC" 3

log info "demarrage"
install -d -m 0750 -o helios -g helios "$DEST"
TMPD="$(mktemp -d /tmp/helios-archive.XXXXXX)"
stamp="$(date +%Y%m%d-%H%M%S)"
cp -- "$SRC" "${TMPD}/telemetry-${stamp}.csv"
: > "$SRC"
gzip -9 -- "${TMPD}/telemetry-${stamp}.csv"
install -m 0640 -o helios -g helios \
    "${TMPD}/telemetry-${stamp}.csv.gz" "${DEST}/telemetry-${stamp}.csv.gz"
log info "archive ${DEST}/telemetry-${stamp}.csv.gz ($(zcat "${DEST}/telemetry-${stamp}.csv.gz" | wc -l) lignes)"
purged=$(find "$DEST" -type f -name 'telemetry-*.csv.gz' -mtime "+${RETENTION_DAYS}" -printf . -delete | wc -c)
log info "purge : ${purged} archive(s) supprimee(s)"
exit 0
