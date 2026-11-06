#!/usr/bin/env bash
# helios-suivi-backup.sh - archive le service de suivi (donnees, units, sudoers, Zabbix, scripts)
# Codes retour : 0 succes | 1 erreur interne | 2 autre instance en cours | 3 prerequis manquant
set -euo pipefail
IFS=$'\n\t'

readonly TAG="helios-suivi-backup"
readonly DEST="${HELIOS_BACKUP_DEST:-/srv/helios/archives/suivi}"
readonly KEEP=7
readonly REQUIRED=(
  /srv/helios/suivi
  /etc/systemd/system/helios-suivi.service
  /etc/systemd/system/helios-suivi-publish.service
  /etc/systemd/system/helios-suivi-publish.timer
  /etc/systemd/system/helios-suivi-backup.service
  /etc/systemd/system/helios-suivi-backup.timer
  /etc/sudoers.d/92-helios-suivi
  /etc/zabbix/zabbix_agent2.d/helios-suivi.conf
  /usr/local/sbin/helios-suivi-publish.sh
  /usr/local/sbin/helios-suivi-backup.sh
)
TMP=""

log() { logger -t "$TAG" -p "user.$1" -- "$2" || true; if [[ -t 2 ]]; then echo "[$1] $2" >&2; fi; }
die() { log err "$2"; exit "$1"; }
cleanup() { [[ -n "$TMP" ]] && rm -f -- "$TMP" "$TMP.sha256"; return 0; }
trap cleanup EXIT
trap 'log warning "interrompu par un signal"; exit 1' INT TERM

for c in logger flock tar sha256sum date mktemp sort tail; do
    command -v "$c" >/dev/null 2>&1 || { echo "commande absente: $c" >&2; exit 3; }
done
[[ -d "$DEST" && -w "$DEST" ]] || die 3 "destination non inscriptible: $DEST"
paths=()
for p in "${REQUIRED[@]}"; do
    [[ -e "$p" ]] || die 3 "element a sauvegarder absent: $p"
    paths+=("$p")
done
[[ -e /usr/local/sbin/helios-suivi-audit.sh ]] && paths+=(/usr/local/sbin/helios-suivi-audit.sh)

exec 9<"$DEST" || die 3 "impossible d'ouvrir $DEST"
flock -n 9 || { log warning "une autre instance tourne deja"; exit 2; }

umask 0027
name="suivi-$(date +%Y%m%d-%H%M%S).tar.gz"
TMP="$(mktemp "$DEST/.suivi.XXXXXX")" || die 3 "mktemp impossible"
tar --acls --xattrs --selinux --numeric-owner -czpf "$TMP" -- "${paths[@]}" 2>/dev/null \
    || die 1 "echec de tar"
tar -tzf "$TMP" >/dev/null || die 1 "archive illisible"
mv -f -- "$TMP" "$DEST/$name"; TMP=""
( cd "$DEST" && sha256sum -- "$name" > "$name.sha256" && sha256sum -c --quiet "$name.sha256" ) \
    || die 1 "empreinte invalide"
chown helios:helios -- "$DEST/$name" "$DEST/$name.sha256" 2>/dev/null || true
log info "archive creee: $name"

# --- retention : on garde les $KEEP plus recentes (les noms se trient par date)
mapfile -t old < <(find "$DEST" -maxdepth 1 -name 'suivi-????????-??????.tar.gz' -printf '%f\n' | sort -r | tail -n +"$((KEEP+1))")
for f in "${old[@]}"; do
    [[ -n "$f" ]] || continue
    rm -f -- "$DEST/$f" "$DEST/$f.sha256"
    log info "ancienne archive supprimee: $f"
done
exit 0
