#!/usr/bin/bash
# helios-watch-auth.sh — bloque les sources avec trop d'echecs d'authentification SSH.
# Sortie : 0 OK · 1 erreur interne · 2 verrou deja pris · 3 prerequis manquant
set -euo pipefail
IFS=$'\n\t'
readonly THRESHOLD=5
readonly WINDOW="-10min"
readonly IPSET=helios-blacklist
readonly STATE=/var/lib/helios/blocked.txt
readonly LOCK=/run/lock/helios-watch-auth.lock
readonly TAG=helios-watch-auth
readonly WHITELIST=(192.168.56.1)

log() { logger -t "$TAG" -p "daemon.${1}" -- "$2" ; }
die() { log err "$1" ; exit "${2:-1}" ; }
cleanup() { local rc=$? ; log info "fin d execution rc=${rc}" ; return 0 ; }
trap cleanup EXIT
trap 'die "interrompu par signal" 1' INT TERM

exec 9>"$LOCK"
flock -n 9 || { log warning "une autre instance tourne deja" ; exit 2 ; }

command -v firewall-cmd >/dev/null || die "firewall-cmd absent" 3
firewall-cmd --state >/dev/null 2>&1 || die "firewalld inactif" 3
touch "$STATE"

is_whitelisted() { local w ; for w in "${WHITELIST[@]}" ; do [[ "$1" == "$w" ]] && return 0 ; done ; return 1 ; }

# Reapplique les adresses deja bloquees (un reload ou un reboot vide l'ipset runtime)
current="$(firewall-cmd --ipset="$IPSET" --get-entries)"
while IFS= read -r ip ; do
    [[ -n "$ip" ]] || continue
    grep -qx -- "$ip" <<<"$current" || { firewall-cmd -q --ipset="$IPSET" --add-entry="$ip" ; log info "reapplique $ip" ; }
done < "$STATE"

# Echecs par adresse source sur la fenetre glissante
counts="$(journalctl -u sshd.service --since "$WINDOW" -o cat --no-pager 2>/dev/null \
  | sed -nE 's/^(Invalid user .* from|Failed [a-z-]+ for [^ ]+ from) ([0-9.]+) port .*/\2/p' \
  | sort | uniq -c | awk -v t="$THRESHOLD" '$1 > t {print $2" "$1}')" || true

while IFS=' ' read -r ip n ; do
    [[ -n "${ip:-}" ]] || continue
    if is_whitelisted "$ip" ; then log info "liste blanche : $ip ignore (${n} echecs)" ; continue ; fi
    grep -qx -- "$ip" "$STATE" && continue          # deja bloque : pas de seconde alerte
    firewall-cmd -q --ipset="$IPSET" --add-entry="$ip"
    echo "$ip" >> "$STATE"
    log warning "BLOQUE $ip : ${n} echecs d authentification SSH sur ${WINDOW#-}"
done <<<"$counts"
exit 0
